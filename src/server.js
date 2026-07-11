const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
require("dotenv").config();

const store = require("./db");
const { renderPortal, getTemplate, saveTemplate } = require("./template");
const { activeSessions, disconnectUser, renderSetupScript, renderDiscoveryScript, routerById, routerSnapshot } = require("./mikrotik");
const pesapal = require("./pesapal");
const { startRadiusServers } = require("./radius-server");

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

const publicBaseUrl = process.env.PUBLIC_BASE_URL || `http://localhost:${process.env.PORT || 3000}`;

function requireAccount(req, res, next) {
  const account = store.accountBySlug(req.params.slug);
  if (!account) return res.status(404).json({ success: false, message: "Unknown account." });
  req.account = account;
  next();
}

function makeVoucherCode(prefix = "") {
  const chars = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
  let code = prefix;
  for (let i = 0; i < 8; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

function isIPv4(value) {
  const parts = String(value || "").trim().split(".");
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function maskCode(code) {
  return code.slice(0, 4) + "****" + code.slice(-2);
}

function secondsToDuration(seconds) {
  const s = Math.max(0, Number(seconds || 0));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  return `${m}m`;
}

function readPesapalTrackingId(req) {
  return (
    req.query.OrderTrackingId ||
    req.query.orderTrackingId ||
    req.query.order_tracking_id ||
    req.query.OrderTrackingID ||
    req.body?.OrderTrackingId ||
    req.body?.orderTrackingId ||
    req.body?.order_tracking_id ||
    ""
  );
}

function readPesapalMerchantReference(req) {
  return (
    req.query.OrderMerchantReference ||
    req.query.orderMerchantReference ||
    req.query.merchant_reference ||
    req.query.MerchantReference ||
    req.body?.OrderMerchantReference ||
    req.body?.orderMerchantReference ||
    req.body?.merchant_reference ||
    req.body?.MerchantReference ||
    ""
  );
}

function ensurePaidVoucher(order, statusResult) {
  if (!order) throw new Error("Payment order not found.");
  if (order.voucher_code) return store.getVoucher(order.account_id, order.voucher_code);
  const code = makeVoucherCode("PAY");
  const voucher = store.createVoucher(order.account_id, code, order.plan_id, order.order_tracking_id || order.merchant_reference);
  store.recordRevenue(order.account_id, voucher.code, voucher.plan_id, "mobile_money");
  store.markPaymentOrder({
    merchantReference: order.merchant_reference,
    status: "paid",
    rawStatus: statusResult.rawStatus,
    voucherCode: voucher.code
  });
  return voucher;
}

app.get("/health", (req, res) => res.json({ ok: true }));

app.get("/api/provisioning/check-in/:token", (req, res) => {
  const router = store.routerByCheckinToken(req.params.token);
  if (!router) return res.status(404).json({ success: false, message: "Invalid router check-in token." });
  const updated = store.updateRouterDiscovery(router.id, {
    model: req.query.model || req.query.board || "",
    serial: req.query.serial || req.query.serial_number || "",
    version: req.query.version || req.query.routeros_version || req.query.router_os_version || "",
    identity: req.query.identity || "",
    interfaces: []
  });
  res.json({ success: true, router_id: updated.id });
});

app.get("/api/provisioning/interface/:token", (req, res) => {
  const router = store.routerByCheckinToken(req.params.token);
  if (!router) return res.status(404).json({ success: false, message: "Invalid router check-in token." });
  if (!req.query.name) return res.status(400).json({ success: false, message: "Interface name is required." });
  store.upsertRouterInterface(router.id, req.query);
  res.json({ success: true });
});

app.get("/portal/:slug/login.html", requireAccount, (req, res) => {
  res.type("html").send(renderPortal(req.account, publicBaseUrl));
});

app.get("/api/:slug/plans", requireAccount, (req, res) => {
  res.json({ plans: store.listPlans(req.account.id) });
});

app.get("/api/:slug/mac/check", requireAccount, (req, res) => {
  const voucher = store.getVoucherByMac(req.account.id, req.query.mac);
  if (voucher && !voucher.disabled && voucher.remaining_seconds > 0) {
    return res.json({ found: true, code: voucher.code });
  }
  res.json({ found: false });
});

app.post("/api/:slug/voucher/redeem", requireAccount, (req, res) => {
  const code = store.normalizeCode(req.body.voucherCode);
  const voucher = store.getVoucher(req.account.id, code);
  if (!voucher) return res.status(400).json({ success: false, message: "Invalid voucher code." });
  if (voucher.disabled) return res.status(400).json({ success: false, message: "This voucher has been disabled." });
  if (voucher.remaining_seconds <= 0) return res.status(400).json({ success: false, message: "This voucher has expired." });
  if (!voucher.first_used_at) store.recordRevenue(req.account.id, voucher.code, voucher.plan_id, "voucher");
  res.json({ success: true, code: voucher.code });
});

app.post("/api/:slug/pay", requireAccount, async (req, res) => {
  try {
    const { phone, email, packageId } = req.body;
    if (!packageId) return res.status(400).json({ error: "Missing packageId." });
    const plan = store.db.prepare("SELECT * FROM plans WHERE account_id = ? AND id = ?").get(req.account.id, packageId);
    if (!plan) return res.status(400).json({ error: "Unknown package." });

    const merchantReference = `${req.account.slug.toUpperCase()}-${Date.now()}-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;
    store.createPaymentOrder({
      merchantReference,
      accountId: req.account.id,
      planId: plan.id,
      amount: plan.price,
      phone,
      email
    });

    const callbackUrl = `${publicBaseUrl.replace(/\/+$/, "")}/portal/${req.account.slug}/login.html?pesapal_return=1`;
    const order = await pesapal.submitOrder({
      merchantReference,
      amount: plan.price,
      description: `${req.account.name} - ${plan.name}`,
      callbackUrl,
      phone,
      email
    });
    store.attachPaymentTracking(merchantReference, order.order_tracking_id);
    res.json({
      provider: "pesapal",
      merchantReference,
      orderTrackingId: order.order_tracking_id,
      redirectUrl: order.redirect_url,
      raw: order
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/:slug/pay/status/:id", requireAccount, async (req, res) => {
  try {
    const order = store.getPaymentOrderByTracking(req.params.id) || store.getPaymentOrderByReference(req.params.id);
    if (!order || order.account_id !== req.account.id) return res.status(404).json({ success: false, message: "Payment order not found." });
    const trackingId = order.order_tracking_id || req.params.id;
    const status = await pesapal.getTransactionStatus(trackingId);
    let voucher = null;
    let normalizedStatus = status.status;
    if (status.status === "paid") {
      voucher = ensurePaidVoucher(order, status);
    } else if (status.status === "failed") {
      store.markPaymentOrder({
        merchantReference: order.merchant_reference,
        status: "failed",
        rawStatus: status.rawStatus
      });
    } else {
      store.markPaymentOrder({
        merchantReference: order.merchant_reference,
        status: "pending",
        rawStatus: status.rawStatus
      });
    }
    res.json({
      success: normalizedStatus === "paid",
      provider: "pesapal",
      status: normalizedStatus,
      rawStatus: status.rawStatus,
      voucher: voucher ? voucher.code : null,
      payload: status.payload
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/:slug/pay/connect", requireAccount, (req, res) => {
  res.status(410).json({
    success: false,
    message: "Pesapal no longer uses /pay/connect. Use /pay/status/:orderTrackingId to verify and create the voucher."
  });
});

app.get("/api/:slug/pesapal/callback", requireAccount, async (req, res) => {
  try {
    const trackingId = readPesapalTrackingId(req);
    const merchantReference = readPesapalMerchantReference(req);
    const order = trackingId
      ? store.getPaymentOrderByTracking(trackingId)
      : store.getPaymentOrderByReference(merchantReference);
    if (!order || order.account_id !== req.account.id) {
      return res.status(404).json({ success: false, message: "Payment order not found." });
    }
    const status = await pesapal.getTransactionStatus(order.order_tracking_id || trackingId);
    let voucher = null;
    if (status.status === "paid") voucher = ensurePaidVoucher(order, status);
    else store.markPaymentOrder({ merchantReference: order.merchant_reference, status: status.status === "failed" ? "failed" : "pending", rawStatus: status.rawStatus });
    res.json({
      success: status.status === "paid",
      status: status.status,
      rawStatus: status.rawStatus,
      voucher: voucher ? voucher.code : null,
      payload: status.payload
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get("/api/:slug/pesapal/ipn", requireAccount, async (req, res) => {
  try {
    const trackingId = readPesapalTrackingId(req);
    const merchantReference = readPesapalMerchantReference(req);
    const order = trackingId
      ? store.getPaymentOrderByTracking(trackingId)
      : store.getPaymentOrderByReference(merchantReference);
    if (!order || order.account_id !== req.account.id) {
      return res.status(404).json({ success: false, message: "Payment order not found." });
    }
    const status = await pesapal.getTransactionStatus(order.order_tracking_id || trackingId);
    if (status.status === "paid") ensurePaidVoucher(order, status);
    else store.markPaymentOrder({ merchantReference: order.merchant_reference, status: status.status === "failed" ? "failed" : "pending", rawStatus: status.rawStatus });
    res.json({ success: true, status: status.status, rawStatus: status.rawStatus });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get("/api/pesapal/check-ipn", async (req, res) => {
  try {
    res.json({
      ipnList: await pesapal.getIpnList(),
      env: {
        PESAPAL_IPN_ID: process.env.PESAPAL_IPN_ID,
        PUBLIC_BASE_URL: publicBaseUrl,
        PESAPAL_BASE_URL: process.env.PESAPAL_BASE_URL
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/pesapal/register-ipn/:slug", requireAccount, async (req, res) => {
  try {
    const url = `${publicBaseUrl.replace(/\/+$/, "")}/api/${req.account.slug}/pesapal/ipn`;
    res.json({ url, response: await pesapal.registerIpn(url) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/:slug/voucher/lookup-by-transaction", requireAccount, (req, res) => {
  const voucher = store.getVoucherByTransaction(req.account.id, req.body.transactionId);
  if (!voucher) return res.status(404).json({ success: false, message: "No voucher found for that transaction ID." });
  if (voucher.disabled || voucher.remaining_seconds <= 0) return res.status(400).json({ success: false, message: "Voucher is no longer active." });
  res.json({ success: true, code: voucher.code, masked: maskCode(voucher.code), remaining_seconds: voucher.remaining_seconds });
});

app.get("/api/:slug/session/info", requireAccount, async (req, res) => {
  try {
    const router = store.defaultRouter(req.account.id);
    if (!router) return res.status(404).json({ error: "No router configured." });
    const sessions = await activeSessions(router);
    const session = sessions.find((s) => s.user === req.query.user);
    if (!session) return res.json({ active: false });
    const voucher = store.getVoucher(req.account.id, req.query.user);
    res.json({
      active: true,
      uptime: session.uptime || "0s",
      remaining: secondsToDuration(voucher ? voucher.remaining_seconds : 0)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/:slug/session/logout", requireAccount, async (req, res) => {
  try {
    const router = store.defaultRouter(req.account.id);
    if (!router) return res.status(404).json({ success: false, message: "No router configured." });
    await disconnectUser(router, req.body.user);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.get("/api/admin/accounts", (req, res) => {
  res.json({ accounts: store.db.prepare("SELECT * FROM accounts ORDER BY name").all() });
});

app.post("/api/admin/accounts", (req, res) => {
  const { name, slug, support_phone, primary_color, accent_color } = req.body;
  if (!name || !slug) return res.status(400).json({ success: false, message: "Name and slug are required." });
  const account = store.createAccount({
    name,
    slug,
    supportPhone: support_phone,
    primaryColor: primary_color,
    accentColor: accent_color
  });
  res.json({ success: true, account });
});

app.get("/api/admin/accounts/:accountId/template", (req, res) => {
  res.json({ html: getTemplate(Number(req.params.accountId)) });
});

app.put("/api/admin/accounts/:accountId/template", (req, res) => {
  saveTemplate(Number(req.params.accountId), String(req.body.html || ""));
  res.json({ success: true });
});

app.get("/api/admin/accounts/:accountId/routers", (req, res) => {
  res.json({ routers: store.db.prepare("SELECT * FROM routers WHERE account_id = ? ORDER BY id").all(req.params.accountId) });
});

app.post("/api/admin/accounts/:accountId/routers", (req, res) => {
  const payload = req.body;
  if (!payload.name || !payload.host) return res.status(400).json({ success: false, message: "Router name and host are required." });
  const secret = payload.radius_secret || process.env.DEFAULT_RADIUS_SECRET || "noblifi";
  const router = store.createRouter(req.params.accountId, {
    ...payload,
    secret,
    radius_secret: secret
  });
  res.json({ success: true, router });
});

app.get("/api/admin/routers/:routerId/script", (req, res) => {
  try {
    const router = routerById(req.params.routerId);
    if (!router) return res.status(404).json({ error: "Router not found." });
    const account = store.accountById(router.account_id);
    res.type("text/plain").send(renderSetupScript(router, account, req.query));
  } catch (err) {
    res.status(400).send(err.message);
  }
});

app.put("/api/admin/routers/:routerId/topology", (req, res) => {
  const router = store.updateRouterTopology(req.params.routerId, req.body);
  if (!router) return res.status(404).json({ error: "Router not found." });
  res.json({ success: true, router });
});

app.put("/api/admin/routers/:routerId/radius", (req, res) => {
  const address = String(req.body.radius_server || "").trim();
  if (!isIPv4(address)) {
    return res.status(400).json({ error: "RADIUS server must be the public IPv4 address of the host running NobliFi RADIUS." });
  }
  const router = store.updateRouterRadius(req.params.routerId, address, req.body.radius_secret);
  if (!router) return res.status(404).json({ error: "Router not found." });
  res.json({ success: true, router });
});

app.get("/api/admin/routers/:routerId/discovery-script", (req, res) => {
  try {
    const router = routerById(req.params.routerId);
    if (!router) return res.status(404).json({ error: "Router not found." });
    res.set("Content-Disposition", 'attachment; filename="noblifi-discovery.rsc"');
    res.type("text/plain").send(renderDiscoveryScript(router));
  } catch (err) {
    res.status(400).send(err.message);
  }
});

app.get("/api/admin/routers/:routerId/discovery-command", (req, res) => {
  try {
    const router = routerById(req.params.routerId);
    if (!router) return res.status(404).json({ error: "Router not found." });
    renderDiscoveryScript(router);
    const base = publicBaseUrl.replace(/\/+$/, "");
    res.json({
      script: `/file remove [find name="noblifi-discovery.rsc"]\n/tool fetch url="${base}/api/admin/routers/${router.id}/discovery-script" mode=https dst-path=noblifi-discovery.rsc\n/import file-name=noblifi-discovery.rsc`
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get("/api/admin/radius/status", (req, res) => {
  const address = process.env.BILLING_RADIUS_ADDRESS || "";
  res.json({
    configured: isIPv4(address),
    address,
    auth_port: Number(process.env.RADIUS_AUTH_PORT || 1812),
    accounting_port: Number(process.env.RADIUS_ACCT_PORT || 1813),
    embedded: process.env.RADIUS_EMBEDDED !== "false"
  });
});

app.get("/api/admin/routers/:routerId/live", async (req, res) => {
  try {
    const router = routerById(req.params.routerId);
    if (!router) return res.status(404).json({ error: "Router not found." });
    res.json(await routerSnapshot(router));
  } catch (err) {
    res.status(502).json({ error: err.message });
  }
});

app.get("/api/admin/accounts/:accountId/vouchers", (req, res) => {
  const rows = store.db.prepare("SELECT * FROM vouchers WHERE account_id = ? ORDER BY created_at DESC").all(req.params.accountId);
  res.json({ vouchers: rows.map((row) => ({ ...row, disabled: row.disabled === 1, remaining_seconds: row.expires_at ? Math.max(0, Math.floor((new Date(row.expires_at).getTime() - Date.now()) / 1000)) : row.allocated_seconds })) });
});

app.post("/api/admin/accounts/:accountId/vouchers/generate", (req, res) => {
  const { plan_id, qty, type, length } = req.body;
  const count = Math.min(Math.max(parseInt(qty, 10) || 1, 1), 500);
  const chars = type === "numeric" ? "23456789" : "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
  const codeLen = Math.min(Math.max(parseInt(length, 10) || 8, 6), 16);
  const codes = [];
  for (let i = 0; i < count; i++) {
    let code;
    do {
      code = Array.from({ length: codeLen }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
    } while (store.getVoucher(Number(req.params.accountId), code));
    store.createVoucher(Number(req.params.accountId), code, plan_id);
    codes.push(code);
  }
  res.json({ success: true, count: codes.length, codes });
});

app.post("/api/admin/accounts/:accountId/vouchers/mark-printed", (req, res) => {
  const codes = Array.isArray(req.body.codes) ? req.body.codes : [];
  if (!codes.length) return res.status(400).json({ success: false, message: "No voucher codes provided." });
  const count = store.markVouchersPrinted(Number(req.params.accountId), codes);
  res.json({ success: true, count });
});

app.post("/api/admin/accounts/:accountId/vouchers/:code/disable", async (req, res) => {
  const accountId = Number(req.params.accountId);
  const voucher = store.setVoucherDisabled(accountId, req.params.code, req.body.disabled !== false);
  if (!voucher) return res.status(404).json({ success: false, message: "Voucher not found." });

  const routers = store.db.prepare("SELECT * FROM routers WHERE account_id = ? ORDER BY id").all(accountId);
  const disconnects = await Promise.allSettled(routers.map((router) => disconnectUser(router, voucher.code)));
  const disconnected = disconnects.some((result) => result.status === "fulfilled" && result.value === true);
  res.json({ success: true, voucher, disconnected });
});

app.get("/api/admin/accounts/:accountId/metrics", (req, res) => {
  const period = ["day", "week", "month", "year"].includes(String(req.query.period)) ? String(req.query.period) : "month";
  res.json(store.getRevenueMetrics(Number(req.params.accountId), period));
});

app.get("/api/admin/accounts/:accountId/sessions", async (req, res) => {
  const routers = store.db.prepare("SELECT * FROM routers WHERE account_id = ? ORDER BY id").all(req.params.accountId);
  const results = await Promise.all(routers.map(async (router) => {
    try {
      const sessions = await activeSessions(router);
      return { sessions: sessions.map((session) => ({ ...session, router_id: router.id, router_name: router.name })), error: null };
    } catch (err) {
      return { sessions: [], error: { router_id: router.id, router_name: router.name, error: err.message } };
    }
  }));
  const all = results.flatMap((result) => result.sessions);
  const errors = results.map((result) => result.error).filter(Boolean);
  res.json({ sessions: all, errors });
});

app.listen(Number(process.env.PORT || 3000), () => {
  console.log(`NobliFi backend listening on ${publicBaseUrl}`);
  if (process.env.RADIUS_EMBEDDED !== "false") startRadiusServers();
});
