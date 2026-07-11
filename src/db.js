const Database = require("better-sqlite3");
const path = require("path");
require("dotenv").config();

const dbPath = process.env.DATABASE_PATH || path.join(__dirname, "..", "noblifi.db");
const db = new Database(path.isAbsolute(dbPath) ? dbPath : path.join(__dirname, "..", dbPath));

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    support_phone TEXT,
    primary_color TEXT NOT NULL DEFAULT '#00c6b2',
    accent_color TEXT NOT NULL DEFAULT '#0d1f3c',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS routers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    api_user TEXT NOT NULL,
    api_pass TEXT NOT NULL DEFAULT '',
    radius_secret TEXT NOT NULL,
    nas_ip TEXT,
    wan_interface TEXT NOT NULL DEFAULT 'ether1',
    bridge_name TEXT NOT NULL DEFAULT 'bridge-hotspot',
    hotspot_interface TEXT NOT NULL DEFAULT 'bridge-hotspot',
    lan_cidr TEXT NOT NULL DEFAULT '10.10.10.1/24',
    pool_range TEXT NOT NULL DEFAULT '10.10.10.10-10.10.10.254',
    dns_servers TEXT NOT NULL DEFAULT '1.1.1.1,8.8.8.8',
    topology_json TEXT,
    radius_server TEXT,
    checkin_token TEXT,
    detected_model TEXT,
    serial_number TEXT,
    routeros_version TEXT,
    identity_name TEXT,
    interfaces_json TEXT,
    last_seen_at TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS plans (
    id TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    price INTEGER NOT NULL,
    seconds INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS vouchers (
    code TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    plan_id TEXT NOT NULL,
    allocated_seconds INTEGER NOT NULL,
    used_seconds INTEGER NOT NULL DEFAULT 0,
    first_used_at TEXT,
    expires_at TEXT,
    disabled INTEGER NOT NULL DEFAULT 0,
    printed_at TEXT,
    transaction_id TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL,
    code TEXT NOT NULL,
    started_at TEXT DEFAULT CURRENT_TIMESTAMP,
    last_update TEXT DEFAULT CURRENT_TIMESTAMP,
    session_seconds INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS mac_bindings (
    account_id INTEGER NOT NULL,
    mac TEXT NOT NULL,
    code TEXT NOT NULL,
    bound_at TEXT DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (account_id, mac)
  );

  CREATE TABLE IF NOT EXISTS revenue_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    code TEXT NOT NULL,
    plan_id TEXT NOT NULL,
    source TEXT NOT NULL,
    gross_amount INTEGER NOT NULL,
    net_amount INTEGER NOT NULL,
    recorded_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS portal_templates (
    account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    html TEXT NOT NULL,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS payment_orders (
    merchant_reference TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    plan_id TEXT NOT NULL,
    order_tracking_id TEXT UNIQUE,
    voucher_code TEXT,
    provider TEXT NOT NULL DEFAULT 'pesapal',
    status TEXT NOT NULL DEFAULT 'pending',
    raw_status TEXT,
    amount INTEGER NOT NULL,
    phone TEXT,
    email TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

const planTableInfo = db.prepare("PRAGMA table_info(plans)").all();
const planPkColumns = planTableInfo.filter((column) => column.pk > 0).sort((a, b) => a.pk - b.pk);
if (planPkColumns.length === 1 && planPkColumns[0].name === "id") {
  db.exec(`
    CREATE TABLE IF NOT EXISTS plans_next (
      id TEXT NOT NULL,
      account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      price INTEGER NOT NULL,
      seconds INTEGER NOT NULL,
      PRIMARY KEY (account_id, id)
    );
    INSERT OR IGNORE INTO plans_next (id, account_id, name, price, seconds)
      SELECT id, account_id, name, price, seconds FROM plans;
    DROP TABLE plans;
    ALTER TABLE plans_next RENAME TO plans;
  `);
}

const routerTableInfo = db.prepare("PRAGMA table_info(routers)").all();
const routerColumns = new Set(routerTableInfo.map((column) => column.name));
const routerMigrations = {
  topology_json: "TEXT",
  radius_server: "TEXT",
  checkin_token: "TEXT",
  detected_model: "TEXT",
  serial_number: "TEXT",
  routeros_version: "TEXT",
  identity_name: "TEXT",
  interfaces_json: "TEXT",
  last_seen_at: "TEXT"
};
for (const [column, type] of Object.entries(routerMigrations)) {
  if (!routerColumns.has(column)) db.exec(`ALTER TABLE routers ADD COLUMN ${column} ${type}`);
}

const DEFAULT_PLANS = [
  ["mini-day", "4 Hours", 500, 14400],
  ["1day", "1 Day", 1000, 86400],
  ["1week", "1 Week", 5000, 604800],
  ["1month", "1 Month", 20000, 2592000]
];

function ensureDefaultPlans(accountId) {
  const planCount = db.prepare("SELECT COUNT(*) AS c FROM plans WHERE account_id = ?").get(accountId).c;
  if (!planCount) {
    const insertPlan = db.prepare("INSERT INTO plans (id, account_id, name, price, seconds) VALUES (?, ?, ?, ?, ?)");
    for (const [id, name, price, seconds] of DEFAULT_PLANS) insertPlan.run(id, accountId, name, price, seconds);
  }
}

function cleanupSeededDemoAccount() {
  const account = db.prepare("SELECT * FROM accounts WHERE slug = 'demo' AND name = 'Demo WiFi'").get();
  if (!account) return;
  const usage = db.prepare(`
    SELECT
      (SELECT COUNT(*) FROM routers WHERE account_id = ?) AS routers,
      (SELECT COUNT(*) FROM vouchers WHERE account_id = ?) AS vouchers,
      (SELECT COUNT(*) FROM sessions WHERE account_id = ?) AS sessions,
      (SELECT COUNT(*) FROM revenue_events WHERE account_id = ?) AS revenue,
      (SELECT COUNT(*) FROM portal_templates WHERE account_id = ?) AS templates,
      (SELECT COUNT(*) FROM payment_orders WHERE account_id = ?) AS payments
  `).get(account.id, account.id, account.id, account.id, account.id, account.id);
  if (usage.routers || usage.vouchers || usage.sessions || usage.revenue || usage.templates || usage.payments) return;
  const remove = db.transaction(() => {
    db.prepare("DELETE FROM plans WHERE account_id = ?").run(account.id);
    db.prepare("DELETE FROM accounts WHERE id = ?").run(account.id);
  });
  remove();
}

function createAccount({ name, slug, supportPhone, primaryColor, accentColor }) {
  const info = db.prepare(`
    INSERT INTO accounts (name, slug, support_phone, primary_color, accent_color)
    VALUES (?, ?, ?, ?, ?)
  `).run(name, slug, supportPhone || "", primaryColor || "#00c6b2", accentColor || "#0d1f3c");
  ensureDefaultPlans(info.lastInsertRowid);
  return accountById(info.lastInsertRowid);
}

function createRouter(accountId, payload) {
  const checkinToken = payload.checkin_token || require("crypto").randomBytes(24).toString("base64url");
  const info = db.prepare(`
    INSERT INTO routers (
      account_id, name, host, api_user, api_pass, radius_secret, nas_ip,
      wan_interface, bridge_name, hotspot_interface, lan_cidr, pool_range, dns_servers,
      radius_server, checkin_token
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    accountId,
    payload.name,
    payload.host,
    payload.api_user || "admin",
    payload.api_pass || "",
    payload.radius_secret,
    payload.nas_ip || payload.host,
    payload.wan_interface || "ether1",
    payload.bridge_name || "bridge-hotspot",
    payload.hotspot_interface || payload.bridge_name || "bridge-hotspot",
    payload.lan_cidr || "10.10.10.1/24",
    payload.pool_range || "10.10.10.10-10.10.10.254",
    payload.dns_servers || "1.1.1.1,8.8.8.8",
    payload.radius_server || process.env.BILLING_RADIUS_ADDRESS || "",
    checkinToken
  );
  return routerById(info.lastInsertRowid);
}

try {
  cleanupSeededDemoAccount();
} catch (err) {
  console.warn(`[db] demo cleanup skipped: ${err.message}`);
}

function normalizeCode(code) {
  return String(code || "").trim().toUpperCase();
}

function normalizeMac(mac) {
  return String(mac || "").trim().toUpperCase().replace(/-/g, ":");
}

function addSeconds(date, seconds) {
  return new Date(date.getTime() + seconds * 1000).toISOString();
}

function getRemaining(row) {
  if (!row) return 0;
  if (!row.expires_at) return row.allocated_seconds;
  return Math.max(0, Math.floor((new Date(row.expires_at).getTime() - Date.now()) / 1000));
}

function accountBySlug(slug) {
  return db.prepare("SELECT * FROM accounts WHERE slug = ?").get(slug);
}

function accountById(id) {
  return db.prepare("SELECT * FROM accounts WHERE id = ?").get(id);
}

function defaultRouter(accountId) {
  return db.prepare("SELECT * FROM routers WHERE account_id = ? ORDER BY id LIMIT 1").get(accountId);
}

function routerById(id) {
  return db.prepare("SELECT * FROM routers WHERE id = ?").get(id);
}

function updateRouterTopology(routerId, topology) {
  const router = routerById(routerId);
  if (!router) return null;
  const assignments = Array.isArray(topology?.assignments) ? topology.assignments : [];
  const wan = assignments.find((item) => item.role === "WAN")?.interface || router.wan_interface;
  const bridge = topology.bridge_name || router.bridge_name || "bridge-hotspot";
  db.prepare(`
    UPDATE routers
    SET topology_json = ?, wan_interface = ?, bridge_name = ?, hotspot_interface = ?
    WHERE id = ?
  `).run(JSON.stringify({ ...topology, assignments }), wan, bridge, bridge, routerId);
  return routerById(routerId);
}

function updateRouterRadius(routerId, radiusServer, radiusSecret) {
  const router = routerById(routerId);
  if (!router) return null;
  db.prepare(`
    UPDATE routers
    SET radius_server = ?, radius_secret = COALESCE(NULLIF(?, ''), radius_secret)
    WHERE id = ?
  `).run(String(radiusServer || "").trim(), String(radiusSecret || "").trim(), routerId);
  return routerById(routerId);
}

function routerByCheckinToken(token) {
  return db.prepare("SELECT * FROM routers WHERE checkin_token = ?").get(String(token || ""));
}

function updateRouterDiscovery(routerId, details = {}) {
  const router = routerById(routerId);
  if (!router) return null;
  const interfaces = Array.isArray(details.interfaces)
    ? details.interfaces
    : safeJsonArray(router.interfaces_json);
  db.prepare(`
    UPDATE routers
    SET detected_model = COALESCE(NULLIF(?, ''), detected_model),
        serial_number = COALESCE(NULLIF(?, ''), serial_number),
        routeros_version = COALESCE(NULLIF(?, ''), routeros_version),
        identity_name = COALESCE(NULLIF(?, ''), identity_name),
        interfaces_json = ?,
        last_seen_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(
    details.model || "",
    details.serial || "",
    details.version || "",
    details.identity || "",
    JSON.stringify(interfaces),
    routerId
  );
  return routerById(routerId);
}

function upsertRouterInterface(routerId, item) {
  const router = routerById(routerId);
  if (!router) return null;
  const interfaces = safeJsonArray(router.interfaces_json);
  const normalized = {
    name: String(item.name || "").trim(),
    type: String(item.type || "ether").trim(),
    "mac-address": String(item.mac || item["mac-address"] || "").trim(),
    running: String(item.running) === "true" || String(item.running) === "yes"
  };
  if (!normalized.name) return router;
  const index = interfaces.findIndex((entry) => entry.name === normalized.name);
  if (index >= 0) interfaces[index] = { ...interfaces[index], ...normalized };
  else interfaces.push(normalized);
  return updateRouterDiscovery(routerId, { interfaces });
}

function safeJsonArray(raw) {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function routerByRadiusAddress(address) {
  return db.prepare(`
    SELECT routers.*, accounts.slug AS account_slug
    FROM routers
    JOIN accounts ON accounts.id = routers.account_id
    WHERE routers.nas_ip = ? OR routers.host = ?
    ORDER BY routers.id
    LIMIT 1
  `).get(address, address);
}

function listPlans(accountId) {
  return db.prepare("SELECT * FROM plans WHERE account_id = ? ORDER BY price").all(accountId);
}

function getVoucher(accountId, code) {
  const row = db.prepare("SELECT * FROM vouchers WHERE account_id = ? AND code = ?").get(accountId, normalizeCode(code));
  if (!row) return null;
  return { ...row, disabled: row.disabled === 1, remaining_seconds: getRemaining(row) };
}

function getVoucherByMac(accountId, mac) {
  const binding = db.prepare("SELECT code FROM mac_bindings WHERE account_id = ? AND mac = ?")
    .get(accountId, normalizeMac(mac));
  return binding ? getVoucher(accountId, binding.code) : null;
}

function getVoucherByTransaction(accountId, transactionId) {
  const row = db.prepare("SELECT code FROM vouchers WHERE account_id = ? AND transaction_id = ?")
    .get(accountId, String(transactionId || "").trim());
  return row ? getVoucher(accountId, row.code) : null;
}

function createVoucher(accountId, code, planId, transactionId = null) {
  const plan = db.prepare("SELECT * FROM plans WHERE account_id = ? AND id = ?").get(accountId, planId);
  if (!plan) throw new Error("Unknown plan");
  db.prepare(`
    INSERT INTO vouchers (code, account_id, plan_id, allocated_seconds, transaction_id)
    VALUES (?, ?, ?, ?, ?)
  `).run(normalizeCode(code), accountId, plan.id, plan.seconds, transactionId);
  return getVoucher(accountId, code);
}

function bindMac(accountId, mac, code) {
  db.prepare(`
    INSERT OR REPLACE INTO mac_bindings (account_id, mac, code, bound_at)
    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
  `).run(accountId, normalizeMac(mac), normalizeCode(code));
}

function startSession(accountId, sessionId, code) {
  const voucher = getVoucher(accountId, code);
  if (!voucher) return;
  if (!voucher.first_used_at) {
    const now = new Date();
    db.prepare("UPDATE vouchers SET first_used_at = ?, expires_at = ? WHERE account_id = ? AND code = ?")
      .run(now.toISOString(), addSeconds(now, voucher.allocated_seconds), accountId, voucher.code);
  }
  db.prepare(`
    INSERT OR REPLACE INTO sessions (session_id, account_id, code, started_at, last_update, session_seconds)
    VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 0)
  `).run(sessionId, accountId, normalizeCode(code));
}

function updateSession(sessionId, cumulativeSeconds) {
  const sess = db.prepare("SELECT * FROM sessions WHERE session_id = ?").get(sessionId);
  if (!sess) return;
  const delta = Number(cumulativeSeconds || 0) - sess.session_seconds;
  if (delta > 0) {
    db.prepare("UPDATE vouchers SET used_seconds = used_seconds + ? WHERE account_id = ? AND code = ?")
      .run(delta, sess.account_id, sess.code);
  }
  db.prepare("UPDATE sessions SET session_seconds = ?, last_update = CURRENT_TIMESTAMP WHERE session_id = ?")
    .run(Number(cumulativeSeconds || 0), sessionId);
}

function markVouchersPrinted(accountId, codes) {
  const normalized = [...new Set((codes || []).map(normalizeCode).filter(Boolean))];
  const update = db.prepare(`
    UPDATE vouchers
    SET printed_at = CURRENT_TIMESTAMP
    WHERE account_id = ? AND code = ? AND printed_at IS NULL
  `);
  const run = db.transaction(() => normalized.reduce((count, code) => count + update.run(accountId, code).changes, 0));
  return run();
}

function setVoucherDisabled(accountId, code, disabled = true) {
  const normalized = normalizeCode(code);
  const result = db.prepare("UPDATE vouchers SET disabled = ? WHERE account_id = ? AND code = ?")
    .run(disabled ? 1 : 0, accountId, normalized);
  if (!result.changes) return null;
  if (disabled) db.prepare("DELETE FROM mac_bindings WHERE account_id = ? AND code = ?").run(accountId, normalized);
  return getVoucher(accountId, normalized);
}

function getRevenueMetrics(accountId, period = "month") {
  const days = { day: 1, week: 7, month: 30, year: 365 }[period] || 30;
  const events = db.prepare(`
    SELECT id, code, plan_id, source, gross_amount, net_amount, recorded_at
    FROM revenue_events
    WHERE account_id = ? AND datetime(recorded_at) >= datetime('now', ?)
    ORDER BY recorded_at DESC
  `).all(accountId, `-${days} days`);
  const rows = db.prepare(`
    SELECT date(recorded_at) AS day,
           SUM(gross_amount) AS gross,
           SUM(net_amount) AS net,
           COUNT(*) AS count,
           SUM(CASE WHEN source = 'mobile_money' THEN net_amount ELSE 0 END) AS mobile_money_net,
           SUM(CASE WHEN source = 'voucher' THEN net_amount ELSE 0 END) AS voucher_net
    FROM revenue_events
    WHERE account_id = ? AND datetime(recorded_at) >= datetime('now', ?)
    GROUP BY date(recorded_at)
    ORDER BY day
  `).all(accountId, `-${days} days`);
  return {
    period,
    totals: events.reduce((totals, event) => ({
      gross: totals.gross + Number(event.gross_amount || 0),
      net: totals.net + Number(event.net_amount || 0),
      count: totals.count + 1,
      mobile_money_net: totals.mobile_money_net + (event.source === "mobile_money" ? Number(event.net_amount || 0) : 0),
      voucher_net: totals.voucher_net + (event.source === "voucher" ? Number(event.net_amount || 0) : 0)
    }), { gross: 0, net: 0, count: 0, mobile_money_net: 0, voucher_net: 0 }),
    rows,
    events
  };
}

function recordRevenue(accountId, code, planId, source) {
  const plan = db.prepare("SELECT * FROM plans WHERE account_id = ? AND id = ?").get(accountId, planId);
  if (!plan) return;
  const netPercent = Number(process.env.PESAPAL_NET_PERCENT || 100);
  const net = source === "mobile_money" ? Math.floor(plan.price * netPercent / 100) : plan.price;
  db.prepare(`
    INSERT INTO revenue_events (account_id, code, plan_id, source, gross_amount, net_amount)
    SELECT ?, ?, ?, ?, ?, ?
    WHERE NOT EXISTS (
      SELECT 1 FROM revenue_events WHERE account_id = ? AND code = ?
    )
  `).run(accountId, normalizeCode(code), planId, source, plan.price, net, accountId, normalizeCode(code));
}

function createPaymentOrder({ merchantReference, accountId, planId, amount, phone, email }) {
  db.prepare(`
    INSERT INTO payment_orders (merchant_reference, account_id, plan_id, amount, phone, email)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(merchantReference, accountId, planId, amount, phone || null, email || null);
  return getPaymentOrderByReference(merchantReference);
}

function attachPaymentTracking(merchantReference, orderTrackingId) {
  db.prepare(`
    UPDATE payment_orders
    SET order_tracking_id = ?, updated_at = CURRENT_TIMESTAMP
    WHERE merchant_reference = ?
  `).run(orderTrackingId, merchantReference);
}

function getPaymentOrderByReference(merchantReference) {
  return db.prepare("SELECT * FROM payment_orders WHERE merchant_reference = ?").get(String(merchantReference || "").trim());
}

function getPaymentOrderByTracking(orderTrackingId) {
  return db.prepare("SELECT * FROM payment_orders WHERE order_tracking_id = ?").get(String(orderTrackingId || "").trim());
}

function markPaymentOrder({ merchantReference, orderTrackingId, status, rawStatus, voucherCode }) {
  const order = merchantReference ? getPaymentOrderByReference(merchantReference) : getPaymentOrderByTracking(orderTrackingId);
  if (!order) return null;
  db.prepare(`
    UPDATE payment_orders
    SET status = ?, raw_status = ?, voucher_code = COALESCE(?, voucher_code), updated_at = CURRENT_TIMESTAMP
    WHERE merchant_reference = ?
  `).run(status, rawStatus || null, voucherCode || null, order.merchant_reference);
  return getPaymentOrderByReference(order.merchant_reference);
}

module.exports = {
  db,
  normalizeCode,
  normalizeMac,
  accountBySlug,
  accountById,
  createAccount,
  createRouter,
  ensureDefaultPlans,
  defaultRouter,
  routerById,
  routerByCheckinToken,
  updateRouterDiscovery,
  upsertRouterInterface,
  updateRouterTopology,
  updateRouterRadius,
  routerByRadiusAddress,
  listPlans,
  getVoucher,
  getVoucherByMac,
  getVoucherByTransaction,
  createVoucher,
  bindMac,
  startSession,
  updateSession,
  stopSession: updateSession,
  markVouchersPrinted,
  setVoucherDisabled,
  getRevenueMetrics,
  recordRevenue,
  createPaymentOrder,
  attachPaymentTracking,
  getPaymentOrderByReference,
  getPaymentOrderByTracking,
  markPaymentOrder
};
