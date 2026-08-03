require("dotenv").config();

const BASE_URL = String(process.env.IOTEC_BASE_URL || "https://pay.iotec.io").replace(/\/+$/, "");
const TOKEN_URL = String(process.env.IOTEC_TOKEN_URL || "https://id.iotec.io/connect/token");

function requireConfig() {
  const missing = [];
  if (!BASE_URL) missing.push("IOTEC_BASE_URL");
  if (!TOKEN_URL) missing.push("IOTEC_TOKEN_URL");
  if (!process.env.IOTEC_CLIENT_ID) missing.push("IOTEC_CLIENT_ID");
  if (!process.env.IOTEC_CLIENT_SECRET) missing.push("IOTEC_CLIENT_SECRET");
  if (!process.env.IOTEC_WALLET_ID) missing.push("IOTEC_WALLET_ID");
  if (missing.length) throw new Error(`ioTec is not configured. Missing: ${missing.join(", ")}`);
}

async function readJSON(response, label) {
  const text = await response.text();
  const data = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(`${label} failed with ${response.status}: ${JSON.stringify(data)}`);
  }
  return data;
}

async function getIotecToken() {
  requireConfig();
  const body = new URLSearchParams();
  body.set("client_id", process.env.IOTEC_CLIENT_ID);
  body.set("client_secret", process.env.IOTEC_CLIENT_SECRET);
  body.set("grant_type", "client_credentials");

  const response = await fetch(TOKEN_URL, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body
  });
  const data = await readJSON(response, "ioTec auth");
  if (!data.access_token) throw new Error(`ioTec auth did not return access_token: ${JSON.stringify(data)}`);
  return data.access_token;
}

async function submitOrder({ merchantReference, amount, description, phone }) {
  const token = await getIotecToken();
  const response = await fetch(`${BASE_URL}/api/collections/collect`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      category: "MobileMoney",
      currency: process.env.IOTEC_CURRENCY || "UGX",
      walletId: process.env.IOTEC_WALLET_ID,
      externalId: merchantReference,
      payer: phone,
      amount,
      payerNote: description,
      payeeNote: `NobliFi voucher ${merchantReference}`
    })
  });
  const data = await readJSON(response, "ioTec collection");
  const id = data.id || data.requestId || data.transactionId;
  if (!id) throw new Error(`ioTec did not return a transaction id: ${JSON.stringify(data)}`);
  return { ...data, order_tracking_id: id, redirect_url: "" };
}

function normalizePaymentStatus(data) {
  const rawStatus = String(data.status || data.statusCode || data.statusMessage || "UNKNOWN");
  const normalized = rawStatus.toLowerCase();
  if (normalized.includes("success")) return { rawStatus, status: "paid" };
  if (normalized.includes("failed") || normalized.includes("cancelled") || normalized.includes("canceled") || normalized.includes("rejected")) return { rawStatus, status: "failed" };
  return { rawStatus, status: "unpaid" };
}

async function getTransactionStatus(orderTrackingId) {
  const token = await getIotecToken();
  const response = await fetch(`${BASE_URL}/api/collections/status/${encodeURIComponent(orderTrackingId)}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json"
    }
  });
  const payload = await readJSON(response, "ioTec collection status");
  return {
    payload,
    ...normalizePaymentStatus(payload)
  };
}

module.exports = {
  getIotecToken,
  submitOrder,
  getTransactionStatus
};
