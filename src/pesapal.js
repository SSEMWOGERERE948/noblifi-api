require("dotenv").config();

const BASE_URL = String(process.env.PESAPAL_BASE_URL || "").replace(/\/+$/, "");

function requireConfig() {
  const missing = [];
  if (!BASE_URL) missing.push("PESAPAL_BASE_URL");
  if (!process.env.PESAPAL_CONSUMER_KEY) missing.push("PESAPAL_CONSUMER_KEY");
  if (!process.env.PESAPAL_CONSUMER_SECRET) missing.push("PESAPAL_CONSUMER_SECRET");
  if (!process.env.PESAPAL_IPN_ID) missing.push("PESAPAL_IPN_ID");
  if (missing.length) throw new Error(`Pesapal is not configured. Missing: ${missing.join(", ")}`);
}

async function readJSON(response, label) {
  const text = await response.text();
  const data = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(`${label} failed with ${response.status}: ${JSON.stringify(data)}`);
  }
  return data;
}

async function getPesapalToken() {
  requireConfig();
  const response = await fetch(`${BASE_URL}/Auth/RequestToken`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      consumer_key: process.env.PESAPAL_CONSUMER_KEY,
      consumer_secret: process.env.PESAPAL_CONSUMER_SECRET
    })
  });
  const data = await readJSON(response, "Pesapal auth");
  if (!data.token) throw new Error(`Pesapal auth did not return token: ${JSON.stringify(data)}`);
  return data.token;
}

async function submitOrder({ merchantReference, amount, description, callbackUrl, phone, email }) {
  const token = await getPesapalToken();
  const response = await fetch(`${BASE_URL}/Transactions/SubmitOrderRequest`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      id: merchantReference,
      currency: process.env.PESAPAL_CURRENCY || "UGX",
      amount,
      description,
      callback_url: callbackUrl,
      notification_id: process.env.PESAPAL_IPN_ID,
      billing_address: {
        email_address: email || undefined,
        phone_number: phone || undefined,
        country_code: "UG"
      }
    })
  });
  const data = await readJSON(response, "Pesapal submit order");
  if (!data.redirect_url || !data.order_tracking_id) {
    throw new Error(`Pesapal did not return redirect_url/order_tracking_id: ${JSON.stringify(data)}`);
  }
  return data;
}

function normalizePaymentStatus(data) {
  const rawStatus = String(
    data.payment_status_description ||
    data.status ||
    data.payment_status ||
    "UNKNOWN"
  );
  const normalized = rawStatus.toLowerCase();
  if (normalized.includes("completed") || normalized.includes("paid") || normalized.includes("success")) return { rawStatus, status: "paid" };
  if (normalized.includes("failed") || normalized.includes("invalid") || normalized.includes("cancelled") || normalized.includes("reversed")) return { rawStatus, status: "failed" };
  return { rawStatus, status: "unpaid" };
}

async function getTransactionStatus(orderTrackingId) {
  const token = await getPesapalToken();
  const url = new URL(`${BASE_URL}/Transactions/GetTransactionStatus`);
  url.searchParams.set("orderTrackingId", orderTrackingId);
  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json"
    }
  });
  const payload = await readJSON(response, "Pesapal transaction status");
  return {
    payload,
    ...normalizePaymentStatus(payload)
  };
}

async function getIpnList() {
  const token = await getPesapalToken();
  const response = await fetch(`${BASE_URL}/URLSetup/GetIpnList`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json"
    }
  });
  return readJSON(response, "Pesapal IPN list");
}

async function registerIpn(url) {
  const token = await getPesapalToken();
  const response = await fetch(`${BASE_URL}/URLSetup/RegisterIPN`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      url,
      ipn_notification_type: "GET"
    })
  });
  return readJSON(response, "Pesapal IPN registration");
}

module.exports = {
  getPesapalToken,
  submitOrder,
  getTransactionStatus,
  getIpnList,
  registerIpn
};
