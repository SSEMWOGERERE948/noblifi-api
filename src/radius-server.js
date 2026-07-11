const dgram = require("dgram");
const radius = require("radius");
require("dotenv").config();

const store = require("./db");

const AUTH_PORT = Number(process.env.RADIUS_AUTH_PORT || 1812);
const ACCT_PORT = Number(process.env.RADIUS_ACCT_PORT || 1813);
const MAC_RE = /^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$|^[0-9A-Fa-f]{12}$/;

function decodeForRouter(msg, rinfo) {
  const router = store.routerByRadiusAddress(rinfo.address);
  if (!router) {
    console.error(`[RADIUS] Unknown NAS ${rinfo.address}. Add this MikroTik as a router first.`);
    return null;
  }
  try {
    return {
      router,
      packet: radius.decode({ packet: msg, secret: router.radius_secret })
    };
  } catch (err) {
    console.error(`[RADIUS] Decode failed for ${router.name}: ${err.message}`);
    return null;
  }
}

function sendResponse(server, packet, code, secret, attrs, rinfo) {
  const encoded = radius.encode_response({
    packet,
    code,
    secret,
    attributes: attrs || []
  });
  server.send(encoded, rinfo.port, rinfo.address);
}

let started = false;

function startRadiusServers() {
  if (started) return;
  started = true;

const authServer = dgram.createSocket("udp4");

authServer.on("message", (msg, rinfo) => {
  const decoded = decodeForRouter(msg, rinfo);
  if (!decoded || decoded.packet.code !== "Access-Request") return;

  const { router, packet } = decoded;
  const username = String(packet.attributes["User-Name"] || "").trim();
  const callingMac = packet.attributes["Calling-Station-Id"] || null;
  const isMacAuth = MAC_RE.test(username);
  const voucher = isMacAuth
    ? store.getVoucherByMac(router.account_id, username)
    : store.getVoucher(router.account_id, username);

  if (!voucher || voucher.disabled || voucher.remaining_seconds <= 0) {
    const message = voucher && voucher.remaining_seconds <= 0
      ? "Voucher expired. Please purchase a new one."
      : "Invalid voucher code.";
    console.log(`[AUTH] reject account=${router.account_id} user=${username} mac=${callingMac || ""}`);
    return sendResponse(authServer, packet, "Access-Reject", router.radius_secret, [["Reply-Message", message]], rinfo);
  }

  const minutes = Math.floor(voucher.remaining_seconds / 60);
  console.log(`[AUTH] accept account=${router.account_id} user=${username} ${minutes}m`);
  sendResponse(authServer, packet, "Access-Accept", router.radius_secret, [
    ["Session-Timeout", voucher.remaining_seconds],
    ["Idle-Timeout", Number(process.env.RADIUS_IDLE_TIMEOUT_SEC || 900)],
    ["Reply-Message", `Welcome. ${minutes} minutes remaining.`]
  ], rinfo);
});

authServer.on("error", (err) => console.error("[AUTH] Server error:", err));
authServer.bind(AUTH_PORT, "0.0.0.0", () => {
  console.log(`NobliFi RADIUS auth listening on UDP ${AUTH_PORT}`);
});

const acctServer = dgram.createSocket("udp4");

acctServer.on("message", (msg, rinfo) => {
  const decoded = decodeForRouter(msg, rinfo);
  if (!decoded || decoded.packet.code !== "Accounting-Request") return;

  const { router, packet } = decoded;
  const statusType = packet.attributes["Acct-Status-Type"] || "Unknown";
  const username = String(packet.attributes["User-Name"] || "").trim();
  const sessionId = packet.attributes["Acct-Session-Id"];
  const sessionSeconds = Number(packet.attributes["Acct-Session-Time"] || 0);
  const clientMac = packet.attributes["Calling-Station-Id"] || null;

  sendResponse(acctServer, packet, "Accounting-Response", router.radius_secret, [], rinfo);

  try {
    if (statusType === "Start") {
      store.startSession(router.account_id, sessionId, username);
      if (clientMac && !MAC_RE.test(username)) store.bindMac(router.account_id, clientMac, username);
    } else if (statusType === "Interim-Update") {
      store.updateSession(sessionId, sessionSeconds);
    } else if (statusType === "Stop") {
      store.stopSession(sessionId, sessionSeconds);
    }
    console.log(`[ACCT] ${statusType} account=${router.account_id} user=${username} seconds=${sessionSeconds}`);
  } catch (err) {
    console.error(`[ACCT] Post-processing failed: ${err.message}`);
  }
});

acctServer.on("error", (err) => console.error("[ACCT] Server error:", err));
acctServer.bind(ACCT_PORT, "0.0.0.0", () => {
  console.log(`NobliFi RADIUS accounting listening on UDP ${ACCT_PORT}`);
});

  return { authServer, acctServer };
}

if (require.main === module) startRadiusServers();

module.exports = { startRadiusServers };
