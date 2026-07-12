const fs = require("fs");
const path = require("path");
require("dotenv").config();

const store = require("./db");
const { mikrotikFetch, renderHotspotLoginInstallScript } = require("./mikrotik");

const ENV_PATH = path.join(__dirname, "..", ".env");
const ENV_EXAMPLE_PATH = path.join(__dirname, "..", ".env.example");

function parseArgs(argv) {
  const args = { apply: false, printScript: true, listRouters: false };
  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--apply") args.apply = true;
    else if (arg === "--no-print") args.printScript = false;
    else if (arg === "--list-routers") args.listRouters = true;
    else if (arg === "--skip-login-template") args.skipLoginTemplate = true;
    else if (arg === "--help" || arg === "-h") args.help = true;
    else if (arg.startsWith("--")) {
      const key = arg.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
      const next = argv[i + 1];
      if (!next || next.startsWith("--")) throw new Error(`${arg} requires a value.`);
      args[key] = next;
      i++;
    }
  }
  return args;
}

function usage() {
  return `
Usage:
  npm run radius:configure -- --radius-address <public-ip> [options]

Options:
  --router-id <id>              Update this router record and use its secret.
  --radius-secret <secret>      Set/update the router RADIUS shared secret.
  --portal-host <host>          Set BILLING_PORTAL_HOST in backend/.env.
  --public-base-url <url>       Set PUBLIC_BASE_URL in backend/.env.
  --auth-port <port>            Set RADIUS auth port. Default: 1812.
  --acct-port <port>            Set RADIUS accounting port. Default: 1813.
  --hotspot-profile <name>      MikroTik HotSpot profile to update. Default: noblifi-profile.
  --skip-login-template         Do not include MikroTik login.html install commands.
  --test-tokens <qty>           Create test voucher codes for this router's account.
  --plan-id <id>                Plan to use for generated test vouchers. Default: cheapest plan.
  --apply                       Apply RADIUS settings to the MikroTik via REST.
  --no-print                    Do not print the RouterOS snippet.
  --list-routers                Show known router IDs.

Examples:
  npm run radius:configure -- --list-routers
  npm run radius:configure -- --router-id 1 --radius-address 203.0.113.10 --radius-secret strong-secret
  npm run radius:configure -- --router-id 1 --radius-address 203.0.113.10 --test-tokens 3
  npm run radius:configure -- --router-id 1 --radius-address 203.0.113.10 --apply
`.trim();
}

function isIPv4(value) {
  const parts = String(value || "").trim().split(".");
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function shellQuote(value) {
  return String(value || "").replace(/"/g, '\\"');
}

function readEnvFile() {
  if (fs.existsSync(ENV_PATH)) return fs.readFileSync(ENV_PATH, "utf8");
  if (fs.existsSync(ENV_EXAMPLE_PATH)) return fs.readFileSync(ENV_EXAMPLE_PATH, "utf8");
  return "";
}

function writeEnv(updates) {
  const lines = readEnvFile().split(/\r?\n/);
  const seen = new Set();
  const next = lines.map((line) => {
    const match = line.match(/^([A-Z0-9_]+)=/);
    if (!match || !(match[1] in updates)) return line;
    seen.add(match[1]);
    return `${match[1]}=${updates[match[1]]}`;
  });
  for (const [key, value] of Object.entries(updates)) {
    if (!seen.has(key)) next.push(`${key}=${value}`);
  }
  fs.writeFileSync(ENV_PATH, next.join("\n").replace(/\n{3,}/g, "\n\n"));
}

function listRouters() {
  const routers = store.db.prepare(`
    SELECT routers.id, accounts.slug AS account, routers.name, routers.host, routers.nas_ip, routers.radius_server
    FROM routers
    JOIN accounts ON accounts.id = routers.account_id
    ORDER BY accounts.slug, routers.id
  `).all();
  if (!routers.length) {
    console.log("No routers found. Create an account and router first.");
    return;
  }
  console.table(routers);
}

function renderRadiusScript({ radiusAddress, radiusSecret, authPort, acctPort, hotspotProfile, loginTemplateCommands }) {
  const lines = [
    "# NobliFi RADIUS-only MikroTik configuration",
    `/radius remove [find comment="NobliFi RADIUS"]`,
    `/radius add service=hotspot address=${radiusAddress} secret="${shellQuote(radiusSecret)}" authentication-port=${authPort} accounting-port=${acctPort} timeout=3s comment="NobliFi RADIUS"`,
    `/radius incoming set accept=yes`,
    `:if ([:len [/ip hotspot profile find name="${shellQuote(hotspotProfile)}"]] > 0) do={ /ip hotspot profile set [find name="${shellQuote(hotspotProfile)}"] use-radius=yes radius-accounting=yes radius-interim-update=5m login-by=http-chap,http-pap }`,
    `:put "NobliFi RADIUS configured for ${radiusAddress}:${authPort}/${acctPort}"`
  ];
  if (loginTemplateCommands && loginTemplateCommands.length) lines.push("", ...loginTemplateCommands);
  return lines.join("\n");
}

function makeVoucherCode(prefix = "TEST") {
  const chars = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
  let code = prefix;
  for (let i = 0; i < 8; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

function generateTestTokens(accountId, qty, planId) {
  const plans = store.listPlans(accountId);
  if (!plans.length) throw new Error("This account has no plans. Create at least one plan before generating test tokens.");
  const selectedPlan = planId
    ? plans.find((plan) => plan.id === planId)
    : plans.slice().sort((a, b) => Number(a.price || 0) - Number(b.price || 0))[0];
  if (!selectedPlan) throw new Error(`Plan "${planId}" was not found for this account.`);

  const count = Math.min(Math.max(Number(qty) || 0, 0), 50);
  const codes = [];
  while (codes.length < count) {
    const code = makeVoucherCode();
    if (store.getVoucher(accountId, code)) continue;
    store.createVoucher(accountId, code, selectedPlan.id, `radius-test-${Date.now()}-${codes.length + 1}`);
    codes.push(code);
  }
  return { plan: selectedPlan, codes };
}

async function removeExistingRadius(router) {
  const clients = await mikrotikFetch(router, "/radius");
  const matches = clients.filter((item) => item.comment === "NobliFi RADIUS" && item[".id"]);
  for (const item of matches) {
    await mikrotikFetch(router, "/radius/remove", {
      method: "POST",
      body: JSON.stringify({ ".id": item[".id"] })
    });
  }
}

async function applyToRouter(router, options) {
  await removeExistingRadius(router);
  await mikrotikFetch(router, "/radius/add", {
    method: "POST",
    body: JSON.stringify({
      service: "hotspot",
      address: options.radiusAddress,
      secret: options.radiusSecret,
      "authentication-port": String(options.authPort),
      "accounting-port": String(options.acctPort),
      timeout: "3s",
      comment: "NobliFi RADIUS"
    })
  });
  await mikrotikFetch(router, "/radius/incoming/set", {
    method: "POST",
    body: JSON.stringify({ accept: "yes" })
  });

  const profiles = await mikrotikFetch(router, "/ip/hotspot/profile");
  const profile = profiles.find((item) => item.name === options.hotspotProfile);
  if (profile && profile[".id"]) {
    await mikrotikFetch(router, "/ip/hotspot/profile/set", {
      method: "POST",
      body: JSON.stringify({
        ".id": profile[".id"],
        "use-radius": "yes",
        "radius-accounting": "yes",
        "radius-interim-update": "5m",
        "login-by": "http-chap,http-pap"
      })
    });
  } else {
    console.warn(`HotSpot profile "${options.hotspotProfile}" was not found; RADIUS client was still configured.`);
  }
}

async function main() {
  const args = parseArgs(process.argv);
  if (args.help) {
    console.log(usage());
    return;
  }
  if (args.listRouters) {
    listRouters();
    return;
  }

  const radiusAddress = String(args.radiusAddress || process.env.BILLING_RADIUS_ADDRESS || "").trim();
  if (!isIPv4(radiusAddress)) {
    throw new Error("Provide --radius-address as the public IPv4 of the host running NobliFi RADIUS.");
  }

  const authPort = Number(args.authPort || process.env.RADIUS_AUTH_PORT || 1812);
  const acctPort = Number(args.acctPort || process.env.RADIUS_ACCT_PORT || 1813);
  if (!Number.isInteger(authPort) || authPort <= 0) throw new Error("--auth-port must be a valid port.");
  if (!Number.isInteger(acctPort) || acctPort <= 0) throw new Error("--acct-port must be a valid port.");

  const envUpdates = {
    BILLING_RADIUS_ADDRESS: radiusAddress,
    RADIUS_AUTH_PORT: String(authPort),
    RADIUS_ACCT_PORT: String(acctPort),
    RADIUS_EMBEDDED: "true"
  };
  if (args.portalHost) envUpdates.BILLING_PORTAL_HOST = args.portalHost;
  const publicBaseUrl = args.publicBaseUrl || process.env.PUBLIC_BASE_URL || `http://${radiusAddress}:3000`;
  envUpdates.PUBLIC_BASE_URL = publicBaseUrl;
  writeEnv(envUpdates);

  let router = null;
  let radiusSecret = String(args.radiusSecret || process.env.DEFAULT_RADIUS_SECRET || "noblifi").trim();
  if (args.routerId) {
    router = store.routerById(args.routerId);
    if (!router) throw new Error(`Router ${args.routerId} was not found.`);
    radiusSecret = String(args.radiusSecret || router.radius_secret || radiusSecret).trim();
    router = store.updateRouterRadius(router.id, radiusAddress, radiusSecret);
  }
  if (!radiusSecret) throw new Error("RADIUS shared secret cannot be empty.");

  const options = {
    radiusAddress,
    radiusSecret,
    authPort,
    acctPort,
    hotspotProfile: args.hotspotProfile || "noblifi-profile"
  };

  let account = null;
  if (router) account = store.accountById(router.account_id);
  if (router && account && !args.skipLoginTemplate) {
    options.loginTemplateCommands = renderHotspotLoginInstallScript(router, account, {
      publicBaseUrl
    });
  }

  let testTokens = null;
  if (args.testTokens) {
    if (!router || !account) throw new Error("--test-tokens requires --router-id.");
    testTokens = generateTestTokens(account.id, args.testTokens, args.planId);
  }

  if (args.printScript) {
    console.log(renderRadiusScript(options));
  }

  if (args.apply) {
    if (!router) throw new Error("--apply requires --router-id.");
    await applyToRouter(router, options);
    console.log(`Applied RADIUS settings to ${router.name} (${router.host}).`);
  }

  console.log(`Updated ${path.relative(process.cwd(), ENV_PATH) || ENV_PATH}.`);
  if (router) console.log(`Updated router ${router.id} (${router.name}) radius_server=${radiusAddress}.`);
  if (testTokens) {
    console.log(`Created ${testTokens.codes.length} RADIUS test voucher(s) on plan ${testTokens.plan.id}:`);
    for (const code of testTokens.codes) console.log(`  ${code}`);
  }
}

main().catch((err) => {
  console.error(err.message);
  console.error("");
  console.error(usage());
  process.exit(1);
});
