const store = require("./db");
const { routerById } = store;

function authHeader(router) {
  return "Basic " + Buffer.from(`${router.api_user}:${router.api_pass || ""}`).toString("base64");
}

async function mikrotikFetch(router, endpoint, options = {}) {
  const url = `http://${router.host}/rest${endpoint}`;
  const response = await fetch(url, {
    ...options,
    signal: options.signal || AbortSignal.timeout(Number(process.env.MIKROTIK_TIMEOUT_MS || 5000)),
    headers: {
      Authorization: authHeader(router),
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });
  if (!response.ok) {
    throw new Error(`MikroTik ${router.name} ${response.status}: ${await response.text()}`);
  }
  const text = await response.text();
  return text ? JSON.parse(text) : {};
}

async function activeSessions(router) {
  return mikrotikFetch(router, "/ip/hotspot/active");
}

async function optionalFetch(router, endpoint, fallback = []) {
  try {
    return await mikrotikFetch(router, endpoint);
  } catch (err) {
    return { error: err.message, data: fallback };
  }
}

async function routerSnapshot(router) {
  const [
    identity,
    resources,
    routerboard,
    interfaces,
    addresses,
    routes,
    natRules,
    radiusClients,
    hotspotServers,
    hotspotProfiles,
    dhcpServers,
    dhcpLeases,
    activeHotspot,
    systemClock
  ] = await Promise.all([
    optionalFetch(router, "/system/identity"),
    optionalFetch(router, "/system/resource"),
    optionalFetch(router, "/system/routerboard"),
    optionalFetch(router, "/interface"),
    optionalFetch(router, "/ip/address"),
    optionalFetch(router, "/ip/route"),
    optionalFetch(router, "/ip/firewall/nat"),
    optionalFetch(router, "/radius"),
    optionalFetch(router, "/ip/hotspot"),
    optionalFetch(router, "/ip/hotspot/profile"),
    optionalFetch(router, "/ip/dhcp-server"),
    optionalFetch(router, "/ip/dhcp-server/lease"),
    optionalFetch(router, "/ip/hotspot/active"),
    optionalFetch(router, "/system/clock")
  ]);

  const liveResources = resultData(resources, {});
  const liveRouterboard = resultData(routerboard, {});
  const liveIdentity = resultData(identity, {});
  const liveInterfaces = resultData(interfaces, []);
  if (Object.keys(liveResources).length || Object.keys(liveRouterboard).length || liveInterfaces.length) {
    store.updateRouterDiscovery(router.id, {
      version: liveResources.version,
      model: liveRouterboard.model || liveResources["board-name"],
      serial: liveRouterboard["serial-number"],
      identity: liveIdentity.name,
      interfaces: liveInterfaces.length ? liveInterfaces : persistedInterfaces(router)
    });
  }

  const refreshed = routerById(router.id) || router;
  return {
    router: {
      id: refreshed.id,
      name: refreshed.name,
      host: refreshed.host,
      nas_ip: refreshed.nas_ip,
      wan_interface: refreshed.wan_interface,
      bridge_name: refreshed.bridge_name,
      hotspot_interface: refreshed.hotspot_interface,
      lan_cidr: refreshed.lan_cidr,
      pool_range: refreshed.pool_range,
      dns_servers: refreshed.dns_servers,
      radius_server: refreshed.radius_server,
      routeros_version: refreshed.routeros_version,
      detected_model: refreshed.detected_model,
      serial_number: refreshed.serial_number,
      identity_name: refreshed.identity_name,
      last_seen_at: refreshed.last_seen_at
    },
    identity: withPersistedFallback(identity, refreshed.identity_name ? { name: refreshed.identity_name } : {}),
    resources: withPersistedFallback(resources, refreshed.routeros_version ? { version: refreshed.routeros_version } : {}),
    routerboard: withPersistedFallback(routerboard, {
      model: refreshed.detected_model || "",
      "serial-number": refreshed.serial_number || ""
    }),
    interfaces: withPersistedFallback(interfaces, persistedInterfaces(refreshed)),
    addresses,
    routes,
    natRules,
    radiusClients,
    hotspotServers,
    hotspotProfiles,
    dhcpServers,
    dhcpLeases,
    activeHotspot,
    systemClock,
    fetched_at: new Date().toISOString()
  };
}

async function disconnectUser(router, username) {
  const active = await activeSessions(router);
  const session = active.find((s) => s.user === username);
  if (!session || !session[".id"]) return false;
  await mikrotikFetch(router, "/ip/hotspot/active/remove", {
    method: "POST",
    body: JSON.stringify({ ".id": session[".id"] })
  });
  return true;
}

function renderSetupScript(router, account, opts = {}) {
  const radiusAddress = opts.radiusAddress || router.radius_server || process.env.BILLING_RADIUS_ADDRESS || "";
  if (!isIPv4(radiusAddress)) {
    throw new Error("RADIUS is not configured. Set BILLING_RADIUS_ADDRESS or the router radius_server to the public IPv4 address of the NobliFi RADIUS host.");
  }
  const portalHost = opts.portalHost || process.env.BILLING_PORTAL_HOST || radiusAddress;
  const publicBase = (opts.publicBaseUrl || process.env.PUBLIC_BASE_URL || `http://${portalHost}:3000`).replace(/\/+$/, "");
  const topology = parseTopology(router.topology_json);
  const assignments = topology.assignments || [];
  const wanInterface = assignments.find((item) => item.role === "WAN")?.interface || router.wan_interface;
  const bridgeConfigs = bridgeOptions(topology, router);
  const hotspotPorts = portsFor(assignments, "HOTSPOT_LAN");
  const managementPorts = portsFor(assignments, "STAFF_LAN");
  if (assignments.length && !managementPorts.length) {
    throw new Error("Refusing to generate script: assign at least one STAFF_LAN management port first.");
  }
  if (assignments.length && !hotspotPorts.length) {
    throw new Error("Refusing to generate script: assign at least one HOTSPOT_LAN port first.");
  }
  const hotspotBridge = bridgeConfigs.HOTSPOT_LAN;
  const bridgeCommands = [
    "# Management ports are configured outside the HotSpot bridge to prevent lockout.",
    ...renderBridge("STAFF_LAN", bridgeConfigs.STAFF_LAN, managementPorts, false),
    ...renderBridge("HOTSPOT_LAN", hotspotBridge, hotspotPorts, true),
    ...renderBridge("POS_LAN", bridgeConfigs.POS_LAN, portsFor(assignments, "POS_LAN"), false),
    ...renderBridge("CCTV_LAN", bridgeConfigs.CCTV_LAN, portsFor(assignments, "CCTV_LAN"), false)
  ];

  return [
    `# NobliFi setup for ${account.name} / ${router.name}`,
    `# Paste into MikroTik terminal after confirming WAN is ${wanInterface}.`,
    `# Generated from dynamic MikroTik port topology. Only selected ports are changed.`,
    `/ip hotspot remove [find name="noblifi-hotspot"]`,
    `/ip hotspot profile remove [find name="noblifi-profile"]`,
    `/ip hotspot user profile remove [find name="noblifi-voucher-profile"]`,
    `/radius remove [find comment="NobliFi RADIUS"]`,
    `/ip firewall nat remove [find comment="NobliFi client NAT"]`,
    `/ip firewall mangle remove [find comment="NobliFi prevent hotspot sharing"]`,
    ...bridgeCommands,
    `/ip dns set allow-remote-requests=yes`,
    `/ip firewall nat add chain=srcnat out-interface=${wanInterface} action=masquerade comment="NobliFi client NAT"`,
    `/radius add service=hotspot address=${radiusAddress} secret="${router.radius_secret}" authentication-port=1812 accounting-port=1813 timeout=3s comment="NobliFi RADIUS"`,
    `/radius incoming set accept=yes`,
    `/ip hotspot user profile add name=noblifi-voucher-profile shared-users=1 keepalive-timeout=2m status-autorefresh=1m`,
    `/ip hotspot profile add name=noblifi-profile hotspot-address=${gatewayIP(hotspotBridge.gateway)} use-radius=yes login-by=http-chap,http-pap radius-accounting=yes radius-interim-update=5m html-directory=noblifi`,
    `/ip hotspot add name=noblifi-hotspot interface=${hotspotBridge.name} profile=noblifi-profile address-pool=${hotspotBridge.poolName} disabled=no`,
    `/ip hotspot walled-garden ip add dst-host=${portalHost} action=accept comment="Allow NobliFi billing portal"`,
    `/ip hotspot walled-garden add dst-host=${portalHost} comment="Allow NobliFi billing portal host"`,
    ...renderHotspotLoginInstallScript(router, account, { publicBaseUrl: publicBase })
  ].join("\n");
}

function renderHotspotLoginTemplate(router, account, opts = {}) {
  const publicBase = (opts.publicBaseUrl || process.env.PUBLIC_BASE_URL || "").replace(/\/+$/, "");
  if (!publicBase) throw new Error("PUBLIC_BASE_URL is required to render MikroTik login.html.");
  const loginUrl = `${publicBase}/portal/${account.slug}/login.html`;
  const redirectUrl = `${loginUrl}?mac=$(mac)&ip=$(ip)&link-login-only=$(link-login-only)&link-orig=$(link-orig)`;
  return [
    "<!doctype html>",
    "<html>",
    "<head>",
    "  <meta charset=\"utf-8\">",
    "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
    `  <title>${escapeHtml(account.name)} WiFi Login</title>`,
    "</head>",
    "<body>",
    "  <script>",
    `    location.replace(${JSON.stringify(redirectUrl)});`,
    "  </script>",
    `  <a href="${escapeHtml(redirectUrl)}">Continue to WiFi login</a>`,
    "</body>",
    "</html>"
  ].join("\n");
}

function renderHotspotLoginInstallScript(router, account, opts = {}) {
  const publicBase = (opts.publicBaseUrl || process.env.PUBLIC_BASE_URL || "").replace(/\/+$/, "");
  if (!publicBase) throw new Error("PUBLIC_BASE_URL is required before generating the MikroTik login template fetch command.");
  const fetchUrl = `${publicBase}/api/admin/routers/${router.id}/hotspot-login.html`;
  const portalHost = hostFromUrl(publicBase);
  const mode = publicBase.toLowerCase().startsWith("https://") ? "https" : "http";
  return [
    `# Install MikroTik HotSpot login template for ${account.name}`,
    ...(portalHost ? [
      `/ip hotspot walled-garden remove [find comment="Allow NobliFi billing portal host"]`,
      `/ip hotspot walled-garden add dst-host=${portalHost} comment="Allow NobliFi billing portal host"`
    ] : []),
    `:if ([:len [/file find name="noblifi"]] = 0) do={ /file make-directory noblifi }`,
    `/file remove [find name="noblifi/login.html"]`,
    `/tool fetch url="${fetchUrl}" mode=${mode} dst-path="noblifi/login.html"`,
    `/ip hotspot profile set [find name="noblifi-profile"] html-directory=noblifi`
  ];
}

function renderDiscoveryScript(router, opts = {}) {
  const publicBase = (opts.publicBaseUrl || process.env.PUBLIC_BASE_URL || "").replace(/\/+$/, "");
  if (!/^https:\/\//i.test(publicBase)) {
    throw new Error("PUBLIC_BASE_URL must be a public HTTPS URL before generating the RouterOS discovery script.");
  }
  if (!router.checkin_token) throw new Error("This router has no check-in token. Recreate it or run the database migration.");
  const checkinBase = `${publicBase}/api/provisioning/check-in/${router.checkin_token}`;
  const interfaceBase = `${publicBase}/api/provisioning/interface/${router.checkin_token}`;
  return [
    `# NobliFi RouterOS 6/7 discovery for ${router.name}`,
    `:local model [/system routerboard get model]`,
    `:local serial [/system routerboard get serial-number]`,
    `:local versionRaw [/system resource get version]`,
    `:local versionEnd [:find $versionRaw " "]`,
    `:local version $versionRaw`,
    `:if ($versionEnd != nil) do={ :set version [:pick $versionRaw 0 $versionEnd] }`,
    `:local checkinUrl ("${checkinBase}" . "?model=" . $model . "&serial=" . $serial . "&version=" . $version)`,
    `/tool fetch url=$checkinUrl mode=https keep-result=no`,
    `:foreach portId in=[/interface ethernet find] do={`,
    `  :local portName [/interface ethernet get $portId name]`,
    `  :local portMac [/interface ethernet get $portId mac-address]`,
    `  :local portRunning [/interface ethernet get $portId running]`,
    `  :local portUrl ("${interfaceBase}" . "?name=" . $portName . "&type=ether&mac=" . $portMac . "&running=" . $portRunning)`,
    `  /tool fetch url=$portUrl mode=https keep-result=no`,
    `}`,
    `:put ("NobliFi discovery complete: " . $model . " RouterOS " . $version)`
  ].join("\n");
}

function portsFor(assignments, role) {
  return assignments.filter((item) => item.role === role).map((item) => item.interface);
}

function bridgeOptions(topology, router) {
  const saved = topology.bridges || {};
  return {
    HOTSPOT_LAN: normalizeBridge(saved.HOTSPOT_LAN, {
      name: router.bridge_name || "br-hotspot",
      gateway: router.lan_cidr || "10.10.10.1/24",
      pool: router.pool_range || "10.10.10.10-10.10.10.254",
      poolName: "pool-hotspot",
      dhcpName: "dhcp-hotspot"
    }),
    STAFF_LAN: normalizeBridge(saved.STAFF_LAN, {
      name: "br-staff",
      gateway: "10.20.20.1/24",
      pool: "10.20.20.10-10.20.20.254",
      poolName: "pool-staff",
      dhcpName: "dhcp-staff"
    }),
    POS_LAN: normalizeBridge(saved.POS_LAN, {
      name: "br-pos",
      gateway: "10.30.30.1/24",
      pool: "10.30.30.10-10.30.30.254",
      poolName: "pool-pos",
      dhcpName: "dhcp-pos"
    }),
    CCTV_LAN: normalizeBridge(saved.CCTV_LAN, {
      name: "br-cctv",
      gateway: "10.40.40.1/24",
      pool: "10.40.40.10-10.40.40.254",
      poolName: "pool-cctv",
      dhcpName: "dhcp-cctv"
    })
  };
}

function normalizeBridge(input = {}, fallback) {
  return {
    name: input.name || fallback.name,
    gateway: input.gateway || fallback.gateway,
    pool: input.pool || fallback.pool,
    poolName: input.poolName || fallback.poolName,
    dhcpName: input.dhcpName || fallback.dhcpName
  };
}

function renderBridge(role, bridge, ports, hotspot) {
  if (!ports.length) return [`# ${role}: no ports assigned; bridge skipped`];
  const network = networkCIDR(bridge.gateway);
  return [
    `# ${role} bridge`,
    `:if ([:len [/interface bridge find name="${bridge.name}"]] = 0) do={ /interface bridge add name=${bridge.name} protocol-mode=rstp comment="NobliFi ${role} bridge" }`,
    ...ports.flatMap((port) => [
      `/interface bridge port remove [find interface=${port}]`,
      `/interface bridge port add bridge=${bridge.name} interface=${port} comment="NobliFi ${role} port"`
    ]),
    `/ip address remove [find comment="NobliFi ${role} gateway"]`,
    `/ip address add address=${bridge.gateway} interface=${bridge.name} comment="NobliFi ${role} gateway"`,
    `/ip dhcp-server remove [find name="${bridge.dhcpName}"]`,
    `/ip dhcp-server network remove [find address=${network}]`,
    `/ip pool remove [find name="${bridge.poolName}"]`,
    `/ip pool add name=${bridge.poolName} ranges=${bridge.pool}`,
    `/ip dhcp-server add name=${bridge.dhcpName} interface=${bridge.name} address-pool=${bridge.poolName} disabled=no`,
    `/ip dhcp-server network add address=${network} gateway=${gatewayIP(bridge.gateway)} dns-server=${gatewayIP(bridge.gateway)}`,
    hotspot ? `/ip firewall mangle add chain=prerouting in-interface=${bridge.name} action=change-ttl new-ttl=set:1 comment="NobliFi prevent hotspot sharing"` : `# ${role}: hotspot services disabled`
  ];
}

function resultData(result, fallback) {
  if (result && typeof result === "object" && "error" in result) return result.data ?? fallback;
  return result ?? fallback;
}

function withPersistedFallback(result, fallback) {
  const data = resultData(result, Array.isArray(fallback) ? [] : {});
  const hasData = Array.isArray(data) ? data.length > 0 : Object.keys(data || {}).length > 0;
  return hasData ? result : fallback;
}

function persistedInterfaces(router) {
  if (!router.interfaces_json) return [];
  try {
    const parsed = JSON.parse(router.interfaces_json);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function isIPv4(value) {
  const parts = String(value || "").trim().split(".");
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function gatewayIP(cidr) {
  return String(cidr || "").split("/")[0];
}

function networkCIDR(cidr) {
  const [ip, prefix = "24"] = String(cidr || "10.10.10.1/24").split("/");
  const parts = ip.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => Number.isNaN(part))) return cidr;
  const mask = prefix === "19" ? [255, 255, 224, 0] : prefix === "20" ? [255, 255, 240, 0] : prefix === "23" ? [255, 255, 254, 0] : [255, 255, 255, 0];
  return `${parts.map((part, index) => part & mask[index]).join(".")}/${prefix}`;
}

function parseTopology(raw) {
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function hostFromUrl(value) {
  try {
    return new URL(value).hostname;
  } catch {
    return "";
  }
}

module.exports = {
  mikrotikFetch,
  activeSessions,
  disconnectUser,
  routerSnapshot,
  renderSetupScript,
  renderHotspotLoginTemplate,
  renderHotspotLoginInstallScript,
  renderDiscoveryScript,
  routerById
};
