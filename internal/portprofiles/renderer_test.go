package portprofiles

import (
	"strings"
	"testing"
)

func validRenderOptions() RenderOptions {
	return RenderOptions{
		RadiusServer: "203.0.113.10",
		APIPassword:  "strong-router-api-password",
	}
}

func TestDefaultWalledGardenHostsDoNotBypassCaptivePortalChecks(t *testing.T) {
	hosts := defaultWalledGardenHosts()
	for _, blocked := range []string{"captive.apple.com", "connectivitycheck.gstatic.com", "connectivitycheck.android.com", "www.msftconnecttest.com"} {
		for _, host := range hosts {
			if host == blocked {
				t.Fatalf("default walled garden hosts must not include captive portal check host %q, got %v", blocked, hosts)
			}
		}
	}
}

func TestRenderRouterOSUsesIdempotentBridgePortAdds(t *testing.T) {
	assignments := []Assignment{
		{InterfaceName: "ether1", Role: "WAN"},
		{InterfaceName: "ether2", Role: "HOTSPOT_LAN"},
		{InterfaceName: "ether5", Role: "STAFF_LAN"},
	}

	script, err := RenderRouterOSWithOptions(assignments, validRenderOptions())
	if err != nil {
		t.Fatalf("RenderRouterOSWithOptions returned error: %v", err)
	}

	if !strings.Contains(script, `/interface bridge port remove [find where interface="ether2"]`) {
		t.Fatalf("expected bridge-port cleanup for ether2, got script:\n%s", script)
	}

	if !strings.Contains(script, `:if ([:len [/interface bridge port find where bridge="br-hotspot" interface="ether2"]] = 0) do={ /interface bridge port add bridge="br-hotspot" interface="ether2" comment="NobliFi HotSpot port" }`) {
		t.Fatalf("expected idempotent bridge-port add guard for ether2, got script:\n%s", script)
	}

	if strings.Contains(script, `bridge="br-hotspot" interface="ether5"`) {
		t.Fatalf("management port ether5 must not be added to HotSpot bridge, got script:\n%s", script)
	}
}

func TestRenderRouterOSRejectsNoManagementPort(t *testing.T) {
	assignments := []Assignment{
		{InterfaceName: "ether1", Role: "WAN"},
		{InterfaceName: "ether2", Role: "HOTSPOT_LAN"},
		{InterfaceName: "ether3", Role: "HOTSPOT_LAN"},
		{InterfaceName: "ether4", Role: "HOTSPOT_LAN"},
		{InterfaceName: "ether5", Role: "HOTSPOT_LAN"},
	}

	_, err := RenderRouterOSWithOptions(assignments, validRenderOptions())
	if err == nil || !strings.Contains(err.Error(), "STAFF_LAN") {
		t.Fatalf("expected missing management port error, got %v", err)
	}
}

func TestRenderRouterOSRejectsPlaceholderRadiusServer(t *testing.T) {
	assignments := []Assignment{
		{InterfaceName: "ether1", Role: "WAN"},
		{InterfaceName: "ether2", Role: "HOTSPOT_LAN"},
		{InterfaceName: "ether5", Role: "STAFF_LAN"},
	}

	options := validRenderOptions()
	options.RadiusServer = "127.0.0.1"
	_, err := RenderRouterOSWithOptions(assignments, options)
	if err == nil || !strings.Contains(err.Error(), "agent-managed RADIUS server") {
		t.Fatalf("expected RADIUS server config error, got %v", err)
	}
}

func TestRenderRouterOSRejectsReplaceWithRadiusServer(t *testing.T) {
	assignments := []Assignment{
		{InterfaceName: "ether1", Role: "WAN"},
		{InterfaceName: "ether2", Role: "HOTSPOT_LAN"},
		{InterfaceName: "ether5", Role: "STAFF_LAN"},
	}

	options := validRenderOptions()
	options.RadiusServer = "REPLACE_WITH_RADIUS_SERVER_PUBLIC_IP_OR_DOMAIN"
	_, err := RenderRouterOSWithOptions(assignments, options)
	if err == nil || !strings.Contains(err.Error(), "agent-managed RADIUS server") {
		t.Fatalf("expected RADIUS server config error, got %v", err)
	}
}

func TestRenderRouterOSRejectsPlaceholderAPIPassword(t *testing.T) {
	for _, password := range []string{"CHANGE_ME_API_PASSWORD", "REPLACE_WITH_STRONG_ROUTER_API_PASSWORD"} {
		options := validRenderOptions()
		options.APIPassword = password
		options.WireGuardEnabled = true
		options.WireGuardEndpoint = "vpn.example.com"
		options.WireGuardPublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		options.WireGuardClientIP = "10.77.0.2"
		_, err := RenderManagementBootstrap(options)
		if err == nil || !strings.Contains(err.Error(), "NOBLIFI_ROUTER_API_PASSWORD") {
			t.Fatalf("expected API password config error for %q, got %v", password, err)
		}
	}
}

func TestRenderRouterOSRejectsFrontendLoginPageURL(t *testing.T) {
	assignments := []Assignment{
		{InterfaceName: "ether1", Role: "WAN"},
		{InterfaceName: "ether2", Role: "HOTSPOT_LAN"},
		{InterfaceName: "ether5", Role: "STAFF_LAN"},
	}

	options := validRenderOptions()
	options.LoginPageURL = "https://noblifi-frontend.vercel.app/hotspot-login/NOB-1234-5678"
	_, err := RenderRouterOSWithOptions(assignments, options)
	if err == nil || !strings.Contains(err.Error(), "NOBLIFI_PROVISIONING_BASE_URL points at the frontend host") {
		t.Fatalf("expected frontend host config error, got %v", err)
	}
}

func TestRenderRouterOSRejectsNonProvisioningLoginPageURL(t *testing.T) {
	assignments := []Assignment{
		{InterfaceName: "ether1", Role: "WAN"},
		{InterfaceName: "ether2", Role: "HOTSPOT_LAN"},
		{InterfaceName: "ether5", Role: "STAFF_LAN"},
	}

	options := validRenderOptions()
	options.LoginPageURL = "https://noblifi.ew.r.appspot.com/dashboard"
	_, err := RenderRouterOSWithOptions(assignments, options)
	if err == nil || !strings.Contains(err.Error(), "backend /api/v1/provisioning/hotspot-login/:token route") {
		t.Fatalf("expected provisioning route config error, got %v", err)
	}
}

func TestRenderRouterOSInstallsHotspotLoginTemplate(t *testing.T) {
	assignments := []Assignment{
		{InterfaceName: "ether1", Role: "WAN"},
		{InterfaceName: "ether2", Role: "HOTSPOT_LAN"},
		{InterfaceName: "ether5", Role: "STAFF_LAN"},
	}

	options := validRenderOptions()
	options.LoginPageURL = "https://api.example.com/api/v1/provisioning/hotspot-login/NOB-1234-5678"
	options.HotspotSupportBaseURL = "https://api.example.com/api/v1/provisioning/hotspot-support/NOB-1234-5678"
	script, err := RenderRouterOSWithOptions(assignments, options)
	if err != nil {
		t.Fatalf("RenderRouterOSWithOptions returned error: %v", err)
	}

	required := []string{
		"/radius add service=hotspot address=203.0.113.10",
		`:if ([:len [/file find where name="flash"]] > 0) do={ :set hotspotHtmlDir "flash/noblifi"; :set hotspotHtmlPath "flash/noblifi" }`,
		"html-directory=$hotspotHtmlDir",
		":if ([:len [/file find where name=$hotspotHtmlPath]] = 0) do={ /file make-directory $hotspotHtmlPath }",
		`:local hotspotLoginFile ($hotspotHtmlPath . "/login.html")`,
		`:local hotspotIndexFile ($hotspotHtmlPath . "/index.html")`,
		`/tool fetch url="https://api.example.com/api/v1/provisioning/hotspot-login/NOB-1234-5678" mode=https dst-path=$hotspotLoginFile keep-result=yes idle-timeout=30s duration=1m`,
		`/tool fetch url="https://api.example.com/api/v1/provisioning/hotspot-login/NOB-1234-5678" mode=https dst-path=$hotspotIndexFile keep-result=yes idle-timeout=30s duration=1m`,
		`:if (!$noblifiPortalFetched) do={ :error "NobliFi custom portal download failed; not activating default MikroTik portal" }`,
		`:error "NobliFi custom portal incomplete; login.html, rlogin.html, or redirect.html missing from active HTML directory"`,
		`:if ([:len [/ip hotspot user profile find where name="noblifi-voucher-profile"]] = 0) do={ /ip hotspot user profile add name="noblifi-voucher-profile" }`,
		`/ip hotspot user profile set [find where name="noblifi-voucher-profile"] shared-users=1 keepalive-timeout=2m status-autorefresh=1m`,
		`:if ([:len [/ip hotspot find where name="noblifi-hotspot"]] = 0) do={ /ip hotspot add name="noblifi-hotspot" interface="br-hotspot" address-pool=pool-hotspot profile="noblifi-hotspot-profile" disabled=no }`,
		`/ip hotspot set [find where name="noblifi-hotspot"] interface="br-hotspot" address-pool=pool-hotspot profile="noblifi-hotspot-profile" disabled=no`,
		`/ip hotspot active remove [find]`,
		`/ip hotspot host remove [find where authorized=no]`,
		`/system scheduler add name="noblifi-hotspot-login-refresh" interval=10m`,
	}
	for _, item := range required {
		if !strings.Contains(script, item) {
			t.Fatalf("expected script to contain %q, got:\n%s", item, script)
		}
	}

	if strings.Contains(script, "action=allow comment=\"NobliFi captive portal\"") {
		t.Fatalf("RouterOS 6 compatible walled garden entries must not use action=allow, got:\n%s", script)
	}
	if strings.Contains(script, "custom portal incomplete; safely falling back") || strings.Contains(script, "not activating default MikroTik portal") == false {
		t.Fatalf("custom login fetch failures must fail the install instead of silently falling back, got:\n%s", script)
	}

	staffIndex := strings.Index(script, "# STAFF bridge, DHCP, and client addressing")
	radiusIndex := strings.Index(script, "/radius add service=hotspot address=203.0.113.10")
	if staffIndex == -1 || radiusIndex == -1 || staffIndex > radiusIndex {
		t.Fatalf("expected selected staff port setup before critical HotSpot services, got:\n%s", script)
	}

	serverIndex := strings.Index(script, `/ip hotspot add name="noblifi-hotspot"`)
	fetchIndex := strings.Index(script, `/tool fetch url="https://api.example.com/api/v1/provisioning/hotspot-login/NOB-1234-5678" mode=https dst-path=$hotspotLoginFile`)
	if serverIndex == -1 || fetchIndex == -1 || serverIndex > fetchIndex {
		t.Fatalf("expected HotSpot server to be installed before custom login fetch can fail, got:\n%s", script)
	}
}

func TestRenderRouterOSAddsFallbackHotspotSupportPages(t *testing.T) {
	assignments := []Assignment{
		{InterfaceName: "ether1", Role: "WAN"},
		{InterfaceName: "ether2", Role: "HOTSPOT_LAN"},
		{InterfaceName: "ether5", Role: "STAFF_LAN"},
	}

	options := validRenderOptions()
	options.LoginPageURL = "https://api.example.com/api/v1/provisioning/hotspot-login/NOB-1234-5678"
	options.HotspotSupportBaseURL = "https://api.example.com/api/v1/provisioning/hotspot-support/NOB-1234-5678"
	script, err := RenderRouterOSWithOptions(assignments, options)
	if err != nil {
		t.Fatalf("RenderRouterOSWithOptions returned error: %v", err)
	}

	required := []string{
		`:if ($f = "flogout.html") do={ :set fallbackURL "https://api.example.com/api/v1/provisioning/hotspot-support/NOB-1234-5678/flogout.html" }`,
		`:if ($f = "fstatus.html") do={ :set fallbackURL "https://api.example.com/api/v1/provisioning/hotspot-support/NOB-1234-5678/fstatus.html" }`,
		`:if ($f = "rstatus.html") do={ :set fallbackURL "https://api.example.com/api/v1/provisioning/hotspot-support/NOB-1234-5678/rstatus.html" }`,
		`:local fallbackResult [/tool fetch url=$fallbackURL output=user as-value idle-timeout=30s duration=1m]`,
		`:put ("NobliFi support file ready: " . $f . " (NobliFi captive portal)")`,
		`:put ("NobliFi WARNING: default HotSpot support file missing: " . $src)`,
	}
	for _, item := range required {
		if !strings.Contains(script, item) {
			t.Fatalf("expected script to contain %q, got:\n%s", item, script)
		}
	}
}
