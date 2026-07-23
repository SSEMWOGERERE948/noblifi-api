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

	if !strings.Contains(script, "/interface bridge port remove [find interface=ether2]") {
		t.Fatalf("expected bridge-port cleanup for ether2, got script:\n%s", script)
	}

	if !strings.Contains(script, ":if ([:len [/interface bridge port find bridge=br-hotspot interface=ether2]] = 0) do={/interface bridge port add bridge=br-hotspot interface=ether2 comment=\"NobliFi HotSpot port\"}") {
		t.Fatalf("expected idempotent bridge-port add guard for ether2, got script:\n%s", script)
	}

	if strings.Contains(script, "bridge=br-hotspot interface=ether5") {
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
	if err == nil || !strings.Contains(err.Error(), "NOBLIFI_RADIUS_SERVER") {
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
	if err == nil || !strings.Contains(err.Error(), "NOBLIFI_RADIUS_SERVER") {
		t.Fatalf("expected RADIUS server config error, got %v", err)
	}
}

func TestRenderRouterOSRejectsPlaceholderAPIPassword(t *testing.T) {
	assignments := []Assignment{
		{InterfaceName: "ether1", Role: "WAN"},
		{InterfaceName: "ether2", Role: "HOTSPOT_LAN"},
		{InterfaceName: "ether5", Role: "STAFF_LAN"},
	}

	for _, password := range []string{"", "CHANGE_ME_API_PASSWORD", "REPLACE_WITH_STRONG_ROUTER_API_PASSWORD"} {
		options := validRenderOptions()
		options.APIPassword = password
		_, err := RenderRouterOSWithOptions(assignments, options)
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
	script, err := RenderRouterOSWithOptions(assignments, options)
	if err != nil {
		t.Fatalf("RenderRouterOSWithOptions returned error: %v", err)
	}

	required := []string{
		"/radius add service=hotspot address=203.0.113.10",
		`:if ([:len [/file find name="flash" type="directory"]] > 0) do={ :set hotspotHtmlDir "flash/noblifi"; :set hotspotHtmlPath "flash/noblifi" }`,
		"html-directory=$hotspotHtmlDir",
		":if ([:len [/file find name=$hotspotHtmlPath]] = 0) do={ /file make-directory $hotspotHtmlPath }",
		`:local hotspotLoginFile ($hotspotHtmlPath . "/login.html")`,
		`:local hotspotIndexFile ($hotspotHtmlPath . "/index.html")`,
		"/tool fetch url=\"https://api.example.com/api/v1/provisioning/hotspot-login/NOB-1234-5678\" mode=https dst-path=$hotspotLoginFile",
		"/tool fetch url=\"https://api.example.com/api/v1/provisioning/hotspot-login/NOB-1234-5678\" mode=https dst-path=$hotspotIndexFile",
		`:if ([:len [/ip hotspot user profile find name=noblifi-voucher-profile]] = 0) do={ /ip hotspot user profile add name=noblifi-voucher-profile }`,
		"/ip hotspot user profile set [find name=noblifi-voucher-profile] shared-users=1 keepalive-timeout=2m status-autorefresh=1m",
		`:if ([:len [/ip hotspot profile find name=noblifi-hotspot-profile]] = 0) do={ /ip hotspot profile add name=noblifi-hotspot-profile hotspot-address=10.10.10.1 dns-name=login.noblifi.local use-radius=yes login-by=http-chap,http-pap }`,
		"/ip hotspot profile set [find name=noblifi-hotspot-profile] hotspot-address=10.10.10.1 dns-name=login.noblifi.local use-radius=yes radius-accounting=yes radius-interim-update=5m login-by=http-chap,http-pap",
		`:if ([:len [/file find name=$hotspotLoginFile]] > 0) do={ /ip hotspot profile set [find name=noblifi-hotspot-profile] html-directory=$hotspotHtmlDir; :put "NobliFi HotSpot login and index pages installed" } else={ :error "NobliFi HotSpot login fetch did not create login.html" }`,
		`:if ([:len [/ip hotspot find name=noblifi-hotspot]] = 0) do={ /ip hotspot add name=noblifi-hotspot interface=br-hotspot address-pool=pool-hotspot profile=noblifi-hotspot-profile disabled=no }`,
		"/ip hotspot set [find name=noblifi-hotspot] interface=br-hotspot address-pool=pool-hotspot profile=noblifi-hotspot-profile disabled=no",
		`:if ([:len [/interface bridge port find bridge=br-hotspot]] = 0) do={ :error "No HotSpot LAN ports were added to br-hotspot" }`,
		`:if ([:len [/ip pool find name=pool-hotspot]] = 0) do={ /ip pool add name=pool-hotspot`,
		`:if ([:len [/ip dhcp-server find name=dhcp-hotspot]] = 0) do={ /ip dhcp-server add name=dhcp-hotspot interface=br-hotspot`,
		`:if ([:len [/ip dhcp-server network find where address=10.10.10.0/24]] = 0) do={ /ip dhcp-server network add address=10.10.10.0/24 gateway=10.10.10.1 dns-server=10.10.10.1 } else={ /ip dhcp-server network set [find where address=10.10.10.0/24] gateway=10.10.10.1 dns-server=10.10.10.1 }`,
		`:if ([:len [/ip dhcp-server find name=dhcp-hotspot interface=br-hotspot disabled=no]] = 0) do={ :error "NobliFi HotSpot DHCP is not enabled on br-hotspot" }`,
		`:if ([:len [/radius find comment="NobliFi RADIUS"]] = 0) do={ :error "NobliFi RADIUS client is missing" }`,
		`:if ([:len [/ip firewall nat find comment="NobliFi client NAT"]] = 0) do={ :error "NobliFi client NAT is missing" }`,
		`:if ([:len [/ip hotspot profile find name=noblifi-hotspot-profile]] = 0) do={ :error "NobliFi HotSpot server profile is missing" }`,
		`:if ([:len [/ip hotspot find name=noblifi-hotspot interface=br-hotspot disabled=no]] = 0) do={ :error "NobliFi HotSpot server is not enabled on br-hotspot" }`,
		"/system scheduler add name=noblifi-hotspot-login-refresh interval=10m",
		`dst-path=\$hotspotIndexFile`,
	}
	for _, item := range required {
		if !strings.Contains(script, item) {
			t.Fatalf("expected script to contain %q, got:\n%s", item, script)
		}
	}

	if strings.Contains(script, "action=allow comment=\"NobliFi captive portal\"") {
		t.Fatalf("RouterOS 6 compatible walled garden entries must not use action=allow, got:\n%s", script)
	}
	if strings.Contains(script, "NobliFi skipped fetch hotspot") || strings.Contains(script, "using default RouterOS login page") {
		t.Fatalf("custom login fetch failures must fail the install instead of silently falling back, got:\n%s", script)
	}

	radiusIndex := strings.Index(script, "/radius add service=hotspot address=203.0.113.10")
	staffIndex := strings.Index(script, "# STAFF bridge, DHCP, and client addressing")
	if radiusIndex == -1 || staffIndex == -1 || radiusIndex > staffIndex {
		t.Fatalf("expected RADIUS and HotSpot setup before staff bridge setup, got:\n%s", script)
	}
}
