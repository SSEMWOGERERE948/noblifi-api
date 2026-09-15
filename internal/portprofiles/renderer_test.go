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
		{InterfaceName: "ether5", Role: "FREE_LAN"},
	}

	script, err := RenderRouterOSWithOptions(assignments, validRenderOptions())
	if err != nil {
		t.Fatalf("RenderRouterOSWithOptions returned error: %v", err)
	}

	if !strings.Contains(script, `/interface bridge port remove [find where interface="ether2"]`) {
		t.Fatalf("expected bridge-port cleanup for ether2, got script:\n%s", script)
	}

	if !strings.Contains(script, `:if ([:len [/interface bridge port find where bridge="br-hotspot" interface="ether2"]] = 0) do={ :do { /interface bridge port remove [find where interface="ether2"] } on-error={}; :do { /interface bridge port add bridge="br-hotspot" interface="ether2" comment="NobliFi HotSpot port" }`) {
		t.Fatalf("expected idempotent bridge-port add guard for ether2, got script:\n%s", script)
	}

	if strings.Contains(script, `bridge="br-hotspot" interface="ether5" comment="NobliFi HotSpot port"`) {
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
	if err == nil || !strings.Contains(err.Error(), "free and outside") {
		t.Fatalf("expected missing management port error, got %v", err)
	}
}

func TestRenderRouterOSRejectsPlaceholderRadiusServer(t *testing.T) {
	assignments := []Assignment{
		{InterfaceName: "ether1", Role: "WAN"},
		{InterfaceName: "ether2", Role: "HOTSPOT_LAN"},
		{InterfaceName: "ether5", Role: "FREE_LAN"},
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
		{InterfaceName: "ether5", Role: "FREE_LAN"},
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
		{InterfaceName: "ether5", Role: "FREE_LAN"},
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

func TestRenderRouterOSInstallsHotspotLoginTemplate(t *testing.T) {
	assignments := []Assignment{
		{InterfaceName: "ether1", Role: "WAN"},
		{InterfaceName: "ether2", Role: "HOTSPOT_LAN"},
		{InterfaceName: "ether5", Role: "FREE_LAN"},
	}

	options := validRenderOptions()
	options.LoginPageURL = "https://api.example.com/api/v1/provisioning/hotspot-login/NOB-1234-5678"
	script, err := RenderRouterOSWithOptions(assignments, options)
	if err != nil {
		t.Fatalf("RenderRouterOSWithOptions returned error: %v", err)
	}

	required := []string{
		`/radius add service=hotspot address="203.0.113.10"`,
		`html-directory="/flash/noblifi"`,
		`/file add name="/flash/noblifi" type=directory`,
		`/tool fetch url="https://api.example.com/api/v1/provisioning/hotspot-login/NOB-1234-5678" mode=https dst-path="flash/noblifi/login.html"`,
		`/ip hotspot profile set $p html-directory="/flash/noblifi"`,
	}
	for _, item := range required {
		if !strings.Contains(script, item) {
			t.Fatalf("expected script to contain %q, got:\n%s", item, script)
		}
	}

	if strings.Contains(script, "action=allow comment=\"NobliFi captive portal\"") {
		t.Fatalf("RouterOS 6 compatible walled garden entries must not use action=allow, got:\n%s", script)
	}

	radiusIndex := strings.Index(script, `/radius add service=hotspot address="203.0.113.10"`)
	portAttachIndex := strings.Index(script, "# Final HotSpot physical-port assignment")
	if radiusIndex == -1 || portAttachIndex == -1 || radiusIndex > portAttachIndex {
		t.Fatalf("expected RADIUS and HotSpot setup before final port attachment, got:\n%s", script)
	}
}

func TestRenderRouterOSUsesNonAggressiveHotspotSessionTimeouts(t *testing.T) {
	assignments := []Assignment{
		{InterfaceName: "ether1", Role: "WAN"},
		{InterfaceName: "ether2", Role: "HOTSPOT_LAN"},
		{InterfaceName: "ether5", Role: "FREE_LAN"},
	}

	script, err := RenderRouterOSWithOptions(assignments, validRenderOptions())
	if err != nil {
		t.Fatalf("RenderRouterOSWithOptions returned error: %v", err)
	}

	required := []string{
		`/ip hotspot user profile set noblifi-voucher-profile idle-timeout=none`,
		`/ip hotspot user profile set noblifi-voucher-profile keepalive-timeout=10m`,
		`/ip hotspot profile set $p radius-interim-update=5m`,
	}
	for _, item := range required {
		if !strings.Contains(script, item) {
			t.Fatalf("expected script to contain %q, got:\n%s", item, script)
		}
	}

	forbidden := []string{
		`idle-timeout=5m`,
		`keepalive-timeout=2m`,
	}
	for _, item := range forbidden {
		if strings.Contains(script, item) {
			t.Fatalf("script contains aggressive timeout %q:\n%s", item, script)
		}
	}
}

func TestRenderRouterOSUsesAbsoluteRouterOSCaptivePortalLinks(t *testing.T) {
	assignments := []Assignment{
		{InterfaceName: "ether1", Role: "WAN"},
		{InterfaceName: "ether2", Role: "HOTSPOT_LAN"},
		{InterfaceName: "ether5", Role: "FREE_LAN"},
	}

	options := validRenderOptions()
	options.LoginPageURL = "https://api.example.com/api/v1/provisioning/hotspot-login/NOB-1234-5678"
	script, err := RenderRouterOSWithOptions(assignments, options)
	if err != nil {
		t.Fatalf("RenderRouterOSWithOptions returned error: %v", err)
	}

	required := []string{
		`\$(if http-status == 302)NobliFi login successful\$(endif)`,
		`\$(if http-header == \"Location\")\$(link-orig)\$(endif)`,
		`href=\"\$(link-login-only)?noblifi_manual=1\"`,
		`href=\"\$(link-logout)?noblifi_manual=1\"`,
		`href=\"\$(link-status)\"`,
		`background:linear-gradient(145deg,#06111f 0%,#0b1727 52%,#102033 100%)`,
		`class=\"card\"`,
		`class=\"btn\"`,
	}
	for _, item := range required {
		if !strings.Contains(script, item) {
			t.Fatalf("expected script to contain %q, got:\n%s", item, script)
		}
	}

	forbidden := []string{
		`url=/login`,
		`url=/status`,
		`href=\"/login\"`,
		`href=\"/logout\"`,
		`href=\"/status\"`,
	}
	for _, item := range forbidden {
		if strings.Contains(script, item) {
			t.Fatalf("script still contains relative captive portal link %q:\n%s", item, script)
		}
	}
}

func TestRenderRouterOSRemovesCaptiveDetectionWalledGardenRules(t *testing.T) {
	assignments := []Assignment{
		{InterfaceName: "ether1", Role: "WAN"},
		{InterfaceName: "ether2", Role: "HOTSPOT_LAN"},
		{InterfaceName: "ether5", Role: "FREE_LAN"},
	}

	options := validRenderOptions()
	options.LoginPageURL = "https://api.example.com/api/v1/provisioning/hotspot-login/NOB-1234-5678"
	options.WalledGardenHosts = append(options.WalledGardenHosts, "www.msftconnecttest.com")

	script, err := RenderRouterOSWithOptions(assignments, options)
	if err != nil {
		t.Fatalf("RenderRouterOSWithOptions returned error: %v", err)
	}

	if !strings.Contains(script, `/ip hotspot walled-garden remove [find where dst-host="www.msftconnecttest.com" comment="NobliFi captive portal"]`) {
		t.Fatalf("expected cleanup for old NobliFi-owned Windows captive-detection walled garden, got:\n%s", script)
	}
	if strings.Contains(script, `/ip hotspot walled-garden add dst-host="www.msftconnecttest.com"`) {
		t.Fatalf("captive-detection host must not be added to walled garden, got:\n%s", script)
	}
}
