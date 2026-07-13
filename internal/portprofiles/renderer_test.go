package portprofiles

import (
	"strings"
	"testing"
)

func TestRenderRouterOSUsesIdempotentBridgePortAdds(t *testing.T) {
	assignments := []Assignment{
		{InterfaceName: "ether1", Role: "WAN"},
		{InterfaceName: "ether2", Role: "HOTSPOT_LAN"},
		{InterfaceName: "ether5", Role: "STAFF_LAN"},
	}

	script, err := RenderRouterOSWithOptions(assignments, RenderOptions{RadiusServer: "203.0.113.10"})
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

	_, err := RenderRouterOSWithOptions(assignments, RenderOptions{RadiusServer: "203.0.113.10"})
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

	_, err := RenderRouterOSWithOptions(assignments, RenderOptions{RadiusServer: "127.0.0.1"})
	if err == nil || !strings.Contains(err.Error(), "NOBLIFI_RADIUS_SERVER") {
		t.Fatalf("expected RADIUS server config error, got %v", err)
	}
}

func TestRenderRouterOSInstallsHotspotLoginTemplate(t *testing.T) {
	assignments := []Assignment{
		{InterfaceName: "ether1", Role: "WAN"},
		{InterfaceName: "ether2", Role: "HOTSPOT_LAN"},
		{InterfaceName: "ether5", Role: "STAFF_LAN"},
	}

	script, err := RenderRouterOSWithOptions(assignments, RenderOptions{
		RadiusServer: "203.0.113.10",
		LoginPageURL: "https://api.example.com/api/v1/provisioning/hotspot-login/NOB-1234-5678",
	})
	if err != nil {
		t.Fatalf("RenderRouterOSWithOptions returned error: %v", err)
	}

	required := []string{
		"/radius add service=hotspot address=203.0.113.10",
		"html-directory=noblifi",
		":if ([:len [/file find name=\"noblifi\"]] = 0) do={ /file make-directory noblifi }",
		"/tool fetch url=\"https://api.example.com/api/v1/provisioning/hotspot-login/NOB-1234-5678\" mode=https dst-path=\"noblifi/login.html\"",
		"/ip hotspot profile set noblifi-hotspot-profile html-directory=noblifi",
	}
	for _, item := range required {
		if !strings.Contains(script, item) {
			t.Fatalf("expected script to contain %q, got:\n%s", item, script)
		}
	}

	if strings.Contains(script, "action=allow comment=\"NobliFi captive portal\"") {
		t.Fatalf("RouterOS 6 compatible walled garden entries must not use action=allow, got:\n%s", script)
	}
}
