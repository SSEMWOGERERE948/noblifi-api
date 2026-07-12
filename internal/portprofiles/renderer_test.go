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
