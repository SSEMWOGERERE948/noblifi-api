package portprofiles

import (
	"strings"
	"testing"
)

func TestRenderRouterOSUsesIdempotentBridgePortAdds(t *testing.T) {
	assignments := []Assignment{
		{InterfaceName: "ether2", Role: "HOTSPOT_LAN"},
	}

	script, err := RenderRouterOSWithOptions(assignments, RenderOptions{})
	if err != nil {
		t.Fatalf("RenderRouterOSWithOptions returned error: %v", err)
	}

	if !strings.Contains(script, "/interface bridge port remove [find interface=ether2]") {
		t.Fatalf("expected bridge-port cleanup for ether2, got script:\n%s", script)
	}

	if !strings.Contains(script, ":if ([:len [/interface bridge port find bridge=br-hotspot interface=ether2]] = 0) do={/interface bridge port add bridge=br-hotspot interface=ether2 comment=\"NobliFi HotSpot port\"}") {
		t.Fatalf("expected idempotent bridge-port add guard for ether2, got script:\n%s", script)
	}
}
