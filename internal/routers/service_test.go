package routers

import (
	"strings"
	"testing"

	"github.com/noblifi/noblifi/backend/internal/config"
)

func TestNormalizeNetworkProfileReplacesPlaceholderValues(t *testing.T) {
	profile := RouterNetworkProfile{
		RadiusServer:   "REPLACE_WITH_RADIUS_SERVER_PUBLIC_IP_OR_DOMAIN",
		RadiusSecret:   "REPLACE_WITH_STRONG_RADIUS_SECRET",
		APIPassword:    "CHANGE_ME_API_PASSWORD",
		RouterIdentity: "NobliFi-Test",
	}
	cfg := config.Config{
		RadiusServer:      "10.10.10.254",
		RadiusSecret:      "noblifi",
		RouterAPIPassword: "NoblifiApi-7Qv9pL2mR4sX",
	}

	NormalizeNetworkProfile(&profile, cfg)

	if profile.RadiusServer != cfg.RadiusServer {
		t.Fatalf("expected radius server fallback, got %q", profile.RadiusServer)
	}
	if profile.RadiusSecret != cfg.RadiusSecret {
		t.Fatalf("expected radius secret fallback, got %q", profile.RadiusSecret)
	}
	if profile.APIPassword != cfg.RouterAPIPassword {
		t.Fatalf("expected API password fallback, got %q", profile.APIPassword)
	}
	if profile.RouterIdentity != "NobliFi-Test" {
		t.Fatalf("non-placeholder profile fields should be preserved, got %q", profile.RouterIdentity)
	}
}

func TestRenderWireGuardRouterOSIsManagementOnly(t *testing.T) {
	tunnelIP := "10.77.0.2"
	router := Router{
		Name:              "Branch One",
		ClaimToken:        "NOB-TEST-0001",
		WireGuardTunnelIP: &tunnelIP,
	}
	cfg := config.Config{
		ProvisioningBaseURL: "https://api.example.com/api/v1/provisioning",
		WireGuardEnabled:    true,
		WireGuardEndpoint:   "vpn.example.com",
		WireGuardPort:       51820,
		WireGuardPublicKey:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		WireGuardInterface:  "wg0",
		WireGuardServerIP:   "10.77.0.1",
		WireGuardSubnetCIDR: "10.77.0.0/24",
		WireGuardKeepalive:  25,
	}

	script := RenderWireGuardRouterOS(router, cfg)
	required := []string{
		`:local wgName "noblifi-wg"`,
		"/interface wireguard add",
		"address=10.77.0.2/32",
		"allowed-address=10.77.0.1/32",
		"persistent-keepalive=25s",
		"/provisioning/wireguard-key",
		"dst-port=8291,8728,8729",
	}
	for _, value := range required {
		if !strings.Contains(script, value) {
			t.Fatalf("expected WireGuard script to contain %q, got:\n%s", value, script)
		}
	}

	forbidden := []string{
		"allowed-address=0.0.0.0/0",
		"/ip route add",
		"/interface bridge",
		"/ip dhcp-client",
	}
	for _, value := range forbidden {
		if strings.Contains(script, value) {
			t.Fatalf("management tunnel must not contain %q, got:\n%s", value, script)
		}
	}
}

func TestRouterSupportsWireGuardRequiresRouterOS7(t *testing.T) {
	v6 := "6.49.15"
	v7 := "7.20.8 (long-term)"
	if routerSupportsWireGuard(&v6) {
		t.Fatal("expected RouterOS 6 to be rejected")
	}
	if !routerSupportsWireGuard(&v7) {
		t.Fatal("expected RouterOS 7 to be accepted")
	}
}

func TestBootstrapScriptFetchesImportsAndCleansUp(t *testing.T) {
	script := bootstrapScript("NOB-1234-5678", "https://api.example.com/api/v1/provisioning")

	required := []string{
		`/tool fetch url="https://api.example.com/api/v1/provisioning/bootstrap/NOB-1234-5678" mode=https dst-path="noblifi-bootstrap.rsc"`,
		`:delay 2s`,
		`/import file-name="noblifi-bootstrap.rsc"`,
		`:delay 1s`,
		`/file remove "noblifi-bootstrap.rsc"`,
	}
	for _, item := range required {
		if !strings.Contains(script, item) {
			t.Fatalf("expected bootstrap command to contain %q, got:\n%s", item, script)
		}
	}
}

func TestConfigInstallCommandFetchesImportsAndCleansUp(t *testing.T) {
	script := configInstallCommand("NOB-1234-5678", "https://api.example.com/api/v1/provisioning")

	required := []string{
		`/tool fetch url="https://api.example.com/api/v1/provisioning/config/NOB-1234-5678" mode=https dst-path="noblifi-config.rsc"`,
		`:delay 2s`,
		`/import file-name="noblifi-config.rsc"`,
		`:delay 1s`,
		`/file remove "noblifi-config.rsc"`,
	}
	for _, item := range required {
		if !strings.Contains(script, item) {
			t.Fatalf("expected install command to contain %q, got:\n%s", item, script)
		}
	}
}

func TestHotspotInstallCommandRunsDiscoveryConfigAndStatus(t *testing.T) {
	script := hotspotInstallCommand("NOB-1234-5678", "https://api.example.com/api/v1/provisioning")

	required := []string{
		`NobliFi HotSpot install starting`,
		`/tool fetch url="https://api.example.com/api/v1/provisioning/bootstrap/NOB-1234-5678" mode=https dst-path="noblifi-bootstrap.rsc"`,
		`/import file-name="noblifi-bootstrap.rsc"`,
		`/file remove "noblifi-bootstrap.rsc"`,
		`/tool fetch url="https://api.example.com/api/v1/provisioning/config/NOB-1234-5678" mode=https dst-path="noblifi-config.rsc"`,
		`/import file-name="noblifi-config.rsc"`,
		`/file remove "noblifi-config.rsc"`,
		`/tool fetch url="https://api.example.com/api/v1/provisioning/status?token=NOB-1234-5678&status=installed" mode=https keep-result=no`,
		`NobliFi HotSpot install completed`,
	}
	for _, item := range required {
		if !strings.Contains(script, item) {
			t.Fatalf("expected complete install command to contain %q, got:\n%s", item, script)
		}
	}

	bootstrapIndex := strings.Index(script, "/bootstrap/NOB-1234-5678")
	configIndex := strings.Index(script, "/config/NOB-1234-5678")
	statusIndex := strings.Index(script, "/status?token=NOB-1234-5678&status=installed")
	if bootstrapIndex == -1 || configIndex == -1 || statusIndex == -1 || !(bootstrapIndex < configIndex && configIndex < statusIndex) {
		t.Fatalf("expected bootstrap, config, then status order, got:\n%s", script)
	}
}
