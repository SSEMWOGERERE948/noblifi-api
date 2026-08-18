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

func TestRouterSupportsWireGuardParsesMajorVersion(t *testing.T) {
	cases := []struct {
		version string
		want    bool
	}{
		{"7.21.5", true},
		{"7.20.6", true},
		{"7.18", true},
		{"6.49.15", false},
	}
	for _, tc := range cases {
		if got := RouterSupportsWireGuard(&tc.version); got != tc.want {
			t.Fatalf("RouterSupportsWireGuard(%q) = %v, want %v", tc.version, got, tc.want)
		}
	}
}

func TestRenderWireGuardRouterOSCreatesInterfacePeerAndAddress(t *testing.T) {
	tunnelIP := "10.77.0.2"
	router := Router{ClaimToken: "NOB-TEST", WireGuardTunnelIP: &tunnelIP}
	cfg := config.Config{
		ProvisioningBaseURL: "https://api.example.com/api/v1/provisioning",
		WireGuardPublicKey:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		WireGuardEndpoint:   "vpn.example.com",
		WireGuardPort:       51820,
		WireGuardServerIP:   "10.77.0.1",
		WireGuardKeepalive:  25,
		RouterAPIUsername:   "noblifi-api",
		RouterAPIPassword:   "secret",
	}
	script := RenderWireGuardRouterOS(router, cfg)
	for _, expected := range []string{
		`/interface wireguard add name="noblifi-wg"`,
		`/ip address add address="10.77.0.2/32" interface="noblifi-wg"`,
		`/interface wireguard peers add interface="noblifi-wg"`,
		`public-key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="`,
		`endpoint-address="vpn.example.com"`,
		`endpoint-port=51820`,
		`allowed-address="10.77.0.1/32"`,
		`last-handshake`,
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("expected WireGuard script to contain %q, got:\n%s", expected, script)
		}
	}
}
