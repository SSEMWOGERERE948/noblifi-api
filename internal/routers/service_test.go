package routers

import (
	"strings"
	"testing"

	"github.com/google/uuid"
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
	if !strings.Contains(script, `address="10.77.0.1/32,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16" port=8291`) {
		t.Fatalf("expected WinBox to remain available locally and over WireGuard, got:\n%s", script)
	}
}

func TestRouterServiceRequiresAuthenticatedTenant(t *testing.T) {
	service := NewService(nil, config.Config{})

	if _, err := service.List(nil, false); err == nil {
		t.Fatal("normal list without user did not fail closed")
	}
	if _, err := service.Create(CreateRouterInput{Name: "router"}, nil, false); err == nil {
		t.Fatal("normal create without user did not fail closed")
	}
	if _, err := service.Find(uuid.Nil, nil, false); err == nil {
		t.Fatal("normal find without user did not fail closed")
	}
}

func TestDeleteConfirmationTextUsesRouterNameOnly(t *testing.T) {
	if got := deleteConfirmationText("  Mukama Router  "); got != "Mukama Router" {
		t.Fatalf("deleteConfirmationText() = %q, want router name only", got)
	}
}

func TestDeleteRouterInputAcceptsOneRouterNameConfirmation(t *testing.T) {
	input := DeleteRouterInput{
		RouterName:      "Mukama Router",
		ConfirmationOne: "legacy duplicate confirmation",
		ConfirmationTwo: "legacy duplicate confirmation",
	}

	if got := input.deleteConfirmation(); got != "Mukama Router" {
		t.Fatalf("deleteConfirmation() = %q, want router_name field", got)
	}
}

func TestPreferredWinboxTargetUsesWireGuardTunnelIPFirst(t *testing.T) {
	tunnelIP := "10.77.0.44"
	router := Router{WireGuardTunnelIP: &tunnelIP, RemoteWinboxPort: intPtr(22017)}

	host, port, vpnRequired := preferredWinboxAccessTarget(router, "154.65.105.14")
	if host != "10.77.0.44" {
		t.Fatalf("preferredWinboxAccessTarget() host = %q, want %q", host, "10.77.0.44")
	}
	if port != 8291 {
		t.Fatalf("preferredWinboxAccessTarget() port = %d, want 8291", port)
	}
	if !vpnRequired {
		t.Fatal("preferredWinboxAccessTarget() vpnRequired = false, want true")
	}
}

func intPtr(v int) *int { return &v }
