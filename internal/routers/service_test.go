package routers

import (
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
