package config

import "testing"

func TestLoadDefaultsRadiusServerToPublicAddress(t *testing.T) {
	t.Setenv("NOBLIFI_RADIUS_SERVER", "")

	cfg := Load()

	if cfg.RadiusServer != defaultRadiusServer {
		t.Fatalf("expected default RADIUS server %q, got %q", defaultRadiusServer, cfg.RadiusServer)
	}
}
