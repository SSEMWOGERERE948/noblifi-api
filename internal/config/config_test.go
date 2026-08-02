package config

import "testing"

func TestLoadDefaultsRadiusServerToPublicAddress(t *testing.T) {
	t.Setenv("NOBLIFI_RADIUS_SERVER", "")

	cfg := Load()

	if cfg.RadiusServer != defaultRadiusServer {
		t.Fatalf("expected default RADIUS server %q, got %q", defaultRadiusServer, cfg.RadiusServer)
	}
}

func TestLoadTreatsPlaceholderAgentTokenAsMissing(t *testing.T) {
	t.Setenv("NOBLIFI_AGENT_TOKEN", "REPLACE_WITH_XNEELO_AGENT_TOKEN")

	cfg := Load()

	if cfg.AgentToken != "" {
		t.Fatalf("expected placeholder agent token to be ignored, got %q", cfg.AgentToken)
	}
}
