package routers

import (
	"testing"
	"time"
)

func TestHealthStatusOnlineForFreshSuccessfulTelemetry(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	last := now.Add(-90 * time.Second)

	router := Router{TelemetryUpdatedAt: &last}

	if got := HealthStatus(router, now); got != HealthOnline {
		t.Fatalf("HealthStatus() = %q, want %q", got, HealthOnline)
	}
}

func TestHealthStatusDegradedForRecentPollError(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	last := now.Add(-30 * time.Second)
	message := "timeout"

	router := Router{
		TelemetryUpdatedAt: &last,
		TelemetryLastError: &message,
	}

	if got := HealthStatus(router, now); got != HealthDegraded {
		t.Fatalf("HealthStatus() = %q, want %q", got, HealthDegraded)
	}
}

func TestHealthStatusRecoveringForFreshWireGuardWithoutTelemetry(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	handshake := now.Add(-15 * time.Second)

	router := Router{WireGuardLastHandshakeAt: &handshake}

	if got := HealthStatus(router, now); got != HealthRecovering {
		t.Fatalf("HealthStatus() = %q, want %q", got, HealthRecovering)
	}
}

func TestHealthStatusOfflineAfterThreeMissedPolls(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	last := now.Add(-91 * time.Second)

	router := Router{TelemetryUpdatedAt: &last}

	if got := HealthStatus(router, now); got != HealthOffline {
		t.Fatalf("HealthStatus() = %q, want %q", got, HealthOffline)
	}
}

func TestHealthStatusDoesNotUseProvisioningStatusAsRuntimeHealth(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	router := Router{Status: "pending", ProvisioningStatus: "pending"}

	if got := HealthStatus(router, now); got != HealthOffline {
		t.Fatalf("HealthStatus() = %q, want %q", got, HealthOffline)
	}
}
