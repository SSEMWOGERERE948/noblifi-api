package routers

import (
	"strings"
	"time"
)

const (
	HealthOnline     = "online"
	HealthRecovering = "recovering"
	HealthDegraded   = "degraded"
	HealthOffline    = "offline"
)

const (
	telemetryFreshWindow = 90 * time.Second
	connectivityWindow   = 90 * time.Second
	offlineAfter         = 90 * time.Second
)

func HydrateHealthStatus(router *Router, now time.Time) {
	if router == nil {
		return
	}
	health, reason := Health(*router, now)
	router.HealthStatus = health
	router.HealthReason = reason
}

func HydrateHealthStatuses(routers []Router, now time.Time) {
	for i := range routers {
		HydrateHealthStatus(&routers[i], now)
	}
}

func HealthStatus(router Router, now time.Time) string {
	health, _ := Health(router, now)
	return health
}

func Health(router Router, now time.Time) (string, string) {
	if now.IsZero() {
		now = time.Now().UTC()
	}

	telemetryFresh := isFresh(router.TelemetryUpdatedAt, now, telemetryFreshWindow)
	telemetryRecent := isFresh(router.TelemetryUpdatedAt, now, offlineAfter)
	handshakeFresh := isFresh(router.WireGuardLastHandshakeAt, now, connectivityWindow)
	handshakeRecent := isFresh(router.WireGuardLastHandshakeAt, now, offlineAfter)
	heartbeatFresh := isFresh(router.LastSeenAt, now, connectivityWindow)
	heartbeatRecent := isFresh(router.LastSeenAt, now, offlineAfter)
	hasTelemetryError := strings.TrimSpace(stringPtrValue(router.TelemetryLastError)) != ""

	if telemetryFresh && !hasTelemetryError {
		return HealthOnline, "fresh_telemetry"
	}
	if (handshakeFresh || heartbeatFresh) && (router.TelemetryUpdatedAt == nil || !telemetryFresh) {
		return HealthRecovering, freshestReason(handshakeFresh, heartbeatFresh)
	}
	if hasTelemetryError && (telemetryRecent || handshakeRecent || heartbeatRecent) {
		return HealthDegraded, "telemetry_error"
	}
	if telemetryRecent || handshakeRecent || heartbeatRecent {
		return HealthDegraded, "telemetry_stale"
	}
	return HealthOffline, "no_recent_activity"
}

func isFresh(value *time.Time, now time.Time, window time.Duration) bool {
	if value == nil || value.IsZero() {
		return false
	}
	age := now.Sub(value.UTC())
	if age < 0 {
		age = 0
	}
	return age <= window
}

func freshestReason(freshWireGuard, freshHeartbeat bool) string {
	if freshWireGuard {
		return "fresh_wireguard"
	}
	if freshHeartbeat {
		return "fresh_heartbeat"
	}
	return "recent_connectivity"
}

func stringPtrValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
