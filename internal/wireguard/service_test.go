package wireguard

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/config"
	"github.com/noblifi/noblifi/backend/internal/routers"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestAuthenticateAgent(t *testing.T) {
	service := NewService(nil, config.Config{AgentToken: "agent-secret"})

	if !service.AuthenticateAgent("Bearer agent-secret") {
		t.Fatal("AuthenticateAgent rejected valid bearer token")
	}
	if !service.AuthenticateAgent("agent-secret") {
		t.Fatal("AuthenticateAgent rejected valid raw token")
	}
	if service.AuthenticateAgent("Bearer wrong-secret") {
		t.Fatal("AuthenticateAgent accepted invalid token")
	}
	if service.AuthenticateAgent("") {
		t.Fatal("AuthenticateAgent accepted empty token")
	}
}

func TestTelemetryTargetsSelectsRouterWithINETAddress(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		if strings.Contains(err.Error(), "requires cgo") {
			t.Skipf("sqlite driver unavailable: %v", err)
		}
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&routers.Router{}); err != nil {
		t.Fatalf("migrate router: %v", err)
	}
	ip := "10.77.0.2"
	username := "noblifi-api"
	router := routers.Router{ID: uuid.New(), Name: "Telemetry router", WireGuardTunnelIP: &ip, APIUsername: &username}
	if err := db.Create(&router).Error; err != nil {
		t.Fatalf("create router: %v", err)
	}

	service := NewService(db, config.Config{RouterAPIPassword: "secret"})
	targets, err := service.TelemetryTargets()
	if err != nil {
		t.Fatalf("TelemetryTargets returned error: %v", err)
	}
	if len(targets) != 1 || targets[0].RouterIP != ip {
		t.Fatalf("targets = %#v, want router IP %s", targets, ip)
	}
}
