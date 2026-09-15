package wireguard

import (
	"testing"

	"github.com/noblifi/noblifi/backend/internal/config"
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
