package wireguard

import (
	"testing"

	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/routers"
)

func TestRemoteAccessTargetsForRouterIncludesWebFigAndWinBox(t *testing.T) {
	ip := "10.77.0.9"
	webPort, winboxPort := 22001, 22002
	targets := remoteAccessTargetsForRouter(routers.Router{
		ID: uuid.New(), Name: "Branch Router", WireGuardTunnelIP: &ip,
		RemoteWebPort: &webPort, RemoteWinboxPort: &winboxPort,
	})

	if len(targets) != 2 {
		t.Fatalf("target count = %d, want 2", len(targets))
	}
	if targets[0].PublicPort != webPort || targets[0].TargetPort != 80 {
		t.Fatalf("WebFig target = %d -> %d, want %d -> 80", targets[0].PublicPort, targets[0].TargetPort, webPort)
	}
	if targets[1].PublicPort != winboxPort || targets[1].TargetPort != 8291 {
		t.Fatalf("WinBox target = %d -> %d, want %d -> 8291", targets[1].PublicPort, targets[1].TargetPort, winboxPort)
	}
}
