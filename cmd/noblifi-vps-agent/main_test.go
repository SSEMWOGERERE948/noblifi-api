package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixture = `[Interface]
PrivateKey = SERVER_PRIVATE_KEY
Address = 10.77.0.1/24

[Peer]
# unmanaged
PublicKey = OLDKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
AllowedIPs = 10.77.0.9/32
`

func TestParseWGConfigPreservesInterfacePrivateKey(t *testing.T) {
	conf, err := parseWGConfig(fixture)
	if err != nil {
		t.Fatalf("parseWGConfig: %v", err)
	}
	rendered := conf.String()
	if !strings.Contains(rendered, "PrivateKey = SERVER_PRIVATE_KEY") {
		t.Fatalf("expected private key to be preserved, got:\n%s", rendered)
	}
	if !strings.Contains(rendered, "PublicKey = OLDKEY") {
		t.Fatalf("expected unrelated peer to be preserved, got:\n%s", rendered)
	}
}

func TestWGConfigRemovePeerByKey(t *testing.T) {
	conf, err := parseWGConfig(fixture)
	if err != nil {
		t.Fatalf("parseWGConfig: %v", err)
	}
	if !conf.RemovePeerByKey("OLDKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") {
		t.Fatalf("expected peer removal")
	}
	if strings.Contains(conf.String(), "[Peer]") {
		t.Fatalf("expected no peer sections, got:\n%s", conf.String())
	}
}

func TestAgentUpsertPeerReplacesStaleAllowedIP(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(configPath, []byte(fixture), 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	runner := &recordingRunner{}
	agent := &Agent{
		cfg: Config{
			InterfaceName: "wg0",
			ConfigPath:    configPath,
			LockPath:      filepath.Join(dir, "wg.lock"),
			BackupDir:     filepath.Join(dir, "backups"),
		},
		runner: runner,
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	newKey := "NEWKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	if err := agent.upsertPeer(context.Background(), Job{
		RouterID:  "router-1",
		PublicKey: newKey,
		AllowedIP: "10.77.0.9/32",
	}); err != nil {
		t.Fatalf("upsert peer: %v", err)
	}

	rendered, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if strings.Contains(string(rendered), "OLDKEY") {
		t.Fatalf("expected stale peer for allowed IP to be removed, got:\n%s", string(rendered))
	}
	if !strings.Contains(string(rendered), "NEWKEY") || !strings.Contains(string(rendered), "AllowedIPs = 10.77.0.9/32") {
		t.Fatalf("expected new peer, got:\n%s", string(rendered))
	}
	if !runner.sawStaleRemove {
		t.Fatalf("expected stale peer to be removed from live WireGuard interface")
	}
}

type recordingRunner struct {
	sawStaleRemove bool
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	command := name + " " + strings.Join(args, " ")
	if strings.Contains(command, "peer OLDKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= remove") {
		r.sawStaleRemove = true
	}
	if command == "wg show wg0 allowed-ips" {
		return []byte("NEWKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t10.77.0.9/32\n"), nil
	}
	return nil, nil
}
