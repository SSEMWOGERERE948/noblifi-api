package main

import (
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

func TestWGConfigUpsertReplacesStaleAllowedIP(t *testing.T) {
	conf, err := parseWGConfig(fixture)
	if err != nil {
		t.Fatalf("parseWGConfig: %v", err)
	}
	conf.UpsertPeer("NEWKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "10.77.0.9/32")
	rendered := conf.String()
	if strings.Contains(rendered, "OLDKEY") {
		t.Fatalf("expected stale peer for allowed IP to be removed, got:\n%s", rendered)
	}
	if !strings.Contains(rendered, "NEWKEY") || !strings.Contains(rendered, "AllowedIPs = 10.77.0.9/32") {
		t.Fatalf("expected new peer, got:\n%s", rendered)
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
