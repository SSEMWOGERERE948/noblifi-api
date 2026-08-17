package main

import (
	"bufio"
	"errors"
	"strings"
)

type wgConfig struct {
	interfaceLines []string
	peers          []wgPeer
}

type wgPeer struct {
	PublicKey  string
	AllowedIPs string
}

func parseWGConfig(value string) (*wgConfig, error) {
	scanner := bufio.NewScanner(strings.NewReader(value))
	conf := &wgConfig{}
	section := ""
	var peer *wgPeer

	flushPeer := func() {
		if peer != nil {
			conf.peers = append(conf.peers, *peer)
			peer = nil
		}
	}

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		switch trimmed {
		case "[Interface]":
			flushPeer()
			section = "interface"
			conf.interfaceLines = append(conf.interfaceLines, line)
			continue
		case "[Peer]":
			flushPeer()
			section = "peer"
			peer = &wgPeer{}
			continue
		}

		if section == "interface" {
			conf.interfaceLines = append(conf.interfaceLines, line)
			continue
		}
		if section == "peer" && peer != nil {
			key, val, ok := strings.Cut(trimmed, "=")
			if !ok {
				continue
			}
			switch strings.TrimSpace(key) {
			case "PublicKey":
				peer.PublicKey = strings.TrimSpace(val)
			case "AllowedIPs":
				peer.AllowedIPs = strings.TrimSpace(val)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	flushPeer()
	if len(conf.interfaceLines) == 0 {
		return nil, errors.New("WireGuard config is missing [Interface]")
	}
	return conf, nil
}

func (c *wgConfig) PeerByAllowedIP(allowedIP string) (wgPeer, bool) {
	allowedIP = strings.TrimSpace(allowedIP)
	for _, peer := range c.peers {
		if strings.TrimSpace(peer.AllowedIPs) == allowedIP {
			return peer, true
		}
	}
	return wgPeer{}, false
}

func (c *wgConfig) RemovePeerByKey(publicKey string) bool {
	publicKey = strings.TrimSpace(publicKey)
	if publicKey == "" {
		return false
	}
	removed := false
	kept := c.peers[:0]
	for _, peer := range c.peers {
		if strings.TrimSpace(peer.PublicKey) == publicKey {
			removed = true
			continue
		}
		kept = append(kept, peer)
	}
	c.peers = kept
	return removed
}

func (c *wgConfig) UpsertPeer(publicKey, allowedIP string) {
	publicKey = strings.TrimSpace(publicKey)
	allowedIP = strings.TrimSpace(allowedIP)
	for i := range c.peers {
		if c.peers[i].PublicKey == publicKey {
			c.peers[i].AllowedIPs = allowedIP
			return
		}
	}
	c.peers = append(c.peers, wgPeer{PublicKey: publicKey, AllowedIPs: allowedIP})
}

func (c *wgConfig) String() string {
	var out strings.Builder
	for i, line := range c.interfaceLines {
		if i > 0 {
			out.WriteByte('\n')
		}
		out.WriteString(line)
	}
	for _, peer := range c.peers {
		if strings.TrimSpace(peer.PublicKey) == "" || strings.TrimSpace(peer.AllowedIPs) == "" {
			continue
		}
		out.WriteString("\n\n[Peer]\n")
		out.WriteString("PublicKey = ")
		out.WriteString(peer.PublicKey)
		out.WriteString("\nAllowedIPs = ")
		out.WriteString(peer.AllowedIPs)
		out.WriteByte('\n')
	}
	if !strings.HasSuffix(out.String(), "\n") {
		out.WriteByte('\n')
	}
	return out.String()
}
