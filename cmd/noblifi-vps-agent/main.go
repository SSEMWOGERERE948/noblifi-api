package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const version = "dev"

type Config struct {
	ControlPlaneURL   string
	AgentToken        string
	AgentID           string
	InterfaceName     string
	ConfigPath        string
	LockPath          string
	BackupDir         string
	PollInterval      time.Duration
	ReconcileInterval time.Duration
}

type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return out, nil
}

type Agent struct {
	cfg    Config
	client *http.Client
	runner CommandRunner
	log    *slog.Logger
}

type Job struct {
	ID        string `json:"id"`
	RouterID  string `json:"router_id"`
	Operation string `json:"operation"`
	PublicKey string `json:"public_key"`
	AllowedIP string `json:"allowed_ip"`
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		slog.Error("invalid config", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	agent := &Agent{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
		runner: ExecRunner{},
		log:    slog.New(slog.NewJSONHandler(os.Stdout, nil)),
	}
	if err := agent.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		agent.log.Error("agent stopped", "error", err)
		os.Exit(1)
	}
}

func loadConfig() (Config, error) {
	cfg := Config{
		ControlPlaneURL:   strings.TrimRight(os.Getenv("NOBLIFI_CONTROL_PLANE_URL"), "/"),
		AgentToken:        os.Getenv("NOBLIFI_AGENT_TOKEN"),
		AgentID:           env("NOBLIFI_AGENT_ID", "xneelo-wg-agent-01"),
		InterfaceName:     env("NOBLIFI_WIREGUARD_INTERFACE", "wg0"),
		ConfigPath:        env("NOBLIFI_WIREGUARD_CONFIG", "/etc/wireguard/wg0.conf"),
		LockPath:          env("NOBLIFI_WIREGUARD_LOCK", "/run/lock/noblifi-wireguard.lock"),
		BackupDir:         env("NOBLIFI_WIREGUARD_BACKUP_DIR", "/etc/wireguard/backups"),
		PollInterval:      durationEnv("NOBLIFI_AGENT_POLL_INTERVAL", 5*time.Second),
		ReconcileInterval: durationEnv("NOBLIFI_AGENT_RECONCILE_INTERVAL", 5*time.Minute),
	}
	if cfg.ControlPlaneURL == "" {
		return cfg, errors.New("NOBLIFI_CONTROL_PLANE_URL is required")
	}
	if cfg.AgentToken == "" {
		return cfg, errors.New("NOBLIFI_AGENT_TOKEN is required")
	}
	if cfg.AgentID == "" {
		return cfg, errors.New("NOBLIFI_AGENT_ID is required")
	}
	return cfg, nil
}

func (a *Agent) Run(ctx context.Context) error {
	if err := a.heartbeat(ctx, true); err != nil {
		a.log.Warn("heartbeat failed", "error", err)
	}
	ticker := time.NewTicker(a.cfg.PollInterval)
	defer ticker.Stop()
	reconcile := time.NewTicker(a.cfg.ReconcileInterval)
	defer reconcile.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := a.runOnce(ctx); err != nil {
				a.log.Warn("poll failed", "error", err)
			}
		case <-reconcile.C:
			if err := a.heartbeat(ctx, true); err != nil {
				a.log.Warn("heartbeat failed", "error", err)
			}
		}
	}
}

func (a *Agent) runOnce(ctx context.Context) error {
	job, ok, err := a.claim(ctx)
	if err != nil || !ok {
		return err
	}
	start := time.Now()
	a.log.Info("job claimed", "job_id", job.ID, "router_id", job.RouterID, "operation", job.Operation)
	if err := a.post(ctx, "/internal/wireguard/jobs/"+job.ID+"/applying", map[string]any{"agent_id": a.cfg.AgentID}, nil); err != nil {
		return err
	}
	if err := a.applyJob(ctx, job); err != nil {
		_ = a.post(ctx, "/internal/wireguard/jobs/"+job.ID+"/fail", map[string]any{"agent_id": a.cfg.AgentID, "error": err.Error()}, nil)
		a.log.Error("job failed", "job_id", job.ID, "router_id", job.RouterID, "duration_ms", time.Since(start).Milliseconds(), "error", err)
		return nil
	}
	if err := a.post(ctx, "/internal/wireguard/jobs/"+job.ID+"/complete", map[string]any{"agent_id": a.cfg.AgentID}, nil); err != nil {
		return err
	}
	a.log.Info("job succeeded", "job_id", job.ID, "router_id", job.RouterID, "duration_ms", time.Since(start).Milliseconds())
	return nil
}

func (a *Agent) claim(ctx context.Context) (Job, bool, error) {
	var out struct {
		Status string `json:"status"`
		Job    Job    `json:"job"`
	}
	if err := a.post(ctx, "/internal/wireguard/jobs/claim", map[string]any{"agent_id": a.cfg.AgentID, "lease_seconds": 120}, &out); err != nil {
		return Job{}, false, err
	}
	return out.Job, out.Status == "claimed", nil
}

func (a *Agent) applyJob(ctx context.Context, job Job) error {
	switch job.Operation {
	case "upsert_peer", "reconcile_peer":
		return a.upsertPeer(ctx, job)
	case "remove_peer":
		return a.removePeer(ctx, job)
	case "upsert_radius_nas", "remove_radius_nas":
		return nil
	default:
		return fmt.Errorf("unsupported operation %q", job.Operation)
	}
}

func (a *Agent) upsertPeer(ctx context.Context, job Job) error {
	if err := validateAllowedIP(job.AllowedIP); err != nil {
		return err
	}
	if strings.TrimSpace(job.PublicKey) == "" {
		return errors.New("public key is required")
	}
	conf, err := readWGConfig(a.cfg.ConfigPath)
	if err != nil {
		return err
	}
	conf.UpsertPeer(job.PublicKey, job.AllowedIP)
	if err := a.persist(ctx, conf); err != nil {
		return err
	}
	if _, err := a.runner.Run(ctx, "wg", "set", a.cfg.InterfaceName, "peer", job.PublicKey, "allowed-ips", job.AllowedIP); err != nil {
		return sanitizeCommandError(err)
	}
	return a.verifyPeer(ctx, job.PublicKey, job.AllowedIP, true)
}

func (a *Agent) removePeer(ctx context.Context, job Job) error {
	conf, err := readWGConfig(a.cfg.ConfigPath)
	if err != nil {
		return err
	}
	removed := conf.RemovePeer(job.PublicKey, job.AllowedIP)
	if err := a.persist(ctx, conf); err != nil {
		return err
	}
	if strings.TrimSpace(job.PublicKey) != "" {
		_, _ = a.runner.Run(ctx, "wg", "set", a.cfg.InterfaceName, "peer", job.PublicKey, "remove")
	}
	if removed && strings.TrimSpace(job.PublicKey) != "" {
		return a.verifyPeer(ctx, job.PublicKey, job.AllowedIP, false)
	}
	return nil
}

func (a *Agent) persist(ctx context.Context, conf WGConfig) error {
	if err := os.MkdirAll(a.cfg.BackupDir, 0700); err != nil {
		return err
	}
	if current, err := os.ReadFile(a.cfg.ConfigPath); err == nil {
		backup := filepath.Join(a.cfg.BackupDir, "wg0-"+time.Now().UTC().Format("20060102T150405Z")+".conf")
		if err := os.WriteFile(backup, current, 0600); err != nil {
			return err
		}
	}
	tmp := a.cfg.ConfigPath + ".noblifi.tmp"
	if err := os.WriteFile(tmp, []byte(conf.String()), 0600); err != nil {
		return err
	}
	if _, err := a.runner.Run(ctx, "wg-quick", "strip", tmp); err != nil {
		_ = os.Remove(tmp)
		return sanitizeCommandError(err)
	}
	return os.Rename(tmp, a.cfg.ConfigPath)
}

func (a *Agent) verifyPeer(ctx context.Context, publicKey, allowedIP string, present bool) error {
	out, err := a.runner.Run(ctx, "wg", "show", a.cfg.InterfaceName, "allowed-ips")
	if err != nil {
		return sanitizeCommandError(err)
	}
	found := strings.Contains(string(out), publicKey) && strings.Contains(string(out), allowedIP)
	if present && !found {
		return errors.New("peer_verification_failed")
	}
	if !present && found {
		return errors.New("peer_removal_verification_failed")
	}
	return nil
}

func (a *Agent) heartbeat(ctx context.Context, healthy bool) error {
	return a.post(ctx, "/internal/agents/heartbeat", map[string]any{
		"agent_id":            a.cfg.AgentID,
		"version":             version,
		"wireguard_interface": a.cfg.InterfaceName,
		"healthy":             healthy,
		"last_reconciliation": time.Now().UTC(),
	}, nil)
}

func (a *Agent) post(ctx context.Context, path string, payload any, out any) error {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.ControlPlaneURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.cfg.AgentToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("control plane returned HTTP %d", resp.StatusCode)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

type WGConfig struct {
	Interface []string
	Peers     []WGPeer
}

type WGPeer struct {
	Lines      []string
	PublicKey  string
	AllowedIPs string
}

func readWGConfig(path string) (WGConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return WGConfig{}, err
	}
	return parseWGConfig(string(data))
}

func parseWGConfig(data string) (WGConfig, error) {
	var conf WGConfig
	var peer *WGPeer
	section := ""
	for _, raw := range strings.Split(data, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		switch strings.ToLower(trimmed) {
		case "[interface]":
			section = "interface"
			peer = nil
			conf.Interface = append(conf.Interface, line)
			continue
		case "[peer]":
			section = "peer"
			conf.Peers = append(conf.Peers, WGPeer{Lines: []string{line}})
			peer = &conf.Peers[len(conf.Peers)-1]
			continue
		}
		if section == "peer" && peer != nil {
			peer.Lines = append(peer.Lines, line)
			key, value, ok := strings.Cut(trimmed, "=")
			if ok {
				switch strings.ToLower(strings.TrimSpace(key)) {
				case "publickey":
					peer.PublicKey = strings.TrimSpace(value)
				case "allowedips":
					peer.AllowedIPs = strings.TrimSpace(value)
				}
			}
		} else {
			conf.Interface = append(conf.Interface, line)
		}
	}
	if len(conf.Interface) == 0 {
		return conf, errors.New("malformed wg0.conf: missing [Interface]")
	}
	return conf, nil
}

func (c *WGConfig) UpsertPeer(publicKey, allowedIP string) {
	c.RemovePeer(publicKey, allowedIP)
	c.Peers = append(c.Peers, WGPeer{
		PublicKey:  publicKey,
		AllowedIPs: allowedIP,
		Lines: []string{
			"[Peer]",
			"# Managed by NobliFi",
			"PublicKey = " + publicKey,
			"AllowedIPs = " + allowedIP,
		},
	})
}

func (c *WGConfig) RemovePeer(publicKey, allowedIP string) bool {
	next := c.Peers[:0]
	removed := false
	for _, peer := range c.Peers {
		if (publicKey != "" && peer.PublicKey == publicKey) || (allowedIP != "" && peer.AllowedIPs == allowedIP) {
			removed = true
			continue
		}
		next = append(next, peer)
	}
	c.Peers = next
	return removed
}

func (c WGConfig) String() string {
	var out []string
	out = append(out, c.Interface...)
	for _, peer := range c.Peers {
		if len(out) > 0 && strings.TrimSpace(out[len(out)-1]) != "" {
			out = append(out, "")
		}
		out = append(out, peer.Lines...)
	}
	return strings.TrimRight(strings.Join(out, "\n"), "\n") + "\n"
}

func validateAllowedIP(value string) error {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil || prefix.Bits() != 32 {
		return errors.New("allowed IP must be a single IPv4 /32")
	}
	if !prefix.Addr().Is4() {
		return errors.New("allowed IP must be IPv4")
	}
	return nil
}

func sanitizeCommandError(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(strings.TrimSpace(err.Error()))
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return d
}
