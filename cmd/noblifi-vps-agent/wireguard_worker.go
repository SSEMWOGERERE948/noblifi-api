package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/noblifi/noblifi/backend/internal/mikrotik"
)

type commandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return out, nil
}

type wireGuardWorker struct {
	cfg    config
	client *http.Client
	runner commandRunner
}

type wireGuardJob struct {
	ID             string `json:"id"`
	RouterID       string `json:"router_id"`
	Operation      string `json:"operation"`
	PublicKey      string `json:"public_key"`
	AllowedIP      string `json:"allowed_ip"`
	ConfigRevision string `json:"config_revision"`
}

type desiredRouterConfig struct {
	RouterID       string `json:"router_id"`
	ManagementIP   string `json:"management_ip"`
	ConfigRevision string `json:"config_revision"`
	APIUsername    string `json:"api_username"`
	APIPassword    string `json:"api_password"`
	APIPort        int    `json:"api_port"`
	RouterOSScript string `json:"routeros_script"`
}

func runWireGuardWorker(ctx context.Context, client *http.Client, cfg config) {
	worker := wireGuardWorker{cfg: cfg, client: client, runner: execRunner{}}
	if err := worker.heartbeat(ctx, true); err != nil {
		log.Printf("wireguard heartbeat failed: %v", err)
	}
	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()
	heartbeat := time.NewTicker(cfg.HeartbeatInterval)
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := worker.runOnce(ctx); err != nil {
				log.Printf("wireguard poll failed: %v", err)
			}
		case <-heartbeat.C:
			if err := worker.heartbeat(ctx, true); err != nil {
				log.Printf("wireguard heartbeat failed: %v", err)
			}
		}
	}
}

func (w wireGuardWorker) runOnce(ctx context.Context) error {
	job, ok, err := w.claim(ctx)
	if err != nil || !ok {
		return err
	}
	start := time.Now()
	log.Printf("job claimed job_id=%s router_id=%s operation=%s", job.ID, job.RouterID, job.Operation)
	if err := w.post(ctx, "/internal/wireguard/jobs/"+job.ID+"/applying", map[string]any{"agent_id": w.cfg.AgentID}, nil); err != nil {
		return err
	}
	if err := w.applyJob(ctx, job); err != nil {
		_ = w.post(ctx, "/internal/wireguard/jobs/"+job.ID+"/fail", map[string]any{"agent_id": w.cfg.AgentID, "error": err.Error()}, nil)
		log.Printf("job failed job_id=%s router_id=%s duration_ms=%d error=%v", job.ID, job.RouterID, time.Since(start).Milliseconds(), err)
		return nil
	}
	if err := w.post(ctx, "/internal/wireguard/jobs/"+job.ID+"/complete", map[string]any{"agent_id": w.cfg.AgentID}, nil); err != nil {
		return err
	}
	log.Printf("job succeeded job_id=%s router_id=%s duration_ms=%d", job.ID, job.RouterID, time.Since(start).Milliseconds())
	return nil
}

func (w wireGuardWorker) claim(ctx context.Context) (wireGuardJob, bool, error) {
	var out struct {
		Status string       `json:"status"`
		Job    wireGuardJob `json:"job"`
	}
	if err := w.post(ctx, "/internal/wireguard/jobs/claim", map[string]any{"agent_id": w.cfg.AgentID, "lease_seconds": 120}, &out); err != nil {
		return wireGuardJob{}, false, err
	}
	return out.Job, out.Status == "claimed", nil
}

func (w wireGuardWorker) applyJob(ctx context.Context, job wireGuardJob) error {
	switch job.Operation {
	case "upsert_peer", "reconcile_peer":
		return w.upsertPeer(ctx, job)
	case "remove_peer":
		return w.removePeer(ctx, job)
	case "configure_router":
		return w.configureRouter(ctx, job)
	case "upsert_remote_access", "remove_remote_access":
		return nil
	default:
		return fmt.Errorf("unsupported operation %q", job.Operation)
	}
}

func (w wireGuardWorker) withConfigLock(fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(w.cfg.LockPath), 0700); err != nil {
		return fmt.Errorf("prepare lock directory: %w", err)
	}
	lockFile, err := os.OpenFile(w.cfg.LockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("open lock file: %w", err)
	}
	defer lockFile.Close()
	unlock, err := lockFileExclusive(lockFile)
	if err != nil {
		return fmt.Errorf("acquire wireguard config lock: %w", err)
	}
	defer func() { _ = unlock() }()
	return fn()
}

func (w wireGuardWorker) upsertPeer(ctx context.Context, job wireGuardJob) error {
	publicKey := strings.TrimSpace(job.PublicKey)
	allowedIP := strings.TrimSpace(job.AllowedIP)
	if publicKey == "" {
		return errors.New("public key is required")
	}
	if err := validateAllowedIP(allowedIP); err != nil {
		return err
	}
	return w.withConfigLock(func() error {
		conf, err := readWGConfig(w.cfg.ConfigPath)
		if err != nil {
			return fmt.Errorf("read WireGuard configuration: %w", err)
		}
		if stalePeer, found := conf.PeerByAllowedIP(allowedIP); found {
			staleKey := strings.TrimSpace(stalePeer.PublicKey)
			if staleKey != "" && staleKey != publicKey {
				if _, err := w.runner.Run(ctx, "wg", "set", w.cfg.InterfaceName, "peer", staleKey, "remove"); err != nil {
					return fmt.Errorf("remove stale WireGuard peer: %w", sanitizeCommandError(err))
				}
				conf.RemovePeerByKey(staleKey)
			}
		}
		conf.UpsertPeer(publicKey, allowedIP)
		if err := w.persist(ctx, conf); err != nil {
			return fmt.Errorf("persist WireGuard peer: %w", err)
		}
		if _, err := w.runner.Run(ctx, "wg", "set", w.cfg.InterfaceName, "peer", publicKey, "allowed-ips", allowedIP); err != nil {
			return fmt.Errorf("apply WireGuard peer: %w", sanitizeCommandError(err))
		}
		return w.verifyPeer(ctx, publicKey, allowedIP, true)
	})
}

func (w wireGuardWorker) removePeer(ctx context.Context, job wireGuardJob) error {
	publicKey := strings.TrimSpace(job.PublicKey)
	allowedIP := strings.TrimSpace(job.AllowedIP)
	if publicKey == "" {
		return errors.New("public key is required to remove a peer")
	}
	return w.withConfigLock(func() error {
		conf, err := readWGConfig(w.cfg.ConfigPath)
		if err != nil {
			return err
		}
		removed := conf.RemovePeerByKey(publicKey)
		if err := w.persist(ctx, conf); err != nil {
			return err
		}
		if _, err := w.runner.Run(ctx, "wg", "set", w.cfg.InterfaceName, "peer", publicKey, "remove"); err != nil {
			return sanitizeCommandError(err)
		}
		if removed {
			return w.verifyPeer(ctx, publicKey, allowedIP, false)
		}
		return nil
	})
}

func (w wireGuardWorker) persist(ctx context.Context, conf *wgConfig) error {
	if err := os.MkdirAll(w.cfg.BackupDir, 0700); err != nil {
		return err
	}
	if current, err := os.ReadFile(w.cfg.ConfigPath); err == nil {
		backup := filepath.Join(w.cfg.BackupDir, "wg0-"+time.Now().UTC().Format("20060102T150405Z")+".conf")
		if err := os.WriteFile(backup, current, 0600); err != nil {
			return err
		}
	}
	tmp := strings.TrimSuffix(w.cfg.ConfigPath, ".conf") + ".tmp.conf"
	if err := os.WriteFile(tmp, []byte(conf.String()), 0600); err != nil {
		return err
	}
	if _, err := w.runner.Run(ctx, "wg-quick", "strip", tmp); err != nil {
		_ = os.Remove(tmp)
		return sanitizeCommandError(err)
	}
	return os.Rename(tmp, w.cfg.ConfigPath)
}

func readWGConfig(path string) (*wgConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseWGConfig(string(data))
}

func (w wireGuardWorker) verifyPeer(ctx context.Context, publicKey, allowedIP string, shouldExist bool) error {
	out, err := w.runner.Run(ctx, "wg", "show", w.cfg.InterfaceName, "allowed-ips")
	if err != nil {
		return sanitizeCommandError(err)
	}
	found := false
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] == publicKey && fields[1] == allowedIP {
			found = true
			break
		}
	}
	if shouldExist && !found {
		return fmt.Errorf("WireGuard peer verification failed: key %s does not own %s", publicKey, allowedIP)
	}
	if !shouldExist && found {
		return errors.New("WireGuard peer still exists after removal")
	}
	return nil
}

func (w wireGuardWorker) configureRouter(ctx context.Context, job wireGuardJob) error {
	var desired desiredRouterConfig
	if err := w.get(ctx, "/internal/routers/"+job.RouterID+"/desired-config", &desired); err != nil {
		return fmt.Errorf("fetch desired router config: %w", err)
	}
	if strings.TrimSpace(desired.ManagementIP) == "" {
		return errors.New("desired router config has no management_ip")
	}
	if strings.TrimSpace(desired.APIUsername) == "" || desired.APIPassword == "" {
		return errors.New("desired router config has incomplete API credentials")
	}
	if strings.TrimSpace(desired.RouterOSScript) == "" {
		return errors.New("desired router config has empty routeros_script")
	}
	port := desired.APIPort
	if port <= 0 {
		port = 8728
	}
	address := net.JoinHostPort(desired.ManagementIP, strconv.Itoa(port))
	if err := waitForTCP(ctx, address, w.cfg.RouterConnectTimeout); err != nil {
		return err
	}
	client := mikrotik.NewClient(desired.ManagementIP, desired.APIUsername, desired.APIPassword).WithPort(port)
	conn, err := client.DialAndLogin()
	if err != nil {
		return fmt.Errorf("connect RouterOS API: %w", err)
	}
	defer conn.Close()
	return applyRouterOSScript(conn, "noblifi-agent-config", desired.RouterOSScript)
}

func applyRouterOSScript(conn *mikrotik.Conn, name, source string) error {
	_, _ = conn.Command("/system/script/remove", map[string]string{"?name": name})
	if _, err := conn.Command("/system/script/add", map[string]string{
		"=name":   name,
		"=policy": "ftp,reboot,read,write,policy,test,password,sniff,sensitive,romon",
		"=source": source,
	}); err != nil {
		return err
	}
	if _, err := conn.Command("/system/script/run", map[string]string{"=number": name}); err != nil {
		return err
	}
	_, _ = conn.Command("/system/script/remove", map[string]string{"?name": name})
	return nil
}

func waitForTCP(ctx context.Context, address string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		dialer := net.Dialer{Timeout: 5 * time.Second}
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			return fmt.Errorf("router API %s did not become reachable: %w", address, lastErr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func (w wireGuardWorker) heartbeat(ctx context.Context, healthy bool) error {
	publicKey, err := w.serverPublicKey(ctx)
	if err != nil {
		healthy = false
	}
	return w.post(ctx, "/internal/agents/heartbeat", map[string]any{
		"agent_id":             w.cfg.AgentID,
		"version":              "dev",
		"wireguard_interface":  w.cfg.InterfaceName,
		"wireguard_public_key": publicKey,
		"healthy":              healthy,
		"last_reconciliation":  time.Now().UTC(),
	}, nil)
}

func (w wireGuardWorker) serverPublicKey(ctx context.Context) (string, error) {
	out, err := w.runner.Run(ctx, "wg", "show", w.cfg.InterfaceName, "public-key")
	if err != nil {
		return "", sanitizeCommandError(err)
	}
	publicKey := strings.TrimSpace(string(out))
	if publicKey == "" {
		return "", errors.New("WireGuard interface public key is empty")
	}
	return publicKey, nil
}

func (w wireGuardWorker) post(ctx context.Context, path string, payload any, out any) error {
	body, _ := json.Marshal(payload)
	req, err := authedRequest(ctx, w.cfg, http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return responseError(resp)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (w wireGuardWorker) get(ctx context.Context, path string, out any) error {
	req, err := authedRequest(ctx, w.cfg, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return responseError(resp)
	}
	return json.NewDecoder(resp.Body).Decode(out)
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
