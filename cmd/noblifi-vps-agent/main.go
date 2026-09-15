package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/noblifi/noblifi/backend/internal/mikrotik"
	"github.com/noblifi/noblifi/backend/internal/routers"
)

type config struct {
	BaseURL                string
	AgentToken             string
	AgentID                string
	TelemetryInterval      time.Duration
	PollInterval           time.Duration
	HeartbeatInterval      time.Duration
	HTTPTimeout            time.Duration
	InterfaceName          string
	ConfigPath             string
	LockPath               string
	BackupDir              string
	RouterConnectTimeout   time.Duration
	RouterCommandTimeout   time.Duration
	RouterTelemetryLimit   time.Duration
	TelemetryConcurrency   int
	RemoteAccessSourceCIDR string
}

type telemetryTargetsResponse struct {
	Targets []telemetryTarget `json:"targets"`
}

type telemetryTarget struct {
	RouterID    string `json:"router_id"`
	Name        string `json:"name"`
	RouterIP    string `json:"router_ip"`
	APIPort     int    `json:"api_port"`
	APIUsername string `json:"api_username"`
	APIPassword string `json:"api_password"`
}

type telemetryReport struct {
	Identity           string                    `json:"identity,omitempty"`
	Model              string                    `json:"model,omitempty"`
	RouterOSVersion    string                    `json:"routeros_version,omitempty"`
	Uptime             string                    `json:"uptime,omitempty"`
	UptimeSeconds      *int64                    `json:"uptime_seconds,omitempty"`
	CPULoad            string                    `json:"cpu_load,omitempty"`
	FreeMemory         string                    `json:"free_memory,omitempty"`
	TotalMemory        string                    `json:"total_memory,omitempty"`
	ActiveHotspotUsers *int                      `json:"active_hotspot_users,omitempty"`
	Interfaces         []routers.RouterInterface `json:"interfaces,omitempty"`
	Error              string                    `json:"error,omitempty"`
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client := &http.Client{Timeout: cfg.HTTPTimeout}
	log.Printf("noblifi telemetry agent started agent_id=%s interval=%s", cfg.AgentID, cfg.TelemetryInterval)
	go runWireGuardWorker(ctx, client, cfg)

	runTelemetry(ctx, client, cfg)

	telemetryTicker := time.NewTicker(cfg.TelemetryInterval)
	defer telemetryTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("noblifi telemetry agent stopped")
			return
		case <-telemetryTicker.C:
			runTelemetry(ctx, client, cfg)
		}
	}
}

func runTelemetry(ctx context.Context, client *http.Client, cfg config) {
	targets, err := fetchTargets(ctx, client, cfg)
	if err != nil {
		log.Printf("telemetry target fetch failed: %v", err)
		return
	}
	if len(targets) == 0 {
		return
	}

	concurrency := cfg.TelemetryConcurrency
	if concurrency <= 0 {
		concurrency = 5
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, target := range targets {
		target := target
		select {
		case <-ctx.Done():
			return
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			runTargetTelemetry(ctx, client, cfg, target)
		}()
	}
	wg.Wait()
}

func runTargetTelemetry(ctx context.Context, client *http.Client, cfg config, target telemetryTarget) {
	report, err := collectTarget(ctx, target, cfg)
	if err != nil {
		report = telemetryReport{Error: err.Error()}
	}
	if err := submitTelemetry(ctx, client, cfg, target.RouterID, report); err != nil {
		log.Printf("telemetry submit failed router_id=%s name=%q error=%v", target.RouterID, target.Name, err)
		return
	}
	if report.Error != "" {
		log.Printf("telemetry recorded error router_id=%s name=%q error=%q", target.RouterID, target.Name, report.Error)
		return
	}
	log.Printf("telemetry updated router_id=%s name=%q cpu=%s uptime=%s users=%d", target.RouterID, target.Name, report.CPULoad, report.Uptime, derefInt(report.ActiveHotspotUsers))
}

func fetchTargets(ctx context.Context, client *http.Client, cfg config) ([]telemetryTarget, error) {
	req, err := authedRequest(ctx, cfg, http.MethodGet, "/internal/routers/telemetry-targets", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, responseError(resp)
	}
	var out telemetryTargetsResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Targets, nil
}

func collectTarget(ctx context.Context, target telemetryTarget, cfg config) (telemetryReport, error) {
	if strings.TrimSpace(target.RouterIP) == "" {
		return telemetryReport{}, errors.New("router_ip is empty")
	}
	if strings.TrimSpace(target.APIUsername) == "" || strings.TrimSpace(target.APIPassword) == "" {
		return telemetryReport{}, errors.New("router API credentials are missing")
	}
	apiPort := target.APIPort
	if apiPort <= 0 {
		apiPort = 8728
	}
	if cfg.RouterConnectTimeout <= 0 {
		cfg.RouterConnectTimeout = 4 * time.Second
	}
	if cfg.RouterCommandTimeout <= 0 {
		cfg.RouterCommandTimeout = 5 * time.Second
	}
	if cfg.RouterTelemetryLimit <= 0 {
		cfg.RouterTelemetryLimit = 12 * time.Second
	}

	targetCtx, cancel := context.WithTimeout(ctx, cfg.RouterTelemetryLimit)
	defer cancel()
	address := net.JoinHostPort(target.RouterIP, strconv.Itoa(apiPort))
	dialer := net.Dialer{Timeout: cfg.RouterConnectTimeout}
	conn, err := dialer.DialContext(targetCtx, "tcp", address)
	if err != nil {
		return telemetryReport{}, fmt.Errorf("router API TCP preflight failed: %w", err)
	}
	_ = conn.Close()
	log.Printf("telemetry preflight ok router_id=%s name=%q address=%s", target.RouterID, target.Name, address)

	client := mikrotik.NewClient(target.RouterIP, target.APIUsername, target.APIPassword).
		WithPort(apiPort).
		WithTimeout(cfg.RouterCommandTimeout)
	api, err := client.DialAndLogin()
	if err != nil {
		return telemetryReport{}, err
	}
	defer api.Close()

	resourceRows, err := api.Command("/system/resource/print", map[string]string{"=.proplist": "uptime,version,cpu-load,free-memory,total-memory,board-name"})
	if err != nil {
		return telemetryReport{}, err
	}
	identityRows, err := api.Command("/system/identity/print", map[string]string{"=.proplist": "name"})
	if err != nil {
		return telemetryReport{}, err
	}
	interfaceRows, err := api.Command("/interface/print", map[string]string{"=.proplist": "name,type,mac-address,running,disabled"})
	if err != nil {
		return telemetryReport{}, err
	}
	activeRows, err := api.Command("/ip/hotspot/active/print", map[string]string{"=.proplist": ".id,user,address,mac-address,uptime,session-time-left,bytes-in,bytes-out,login-by"})
	if err != nil {
		return telemetryReport{}, err
	}

	return telemetryReportFromRows(resourceRows, identityRows, interfaceRows, activeRows), nil
}

func telemetryReportFromRows(resourceRows, identityRows, interfaceRows, activeRows []map[string]string) telemetryReport {
	resource := firstRow(resourceRows)
	identity := firstRow(identityRows)
	now := time.Now().UTC()
	interfaces := make([]routers.RouterInterface, 0, len(interfaceRows))
	for _, row := range interfaceRows {
		name := routerOSValue(row, "name")
		if name == "" {
			continue
		}
		iface := routers.RouterInterface{
			Name:         name,
			Running:      parseRouterOSBool(routerOSValue(row, "running")),
			Disabled:     parseRouterOSBool(routerOSValue(row, "disabled")),
			DiscoveredAt: now,
		}
		if value := routerOSValue(row, "type"); value != "" {
			iface.Type = &value
		}
		if value := routerOSValue(row, "mac-address"); value != "" {
			iface.MacAddress = &value
		}
		interfaces = append(interfaces, iface)
	}

	activeUsers := len(activeRows)
	uptime := routerOSValue(resource, "uptime")
	uptimeSeconds := parseRouterOSDurationSeconds(uptime)
	return telemetryReport{
		Identity:           routerOSValue(identity, "name"),
		Model:              firstNonEmpty(routerOSValue(resource, "board-name"), routerOSValue(resource, "platform")),
		RouterOSVersion:    routerOSValue(resource, "version"),
		Uptime:             uptime,
		UptimeSeconds:      uptimeSeconds,
		CPULoad:            routerOSValue(resource, "cpu-load"),
		FreeMemory:         routerOSValue(resource, "free-memory"),
		TotalMemory:        routerOSValue(resource, "total-memory"),
		ActiveHotspotUsers: &activeUsers,
		Interfaces:         interfaces,
	}
}

func submitTelemetry(ctx context.Context, client *http.Client, cfg config, routerID string, report telemetryReport) error {
	body, err := json.Marshal(report)
	if err != nil {
		return err
	}
	req, err := authedRequest(ctx, cfg, http.MethodPost, "/internal/routers/"+routerID+"/telemetry", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return responseError(resp)
	}
	return nil
}

func authedRequest(ctx context.Context, cfg config, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(cfg.BaseURL, "/")+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.AgentToken)
	req.Header.Set("User-Agent", "noblifi-vps-agent")
	return req, nil
}

func responseError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	message := strings.TrimSpace(string(body))
	if message == "" {
		message = resp.Status
	}
	return fmt.Errorf("control plane returned %s: %s", resp.Status, message)
}

func loadConfig() (config, error) {
	cfg := config{
		BaseURL:                strings.TrimRight(strings.TrimSpace(os.Getenv("NOBLIFI_CONTROL_PLANE_URL")), "/"),
		AgentToken:             strings.TrimSpace(os.Getenv("NOBLIFI_AGENT_TOKEN")),
		AgentID:                firstNonEmpty(os.Getenv("NOBLIFI_AGENT_ID"), "noblifi-agent-01"),
		TelemetryInterval:      durationEnv("NOBLIFI_AGENT_TELEMETRY_INTERVAL", 30*time.Second),
		PollInterval:           durationEnv("NOBLIFI_AGENT_POLL_INTERVAL", 5*time.Second),
		HeartbeatInterval:      durationEnv("NOBLIFI_AGENT_HEARTBEAT_INTERVAL", 5*time.Minute),
		HTTPTimeout:            durationEnv("NOBLIFI_AGENT_HTTP_TIMEOUT", 30*time.Second),
		InterfaceName:          firstNonEmpty(os.Getenv("NOBLIFI_WIREGUARD_INTERFACE"), "wg0"),
		ConfigPath:             firstNonEmpty(os.Getenv("NOBLIFI_WIREGUARD_CONFIG"), "/etc/wireguard/wg0.conf"),
		LockPath:               firstNonEmpty(os.Getenv("NOBLIFI_WIREGUARD_LOCK"), "/run/lock/noblifi-wireguard.lock"),
		BackupDir:              firstNonEmpty(os.Getenv("NOBLIFI_WIREGUARD_BACKUP_DIR"), "/etc/wireguard/backups"),
		RouterConnectTimeout:   durationEnv("NOBLIFI_ROUTER_CONNECT_TIMEOUT", 4*time.Second),
		RouterCommandTimeout:   durationEnv("NOBLIFI_ROUTER_COMMAND_TIMEOUT", 5*time.Second),
		RouterTelemetryLimit:   durationEnv("NOBLIFI_ROUTER_TELEMETRY_TIMEOUT", 12*time.Second),
		TelemetryConcurrency:   intEnv("NOBLIFI_AGENT_TELEMETRY_CONCURRENCY", 5),
		RemoteAccessSourceCIDR: strings.TrimSpace(os.Getenv("NOBLIFI_REMOTE_ACCESS_SOURCE_CIDR")),
	}
	if cfg.BaseURL == "" {
		return config{}, errors.New("NOBLIFI_CONTROL_PLANE_URL is required")
	}
	if cfg.AgentToken == "" {
		return config{}, errors.New("NOBLIFI_AGENT_TOKEN is required")
	}
	return cfg, nil
}

func intEnv(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	duration, err := time.ParseDuration(value)
	if err == nil && duration > 0 {
		return duration
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return fallback
}

func firstRow(rows []map[string]string) map[string]string {
	if len(rows) == 0 {
		return map[string]string{}
	}
	return rows[0]
}

func routerOSValue(row map[string]string, key string) string {
	if row == nil {
		return ""
	}
	key = strings.TrimSpace(strings.TrimPrefix(key, "="))
	if value := strings.TrimSpace(row["="+key]); value != "" {
		return value
	}
	return strings.TrimSpace(row[key])
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func parseRouterOSBool(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "true" || value == "yes" || value == "1"
}

func parseRouterOSDurationSeconds(value string) *int64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	var total int64
	var number int64
	hasNumber := false
	for _, r := range value {
		if r >= '0' && r <= '9' {
			hasNumber = true
			number = number*10 + int64(r-'0')
			continue
		}
		if !hasNumber {
			continue
		}
		switch r {
		case 'w':
			total += number * 7 * 24 * 60 * 60
		case 'd':
			total += number * 24 * 60 * 60
		case 'h':
			total += number * 60 * 60
		case 'm':
			total += number * 60
		case 's':
			total += number
		default:
			number = 0
			hasNumber = false
			continue
		}
		number = 0
		hasNumber = false
	}
	if hasNumber {
		total += number
	}
	return &total
}

func derefInt(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}
