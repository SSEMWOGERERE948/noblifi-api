package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/noblifi/noblifi/backend/internal/mikrotik"
	"github.com/noblifi/noblifi/backend/internal/routers"
)

type config struct {
	BaseURL           string
	AgentToken        string
	AgentID           string
	TelemetryInterval time.Duration
	HTTPTimeout       time.Duration
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
	for _, target := range targets {
		report, err := collectTarget(target)
		if err != nil {
			report = telemetryReport{Error: err.Error()}
		}
		if err := submitTelemetry(ctx, client, cfg, target.RouterID, report); err != nil {
			log.Printf("telemetry submit failed router_id=%s name=%q error=%v", target.RouterID, target.Name, err)
			continue
		}
		if report.Error != "" {
			log.Printf("telemetry recorded error router_id=%s name=%q error=%q", target.RouterID, target.Name, report.Error)
		} else {
			log.Printf("telemetry updated router_id=%s name=%q cpu=%s uptime=%s users=%d", target.RouterID, target.Name, report.CPULoad, report.Uptime, derefInt(report.ActiveHotspotUsers))
		}
	}
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

func collectTarget(target telemetryTarget) (telemetryReport, error) {
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
	client := mikrotik.NewClient(target.RouterIP, target.APIUsername, target.APIPassword).WithPort(apiPort)
	resourceRows, err := client.Command("/system/resource/print", nil)
	if err != nil {
		return telemetryReport{}, err
	}
	identityRows, _ := client.Command("/system/identity/print", nil)
	interfaceRows, _ := client.Command("/interface/print", nil)
	activeRows, _ := client.Command("/ip/hotspot/active/print", nil)

	resource := firstRow(resourceRows)
	identity := firstRow(identityRows)
	now := time.Now().UTC()
	interfaces := make([]routers.RouterInterface, 0, len(interfaceRows))
	for _, row := range interfaceRows {
		name := row["=name"]
		if name == "" {
			continue
		}
		iface := routers.RouterInterface{
			Name:         name,
			Running:      parseRouterOSBool(row["=running"]),
			Disabled:     parseRouterOSBool(row["=disabled"]),
			DiscoveredAt: now,
		}
		if value := row["=type"]; value != "" {
			iface.Type = &value
		}
		if value := row["=mac-address"]; value != "" {
			iface.MacAddress = &value
		}
		interfaces = append(interfaces, iface)
	}

	activeUsers := len(activeRows)
	return telemetryReport{
		Identity:           identity["=name"],
		Model:              firstNonEmpty(resource["=board-name"], resource["=platform"]),
		RouterOSVersion:    resource["=version"],
		Uptime:             resource["=uptime"],
		CPULoad:            resource["=cpu-load"],
		FreeMemory:         resource["=free-memory"],
		TotalMemory:        resource["=total-memory"],
		ActiveHotspotUsers: &activeUsers,
		Interfaces:         interfaces,
	}, nil
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
		BaseURL:           strings.TrimRight(strings.TrimSpace(os.Getenv("NOBLIFI_CONTROL_PLANE_URL")), "/"),
		AgentToken:        strings.TrimSpace(os.Getenv("NOBLIFI_AGENT_TOKEN")),
		AgentID:           firstNonEmpty(os.Getenv("NOBLIFI_AGENT_ID"), "xneelo-wg-agent-01"),
		TelemetryInterval: durationEnv("NOBLIFI_AGENT_TELEMETRY_INTERVAL", 2*time.Minute),
		HTTPTimeout:       durationEnv("NOBLIFI_AGENT_HTTP_TIMEOUT", 15*time.Second),
	}
	if cfg.BaseURL == "" {
		return config{}, errors.New("NOBLIFI_CONTROL_PLANE_URL is required")
	}
	if cfg.AgentToken == "" {
		return config{}, errors.New("NOBLIFI_AGENT_TOKEN is required")
	}
	return cfg, nil
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

func derefInt(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}
