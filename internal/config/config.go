package config

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/noblifi/noblifi/backend/internal/placeholders"
)

const defaultRadiusServer = "154.65.105.14"

type Config struct {
	Port                     string
	DatabaseURL              string
	JWTSecret                string
	AppEnv                   string
	PublicAPIBaseURL         string
	PublicSiteURL            string
	ProvisioningBaseURL      string
	AgentToken               string
	RadiusServer             string
	RadiusSecret             string
	RouterIdentityPrefix     string
	RouterAPIUsername        string
	RouterAPIPassword        string
	WireGuardEnabled         bool
	WireGuardInterface       string
	WireGuardEndpoint        string
	WireGuardPublicKey       string
	WireGuardServerIP        string
	WireGuardPort            int
	WireGuardSubnetCIDR      string
	WireGuardKeepalive       int
	RemoteAccessHost         string
	RemoteWinboxPortBase     int
	HotspotBridgeName        string
	StaffBridgeName          string
	POSBridgeName            string
	CCTVBridgeName           string
	HotspotSubnetCIDR        string
	HotspotGatewayCIDR       string
	HotspotPoolRange         string
	StaffSubnetCIDR          string
	StaffGatewayCIDR         string
	StaffPoolRange           string
	POSSubnetCIDR            string
	POSGatewayCIDR           string
	POSPoolRange             string
	CCTVSubnetCIDR           string
	CCTVGatewayCIDR          string
	CCTVPoolRange            string
	HotspotDNSName           string
	HotspotPortalName        string
	HotspotWalledGardenHosts []string
	DisableWWWService        bool
	EnableAPIService         bool
	EnableAPISSLService      bool
	RadiusAuthPort           int
	RadiusAcctPort           int
	ProvisioningTokenTTLHour int
	IotecBaseURL             string
	IotecTokenURL            string
	IotecClientID            string
	IotecClientSecret        string
	IotecWalletID            string
	IotecWalletCode          string
	IotecPaymentLink         string
	IotecCurrency            string
	MobileMoneyCommissionBPS int
	MinimumWithdrawalUGX     int
}

func Load() Config {
	cfg, _ := LoadWithContext(context.Background())
	return cfg
}

func LoadWithContext(ctx context.Context) (Config, error) {
	loadDotEnv(".env")

	cfg := Config{
		Port:                getEnv("PORT", "8080"),
		DatabaseURL:         getEnv("DATABASE_URL", "postgres://noblifi:noblifi@localhost:5432/noblifi?sslmode=disable"),
		JWTSecret:           getEnv("JWT_SECRET", "change-this-secret"),
		AppEnv:              getEnv("APP_ENV", "development"),
		PublicAPIBaseURL:    getEnv("PUBLIC_API_BASE_URL", "http://localhost:8080"),
		PublicSiteURL:       getEnv("NOBLIFI_PUBLIC_SITE_URL", "http://localhost:3000"),
		ProvisioningBaseURL: getEnv("NOBLIFI_PROVISIONING_BASE_URL", "http://localhost:8080/api/v1/provisioning"),
		AgentToken:          getEnv("NOBLIFI_AGENT_TOKEN", ""),

		RadiusServer: getEnv(
			"NOBLIFI_RADIUS_SERVER",
			defaultRadiusServer,
		),
		RadiusSecret: normalizeRadiusSecret(
			getEnv("NOBLIFI_RADIUS_SECRET", "noblifi"),
		),

		RouterIdentityPrefix: getEnv(
			"NOBLIFI_ROUTER_IDENTITY_PREFIX",
			"NobliFi",
		),
		RouterAPIUsername: getEnv(
			"NOBLIFI_ROUTER_API_USERNAME",
			"noblifi-api",
		),
		RouterAPIPassword: getEnv(
			"NOBLIFI_ROUTER_API_PASSWORD",
			"CHANGE_ME_API_PASSWORD",
		),

		// WireGuard VPS management tunnel.
		WireGuardEnabled: getBoolEnv(
			"NOBLIFI_WIREGUARD_ENABLED",
			false,
		),
		WireGuardInterface: getEnv(
			"NOBLIFI_WIREGUARD_INTERFACE",
			"wg0",
		),
		WireGuardEndpoint: getEnv(
			"NOBLIFI_WIREGUARD_ENDPOINT",
			"",
		),
		WireGuardPublicKey: getEnv(
			"NOBLIFI_WIREGUARD_PUBLIC_KEY",
			"",
		),
		WireGuardServerIP: getEnv(
			"NOBLIFI_WIREGUARD_SERVER_IP",
			"10.77.0.1",
		),
		WireGuardPort: getIntEnv(
			"NOBLIFI_WIREGUARD_PORT",
			51820,
		),
		WireGuardSubnetCIDR: getEnv(
			"NOBLIFI_WIREGUARD_SUBNET",
			"10.77.0.0/24",
		),
		WireGuardKeepalive: getIntEnv(
			"NOBLIFI_WIREGUARD_KEEPALIVE",
			25,
		),
		RemoteAccessHost: getEnv(
			"NOBLIFI_REMOTE_ACCESS_HOST",
			"",
		),
		RemoteWinboxPortBase: getIntEnv(
			"NOBLIFI_REMOTE_WINBOX_PORT_BASE",
			22000,
		),

		HotspotBridgeName: getEnv(
			"NOBLIFI_HOTSPOT_BRIDGE",
			"br-hotspot",
		),
		StaffBridgeName: getEnv(
			"NOBLIFI_STAFF_BRIDGE",
			"br-staff",
		),
		POSBridgeName: getEnv(
			"NOBLIFI_POS_BRIDGE",
			"br-pos",
		),
		CCTVBridgeName: getEnv(
			"NOBLIFI_CCTV_BRIDGE",
			"br-cctv",
		),

		HotspotSubnetCIDR: getEnv(
			"NOBLIFI_HOTSPOT_SUBNET",
			"10.10.10.0/24",
		),
		HotspotGatewayCIDR: getEnv(
			"NOBLIFI_HOTSPOT_GATEWAY",
			"10.10.10.1/24",
		),
		HotspotPoolRange: getEnv(
			"NOBLIFI_HOTSPOT_POOL",
			"10.10.10.10-10.10.10.254",
		),

		StaffSubnetCIDR: getEnv(
			"NOBLIFI_STAFF_SUBNET",
			"10.20.20.0/24",
		),
		StaffGatewayCIDR: getEnv(
			"NOBLIFI_STAFF_GATEWAY",
			"10.20.20.1/24",
		),
		StaffPoolRange: getEnv(
			"NOBLIFI_STAFF_POOL",
			"10.20.20.10-10.20.20.254",
		),

		POSSubnetCIDR: getEnv(
			"NOBLIFI_POS_SUBNET",
			"10.30.30.0/24",
		),
		POSGatewayCIDR: getEnv(
			"NOBLIFI_POS_GATEWAY",
			"10.30.30.1/24",
		),
		POSPoolRange: getEnv(
			"NOBLIFI_POS_POOL",
			"10.30.30.10-10.30.30.254",
		),

		CCTVSubnetCIDR: getEnv(
			"NOBLIFI_CCTV_SUBNET",
			"10.40.40.0/24",
		),
		CCTVGatewayCIDR: getEnv(
			"NOBLIFI_CCTV_GATEWAY",
			"10.40.40.1/24",
		),
		CCTVPoolRange: getEnv(
			"NOBLIFI_CCTV_POOL",
			"10.40.40.10-10.40.40.254",
		),

		HotspotDNSName: getEnv(
			"NOBLIFI_HOTSPOT_DNS_NAME",
			"login.noblifi.local",
		),
		HotspotPortalName: getEnv(
			"NOBLIFI_HOTSPOT_PORTAL_NAME",
			"NobliFi WiFi",
		),
		HotspotWalledGardenHosts: withURLHost(
			getListEnv(
				"NOBLIFI_HOTSPOT_WALLED_GARDEN_HOSTS",
				"noblifi-frontend.vercel.app,noblifi.ew.r.appspot.com,noblifi.uc.r.appspot.com",
			),
			getEnv("NOBLIFI_PUBLIC_SITE_URL", "http://localhost:3000"),
		),

		DisableWWWService: getBoolEnv(
			"NOBLIFI_DISABLE_WWW_SERVICE",
			true,
		),
		EnableAPIService: getBoolEnv(
			"NOBLIFI_ENABLE_API_SERVICE",
			true,
		),
		EnableAPISSLService: getBoolEnv(
			"NOBLIFI_ENABLE_API_SSL_SERVICE",
			true,
		),

		RadiusAuthPort: getIntEnv(
			"NOBLIFI_RADIUS_AUTH_PORT",
			1812,
		),
		RadiusAcctPort: getIntEnv(
			"NOBLIFI_RADIUS_ACCT_PORT",
			1813,
		),

		ProvisioningTokenTTLHour: getIntEnv(
			"NOBLIFI_PROVISIONING_TOKEN_TTL_HOURS",
			24,
		),

		IotecBaseURL: getEnv(
			"IOTEC_BASE_URL",
			"",
		),
		IotecTokenURL: getEnv(
			"IOTEC_TOKEN_URL",
			"",
		),
		IotecClientID: getEnv(
			"IOTEC_CLIENT_ID",
			"",
		),
		IotecClientSecret: getEnv(
			"IOTEC_CLIENT_SECRET",
			"",
		),
		IotecWalletID: getEnv(
			"IOTEC_WALLET_ID",
			"01a023f3-c9d7-7103-b774-b83336aa4699",
		),
		IotecWalletCode: getEnv(
			"IOTEC_WALLET_CODE",
			"02608627",
		),
		IotecPaymentLink: getEnv(
			"IOTEC_PAYMENT_LINK",
			"https://pay.iotec.io/p/02608627",
		),
		IotecCurrency: getEnv(
			"IOTEC_CURRENCY",
			"UGX",
		),
		MobileMoneyCommissionBPS: getIntEnv(
			"NOBLIFI_MOBILE_MONEY_COMMISSION_BPS",
			500,
		),
		MinimumWithdrawalUGX: getIntEnv(
			"NOBLIFI_MINIMUM_WITHDRAWAL_UGX",
			0,
		),
	}

	if strings.EqualFold(cfg.AppEnv, "production") {
		if err := loadProductionIotecSecrets(ctx, &cfg); err != nil {
			return cfg, err
		}
	}

	return cfg, nil
}

func loadProductionIotecSecrets(ctx context.Context, cfg *Config) error {
	var err error

	if cfg.IotecBaseURL, err = loadSecretOrEnv(ctx, "IOTEC_BASE_URL"); err != nil {
		return err
	}
	if cfg.IotecClientID, err = loadSecretOrEnv(ctx, "IOTEC_CLIENT_ID"); err != nil {
		return err
	}
	if cfg.IotecClientSecret, err = loadSecretOrEnv(ctx, "IOTEC_CLIENT_SECRET"); err != nil {
		return err
	}
	if cfg.IotecPaymentLink, err = loadSecretOrEnv(ctx, "IOTEC_PAYMENT_LINK"); err != nil {
		return err
	}
	if cfg.IotecTokenURL, err = loadSecretOrEnv(ctx, "IOTEC_TOKEN_URL"); err != nil {
		return err
	}
	if cfg.IotecWalletCode, err = loadSecretOrEnv(ctx, "IOTEC_WALLET_CODE"); err != nil {
		return err
	}
	if cfg.IotecWalletID, err = loadSecretOrEnv(ctx, "IOTEC_WALLET_ID"); err != nil {
		return err
	}

	return nil
}

func LoadIotecClientSecret(ctx context.Context) (string, error) {
	return loadSecretOrEnv(ctx, "IOTEC_CLIENT_SECRET")
}

func loadSecretOrEnv(ctx context.Context, name string) (string, error) {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value, nil
	}
	return loadSecret(ctx, name)
}

func loadSecret(ctx context.Context, name string) (string, error) {
	projectID := firstNonEmptyEnv("GCP_PROJECT_ID", "GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT")
	if projectID == "" {
		return "", fmt.Errorf("GCP_PROJECT_ID not set")
	}

	token, err := metadataAccessToken(ctx)
	if err != nil {
		return "", fmt.Errorf("metadata access token: %w", err)
	}

	secretName := url.PathEscape(name)
	endpoint := fmt.Sprintf(
		"https://secretmanager.googleapis.com/v1/projects/%s/secrets/%s/versions/latest:access",
		url.PathEscape(projectID),
		secretName,
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("access secret %s failed with %s: %s", name, resp.Status, strings.TrimSpace(string(body)))
	}

	var out struct {
		Payload struct {
			Data string `json:"data"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("decode secret %s response: %w", name, err)
	}
	decoded, err := base64.StdEncoding.DecodeString(out.Payload.Data)
	if err != nil {
		return "", fmt.Errorf("decode secret %s payload: %w", name, err)
	}
	value := strings.TrimSpace(string(decoded))
	if value == "" {
		return "", fmt.Errorf("secret %s is empty", name)
	}
	return value, nil
}

func metadataAccessToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("metadata server returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	if strings.TrimSpace(out.AccessToken) == "" {
		return "", fmt.Errorf("metadata server did not return an access token")
	}
	return strings.TrimSpace(out.AccessToken), nil
}

func withURLHost(hosts []string, rawURL string) []string {
	host := strings.TrimSpace(rawURL)
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	if slash := strings.Index(host, "/"); slash >= 0 {
		host = host[:slash]
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return hosts
	}
	for _, existing := range hosts {
		clean := strings.TrimSpace(existing)
		clean = strings.TrimPrefix(clean, "https://")
		clean = strings.TrimPrefix(clean, "http://")
		if slash := strings.Index(clean, "/"); slash >= 0 {
			clean = clean[:slash]
		}
		if strings.EqualFold(clean, host) {
			return hosts
		}
	}
	return append(hosts, host)
}

func normalizeRadiusSecret(value string) string {
	if placeholders.Is(value) {
		return "noblifi"
	}

	return strings.TrimSpace(value)
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}

	return fallback
}

func firstNonEmptyEnv(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}

func getListEnv(key, fallback string) []string {
	value := getEnv(key, fallback)
	parts := strings.Split(value, ",")

	items := make([]string, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)

		if part != "" {
			items = append(items, part)
		}
	}

	return items
}

func getBoolEnv(key string, fallback bool) bool {
	value := strings.ToLower(
		strings.TrimSpace(os.Getenv(key)),
	)

	if value == "" {
		return fallback
	}

	return value == "1" ||
		value == "true" ||
		value == "yes" ||
		value == "on"
}

func getIntEnv(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))

	if value == "" {
		return fallback
	}

	result := 0

	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return fallback
		}

		result = result*10 + int(ch-'0')
	}

	if result == 0 {
		return fallback
	}

	return result
}

func loadDotEnv(path string) {
	file, err := os.Open(path)

	if err != nil {
		return
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(
			scanner.Text(),
		)

		if line == "" ||
			strings.HasPrefix(line, "#") {
			continue
		}

		key, value, ok := strings.Cut(
			line,
			"=",
		)

		if !ok {
			continue
		}

		key = strings.TrimSpace(key)
		value = strings.Trim(
			strings.TrimSpace(value),
			`"'`,
		)

		if key != "" &&
			os.Getenv(key) == "" {
			_ = os.Setenv(key, value)
		}
	}
}
