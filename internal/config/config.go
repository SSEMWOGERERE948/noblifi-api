package config

import (
	"bufio"
	"os"
	"strings"
)

type Config struct {
	Port                     string
	DatabaseURL              string
	JWTSecret                string
	AppEnv                   string
	PublicAPIBaseURL         string
	ProvisioningBaseURL      string
	RadiusServer             string
	RadiusSecret             string
	RouterIdentityPrefix     string
	RouterAPIUsername        string
	RouterAPIPassword        string
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
	HotspotWalledGardenHosts []string
	DisableWWWService        bool
	EnableAPIService         bool
	EnableAPISSLService      bool
	ProvisioningTokenTTLHour int
}

func Load() Config {
	loadDotEnv(".env")

	return Config{
		Port:                     getEnv("PORT", "8080"),
		DatabaseURL:              getEnv("DATABASE_URL", "postgres://noblifi:noblifi@localhost:5432/noblifi?sslmode=disable"),
		JWTSecret:                getEnv("JWT_SECRET", "change-this-secret"),
		AppEnv:                   getEnv("APP_ENV", "development"),
		PublicAPIBaseURL:         getEnv("PUBLIC_API_BASE_URL", "http://localhost:8080"),
		ProvisioningBaseURL:      getEnv("NOBLIFI_PROVISIONING_BASE_URL", "http://localhost:8080/api/v1/provisioning"),
		RadiusServer:             getEnv("NOBLIFI_RADIUS_SERVER", ""),
		RadiusSecret:             normalizeRadiusSecret(getEnv("NOBLIFI_RADIUS_SECRET", "noblifi")),
		RouterIdentityPrefix:     getEnv("NOBLIFI_ROUTER_IDENTITY_PREFIX", "NobliFi"),
		RouterAPIUsername:        getEnv("NOBLIFI_ROUTER_API_USERNAME", "noblifi-api"),
		RouterAPIPassword:        getEnv("NOBLIFI_ROUTER_API_PASSWORD", "CHANGE_ME_API_PASSWORD"),
		HotspotBridgeName:        getEnv("NOBLIFI_HOTSPOT_BRIDGE", "br-hotspot"),
		StaffBridgeName:          getEnv("NOBLIFI_STAFF_BRIDGE", "br-staff"),
		POSBridgeName:            getEnv("NOBLIFI_POS_BRIDGE", "br-pos"),
		CCTVBridgeName:           getEnv("NOBLIFI_CCTV_BRIDGE", "br-cctv"),
		HotspotSubnetCIDR:        getEnv("NOBLIFI_HOTSPOT_SUBNET", "10.10.10.0/24"),
		HotspotGatewayCIDR:       getEnv("NOBLIFI_HOTSPOT_GATEWAY", "10.10.10.1/24"),
		HotspotPoolRange:         getEnv("NOBLIFI_HOTSPOT_POOL", "10.10.10.10-10.10.10.254"),
		StaffSubnetCIDR:          getEnv("NOBLIFI_STAFF_SUBNET", "10.20.20.0/24"),
		StaffGatewayCIDR:         getEnv("NOBLIFI_STAFF_GATEWAY", "10.20.20.1/24"),
		StaffPoolRange:           getEnv("NOBLIFI_STAFF_POOL", "10.20.20.10-10.20.20.254"),
		POSSubnetCIDR:            getEnv("NOBLIFI_POS_SUBNET", "10.30.30.0/24"),
		POSGatewayCIDR:           getEnv("NOBLIFI_POS_GATEWAY", "10.30.30.1/24"),
		POSPoolRange:             getEnv("NOBLIFI_POS_POOL", "10.30.30.10-10.30.30.254"),
		CCTVSubnetCIDR:           getEnv("NOBLIFI_CCTV_SUBNET", "10.40.40.0/24"),
		CCTVGatewayCIDR:          getEnv("NOBLIFI_CCTV_GATEWAY", "10.40.40.1/24"),
		CCTVPoolRange:            getEnv("NOBLIFI_CCTV_POOL", "10.40.40.10-10.40.40.254"),
		HotspotDNSName:           getEnv("NOBLIFI_HOTSPOT_DNS_NAME", "login.noblifi.local"),
		HotspotWalledGardenHosts: getListEnv("NOBLIFI_HOTSPOT_WALLED_GARDEN_HOSTS", "noblifi-frontend.vercel.app,noblifi.ew.r.appspot.com,noblifi.uc.r.appspot.com"),
		DisableWWWService:        getBoolEnv("NOBLIFI_DISABLE_WWW_SERVICE", true),
		EnableAPIService:         getBoolEnv("NOBLIFI_ENABLE_API_SERVICE", true),
		EnableAPISSLService:      getBoolEnv("NOBLIFI_ENABLE_API_SSL_SERVICE", true),
		ProvisioningTokenTTLHour: 24,
	}
}

func normalizeRadiusSecret(value string) string {
	if isPlaceholderValue(value) {
		return "noblifi"
	}
	return strings.TrimSpace(value)
}

func isPlaceholderValue(value string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	return normalized == "" ||
		strings.HasPrefix(normalized, "CHANGE_ME") ||
		strings.HasPrefix(normalized, "REPLACE_WITH")
}
func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
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
	value := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if value == "" {
		return fallback
	}
	return value == "1" || value == "true" || value == "yes" || value == "on"
}

func loadDotEnv(path string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if key != "" && os.Getenv(key) == "" {
			_ = os.Setenv(key, value)
		}
	}
}
