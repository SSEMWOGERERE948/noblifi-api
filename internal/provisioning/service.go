package provisioning

import (
	"crypto/sha256"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/config"
	"github.com/noblifi/noblifi/backend/internal/plans"
	"github.com/noblifi/noblifi/backend/internal/portprofiles"
	"github.com/noblifi/noblifi/backend/internal/routers"
	"github.com/noblifi/noblifi/backend/internal/wireguard"
)

//go:embed hotspot/*.html
var hotspotSupportFiles embed.FS

type RadiusRegistrar interface {
	RegisterNAS(nasName, shortName, secret, description string) error
}

type WireGuardPeerQueuer interface {
	QueuePeerUpsert(router routers.Router) (wireguard.WireGuardJob, error)
}

type WireGuardServerPublicKeyResolver interface {
	ActiveServerPublicKey() (string, error)
}

// RouterConfigureQueuer is implemented by the agent job service once it also
// supports the configure_router operation. Keeping it separate preserves
// compatibility with the existing upsert_peer implementation during rollout.
type RouterConfigureQueuer interface {
	QueueRouterConfigure(router routers.Router, configRevision string) (wireguard.WireGuardJob, error)
}

type PlanLister interface {
	ActiveList() ([]plans.Plan, error)
}

type Service struct {
	repo   *routers.Repository
	cfg    config.Config
	radius RadiusRegistrar
	plans  PlanLister
	wg     WireGuardPeerQueuer
}

func NewService(repo *routers.Repository, cfg config.Config, radius RadiusRegistrar, plans PlanLister, wg WireGuardPeerQueuer) *Service {
	return &Service{repo: repo, cfg: cfg, radius: radius, plans: plans, wg: wg}
}
func (s *Service) BootstrapScript(token string) (string, error) {
	router, err := s.repo.FindByClaimToken(token)
	if err != nil {
		return "", errors.New("invalid claim token")
	}
	if router.ClaimTokenExpiresAt != nil && router.ClaimTokenExpiresAt.Before(time.Now()) {
		return "", errors.New("claim token expired")
	}
	return renderBootstrapScript(token, s.cfg.ProvisioningBaseURL), nil
}

func (s *Service) InstallScript(token, sourceIP string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", errors.New("claim token is required")
	}

	// Consume the public installer URL once. The callback token remains usable
	// by the RouterOS script while provisioning is in progress.
	if _, err := s.repo.ConsumeClaimToken(token); err != nil {
		return "", err
	}

	router, err := s.repo.FindByClaimToken(token)
	if err != nil {
		return "", errors.New("invalid claim token")
	}

	now := time.Now().UTC()
	router.LastSeenAt = &now
	router.Status = "provisioning"
	if err := s.repo.Save(&router); err != nil {
		return "", err
	}

	options := s.renderOptionsForRouter(router)
	options.LoginPageURL = hotspotLoginURL(token, s.cfg.ProvisioningBaseURL)
	options.HotspotSupportBaseURL = hotspotSupportURL(token, s.cfg.ProvisioningBaseURL)
	options.ProvisioningBaseURL = normalizeProvisioningBaseURL(s.cfg.ProvisioningBaseURL)
	options.ProvisioningClaimToken = token
	s.applyWireGuardRenderOptions(&options, router)

	assignments := make([]portprofiles.Assignment, 0, len(router.PortAssignments))
	for _, assignment := range router.PortAssignments {
		assignments = append(assignments, portprofiles.Assignment{
			InterfaceName: assignment.InterfaceName,
			Role:          assignment.Role,
		})
	}
	if len(assignments) == 0 {
		assignments = portprofiles.DefaultAssignments()
	}

	managementScript, err := portprofiles.RenderManagementBootstrap(options)
	if err != nil {
		return "", err
	}
	managedScript, err := portprofiles.RenderManagedRouterConfig(assignments, options)
	if err != nil {
		return "", err
	}

	// sourceIP is intentionally not used for NAS registration here. FreeRADIUS
	// is registered with the unique tunnel IP after WireGuard reports connected.
	_ = sourceIP

	var builder strings.Builder
	builder.WriteString("# NobliFi MikroTik install\n")
	builder.WriteString("# The router establishes management first, then applies HotSpot, RADIUS, DHCP, NAT, and portal files.\n\n")
	builder.WriteString(`:put "NobliFi management bootstrap starting"`)
	builder.WriteString("\n\n")
	builder.WriteString(renderBootstrapScript(token, s.cfg.ProvisioningBaseURL))
	builder.WriteString("\n\n")
	builder.WriteString(managementScript)
	builder.WriteString("\n")
	builder.WriteString(managedScript)
	builder.WriteString("\n")
	builder.WriteString(renderStatusCommand(token, "installed", s.cfg.ProvisioningBaseURL))
	return builder.String(), nil
}

func (s *Service) WireGuardScript(token string) (string, error) {
	if err := routers.ValidateWireGuardConfig(s.cfg); err != nil {
		return "", err
	}
	router, err := s.repo.FindByClaimToken(token)
	if err != nil {
		return "", errors.New("invalid claim token")
	}
	if router.WireGuardTunnelIP == nil || strings.TrimSpace(*router.WireGuardTunnelIP) == "" {
		return "", errors.New("WireGuard has not been prepared for this router")
	}
	if router.ClaimTokenExpiresAt != nil && router.ClaimTokenExpiresAt.Before(time.Now()) && !canFetchConfigAfterClaimExpiry(router) {
		return "", errors.New("claim token expired")
	}
	cfg := s.cfg
	serverPublicKey, err := s.activeWireGuardServerPublicKey()
	if err != nil {
		return "", fmt.Errorf("resolve active WireGuard server public key: %w", err)
	}
	cfg.WireGuardPublicKey = serverPublicKey
	return routers.RenderWireGuardRouterOS(router, cfg), nil
}

func (s *Service) HotspotLoginPage(token string) (string, error) {
	router, err := s.repo.FindByClaimToken(token)
	if err != nil {
		return "", errors.New("invalid claim token")
	}
	if router.ClaimTokenExpiresAt != nil && router.ClaimTokenExpiresAt.Before(time.Now()) && !canFetchConfigAfterClaimExpiry(router) {
		return "", errors.New("claim token expired")
	}
	options := s.renderOptionsForRouter(router)
	planList := []plans.Plan{}
	if s.plans != nil {
		items, err := s.plans.ActiveList()
		if err != nil {
			log.Printf("provisioning: plan list unavailable for hotspot login page: %v", err)
		} else {
			planList = items
		}
	}
	return renderHotspotLoginPage(options.HotspotPortalName, planList), nil
}

func (s *Service) HotspotSupportFile(token, filename string) (string, error) {
	router, err := s.repo.FindByClaimToken(token)
	if err != nil {
		return "", errors.New("invalid claim token")
	}
	if router.ClaimTokenExpiresAt != nil && router.ClaimTokenExpiresAt.Before(time.Now()) && !canFetchConfigAfterClaimExpiry(router) {
		return "", errors.New("claim token expired")
	}
	switch filename {
	case "flogout.html", "fstatus.html", "rstatus.html":
	default:
		return "", errors.New("unsupported hotspot support file")
	}
	data, err := hotspotSupportFiles.ReadFile("hotspot/" + filename)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (s *Service) ClaimConfig(token, serial string, sourceIP string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", errors.New("claim token is required")
	}

	router, err := s.repo.FindByClaimToken(token)
	if err != nil {
		return "", errors.New("invalid claim token")
	}
	if router.ClaimTokenExpiresAt != nil &&
		router.ClaimTokenExpiresAt.Before(time.Now()) &&
		!canFetchConfigAfterClaimExpiry(router) {
		return "", errors.New("claim token expired")
	}
	if serial != "" {
		router.SerialNumber = &serial
	}

	now := time.Now()
	router.LastSeenAt = &now
	router.Status = "provisioning"
	if err := s.repo.Save(&router); err != nil {
		return "", err
	}

	assignments := make([]portprofiles.Assignment, 0, len(router.PortAssignments))
	for _, assignment := range router.PortAssignments {
		assignments = append(assignments, portprofiles.Assignment{
			InterfaceName: assignment.InterfaceName,
			Role:          assignment.Role,
		})
	}
	if len(assignments) == 0 {
		assignments = portprofiles.DefaultAssignments()
	}

	options := s.renderOptionsForRouter(router)
	options.LoginPageURL = hotspotLoginURL(token, s.cfg.ProvisioningBaseURL)
	options.HotspotSupportBaseURL = hotspotSupportURL(token, s.cfg.ProvisioningBaseURL)
	options.ProvisioningBaseURL = normalizeProvisioningBaseURL(s.cfg.ProvisioningBaseURL)
	options.ProvisioningClaimToken = token
	s.applyWireGuardRenderOptions(&options, router)

	if err := s.registerRadiusNAS(router, options, sourceIP); err != nil {
		log.Printf("provisioning: radius NAS registration failed for router %s from %q: %v", router.ID, sourceIP, err)
	}
	return portprofiles.RenderManagedRouterConfig(assignments, options)
}

// DesiredRouterConfig is returned only through an agent-authenticated internal
// endpoint. Never include this object in a public provisioning response or logs.
type DesiredRouterConfig struct {
	RouterID       string `json:"router_id"`
	ManagementIP   string `json:"management_ip"`
	ConfigRevision string `json:"config_revision"`
	APIUsername    string `json:"api_username"`
	APIPassword    string `json:"api_password"`
	APIPort        int    `json:"api_port"`
	APITLS         bool   `json:"api_tls"`
	RouterOSScript string `json:"routeros_script"`
}

// DesiredRouterConfigForRouter prepares the exact desired state that the xneelo
// agent applies after upsert_peer succeeds. The caller is responsible for
// resolving the router and authenticating the agent request.
func (s *Service) DesiredRouterConfigForRouter(router routers.Router, token string) (DesiredRouterConfig, error) {
	if router.WireGuardTunnelIP == nil || strings.TrimSpace(*router.WireGuardTunnelIP) == "" {
		return DesiredRouterConfig{}, errors.New("router management tunnel IP is missing")
	}

	assignments := make([]portprofiles.Assignment, 0, len(router.PortAssignments))
	for _, assignment := range router.PortAssignments {
		assignments = append(assignments, portprofiles.Assignment{
			InterfaceName: assignment.InterfaceName,
			Role:          assignment.Role,
		})
	}
	if len(assignments) == 0 {
		assignments = portprofiles.DefaultAssignments()
	}

	options := s.renderOptionsForRouter(router)
	options.LoginPageURL = hotspotLoginURL(token, s.cfg.ProvisioningBaseURL)
	options.HotspotSupportBaseURL = hotspotSupportURL(token, s.cfg.ProvisioningBaseURL)
	options.ProvisioningBaseURL = normalizeProvisioningBaseURL(s.cfg.ProvisioningBaseURL)
	options.ProvisioningClaimToken = strings.TrimSpace(token)
	s.applyWireGuardRenderOptions(&options, router)
	options.RadiusServer = options.WireGuardServerIP

	if err := s.registerRadiusNAS(router, options, ""); err != nil {
		return DesiredRouterConfig{}, fmt.Errorf("register FreeRADIUS NAS: %w", err)
	}

	script, err := portprofiles.RenderManagedRouterConfig(assignments, options)
	if err != nil {
		return DesiredRouterConfig{}, err
	}

	sum := sha256.Sum256([]byte(script))
	return DesiredRouterConfig{
		RouterID:       fmt.Sprint(router.ID),
		ManagementIP:   hostOnly(strings.TrimSpace(*router.WireGuardTunnelIP)),
		ConfigRevision: fmt.Sprintf("%x", sum[:]),
		APIUsername:    options.APIUsername,
		APIPassword:    options.APIPassword,
		// The bootstrap API connection runs inside WireGuard. Use RouterOS'
		// plain API here because api-ssl commonly rejects TLS until a
		// certificate is configured on the MikroTik.
		APIPort:        8728,
		APITLS:         false,
		RouterOSScript: script,
	}, nil
}

func (s *Service) DesiredRouterConfig(routerID string) (DesiredRouterConfig, error) {
	id, err := uuid.Parse(strings.TrimSpace(routerID))
	if err != nil {
		return DesiredRouterConfig{}, errors.New("invalid router id")
	}
	router, err := s.repo.Find(id)
	if err != nil {
		return DesiredRouterConfig{}, err
	}
	return s.DesiredRouterConfigForRouter(router, router.ClaimToken)
}

func (s *Service) queueRouterConfigure(router routers.Router, token string) error {
	queuer, ok := s.wg.(RouterConfigureQueuer)
	if !ok {
		return errors.New("WireGuard job service does not implement QueueRouterConfigure")
	}

	desired, err := s.DesiredRouterConfigForRouter(router, token)
	if err != nil {
		return err
	}
	if _, err := queuer.QueueRouterConfigure(router, desired.ConfigRevision); err != nil {
		return fmt.Errorf("queue configure_router job: %w", err)
	}
	return nil
}

func (s *Service) applyWireGuardRenderOptions(options *portprofiles.RenderOptions, router routers.Router) {
	if options == nil {
		return
	}

	enabled := shouldIncludeWireGuard(router, s.cfg)
	options.WireGuardEnabled = enabled
	options.WireGuardAgentManaged = enabled
	options.WireGuardHandshakeWaitSeconds = 120
	if !enabled {
		return
	}

	// These are deployment-level public values. Never place the VPS private key
	// or NOBLIFI_AGENT_TOKEN in generated RouterOS.
	options.WireGuardEndpoint = strings.TrimSpace(os.Getenv("NOBLIFI_WIREGUARD_ENDPOINT"))
	options.WireGuardPublicKey = strings.TrimSpace(s.cfg.WireGuardPublicKey)
	if serverPublicKey, err := s.activeWireGuardServerPublicKey(); err == nil {
		options.WireGuardPublicKey = serverPublicKey
	}
	options.WireGuardInterface = envOrDefault("NOBLIFI_ROUTER_WIREGUARD_INTERFACE", "noblifi-wg")
	options.WireGuardServerIP = envOrDefault("NOBLIFI_WIREGUARD_SERVER_IP", "10.77.0.1")
	options.WireGuardPort = envIntOrDefault("NOBLIFI_WIREGUARD_PORT", 51820)
	options.WireGuardKeepalive = envIntOrDefault("NOBLIFI_WIREGUARD_KEEPALIVE", 25)

	if router.WireGuardTunnelIP != nil {
		options.WireGuardClientIP = strings.TrimSpace(*router.WireGuardTunnelIP)
	}
}

func (s *Service) activeWireGuardServerPublicKey() (string, error) {
	resolver, ok := s.wg.(WireGuardServerPublicKeyResolver)
	if ok {
		return resolver.ActiveServerPublicKey()
	}
	if strings.TrimSpace(s.cfg.WireGuardPublicKey) != "" {
		return strings.TrimSpace(s.cfg.WireGuardPublicKey), nil
	}
	return "", errors.New("WireGuard server public key is unavailable")
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envIntOrDefault(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return fallback
	}
	return parsed
}

func (s *Service) registerRadiusNAS(router routers.Router, options portprofiles.RenderOptions, sourceIP string) error {
	if s.radius == nil {
		log.Printf("provisioning: radius NAS registration skipped for router %s: radius registrar is nil", router.ID)
		return nil
	}

	nasName := firstForwardedIP(sourceIP)
	if router.WireGuardTunnelIP != nil && strings.TrimSpace(*router.WireGuardTunnelIP) != "" {
		nasName = hostOnly(strings.TrimSpace(*router.WireGuardTunnelIP))
	}
	if nasName == "" {
		return nil
	}

	shortName := sanitizeNASName(options.RouterIdentity)
	if shortName == "" {
		shortName = sanitizeNASName(router.Name)
	}
	description := "NobliFi MikroTik router"
	if router.SerialNumber != nil && strings.TrimSpace(*router.SerialNumber) != "" {
		description += " serial=" + strings.TrimSpace(*router.SerialNumber)
	}
	return s.radius.RegisterNAS(nasName, shortName, options.RadiusSecret, description)
}

type WireGuardKeyInput struct {
	ClaimToken   string `json:"claim_token"`
	Token        string `json:"token"`
	SerialNumber string `json:"serial_number"`
	PublicKey    string `json:"public_key"`
}

type WireGuardStatusInput struct {
	ClaimToken string `json:"claim_token"`
	Token      string `json:"token"`
	Status     string `json:"status"`
}

type WireGuardKeyResponse struct {
	Status       string `json:"status"`
	ClientIP     string `json:"client_ip"`
	RadiusServer string `json:"radius_server"`
	LastError    string `json:"last_error"`
}

func (s *Service) WireGuardKey(input WireGuardKeyInput) (WireGuardKeyResponse, error) {
	token := strings.TrimSpace(input.ClaimToken)
	if token == "" {
		token = strings.TrimSpace(input.Token)
	}
	if token == "" {
		return WireGuardKeyResponse{}, errors.New("claim token is required")
	}

	publicKey := strings.TrimSpace(input.PublicKey)
	if err := routers.ValidateWireGuardPublicKey(publicKey); err != nil {
		return WireGuardKeyResponse{}, err
	}

	router, err := s.repo.FindByClaimToken(token)
	if err != nil {
		return WireGuardKeyResponse{}, errors.New("invalid claim token")
	}
	if router.ClaimTokenExpiresAt != nil &&
		router.ClaimTokenExpiresAt.Before(time.Now()) &&
		!canFetchConfigAfterClaimExpiry(router) {
		return WireGuardKeyResponse{}, errors.New("claim token expired")
	}
	if router.WireGuardTunnelIP == nil || strings.TrimSpace(*router.WireGuardTunnelIP) == "" {
		return WireGuardKeyResponse{}, errors.New("WireGuard has not been prepared for this router")
	}
	if s.wg == nil {
		return WireGuardKeyResponse{}, errors.New("WireGuard job service is unavailable")
	}

	now := time.Now().UTC()
	tunnelIP := strings.TrimSpace(*router.WireGuardTunnelIP)
	if strings.TrimSpace(input.SerialNumber) != "" {
		serial := strings.TrimSpace(input.SerialNumber)
		router.SerialNumber = &serial
	}
	router.WireGuardPublicKey = &publicKey
	router.WireGuardStatus = "awaiting_vps_peer"
	router.WireGuardPeerStatus = "peer_queued"
	router.WireGuardLastSeenAt = &now
	router.WireGuardPeerUpdatedAt = &now
	router.WireGuardLastError = nil
	router.ManagementIP = router.WireGuardTunnelIP
	if err := s.repo.Save(&router); err != nil {
		return WireGuardKeyResponse{}, err
	}

	// QueuePeerUpsert must be idempotent in the existing wire_guard_jobs table.
	// Re-reporting the same key/IP should reuse active work; changed desired state
	// should supersede stale pending work for this router.
	if _, err := s.wg.QueuePeerUpsert(router); err != nil {
		message := err.Error()
		router.WireGuardStatus = "failed"
		router.WireGuardPeerStatus = "failed"
		router.WireGuardLastError = &message
		_ = s.repo.Save(&router)
		return WireGuardKeyResponse{}, fmt.Errorf("queue WireGuard peer job: %w", err)
	}

	router.WireGuardStatus = "peer_queued"
	router.WireGuardPeerStatus = "peer_queued"
	if err := s.repo.Save(&router); err != nil {
		return WireGuardKeyResponse{}, err
	}

	payload, _ := json.Marshal(map[string]string{
		"public_key": publicKey,
		"tunnel_ip":  tunnelIP,
		"job_status": router.WireGuardPeerStatus,
	})
	if err := s.repo.CreateConfigLog(&routers.RouterConfigLog{
		RouterID:        router.ID,
		Action:          "wireguard_peer_queued",
		Status:          router.WireGuardStatus,
		ResponsePayload: payload,
	}); err != nil {
		return WireGuardKeyResponse{}, err
	}

	return WireGuardKeyResponse{
		Status:       router.WireGuardPeerStatus,
		ClientIP:     tunnelIP,
		RadiusServer: s.cfg.WireGuardServerIP,
	}, nil
}

func (s *Service) WireGuardStatus(input WireGuardStatusInput) error {
	token := strings.TrimSpace(input.ClaimToken)
	if token == "" {
		token = strings.TrimSpace(input.Token)
	}
	status := strings.ToLower(strings.TrimSpace(input.Status))
	if token == "" {
		return errors.New("claim token is required")
	}
	if status != "connected" && status != "failed" {
		return errors.New("WireGuard status must be connected or failed")
	}

	router, err := s.repo.FindByClaimToken(token)
	if err != nil {
		return errors.New("invalid claim token")
	}
	if router.ClaimTokenExpiresAt != nil &&
		router.ClaimTokenExpiresAt.Before(time.Now()) &&
		!canFetchConfigAfterClaimExpiry(router) {
		return errors.New("claim token expired")
	}
	if router.WireGuardTunnelIP == nil || router.WireGuardPublicKey == nil {
		return errors.New("WireGuard setup is incomplete for this router")
	}

	now := time.Now().UTC()
	previousPeerStatus := strings.TrimSpace(router.WireGuardPeerStatus)
	router.WireGuardStatus = status
	router.WireGuardPeerStatus = status
	router.WireGuardLastSeenAt = &now
	router.WireGuardPeerUpdatedAt = &now

	if status == "connected" {
		router.ManagementIP = router.WireGuardTunnelIP
		router.WireGuardLastError = nil
		router.WireGuardLastHandshakeAt = &now
		router.Status = "online"
		if err := s.repo.Save(&router); err != nil {
			return err
		}

		if previousPeerStatus == "peer_ready" || previousPeerStatus == "connected" {
			// Register the NAS with its unique tunnel IP, then queue the full router
			// configuration. This runs only after peer install and handshake are both true.
			if err := s.queueRouterConfigure(router, token); err != nil {
				message := err.Error()
				router.Status = "router_config_failed"
				router.WireGuardLastError = &message
				_ = s.repo.Save(&router)
				return err
			}

			router.Status = "router_config_queued"
			if err := s.repo.Save(&router); err != nil {
				return err
			}
		}
	} else {
		router.Status = "peer_failed"
		if err := s.repo.Save(&router); err != nil {
			return err
		}
	}

	payload, _ := json.Marshal(map[string]string{
		"status":        status,
		"tunnel_ip":     strings.TrimSpace(*router.WireGuardTunnelIP),
		"router_status": router.Status,
	})
	return s.repo.CreateConfigLog(&routers.RouterConfigLog{
		RouterID:        router.ID,
		Action:          "wireguard_status",
		Status:          router.Status,
		ResponsePayload: payload,
	})
}

func hostOnly(value string) string {
	value = strings.TrimSpace(value)
	if slash := strings.Index(value, "/"); slash >= 0 {
		return strings.TrimSpace(value[:slash])
	}
	return value
}

func firstForwardedIP(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parts := strings.Split(value, ",")
	return strings.TrimSpace(parts[0])
}

func sanitizeNASName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	for _, ch := range value {
		switch {
		case ch >= 'a' && ch <= 'z':
			builder.WriteRune(ch)
		case ch >= '0' && ch <= '9':
			builder.WriteRune(ch)
		case ch == '-' || ch == '_':
			builder.WriteRune(ch)
		case ch == ' ' || ch == '.':
			builder.WriteRune('-')
		}
	}
	return strings.Trim(builder.String(), "-")
}
func (s *Service) renderOptionsForRouter(router routers.Router) portprofiles.RenderOptions {
	if router.NetworkProfile != nil {
		profile := *router.NetworkProfile
		routers.NormalizeNetworkProfile(&profile, s.cfg)
		return profile.RenderOptions()
	}
	profile, err := s.repo.NetworkProfile(router.ID)
	if err == nil {
		routers.NormalizeNetworkProfile(&profile, s.cfg)
		return profile.RenderOptions()
	}
	return portprofiles.RenderOptions{
		RadiusServer:        s.cfg.RadiusServer,
		RadiusSecret:        s.cfg.RadiusSecret,
		RouterIdentity:      s.cfg.RouterIdentityPrefix + "-Router",
		APIUsername:         s.cfg.RouterAPIUsername,
		APIPassword:         s.cfg.RouterAPIPassword,
		HotspotBridge:       s.cfg.HotspotBridgeName,
		StaffBridge:         s.cfg.StaffBridgeName,
		POSBridge:           s.cfg.POSBridgeName,
		CCTVBridge:          s.cfg.CCTVBridgeName,
		HotspotSubnet:       s.cfg.HotspotSubnetCIDR,
		HotspotGateway:      s.cfg.HotspotGatewayCIDR,
		HotspotPool:         s.cfg.HotspotPoolRange,
		StaffSubnet:         s.cfg.StaffSubnetCIDR,
		StaffGateway:        s.cfg.StaffGatewayCIDR,
		StaffPool:           s.cfg.StaffPoolRange,
		POSSubnet:           s.cfg.POSSubnetCIDR,
		POSGateway:          s.cfg.POSGatewayCIDR,
		POSPool:             s.cfg.POSPoolRange,
		CCTVSubnet:          s.cfg.CCTVSubnetCIDR,
		CCTVGateway:         s.cfg.CCTVGatewayCIDR,
		CCTVPool:            s.cfg.CCTVPoolRange,
		HotspotDNSName:      s.cfg.HotspotDNSName,
		HotspotPortalName:   s.cfg.HotspotPortalName,
		WalledGardenHosts:   s.cfg.HotspotWalledGardenHosts,
		DisableWWWService:   s.cfg.DisableWWWService,
		EnableAPIService:    s.cfg.EnableAPIService,
		EnableAPISSLService: s.cfg.EnableAPISSLService,
	}
}

type InterfaceCheckIn struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	MacAddress string `json:"mac_address"`
	Running    bool   `json:"running"`
	Disabled   bool   `json:"disabled"`
}

type InterfaceCheckInInput struct {
	ClaimToken string `json:"claim_token"`
	Token      string `json:"token"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	MacAddress string `json:"mac_address"`
	Running    string `json:"running"`
	Disabled   string `json:"disabled"`
}
type CheckInInput struct {
	ClaimToken      string             `json:"claim_token"`
	Token           string             `json:"token"`
	SerialNumber    string             `json:"serial_number"`
	Serial          string             `json:"serial"`
	Model           string             `json:"model"`
	RouterOSVersion string             `json:"routeros_version"`
	Interfaces      []InterfaceCheckIn `json:"interfaces"`
}

func (s *Service) CheckIn(input CheckInInput) error {
	token := input.ClaimToken
	if token == "" {
		token = input.Token
	}
	serial := input.SerialNumber
	if serial == "" {
		serial = input.Serial
	}
	router, err := s.repo.FindByClaimToken(token)
	if err != nil {
		return errors.New("invalid claim token")
	}
	if serial != "" {
		router.SerialNumber = &serial
	}
	if input.Model != "" {
		router.Model = &input.Model
	}
	if input.RouterOSVersion != "" {
		router.RouterOSVersion = &input.RouterOSVersion
	}
	now := time.Now()
	router.LastSeenAt = &now
	router.Status = "online"
	if err := s.repo.Save(&router); err != nil {
		return err
	}
	if len(input.Interfaces) == 0 {
		return nil
	}
	interfaces := make([]routers.RouterInterface, 0, len(input.Interfaces))
	for _, item := range input.Interfaces {
		if item.Name == "" {
			continue
		}
		var kind *string
		if item.Type != "" {
			kind = &item.Type
		}
		var mac *string
		if item.MacAddress != "" {
			mac = &item.MacAddress
		}
		interfaces = append(interfaces, routers.RouterInterface{
			RouterID:     router.ID,
			Name:         item.Name,
			Type:         kind,
			MacAddress:   mac,
			Running:      item.Running,
			Disabled:     item.Disabled,
			DiscoveredAt: now,
		})
	}
	return s.repo.ReplaceInterfaces(router.ID, interfaces)
}

func (s *Service) InterfaceCheckIn(input InterfaceCheckInInput) error {
	token := input.ClaimToken
	if token == "" {
		token = input.Token
	}
	if strings.TrimSpace(input.Name) == "" {
		return errors.New("interface name is required")
	}
	router, err := s.repo.FindByClaimToken(token)
	if err != nil {
		return errors.New("invalid claim token")
	}
	if router.ClaimTokenExpiresAt != nil && router.ClaimTokenExpiresAt.Before(time.Now()) && !canFetchConfigAfterClaimExpiry(router) {
		return errors.New("claim token expired")
	}
	now := time.Now()
	router.LastSeenAt = &now
	if router.Status == "pending" {
		router.Status = "online"
	}
	if err := s.repo.Save(&router); err != nil {
		return err
	}
	var kind *string
	if input.Type != "" {
		kind = &input.Type
	}
	var mac *string
	if input.MacAddress != "" {
		mac = &input.MacAddress
	}
	iface := routers.RouterInterface{
		Name:         input.Name,
		Type:         kind,
		MacAddress:   mac,
		Running:      parseRouterOSBool(input.Running),
		Disabled:     parseRouterOSBool(input.Disabled),
		DiscoveredAt: now,
	}
	return s.repo.UpsertInterface(router.ID, iface)
}

func canFetchConfigAfterClaimExpiry(router routers.Router) bool {
	if router.LastSeenAt != nil || router.SerialNumber != nil {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(router.Status)) {
	case "linked", "online", "provisioning", "provisioned", "queued":
		return true
	default:
		return false
	}
}
func parseRouterOSBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
func (s *Service) Status(token, serial, status string) error {
	router, err := s.repo.FindByClaimToken(token)
	if err != nil {
		return errors.New("invalid claim token")
	}
	if serial != "" {
		router.SerialNumber = &serial
	}
	now := time.Now()
	router.LastSeenAt = &now
	if status != "" {
		switch status {
		case "installed":
			router.Status = "provisioned"
			router.ProvisionedAt = &now
		case "failed":
			router.Status = "failed"
		default:
			router.Status = status
		}
	}
	if err := s.repo.Save(&router); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{"serial": serial, "status": status})
	return s.repo.CreateConfigLog(&routers.RouterConfigLog{
		RouterID:        router.ID,
		Action:          "provisioning_status",
		Status:          router.Status,
		ResponsePayload: payload,
	})
}

func renderBootstrapScript(token, baseURL string) string {
	baseURL = normalizeProvisioningBaseURL(baseURL)

	// Send one JSON check-in containing all interfaces. This avoids the fragile
	// per-interface GET loop and its RouterOS 401/WWW-Authenticate failure mode.
	return fmt.Sprintf(`:global claimToken "%s"
:global baseUrl "%s"

/system identity set name=("noblifi-pending-" . $claimToken)

:local serial [/system routerboard get serial-number]
:local model [/system routerboard get model]
:local versionRaw [/system resource get version]
:local version $versionRaw
:local spacePos [:find $versionRaw " "]
:if ($spacePos != nil) do={ :set version [:pick $versionRaw 0 $spacePos] }

:put ("RAW VERSION: " . $versionRaw)
:put ("PARSED VERSION: " . $version)

:local ifaceJson ""
:foreach iface in=[/interface find] do={
  :local name [/interface get $iface name]
  :local type [/interface get $iface type]
  :local mac ""
  :do { :set mac [/interface get $iface mac-address] } on-error={ :set mac "" }
  :local running [/interface get $iface running]
  :local disabled [/interface get $iface disabled]
  :if ([:len $ifaceJson] > 0) do={ :set ifaceJson ($ifaceJson . ",") }
  :set ifaceJson ($ifaceJson . "{\"name\":\"" . $name . "\",\"type\":\"" . $type . "\",\"mac_address\":\"" . $mac . "\",\"running\":" . $running . ",\"disabled\":" . $disabled . "}")
}

:local payload ("{\"claim_token\":\"" . $claimToken . "\",\"serial_number\":\"" . $serial . "\",\"model\":\"" . $model . "\",\"routeros_version\":\"" . $version . "\",\"interfaces\":[" . $ifaceJson . "]}")
:local checkInURL ($baseUrl . "/check-in")
:local statusURL ($baseUrl . "/status?token=" . $claimToken . "&serial=" . $serial . "&status=linked")

:put ("NobliFi check-in URL: " . $checkInURL)
:local checkInResult [/tool fetch url=$checkInURL http-method=post http-header-field="Content-Type: application/json" http-data=$payload output=user as-value idle-timeout=30s duration=1m]
:if (($checkInResult->"status") != "finished") do={ :error "NobliFi router check-in failed" }

:do {
  /tool fetch url=$statusURL keep-result=no idle-timeout=30s duration=1m
} on-error={
  :put "NobliFi WARNING: failed to report linked status; continuing installation"
}

:put "NobliFi router linked; continuing complete installation"`, token, baseURL)
}

func shouldIncludeWireGuard(router routers.Router, cfg config.Config) bool {
	if router.WireGuardTunnelIP == nil || strings.TrimSpace(*router.WireGuardTunnelIP) == "" {
		return false
	}
	return routers.ValidateWireGuardConfig(cfg) == nil
}

func renderStatusCommand(token, status, baseURL string) string {
	baseURL = normalizeProvisioningBaseURL(baseURL)
	fetchMode := provisioningFetchMode(baseURL)
	statusURL := baseURL + "/status?token=" + token + "&status=" + status
	return fmt.Sprintf(
		`:do { /tool fetch url="%s" mode=%s keep-result=no } on-error={ :put "NobliFi WARNING: failed to report status %s; configuration remains installed" }`,
		statusURL,
		fetchMode,
		status,
	)
}

func hotspotLoginURL(token, baseURL string) string {
	return normalizeProvisioningBaseURL(baseURL) + "/hotspot-login/" + token
}

func hotspotSupportURL(token, baseURL string) string {
	return normalizeProvisioningBaseURL(baseURL) + "/hotspot-support/" + token
}

func renderHotspotLoginPage(portalName string, planList []plans.Plan) string {
	portalName = strings.TrimSpace(portalName)
	if portalName == "" {
		portalName = "NobliFi WiFi"
	}
	escapedPortalName := html.EscapeString(portalName)
	packageHTML := renderHotspotPackageList(planList)
	return `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>` + escapedPortalName + ` Login</title>
  <style>
    :root { color-scheme: dark; --bg: #06111f; --panel: #0b1727; --line: #24384f; --text: #f8fbff; --muted: #9fb0c5; --brand: #7dd3fc; --accent: #34d399; --danger: #fca5a5; }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: Arial, sans-serif; background: linear-gradient(145deg, #06111f 0%, #0b1727 52%, #102033 100%); color: var(--text); }
    main { min-height: 100vh; display: grid; place-items: center; padding: 24px 16px; }
    form { width: min(420px, 100%); border: 1px solid var(--line); background: rgba(11,23,39,.94); border-radius: 12px; padding: 26px; box-shadow: 0 18px 50px rgba(0,0,0,.32); }
    .mark { width: 48px; height: 48px; display: grid; place-items: center; margin: 0 auto 16px; border-radius: 10px; background: var(--brand); color: #06111f; font-weight: 900; letter-spacing: 0; }
    h1 { margin: 0 0 8px; text-align: center; font-size: 30px; line-height: 1.1; letter-spacing: 0; }
    p { margin: 0 0 22px; color: var(--muted); line-height: 1.5; text-align: center; }
    .packages { width: min(420px, 100%); margin-top: 14px; border: 1px solid var(--line); background: rgba(7,17,29,.86); border-radius: 12px; padding: 18px; }
    .packages h2 { margin: 0 0 12px; font-size: 16px; letter-spacing: 0; }
    .package-list { display: grid; gap: 10px; }
    .package { display: grid; grid-template-columns: 1fr auto; gap: 8px; align-items: center; border: 1px solid var(--line); border-radius: 9px; padding: 12px; background: #07111d; }
    .package strong { display: block; font-size: 15px; }
    .package span { color: var(--muted); font-size: 13px; }
    .price { font-weight: 900; color: var(--accent); white-space: nowrap; }
    label { display: block; margin-bottom: 8px; font-weight: 700; }
    input { width: 100%; border: 1px solid var(--line); background: #07111d; color: var(--text); border-radius: 9px; padding: 13px; font-size: 16px; }
    button { width: 100%; margin-top: 16px; border: 0; border-radius: 9px; padding: 13px; background: var(--brand); color: #06111f; font-weight: 800; font-size: 16px; }
    .hint { margin: 14px 0 0; font-size: 13px; }
    .error { margin-top: 14px; color: var(--danger); font-size: 14px; min-height: 18px; }
    @media (max-width: 420px) { form { padding: 22px; } h1 { font-size: 26px; } }
  </style>
</head>
<body>
  <main>
    <form name="login" action="$(link-login-only)" method="post">
      <input type="hidden" name="dst" value="$(link-orig)">
      <input type="hidden" name="popup" value="true">
      <div class="mark">NF</div>
      <h1>` + escapedPortalName + `</h1>
      <p>Enter your voucher code to connect.</p>
      <label for="username">Voucher code</label>
      <input id="username" name="username" autocomplete="one-time-code" placeholder="NF-XXXXXXXX" autofocus>
      <input id="password" name="password" type="hidden">
      <button type="submit">Connect</button>
      <p class="hint">Your voucher code is used for both username and password.</p>
      <div class="error">$(if error)$(error)$(endif)</div>
    </form>
    ` + packageHTML + `
  </main>
  <script>
    document.forms.login.addEventListener("submit", function () {
      this.password.value = this.username.value;
    });
  </script>
</body>
</html>`
}

func renderHotspotPackageList(planList []plans.Plan) string {
	if len(planList) == 0 {
		return ""
	}
	var builder strings.Builder
	builder.WriteString(`<section class="packages" aria-label="Packages"><h2>Packages</h2><div class="package-list">`)
	for _, plan := range planList {
		if !plan.IsActive {
			continue
		}
		builder.WriteString(`<div class="package"><div><strong>`)
		builder.WriteString(html.EscapeString(plan.Name))
		builder.WriteString(`</strong><span>`)
		builder.WriteString(html.EscapeString(planDuration(plan.DurationMinutes)))
		if plan.DownloadSpeed != "" {
			builder.WriteString(` - Down `)
			builder.WriteString(html.EscapeString(plan.DownloadSpeed))
		}
		builder.WriteString(`</span></div><div class="price">UGX `)
		builder.WriteString(formatUGX(plan.Price))
		builder.WriteString(`</div></div>`)
	}
	builder.WriteString(`</div></section>`)
	return builder.String()
}

func planDuration(minutes int) string {
	if minutes <= 0 {
		return "Time limited"
	}
	if minutes%1440 == 0 {
		days := minutes / 1440
		if days == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", days)
	}
	if minutes%60 == 0 {
		hours := minutes / 60
		if hours == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", hours)
	}
	return fmt.Sprintf("%d minutes", minutes)
}

func formatUGX(amount int) string {
	raw := fmt.Sprintf("%d", amount)
	if len(raw) <= 3 {
		return raw
	}
	first := len(raw) % 3
	if first == 0 {
		first = 3
	}
	var builder strings.Builder
	builder.WriteString(raw[:first])
	for i := first; i < len(raw); i += 3 {
		builder.WriteString(",")
		builder.WriteString(raw[i : i+3])
	}
	return builder.String()
}

func normalizeProvisioningBaseURL(baseURL string) string {
	baseURL = strings.TrimSpace(baseURL)
	baseURL = strings.TrimRight(baseURL, "/")
	if baseURL == "" {
		return "http://localhost:8080/api/v1/provisioning"
	}
	lower := strings.ToLower(baseURL)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return "https://" + baseURL
	}
	return baseURL
}

func provisioningFetchMode(baseURL string) string {
	if strings.HasPrefix(strings.ToLower(baseURL), "https://") {
		return "https"
	}
	return "http"
}
