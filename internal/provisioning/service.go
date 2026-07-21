package provisioning

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log"
	"strings"
	"time"

	"github.com/noblifi/noblifi/backend/internal/config"
	"github.com/noblifi/noblifi/backend/internal/portprofiles"
	"github.com/noblifi/noblifi/backend/internal/routers"
)

type RadiusRegistrar interface {
	RegisterNAS(nasName, shortName, secret, description string) error
}

type Service struct {
	repo   *routers.Repository
	cfg    config.Config
	radius RadiusRegistrar
}

func NewService(repo *routers.Repository, cfg config.Config, radius RadiusRegistrar) *Service {
	return &Service{repo: repo, cfg: cfg, radius: radius}
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
	return routers.RenderWireGuardRouterOS(router, s.cfg), nil
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
	return renderHotspotLoginPage(options.HotspotPortalName), nil
}

func (s *Service) ClaimConfig(token, serial string, sourceIP string) (string, error) {
	router, err := s.repo.FindByClaimToken(token)
	if err != nil {
		return "", errors.New("invalid claim token")
	}
	if router.ClaimTokenExpiresAt != nil && router.ClaimTokenExpiresAt.Before(time.Now()) && !canFetchConfigAfterClaimExpiry(router) {
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
		assignments = append(assignments, portprofiles.Assignment{InterfaceName: assignment.InterfaceName, Role: assignment.Role})
	}
	if len(assignments) == 0 {
		assignments = portprofiles.DefaultAssignments()
	}
	options := s.renderOptionsForRouter(router)
	options.LoginPageURL = hotspotLoginURL(token, s.cfg.ProvisioningBaseURL)
	if err := s.registerRadiusNAS(router, options, sourceIP); err != nil {
		log.Printf("provisioning: radius NAS registration failed for router %s from %q: %v", router.ID, sourceIP, err)
	}
	return portprofiles.RenderRouterOSWithOptions(assignments, options)
}

func (s *Service) registerRadiusNAS(router routers.Router, options portprofiles.RenderOptions, sourceIP string) error {
	if s.radius == nil {
		log.Printf("provisioning: radius NAS registration skipped for router %s: radius registrar is nil", router.ID)
		return nil
	}
	nasName := firstForwardedIP(sourceIP)
	if router.WireGuardTunnelIP != nil && strings.TrimSpace(*router.WireGuardTunnelIP) != "" {
		nasName = strings.TrimSpace(*router.WireGuardTunnelIP)
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
	ClaimToken string `json:"claim_token"`
	Token      string `json:"token"`
	PublicKey  string `json:"public_key"`
}

type WireGuardStatusInput struct {
	ClaimToken string `json:"claim_token"`
	Token      string `json:"token"`
	Status     string `json:"status"`
}

func (s *Service) WireGuardKey(input WireGuardKeyInput) error {
	token := strings.TrimSpace(input.ClaimToken)
	if token == "" {
		token = strings.TrimSpace(input.Token)
	}
	if token == "" {
		return errors.New("claim token is required")
	}
	if err := routers.ValidateWireGuardPublicKey(input.PublicKey); err != nil {
		return err
	}
	router, err := s.repo.FindByClaimToken(token)
	if err != nil {
		return errors.New("invalid claim token")
	}
	if router.WireGuardTunnelIP == nil || strings.TrimSpace(*router.WireGuardTunnelIP) == "" {
		return errors.New("WireGuard has not been prepared for this router")
	}
	if router.ClaimTokenExpiresAt != nil && router.ClaimTokenExpiresAt.Before(time.Now()) && !canFetchConfigAfterClaimExpiry(router) {
		return errors.New("claim token expired")
	}
	publicKey := strings.TrimSpace(input.PublicKey)
	now := time.Now()
	router.WireGuardPublicKey = &publicKey
	router.WireGuardStatus = "awaiting_vps_peer"
	router.WireGuardLastSeenAt = &now
	if err := s.repo.Save(&router); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{
		"public_key": publicKey,
		"tunnel_ip":  strings.TrimSpace(*router.WireGuardTunnelIP),
	})
	return s.repo.CreateConfigLog(&routers.RouterConfigLog{
		RouterID:        router.ID,
		Action:          "wireguard_key_reported",
		Status:          router.WireGuardStatus,
		ResponsePayload: payload,
	})
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
	if router.WireGuardTunnelIP == nil || router.WireGuardPublicKey == nil {
		return errors.New("WireGuard setup is incomplete for this router")
	}
	now := time.Now()
	router.WireGuardStatus = status
	router.WireGuardLastSeenAt = &now
	if status == "connected" {
		router.ManagementIP = router.WireGuardTunnelIP
	}
	if err := s.repo.Save(&router); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{
		"status":    status,
		"tunnel_ip": strings.TrimSpace(*router.WireGuardTunnelIP),
	})
	return s.repo.CreateConfigLog(&routers.RouterConfigLog{
		RouterID:        router.ID,
		Action:          "wireguard_status",
		Status:          status,
		ResponsePayload: payload,
	})
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
	if router.ClaimTokenExpiresAt != nil && router.ClaimTokenExpiresAt.Before(time.Now()) {
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
	fetchMode := provisioningFetchMode(baseURL)

	return fmt.Sprintf(`:global claimToken "%s"
:global baseUrl "%s"

/system identity set name=("noblifi-pending-" . $claimToken)

:global serial [/system routerboard get serial-number]
:global model [/system routerboard get model]
:global versionRaw [/system resource get version]
:global version $versionRaw
:global spacePos [:find $versionRaw " "]
:if ($spacePos != nil) do={ :set version [:pick $versionRaw 0 $spacePos] }

:put ("RAW VERSION: " . $versionRaw)
:put ("PARSED VERSION: " . $version)

:global checkInUrl ($baseUrl . "/check-in?token=" . $claimToken . "&serial=" . $serial . "&model=" . $model . "&routeros_version=" . $version)
:global statusUrl ($baseUrl . "/status?token=" . $claimToken . "&serial=" . $serial . "&status=linked")

:put ("NobliFi check-in URL: " . $checkInUrl)
:put ("NobliFi status URL: " . $statusUrl)

/tool fetch url=$checkInUrl mode=%s keep-result=no

:foreach iface in=[/interface find] do={
  :local name [/interface get $iface name]
  :local type [/interface get $iface type]
  :local mac ""
  :do { :set mac [/interface get $iface mac-address] } on-error={ :set mac "" }
  :local running [/interface get $iface running]
  :local disabled [/interface get $iface disabled]
  :local ifaceUrl ($baseUrl . "/interface?token=" . $claimToken . "&name=" . $name . "&type=" . $type . "&mac_address=" . $mac . "&running=" . $running . "&disabled=" . $disabled)
  :put ("NobliFi interface URL: " . $ifaceUrl)
  /tool fetch url=$ifaceUrl mode=%s keep-result=no
}

/tool fetch url=$statusUrl mode=%s keep-result=no

:put "NobliFi router linked. Return to the dashboard and choose automatic or manual setup."`, token, baseURL, fetchMode, fetchMode, fetchMode)
}

func hotspotLoginURL(token, baseURL string) string {
	return normalizeProvisioningBaseURL(baseURL) + "/hotspot-login/" + token
}

func renderHotspotLoginPage(portalName string) string {
	portalName = strings.TrimSpace(portalName)
	if portalName == "" {
		portalName = "NobliFi WiFi"
	}
	escapedPortalName := html.EscapeString(portalName)
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
  </main>
  <script>
    document.forms.login.addEventListener("submit", function () {
      this.password.value = this.username.value;
    });
  </script>
</body>
</html>`
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
