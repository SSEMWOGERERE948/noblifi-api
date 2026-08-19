package provisioning

import (
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/noblifi/noblifi/backend/internal/config"
	"github.com/noblifi/noblifi/backend/internal/portprofiles"
	"github.com/noblifi/noblifi/backend/internal/routers"
	"github.com/noblifi/noblifi/backend/internal/wireguard"
)

type RadiusRegistrar interface {
	RegisterNAS(nasName, shortName, secret, description string) error
}

// VoucherDeviceAuthorizer is intentionally separate from RadiusRegistrar.
//
// Keeping this interface separate means NewService keeps its existing
// four-argument constructor while the concrete *radius.Service can expose the
// same-device voucher authorization behavior.
//
// The concrete RADIUS service should implement:
//
//	AuthorizeVoucherForDevice(code, deviceMAC string) (bool, error)
type VoucherDeviceAuthorizer interface {
	AuthorizeVoucherForDevice(code, deviceMAC string) (bool, error)
}

// VoucherAutoConnector resolves an already-active voucher bound to a client MAC.
type VoucherAutoConnector interface {
	ValidVoucherForDevice(deviceMAC string) (string, bool, error)
}

type WireGuardJobQueuer interface {
	QueuePeerUpsert(router routers.Router) (wireguard.WireGuardJob, error)
	QueueRouterConfigure(router routers.Router, configRevision string) (wireguard.WireGuardJob, error)
	ActiveServerPublicKey() (string, error)
}

type Service struct {
	repo   *routers.Repository
	cfg    config.Config
	radius RadiusRegistrar
	wg     WireGuardJobQueuer

	plans           TenantPlanLister
	hotspotPayments HotspotPaymentService
}

func NewService(repo *routers.Repository, cfg config.Config, radius RadiusRegistrar, wg WireGuardJobQueuer) *Service {
	return &Service{repo: repo, cfg: cfg, radius: radius, wg: wg}
}
func (s *Service) BootstrapScript(token string) (string, error) {
	router, err := s.repo.FindByClaimToken(token)
	if err != nil {
		return "", errors.New("invalid claim token")
	}
	if router.ClaimTokenExpiresAt != nil && router.ClaimTokenExpiresAt.Before(time.Now()) && !canFetchConfigAfterClaimExpiry(router) {
		return "", errors.New("claim token expired")
	}
	return renderBootstrapScript(token, s.cfg.ProvisioningBaseURL), nil
}

func (s *Service) HotspotLoginPage(token string) (string, error) {
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

	options := s.renderOptionsForRouter(router)

	authURL := hotspotAuthorizeURL(
		token,
		s.cfg.ProvisioningBaseURL,
	)

	autoURL := hotspotAutoConnectURL(
		token,
		s.cfg.ProvisioningBaseURL,
	)

	return renderHotspotLoginPageWithAutoConnect(
		options.HotspotPortalName,
		authURL,
		autoURL,
	), nil
}

type HotspotAuthenticateInput struct {
	VoucherCode string
	MAC         string
	LinkLogin   string
	LinkOrig    string
}

// HotspotAuthenticate prepares a voucher BEFORE MikroTik sends the RADIUS
// Access-Request.
//
// The browser sends:
//   - voucher_code
//   - $(mac)
//   - $(link-login-only)
//   - $(link-orig)
//
// NobliFi then:
//  1. validates/binds the voucher to the first device MAC;
//  2. synchronizes FreeRADIUS through AuthorizeVoucherForDevice;
//  3. returns a hidden auto-submit form to the MikroTik login servlet.
//
// This is what allows a valid voucher to reconnect from the SAME device after
// manual logout while rejecting use from a different device.
type HotspotAutoConnectInput struct {
	MAC       string
	LinkLogin string
	LinkOrig  string
}

// HotspotAutoConnect automatically reuses a still-valid voucher that is
// already bound to this device MAC. If no reusable voucher exists, the normal
// voucher-entry form is returned.
func (s *Service) HotspotAutoConnect(token string, input HotspotAutoConnectInput) (string, error) {
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

	options := s.renderOptionsForRouter(router)
	portalName := strings.TrimSpace(options.HotspotPortalName)
	if portalName == "" {
		portalName = "NobliFi WiFi"
	}

	authURL := hotspotAuthorizeURL(token, s.cfg.ProvisioningBaseURL)
	deviceMAC := strings.TrimSpace(input.MAC)

	manual := func(message string) (string, error) {
		return s.renderHotspotManualCommercePage(
			router, token, portalName, authURL, deviceMAC,
			input.LinkLogin, input.LinkOrig, message,
		)
	}

	if deviceMAC == "" || s.radius == nil {
		return manual("")
	}

	autoConnector, ok := s.radius.(VoucherAutoConnector)
	if !ok {
		return manual("")
	}

	voucherCode, found, err := autoConnector.ValidVoucherForDevice(deviceMAC)
	if err != nil {
		log.Printf("provisioning: hotspot auto-connect lookup failed token=%q mac=%q: %v", token, deviceMAC, err)
		return manual("Automatic reconnect is temporarily unavailable. Enter your voucher code.")
	}
	if !found || strings.TrimSpace(voucherCode) == "" {
		return manual("")
	}

	linkLogin, err := validateHotspotReturnURL(
		input.LinkLogin,
		options.HotspotDNSName,
		options.HotspotGateway,
	)
	if err != nil {
		return "", err
	}

	return renderHotspotAutoLoginPage(
		portalName,
		linkLogin,
		input.LinkOrig,
		strings.ToUpper(strings.TrimSpace(voucherCode)),
	), nil
}

func (s *Service) HotspotAuthenticate(
	token string,
	input HotspotAuthenticateInput,
) (string, error) {
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

	if s.radius == nil {
		return "", errors.New("RADIUS voucher authorization is unavailable")
	}

	authorizer, ok := s.radius.(VoucherDeviceAuthorizer)
	if !ok {
		return "", errors.New(
			"RADIUS service does not implement same-device voucher authorization",
		)
	}

	options := s.renderOptionsForRouter(router)

	portalName := strings.TrimSpace(options.HotspotPortalName)
	if portalName == "" {
		portalName = "NobliFi WiFi"
	}

	voucherCode := strings.ToUpper(
		strings.TrimSpace(input.VoucherCode),
	)

	deviceMAC := strings.TrimSpace(input.MAC)

	if voucherCode == "" {
		return renderHotspotExternalAuthError(
			portalName,
			input.LinkLogin,
			"Enter a valid voucher code.",
		), nil
	}

	if deviceMAC == "" {
		return renderHotspotExternalAuthError(
			portalName,
			input.LinkLogin,
			"Could not identify this device. Reconnect to the WiFi and try again.",
		), nil
	}

	allowed, err := authorizer.AuthorizeVoucherForDevice(
		voucherCode,
		deviceMAC,
	)
	if err != nil {
		log.Printf(
			"provisioning: voucher authorization failed token=%q voucher=%q mac=%q: %v",
			token,
			voucherCode,
			deviceMAC,
			err,
		)

		return renderHotspotExternalAuthError(
			portalName,
			input.LinkLogin,
			"Could not validate this voucher. Please try again.",
		), nil
	}

	if !allowed {
		return renderHotspotExternalAuthError(
			portalName,
			input.LinkLogin,
			"This voucher is invalid, expired, or already assigned to another device.",
		), nil
	}

	linkLogin, err := validateHotspotReturnURL(
		input.LinkLogin,
		options.HotspotDNSName,
		options.HotspotGateway,
	)
	if err != nil {
		return "", err
	}

	return renderHotspotAutoLoginPage(
		portalName,
		linkLogin,
		input.LinkOrig,
		voucherCode,
	), nil
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

func (s *Service) WireGuardScript(token string) (string, error) {
	router, err := s.repo.FindByClaimToken(token)
	if err != nil {
		return "", errors.New("invalid claim token")
	}
	if router.ClaimTokenExpiresAt != nil && router.ClaimTokenExpiresAt.Before(time.Now()) && !canFetchConfigAfterClaimExpiry(router) {
		return "", errors.New("claim token expired")
	}
	cfg := s.cfg
	if s.wg != nil {
		publicKey, err := s.wg.ActiveServerPublicKey()
		if err != nil {
			return "", fmt.Errorf("resolve active WireGuard server public key: %w", err)
		}
		cfg.WireGuardPublicKey = publicKey
	}
	if err := routers.ValidateWireGuardConfig(cfg); err != nil {
		return "", err
	}
	if !routers.RouterSupportsWireGuard(router.RouterOSVersion) {
		return "", errors.New("WireGuard requires RouterOS 7")
	}
	if router.WireGuardTunnelIP == nil || strings.TrimSpace(*router.WireGuardTunnelIP) == "" {
		address, err := routers.AllocateWireGuardIP(s.repo, cfg)
		if err != nil {
			return "", fmt.Errorf("allocate WireGuard tunnel IP: %w", err)
		}
		router.WireGuardTunnelIP = &address
		router.ManagementIP = &address
		router.WireGuardStatus = "wireguard_configuring"
		router.WireGuardPeerStatus = "waiting_for_router_key"
		if err := s.repo.Save(&router); err != nil {
			return "", err
		}
	}
	return routers.RenderWireGuardRouterOS(router, cfg), nil
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
		return errors.New("invalid claim token")
	}
	if strings.TrimSpace(input.PublicKey) == "" {
		return errors.New("invalid public key")
	}
	if err := routers.ValidateWireGuardPublicKey(input.PublicKey); err != nil {
		return err
	}
	router, err := s.repo.FindByClaimToken(token)
	if err != nil {
		return errors.New("invalid claim token")
	}
	key := strings.TrimSpace(input.PublicKey)
	router.WireGuardPublicKey = &key
	router.WireGuardStatus = "awaiting_vps_peer"
	router.WireGuardPeerStatus = "peer_queued"
	now := time.Now().UTC()
	router.LastSeenAt = &now
	router.WireGuardPeerUpdatedAt = &now
	router.WireGuardLastError = nil
	router.ManagementIP = router.WireGuardTunnelIP
	if err := s.repo.Save(&router); err != nil {
		return err
	}
	if s.wg == nil {
		return errors.New("WireGuard job service is unavailable")
	}
	if _, err := s.wg.QueuePeerUpsert(router); err != nil {
		return fmt.Errorf("queue xneelo WireGuard peer installation: %w", err)
	}
	return nil
}

func (s *Service) WireGuardStatus(input WireGuardStatusInput) error {
	token := strings.TrimSpace(input.ClaimToken)
	if token == "" {
		token = strings.TrimSpace(input.Token)
	}
	if token == "" {
		return errors.New("invalid claim token")
	}
	status := strings.ToLower(strings.TrimSpace(input.Status))
	if status == "" {
		return errors.New("status required")
	}
	if status != "connected" && status != "failed" {
		return errors.New("invalid WireGuard status")
	}
	router, err := s.repo.FindByClaimToken(token)
	if err != nil {
		return errors.New("invalid claim token")
	}
	router.WireGuardStatus = status
	router.WireGuardPeerStatus = status
	now := time.Now().UTC()
	router.LastSeenAt = &now
	router.WireGuardPeerUpdatedAt = &now
	if status == "connected" {
		router.WireGuardLastHandshakeAt = &now
		router.Status = "online"
	}
	if err := s.repo.Save(&router); err != nil {
		return err
	}
	if status == "connected" && s.wg != nil {
		if _, err := s.wg.QueueRouterConfigure(router, ""); err != nil {
			return fmt.Errorf("queue router configuration: %w", err)
		}
	}
	return nil
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
	if router.ClaimTokenExpiresAt != nil && router.ClaimTokenExpiresAt.Before(time.Now()) && !canFetchConfigAfterClaimExpiry(router) {
		return errors.New("claim token expired")
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

:local checkInPayload ("{\"claim_token\":\"" . $claimToken . "\",\"serial_number\":\"" . $serial . "\",\"model\":\"" . $model . "\",\"routeros_version\":\"" . $version . "\",\"interfaces\":[" . $ifaceJson . "]}")
:local checkInUrl ($baseUrl . "/check-in")
:local statusUrl ($baseUrl . "/status?token=" . $claimToken . "&serial=" . $serial . "&status=linked")
:local wireGuardUrl ($baseUrl . "/wireguard/" . $claimToken)
:put ("NobliFi check-in URL: " . $checkInUrl)
:put ("NobliFi status URL: " . $statusUrl)
:local checkInResult [/tool fetch url=$checkInUrl mode=%s http-method=post http-header-field="Content-Type: application/json" http-data=$checkInPayload output=user as-value idle-timeout=30s duration=1m]
:if (($checkInResult->"status") != "finished") do={ :error "NobliFi router check-in failed" }

:local dotPos [:find $version "."]
:local majorVersion $version
:if ($dotPos != nil) do={ :set majorVersion [:pick $version 0 $dotPos] }

:if ($majorVersion = "7") do={
  :put ("NobliFi WireGuard URL: " . $wireGuardUrl)
  /tool fetch url=$wireGuardUrl mode=%s dst-path="noblifi-wireguard.rsc" idle-timeout=30s duration=1m
  :delay 2s
  /import file-name="noblifi-wireguard.rsc"
  :delay 1s
  :do { /file remove "noblifi-wireguard.rsc" } on-error={ :put "NobliFi WARNING: could not remove WireGuard installer file" }
} else={
  :put ("NobliFi WireGuard skipped because RouterOS major version is " . $majorVersion)
}

/tool fetch url=$statusUrl mode=%s keep-result=no

:put "NobliFi router linked. Return to the dashboard and choose automatic or manual setup."`, token, baseURL, fetchMode, fetchMode, fetchMode)
}

func hotspotLoginURL(token, baseURL string) string {
	return normalizeProvisioningBaseURL(baseURL) + "/hotspot-login/" + token
}

func hotspotAuthorizeURL(token, baseURL string) string {
	return normalizeProvisioningBaseURL(baseURL) + "/hotspot-auth/" + token
}

func hotspotAutoConnectURL(token, baseURL string) string {
	return normalizeProvisioningBaseURL(baseURL) + "/hotspot-auto/" + token
}

// renderHotspotLoginPageWithAuth is the production captive-portal renderer.
//
// The original one-argument renderHotspotLoginPage remains below for
// compatibility with existing tests. Runtime provisioning uses this function.
// renderHotspotLoginPageWithAutoConnect is the RouterOS-served entry page.
// It immediately asks NobliFi whether this MAC already owns a valid voucher.
func renderHotspotLoginPageWithAutoConnect(portalName, authURL, autoURL string) string {
	portalName = strings.TrimSpace(portalName)
	if portalName == "" {
		portalName = "NobliFi WiFi"
	}

	// authURL is intentionally kept in the signature for compatibility with the
	// existing renderer call. The RouterOS entry page only needs autoURL here.
	_ = authURL

	return `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#06111f">
  <title>` + html.EscapeString(portalName) + ` Login</title>
  <style>
    :root{color-scheme:dark;--bg:#06111f;--panel:#0b1727;--line:#24384f;--text:#f8fbff;--muted:#9fb0c5;--brand:#7dd3fc;--accent:#34d399}
    *{box-sizing:border-box}body{margin:0;font-family:Arial,Helvetica,sans-serif;background:linear-gradient(145deg,#06111f 0%,#0b1727 52%,#102033 100%);color:var(--text)}
    main{min-height:100vh;display:grid;place-items:center;padding:24px 16px}.card{width:min(420px,100%);border:1px solid var(--line);background:rgba(11,23,39,.94);border-radius:12px;padding:26px;text-align:center;box-shadow:0 18px 50px rgba(0,0,0,.32)}
    .mark{width:48px;height:48px;display:grid;place-items:center;margin:0 auto 16px;border-radius:10px;background:var(--brand);color:#06111f;font-weight:900}.eyebrow{margin:0 0 7px;color:var(--brand);font-size:11px;font-weight:800;letter-spacing:.16em;text-transform:uppercase}h1{margin:0;font-size:30px}p{color:var(--muted);line-height:1.5}
    .pulse{width:42px;height:42px;margin:22px auto 0;border-radius:50%;border:4px solid rgba(52,211,153,.2);border-top-color:var(--accent);animation:spin .8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}
  </style>
</head>
<body>
<main><section class="card">
  <div class="mark">NF</div>
  <p class="eyebrow">WiFi Access</p>
  <h1>` + html.EscapeString(portalName) + `</h1>
  <p id="noblifi-status">Checking whether this device already has valid access…</p>
  <div class="pulse" aria-hidden="true"></div>

  <!--
    This form goes from the LOCAL HTTP HotSpot page to NobliFi HTTPS.
    That direction is safe and does not trigger Chrome's insecure-form warning.
  -->
  <form id="noblifi-auto-connect" action="` + html.EscapeString(strings.TrimSpace(autoURL)) + `" method="post">
    <input type="hidden" name="mac" value="$(mac)">
    <input type="hidden" name="link_login" value="$(link-login-only)">
    <input type="hidden" name="link_orig" value="$(link-orig)">
    <noscript><button type="submit">Continue</button></noscript>
  </form>

  <!--
    The external HTTPS backend NEVER posts directly back to this HTTP endpoint.
    Instead it navigates back here using a URL fragment. The fragment is not
    sent to the router. This local page then performs the final same-origin
    HTTP POST to the MikroTik HotSpot login servlet.
  -->
  <form id="noblifi-router-login" action="$(link-login-only)" method="post" style="display:none">
    <input id="noblifi-router-username" type="hidden" name="username" value="">
    <input id="noblifi-router-password" type="hidden" name="password" value="">
    <input id="noblifi-router-dst" type="hidden" name="dst" value="$(link-orig)">
    <input type="hidden" name="popup" value="true">
  </form>
</section></main>

<script>
(function () {
  var alreadySubmitting = false;

  function localRouterLoginFromFragment() {
    var raw = window.location.hash ? window.location.hash.substring(1) : "";
    if (!raw) return false;

    var params;
    try {
      params = new URLSearchParams(raw);
    } catch (_) {
      return false;
    }

    if (params.get("noblifi") !== "1") return false;

    var voucher = (params.get("voucher") || "").trim().toUpperCase();
    if (!voucher) return false;

    var dst = params.get("dst") || "$(link-orig)";

    // Clear the credential-bearing fragment BEFORE submitting. Fragments are
    // not sent to the HTTP server, and clearing it prevents refresh/back from
    // submitting the same bridge request repeatedly.
    try {
      window.history.replaceState(
        null,
        "",
        window.location.pathname + window.location.search
      );
    } catch (_) {}

    document.getElementById("noblifi-status").textContent =
      "Access approved. Connecting…";

    document.getElementById("noblifi-router-username").value = voucher;
    document.getElementById("noblifi-router-password").value = voucher;
    document.getElementById("noblifi-router-dst").value = dst;

    if (alreadySubmitting) return true;
    alreadySubmitting = true;

    window.setTimeout(function () {
      document.getElementById("noblifi-router-login").submit();
    }, 40);

    return true;
  }

  if (localRouterLoginFromFragment()) {
    return;
  }

  // Throttle rapid reloads so one browser cannot create a burst of identical
  // voucher lookup requests. This does not disable reconnect; it only spaces
  // repeated requests by roughly 1.5 seconds.
  var delay = 120;
  var storageKey = "noblifi-auto-last:$(mac)";

  try {
    var now = Date.now();
    var last = parseInt(window.sessionStorage.getItem(storageKey) || "0", 10);
    var remaining = 1500 - (now - last);
    if (remaining > delay) delay = remaining;
  } catch (_) {}

  window.setTimeout(function () {
    var form = document.getElementById("noblifi-auto-connect");
    if (!form || form.dataset.sent === "1") return;

    form.dataset.sent = "1";

    try {
      window.sessionStorage.setItem(storageKey, String(Date.now()));
    } catch (_) {}

    form.submit();
  }, delay);
})();
</script>
</body>
</html>`
}

// renderHotspotManualLoginPage is returned when no active bound voucher can be reused.
func renderHotspotManualLoginPage(portalName, authURL, deviceMAC, linkLogin, linkOrig, message string) string {
	portalName = strings.TrimSpace(portalName)
	if portalName == "" {
		portalName = "NobliFi WiFi"
	}
	notice := ""
	if strings.TrimSpace(message) != "" {
		notice = `<div class="notice">` + html.EscapeString(strings.TrimSpace(message)) + `</div>`
	}
	return `<!doctype html>
<html>
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="theme-color" content="#06111f">
  <title>` + html.EscapeString(portalName) + ` Login</title>
  <style>
    :root{color-scheme:dark;--bg:#06111f;--panel:#0b1727;--line:#24384f;--text:#f8fbff;--muted:#9fb0c5;--brand:#7dd3fc;--warning:#fcd34d}*{box-sizing:border-box}
    body{margin:0;font-family:Arial,Helvetica,sans-serif;background:linear-gradient(145deg,#06111f 0%,#0b1727 52%,#102033 100%);color:var(--text)}main{min-height:100vh;display:grid;place-items:center;padding:24px 16px}
    form{width:min(420px,100%);border:1px solid var(--line);background:rgba(11,23,39,.94);border-radius:12px;padding:26px;box-shadow:0 18px 50px rgba(0,0,0,.32)}.mark{width:48px;height:48px;display:grid;place-items:center;margin:0 auto 16px;border-radius:10px;background:var(--brand);color:#06111f;font-weight:900}h1{margin:0 0 8px;text-align:center;font-size:30px}p{color:var(--muted);text-align:center;line-height:1.5}label{display:block;margin:22px 0 8px;font-weight:700}input{width:100%;border:1px solid var(--line);background:#07111d;color:var(--text);border-radius:9px;padding:13px;font-size:16px}button{width:100%;margin-top:16px;border:0;border-radius:9px;padding:13px;background:var(--brand);color:#06111f;font-weight:800;font-size:16px}.notice{margin:16px 0;padding:12px 14px;border:1px solid rgba(252,211,77,.28);background:rgba(252,211,77,.08);border-radius:10px;color:#fde68a;font-size:13px;line-height:1.45}.hint{margin:14px 0 0;font-size:13px}
  </style>
</head>
<body><main>
<form action="` + html.EscapeString(strings.TrimSpace(authURL)) + `" method="post">
  <input type="hidden" name="mac" value="` + html.EscapeString(strings.TrimSpace(deviceMAC)) + `">
  <input type="hidden" name="link_login" value="` + html.EscapeString(strings.TrimSpace(linkLogin)) + `">
  <input type="hidden" name="link_orig" value="` + html.EscapeString(strings.TrimSpace(linkOrig)) + `">
  <div class="mark">NF</div><h1>` + html.EscapeString(portalName) + `</h1>
  <p>No reusable voucher was found for this device. Enter a voucher code to connect.</p>` + notice + `
  <label for="voucher_code">Voucher code</label>
  <input id="voucher_code" name="voucher_code" autocomplete="one-time-code" placeholder="NF-XXXXXXXX" autofocus required>
  <button type="submit">Connect</button>
  <p class="hint">Once activated, this voucher stays assigned to this device until it expires.</p>
</form></main></body></html>`
}

func renderHotspotLoginPageWithAuth(
	portalName string,
	authURL string,
) string {
	portalName = strings.TrimSpace(portalName)
	if portalName == "" {
		portalName = "NobliFi WiFi"
	}

	escapedPortalName := html.EscapeString(portalName)
	escapedAuthURL := html.EscapeString(strings.TrimSpace(authURL))

	return `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#06111f">
  <title>` + escapedPortalName + ` Login</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #06111f;
      --panel: #0b1727;
      --line: #24384f;
      --text: #f8fbff;
      --muted: #9fb0c5;
      --brand: #7dd3fc;
      --accent: #34d399;
      --danger: #fca5a5;
    }

    * {
      box-sizing: border-box;
    }

    html,
    body {
      min-height: 100%;
    }

    body {
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      background: linear-gradient(
        145deg,
        #06111f 0%,
        #0b1727 52%,
        #102033 100%
      );
      color: var(--text);
    }

    main {
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 24px 16px;
    }

    form {
      width: min(420px, 100%);
      border: 1px solid var(--line);
      background: rgba(11, 23, 39, .94);
      border-radius: 12px;
      padding: 26px;
      box-shadow: 0 18px 50px rgba(0, 0, 0, .32);
    }

    .mark {
      width: 48px;
      height: 48px;
      display: grid;
      place-items: center;
      margin: 0 auto 16px;
      border-radius: 10px;
      background: var(--brand);
      color: #06111f;
      font-weight: 900;
      letter-spacing: 0;
    }

    .eyebrow {
      margin: 0 0 7px;
      text-align: center;
      color: var(--brand);
      font-size: 11px;
      font-weight: 800;
      letter-spacing: .16em;
      text-transform: uppercase;
    }

    h1 {
      margin: 0 0 8px;
      text-align: center;
      font-size: 30px;
      line-height: 1.1;
      letter-spacing: 0;
    }

    p {
      margin: 0 0 22px;
      color: var(--muted);
      line-height: 1.5;
      text-align: center;
    }

    label {
      display: block;
      margin-bottom: 8px;
      font-weight: 700;
    }

    input {
      width: 100%;
      border: 1px solid var(--line);
      background: #07111d;
      color: var(--text);
      border-radius: 9px;
      padding: 13px;
      font-size: 16px;
      outline: none;
    }

    input:focus {
      border-color: var(--brand);
      box-shadow: 0 0 0 3px rgba(125, 211, 252, .12);
    }

    button {
      width: 100%;
      margin-top: 16px;
      border: 0;
      border-radius: 9px;
      padding: 13px;
      background: var(--brand);
      color: #06111f;
      font-weight: 800;
      font-size: 16px;
      cursor: pointer;
    }

    .hint {
      margin: 14px 0 0;
      font-size: 13px;
    }

    .error {
      margin-top: 14px;
      color: var(--danger);
      font-size: 14px;
      min-height: 18px;
      text-align: center;
    }

    @media (max-width: 420px) {
      form {
        padding: 22px;
      }

      h1 {
        font-size: 26px;
      }
    }
  </style>
</head>
<body>
  <main>
    <form name="login" action="` + escapedAuthURL + `" method="post">
      <input type="hidden" name="mac" value="$(mac)">
      <input type="hidden" name="link_login" value="$(link-login-only)">
      <input type="hidden" name="link_orig" value="$(link-orig)">

      <div class="mark">NF</div>

      <p class="eyebrow">WiFi Access</p>

      <h1>` + escapedPortalName + `</h1>

      <p>Enter your voucher code to connect.</p>

      <label for="voucher_code">
        Voucher code
      </label>

      <input
        id="voucher_code"
        name="voucher_code"
        autocomplete="one-time-code"
        placeholder="NF-XXXXXXXX"
        autofocus
        required
      >

      <button type="submit">
        Connect
      </button>

      <p class="hint">
        Your voucher remains usable on this device until its access time expires.
      </p>

      <div class="error">
        $(if error)$(error)$(endif)
      </div>
    </form>
  </main>
</body>
</html>`
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

func validateHotspotReturnURL(
	rawURL string,
	hotspotDNSName string,
	hotspotGatewayCIDR string,
) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", errors.New("HotSpot return URL is missing")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil || parsed == nil {
		return "", errors.New("HotSpot return URL is invalid")
	}

	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	default:
		return "", errors.New(
			"HotSpot return URL must use HTTP or HTTPS",
		)
	}

	host := strings.ToLower(
		strings.TrimSpace(parsed.Hostname()),
	)
	if host == "" {
		return "", errors.New(
			"HotSpot return URL host is missing",
		)
	}

	allowedHosts := map[string]struct{}{}

	if dnsName := strings.ToLower(
		strings.TrimSpace(hotspotDNSName),
	); dnsName != "" {
		allowedHosts[dnsName] = struct{}{}
	}

	if gateway := strings.TrimSpace(
		hotspotGatewayCIDR,
	); gateway != "" {
		if gatewayIP, _, err := net.ParseCIDR(gateway); err == nil &&
			gatewayIP != nil {
			allowedHosts[strings.ToLower(gatewayIP.String())] = struct{}{}
		}
	}

	if _, ok := allowedHosts[host]; !ok {
		return "", fmt.Errorf(
			"HotSpot return URL host %q does not match the configured tenant HotSpot",
			host,
		)
	}

	return parsed.String(), nil
}

func hotspotLocalBridgeURL(
	linkLogin string,
	linkOrig string,
	voucherCode string,
) string {
	parsed, err := url.Parse(strings.TrimSpace(linkLogin))
	if err != nil || parsed == nil {
		return strings.TrimSpace(linkLogin)
	}

	fragment := url.Values{}
	fragment.Set("noblifi", "1")
	fragment.Set(
		"voucher",
		strings.ToUpper(strings.TrimSpace(voucherCode)),
	)

	if destination := strings.TrimSpace(linkOrig); destination != "" {
		fragment.Set("dst", destination)
	}

	parsed.Fragment = fragment.Encode()
	return parsed.String()
}

func renderHotspotAutoLoginPage(
	portalName string,
	linkLogin string,
	linkOrig string,
	voucherCode string,
) string {
	portalName = strings.TrimSpace(portalName)
	if portalName == "" {
		portalName = "NobliFi WiFi"
	}

	bridgeURL := hotspotLocalBridgeURL(
		linkLogin,
		linkOrig,
		voucherCode,
	)

	bridgeJSON, _ := json.Marshal(bridgeURL)

	return `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#06111f">
  <title>Connecting · ` + html.EscapeString(portalName) + `</title>
  <style>
    :root{color-scheme:dark;--bg:#06111f;--panel:#0b1727;--line:#24384f;--text:#f8fbff;--muted:#9fb0c5;--brand:#7dd3fc;--accent:#34d399}
    *{box-sizing:border-box}
    body{margin:0;font-family:Arial,Helvetica,sans-serif;background:linear-gradient(145deg,#06111f 0%,#0b1727 52%,#102033 100%);color:var(--text)}
    main{min-height:100vh;display:grid;place-items:center;padding:24px 16px}
    .card{width:min(420px,100%);border:1px solid var(--line);background:rgba(11,23,39,.94);border-radius:12px;padding:26px;text-align:center;box-shadow:0 18px 50px rgba(0,0,0,.32)}
    .mark{width:48px;height:48px;display:grid;place-items:center;margin:0 auto 16px;border-radius:10px;background:var(--brand);color:#06111f;font-weight:900}
    .eyebrow{margin:0 0 7px;color:var(--brand);font-size:11px;font-weight:800;letter-spacing:.16em;text-transform:uppercase}
    h1{margin:0;font-size:30px}
    p{color:var(--muted);line-height:1.5}
    .pulse{width:42px;height:42px;margin:22px auto 0;border-radius:50%;border:4px solid rgba(52,211,153,.2);border-top-color:var(--accent);animation:spin .8s linear infinite}
    @keyframes spin{to{transform:rotate(360deg)}}
  </style>
</head>
<body>
<main>
  <section class="card">
    <div class="mark">NF</div>
    <p class="eyebrow">Authorizing</p>
    <h1>` + html.EscapeString(portalName) + `</h1>
    <p>Your voucher is valid. Connecting this device to the internet…</p>
    <div class="pulse" aria-hidden="true"></div>
  </section>
</main>

<script>
(function () {
  /*
   * IMPORTANT:
   * Do NOT create an HTTPS-page form whose action is the HTTP MikroTik login
   * URL. Chromium displays "The information you're about to submit is not
   * secure" for that HTTPS -> HTTP form submission.
   *
   * We perform a top-level navigation back to the local HotSpot page instead.
   * The voucher is carried in the URL fragment, which is not sent to the
   * router. The local RouterOS-served login.html reads it, clears it, and then
   * performs the final same-origin HTTP POST to the MikroTik login servlet.
   */
  window.location.replace(` + string(bridgeJSON) + `);
})();
</script>
</body>
</html>`
}

func renderHotspotExternalAuthError(
	portalName string,
	linkLogin string,
	message string,
) string {
	portalName = strings.TrimSpace(portalName)
	if portalName == "" {
		portalName = "NobliFi WiFi"
	}

	backURL := strings.TrimSpace(linkLogin)
	if backURL == "" {
		backURL = "#"
	}

	return `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta
    name="viewport"
    content="width=device-width, initial-scale=1"
  >
  <meta name="theme-color" content="#06111f">

  <title>
    Could not connect · ` + html.EscapeString(portalName) + `
  </title>

  <style>
    :root {
      color-scheme:dark;
      --bg:#06111f;
      --panel:#0b1727;
      --line:#24384f;
      --text:#f8fbff;
      --muted:#9fb0c5;
      --brand:#7dd3fc;
      --accent:#34d399;
      --danger:#fca5a5;
    }

    * {
      box-sizing:border-box;
    }

    body {
      margin:0;
      font-family:Arial, Helvetica, sans-serif;
      background:linear-gradient(
        145deg,
        #06111f 0%,
        #0b1727 52%,
        #102033 100%
      );
      color:var(--text);
    }

    main {
      min-height:100vh;
      display:grid;
      place-items:center;
      padding:24px 16px;
    }

    .card {
      width:min(420px,100%);
      border:1px solid var(--line);
      background:rgba(11,23,39,.94);
      border-radius:12px;
      padding:26px;
      box-shadow:0 18px 50px rgba(0,0,0,.32);
    }

    .mark {
      width:48px;
      height:48px;
      display:grid;
      place-items:center;
      margin:0 auto 16px;
      border-radius:10px;
      background:var(--brand);
      color:#06111f;
      font-weight:900;
    }

    .eyebrow {
      margin:0 0 7px;
      text-align:center;
      color:var(--brand);
      font-size:11px;
      font-weight:800;
      letter-spacing:.16em;
      text-transform:uppercase;
    }

    h1 {
      margin:0;
      text-align:center;
      font-size:30px;
    }

    .lead {
      margin:10px auto 22px;
      color:var(--muted);
      line-height:1.5;
      text-align:center;
    }

    .notice {
      margin:18px 0;
      padding:12px 14px;
      border:1px solid rgba(252,165,165,.3);
      background:rgba(252,165,165,.08);
      border-radius:10px;
      color:#ffd8d8;
      line-height:1.45;
    }

    .btn {
      display:block;
      width:100%;
      padding:13px 16px;
      border-radius:10px;
      background:var(--accent);
      color:#04150f;
      text-align:center;
      text-decoration:none;
      font-weight:900;
    }

    .footer {
      margin:18px 0 0;
      color:var(--muted);
      font-size:11px;
      text-align:center;
    }
  </style>
</head>

<body>
<main>
  <section class="card">
    <div class="mark">NF</div>

    <p class="eyebrow">
      Could not connect
    </p>

    <h1>` + html.EscapeString(portalName) + `</h1>

    <p class="lead">
      We could not authorize this voucher on this device.
    </p>

    <div class="notice">
      ` + html.EscapeString(message) + `
    </div>

    <a
      class="btn"
      href="` + html.EscapeString(backURL) + `"
    >
      Try again
    </a>

    <p class="footer">
      Secure WiFi access powered by NobliFi
    </p>
  </section>
</main>
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