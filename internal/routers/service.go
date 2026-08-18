package routers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/config"
	"github.com/noblifi/noblifi/backend/internal/placeholders"
	"github.com/noblifi/noblifi/backend/internal/portprofiles"
)

type Service struct {
	repo                    *Repository
	cfg                     config.Config
	serverPublicKeyResolver WireGuardServerPublicKeyResolver
}

type WireGuardServerPublicKeyResolver interface {
	ActiveServerPublicKey() (string, error)
}

func NewService(repo *Repository, cfg config.Config) *Service {
	return &Service{repo: repo, cfg: cfg}
}

func (s *Service) SetWireGuardServerPublicKeyResolver(resolver WireGuardServerPublicKeyResolver) {
	s.serverPublicKeyResolver = resolver
}

type CreateRouterInput struct {
	Name          string `json:"name"`
	SiteName      string `json:"site_name"`
	Model         string `json:"model"`
	ExpectedModel string `json:"expected_model"`
}

func (s *Service) Create(input CreateRouterInput, userID *uuid.UUID, isSuperadmin bool) (Router, error) {
	expires := time.Now().Add(time.Duration(s.cfg.ProvisioningTokenTTLHour) * time.Hour)
	var siteName *string
	if strings.TrimSpace(input.SiteName) != "" {
		value := strings.TrimSpace(input.SiteName)
		siteName = &value
	}
	expectedModel := strings.TrimSpace(input.ExpectedModel)
	if expectedModel == "" {
		expectedModel = strings.TrimSpace(input.Model)
	}
	var expectedModelPtr *string
	if expectedModel != "" {
		expectedModelPtr = &expectedModel
	}
	router := Router{
		Name:                input.Name,
		SiteName:            siteName,
		ExpectedModel:       expectedModelPtr,
		Status:              "pending",
		ClaimToken:          randomToken(),
		ClaimTokenExpiresAt: &expires,
	}
	if !isSuperadmin && userID != nil {
		router.UserID = userID
	}
	err := s.repo.Create(&router)
	if err != nil {
		return router, err
	}
	return router, nil
}

func (s *Service) List(userID *uuid.UUID, isSuperadmin bool) ([]Router, error) {
	if isSuperadmin || userID == nil {
		return s.repo.List()
	}
	return s.repo.ListForUser(*userID)
}

func (s *Service) Find(id uuid.UUID, userID *uuid.UUID, isSuperadmin bool) (Router, error) {
	if isSuperadmin || userID == nil {
		return s.repo.Find(id)
	}
	return s.repo.FindForUser(id, *userID)
}

func (s *Service) NetworkProfile(
	routerID uuid.UUID,
	userID *uuid.UUID,
	isSuperadmin bool,
) (RouterNetworkProfile, error) {
	if !isSuperadmin && userID != nil {
		if _, err := s.repo.FindForUser(routerID, *userID); err != nil {
			return RouterNetworkProfile{}, err
		}
	}

	profile, err := s.repo.NetworkProfile(routerID)
	if err == nil {
		s.normalizeNetworkProfile(&profile)

		// The user's chosen hotspot_name is the source of truth for both the
		// visible portal name and RouterOS dns-name. Persist it into the network
		// profile so every rendering path, including provisioning/config/:token,
		// receives the same deterministic tenant identity.
		if err := s.applyTenantHotspotIdentity(routerID, &profile); err != nil {
			return RouterNetworkProfile{}, err
		}

		if err := s.repo.SaveNetworkProfile(&profile); err != nil {
			return RouterNetworkProfile{}, err
		}

		return profile, nil
	}

	router, findErr := s.repo.Find(routerID)
	if findErr != nil {
		return RouterNetworkProfile{}, findErr
	}

	profile = s.defaultNetworkProfile(routerID, router.Name)

	if err := s.applyTenantHotspotIdentity(routerID, &profile); err != nil {
		return RouterNetworkProfile{}, err
	}

	if err := s.repo.CreateNetworkProfile(&profile); err != nil {
		return RouterNetworkProfile{}, err
	}

	return profile, nil
}

func (s *Service) UpdateNetworkProfile(routerID uuid.UUID, input RouterNetworkProfile, userID *uuid.UUID, isSuperadmin bool) (RouterNetworkProfile, error) {
	profile, err := s.NetworkProfile(routerID, userID, isSuperadmin)
	if err != nil {
		return profile, err
	}
	mergeNetworkProfile(&profile, input)
	err = s.repo.SaveNetworkProfile(&profile)
	return profile, err
}

func (s *Service) RegenerateClaimToken(id uuid.UUID, userID *uuid.UUID, isSuperadmin bool) (Router, error) {
	router, err := s.Find(id, userID, isSuperadmin)
	if err != nil {
		return router, err
	}
	expires := time.Now().Add(time.Duration(s.cfg.ProvisioningTokenTTLHour) * time.Hour)
	router.ClaimToken = randomToken()
	router.ClaimTokenExpiresAt = &expires
	err = s.repo.Save(&router)
	return router, err
}

func (s *Service) SavePortAssignments(routerID uuid.UUID, inputs []portprofiles.Assignment, userID *uuid.UUID, isSuperadmin bool) error {
	if !isSuperadmin && userID != nil {
		if _, err := s.repo.FindForUser(routerID, *userID); err != nil {
			return err
		}
	}
	if err := portprofiles.Validate(inputs); err != nil {
		return err
	}
	if err := s.validateAssignablePorts(routerID, inputs); err != nil {
		return err
	}
	assignments := make([]RouterPortAssignment, 0, len(inputs))
	for _, input := range inputs {
		assignments = append(assignments, RouterPortAssignment{
			RouterID:      routerID,
			InterfaceName: input.Name(),
			Role:          input.Role,
		})
	}
	if err := s.repo.ReplacePortAssignments(routerID, assignments); err != nil {
		return err
	}
	session, err := s.repo.EnsureSetupSession(routerID)
	if err != nil {
		return err
	}
	session.CurrentStep = "preview"
	return s.repo.SaveSetupSession(&session)
}

func (s *Service) validateAssignablePorts(routerID uuid.UUID, inputs []portprofiles.Assignment) error {
	interfaces, err := s.repo.Interfaces(routerID)
	if err != nil {
		return err
	}

	byName := map[string]RouterInterface{}
	for _, iface := range interfaces {
		byName[iface.Name] = iface
	}

	for _, input := range inputs {
		role := strings.ToUpper(strings.TrimSpace(input.Role))
		if role == "DISABLED" {
			continue
		}

		iface, ok := byName[input.Name()]
		if !ok {
			return fmt.Errorf("interface %s was not discovered on this MikroTik", input.Name())
		}

		// WAN, HOTSPOT_LAN and FREE_LAN must always be real physical ports.
		if role == "WAN" || role == "HOTSPOT_LAN" || role == "FREE_LAN" {
			if iface.Disabled {
				return fmt.Errorf("interface %s is disabled and cannot be used for %s", iface.Name, role)
			}

			if isVirtualInterface(iface) {
				return fmt.Errorf(
					"interface %s is %s and cannot be used for %s; select a physical Ethernet port like ether1",
					iface.Name,
					interfaceType(iface),
					role,
				)
			}
		}
	}

	return nil
}
func isVirtualInterface(iface RouterInterface) bool {
	typeName := strings.ToLower(strings.TrimSpace(interfaceType(iface)))
	name := strings.ToLower(strings.TrimSpace(iface.Name))

	return strings.Contains(typeName, "bridge") ||
		strings.Contains(name, "bridge") ||
		strings.HasPrefix(name, "br-") ||
		strings.Contains(typeName, "loopback") ||
		name == "lo" ||
		strings.Contains(typeName, "tunnel") ||
		strings.Contains(typeName, "wireguard") ||
		typeName == "wg" ||
		strings.Contains(name, "wireguard") ||
		strings.Contains(name, "-wg")
}
func interfaceType(iface RouterInterface) string {
	if iface.Type == nil || strings.TrimSpace(*iface.Type) == "" {
		return "unknown"
	}
	return *iface.Type
}

type RemoteAccessInput struct {
	RemoteAccessMethod string `json:"remote_access_method"`
	Host               string `json:"host"`
	APIPort            int    `json:"api_port"`
	Username           string `json:"username"`
	Password           string `json:"password"`
}

type MethodInput struct {
	ConfigurationMethod string `json:"configuration_method"`
}

type ConfigPreview struct {
	Summary portprofiles.Summary `json:"summary"`
	Script  string               `json:"script"`
}

func (s *Service) SaveRemoteAccess(
	routerID uuid.UUID,
	input RemoteAccessInput,
	userID *uuid.UUID,
	isSuperadmin bool,
) (RouterSetupSession, error) {
	// Require a valid scoped user for ordinary accounts.
	// Superadmin is permitted to have userID == nil.
	if !isSuperadmin {
		if userID == nil {
			return RouterSetupSession{},
				errors.New(
					"authenticated user is required",
				)
		}

		if _, err := s.repo.FindForUser(
			routerID,
			*userID,
		); err != nil {
			return RouterSetupSession{}, err
		}
	}

	method := strings.TrimSpace(
		input.RemoteAccessMethod,
	)

	if method != "wireguard" &&
		method != "bootstrap" &&
		method != "direct_api" {
		return RouterSetupSession{},
			errors.New(
				"remote_access_method must be wireguard, bootstrap, or direct_api",
			)
	}

	// This avoids the previous unconditional *userID dereference,
	// which could fail for superadmin.
	router, err := s.Find(
		routerID,
		userID,
		isSuperadmin,
	)

	if err != nil {
		return RouterSetupSession{}, err
	}

	switch method {
	case "wireguard":
		// Restore the completed WireGuard orchestration.
		//
		// PrepareWireGuard:
		// 1. validates the configured VPS WireGuard environment;
		// 2. allocates the router's tunnel IP;
		// 3. stores the tunnel IP as ManagementIP;
		// 4. prepares the router WireGuard state;
		// 5. updates the router NetworkProfile so RADIUS uses the
		//    WireGuard VPS/server IP.
		if _, err := s.PrepareWireGuard(
			routerID,
		); err != nil {
			return RouterSetupSession{}, err
		}

	case "direct_api":
		if input.Host == "" ||
			input.APIPort == 0 ||
			input.Username == "" ||
			input.Password == "" {
			return RouterSetupSession{},
				errors.New(
					"host, api_port, username, and password are required for direct API access",
				)
		}

		if err := TestRouterConnection(
			input.Host,
			input.APIPort,
			input.Username,
			input.Password,
		); err != nil {
			return RouterSetupSession{}, err
		}

		router.ManagementIP = &input.Host
		router.APIUsername = &input.Username

		encrypted :=
			"encrypted-placeholder:" +
				input.Password

		router.APIPasswordEncrypted =
			&encrypted

		if err := s.repo.Save(
			&router,
		); err != nil {
			return RouterSetupSession{}, err
		}

	case "bootstrap":
		// Bootstrap uses the claim-token provisioning flow and
		// does not need to overwrite ManagementIP here.
	}

	session, err :=
		s.repo.EnsureSetupSession(routerID)

	if err != nil {
		return session, err
	}

	session.RemoteAccessMethod = &method

	if method == "wireguard" {
		session.CurrentStep = "wireguard"
	} else {
		session.CurrentStep = "method"
	}

	return session,
		s.repo.SaveSetupSession(&session)
}

func TestRouterConnection(host string, apiPort int, username, password string) error {
	return nil
}

func (s *Service) SaveMethod(routerID uuid.UUID, input MethodInput) (RouterSetupSession, error) {
	method := strings.TrimSpace(input.ConfigurationMethod)
	if method != "automatic" && method != "manual" {
		return RouterSetupSession{}, errors.New("configuration_method must be automatic or manual")
	}
	session, err := s.repo.EnsureSetupSession(routerID)
	if err != nil {
		return session, err
	}
	session.ConfigurationMethod = &method
	if method == "automatic" {
		session.CurrentStep = "topology"
	} else {
		session.CurrentStep = "manual"
	}
	return session, s.repo.SaveSetupSession(&session)
}

func (s *Service) Interfaces(routerID uuid.UUID) ([]RouterInterface, error) {
	interfaces, err := s.repo.Interfaces(routerID)
	if err != nil {
		return nil, err
	}
	if len(interfaces) > 0 {
		return interfaces, nil
	}
	return interfaces, nil
}

func (s *Service) BootstrapScript(routerID uuid.UUID) (string, error) {
	router, err := s.repo.Find(routerID)
	if err != nil {
		return "", err
	}
	return bootstrapScript(router.ClaimToken, s.cfg.ProvisioningBaseURL), nil
}

func (s *Service) ConfigInstallCommand(routerID uuid.UUID) (string, error) {
	if _, err := s.ConfigPreview(routerID); err != nil {
		return "", err
	}
	router, err := s.repo.Find(routerID)
	if err != nil {
		return "", err
	}
	return configInstallCommand(router.ClaimToken, s.cfg.ProvisioningBaseURL), nil
}

func (s *Service) ConfigPreview(routerID uuid.UUID) (ConfigPreview, error) {
	router, err := s.repo.Find(routerID)
	if err != nil {
		return ConfigPreview{}, err
	}

	assignments := make([]portprofiles.Assignment, 0, len(router.PortAssignments))
	for _, assignment := range router.PortAssignments {
		assignments = append(assignments, portprofiles.Assignment{
			InterfaceName: assignment.InterfaceName,
			Role:          assignment.Role,
		})
	}

	// A new router with no saved assignments gets NobliFi's safe topology:
	// ether1 = WAN, ether2-ether4 = HOTSPOT_LAN, ether5 = FREE_LAN.
	if len(assignments) == 0 {
		assignments = portprofiles.DefaultAssignments()
	}

	if err := portprofiles.Validate(assignments); err != nil {
		return ConfigPreview{}, err
	}

	summary := portprofiles.BuildSummary(assignments)
	if len(summary.WAN) == 0 {
		return ConfigPreview{}, errors.New("NobliFi DHCP cannot be configured because no WAN port is assigned")
	}
	if len(summary.HotspotLAN) == 0 {
		return ConfigPreview{}, errors.New("NobliFi DHCP cannot be configured because no HOTSPOT_LAN port is assigned")
	}

	options, err := s.renderOptionsForRouter(routerID)
	if err != nil {
		return ConfigPreview{}, err
	}

	options.LoginPageURL = hotspotLoginURL(
		router.ClaimToken,
		s.cfg.ProvisioningBaseURL,
	)

	// Do not allow a partial/old DB network profile to suppress the HotSpot
	// DHCP configuration. These values are required by portprofiles to create:
	//   - br-hotspot
	//   - pool-hotspot
	//   - dhcp-hotspot
	//   - /ip dhcp-server network
	options = ensureNobliFiDHCPOptions(options, s.cfg)

	script, err := portprofiles.RenderRouterOSWithOptions(assignments, options)
	if err != nil {
		return ConfigPreview{}, err
	}

	// Treat missing DHCP commands as a generation failure. This catches future
	// renderer regressions before a broken script is sent to the MikroTik.
	requiredDHCPCommands := []string{
		"/ip dhcp-client add interface=",
		"/ip pool add name=pool-hotspot",
		"/ip dhcp-server add name=dhcp-hotspot",
		"/ip dhcp-server network",
	}

	for _, command := range requiredDHCPCommands {
		if !strings.Contains(script, command) {
			return ConfigPreview{}, fmt.Errorf(
				"generated NobliFi configuration is missing required DHCP command %q",
				command,
			)
		}
	}

	return ConfigPreview{
		Summary: summary,
		Script:  script,
	}, nil
}

func (s *Service) Deploy(routerID uuid.UUID) (map[string]string, error) {
	preview, err := s.ConfigPreview(routerID)
	if err != nil {
		return nil, err
	}
	router, err := s.repo.Find(routerID)
	if err != nil {
		return nil, err
	}
	payload, _ := json.Marshal(preview.Summary)
	log := RouterConfigLog{
		RouterID:       routerID,
		Action:         "deploy",
		Status:         "queued",
		RequestPayload: payload,
	}
	if err := s.repo.CreateConfigLog(&log); err != nil {
		return nil, err
	}
	router.Status = "provisioning"
	if err := s.repo.Save(&router); err != nil {
		return nil, err
	}
	session, err := s.repo.EnsureSetupSession(routerID)
	if err != nil {
		return nil, err
	}
	session.CurrentStep = "deploy_queued"
	session.DeploymentStatus = "queued"
	if err := s.repo.SaveSetupSession(&session); err != nil {
		return nil, err
	}
	return map[string]string{"message": "Configuration deployment queued", "status": "queued"}, nil
}

func randomToken() string {
	left := make([]byte, 2)
	right := make([]byte, 2)
	if _, err := rand.Read(left); err != nil {
		return "NOB-" + strings.ToUpper(uuid.NewString()[0:4]) + "-" + strings.ToUpper(uuid.NewString()[0:4])
	}
	if _, err := rand.Read(right); err != nil {
		return "NOB-" + strings.ToUpper(uuid.NewString()[0:4]) + "-" + strings.ToUpper(uuid.NewString()[0:4])
	}
	return fmt.Sprintf("NOB-%s-%s", strings.ToUpper(hex.EncodeToString(left)), strings.ToUpper(hex.EncodeToString(right)))
}

func bootstrapScript(token, baseURL string) string {
	baseURL = normalizeProvisioningBaseURL(baseURL)
	fetchMode := provisioningFetchMode(baseURL)
	bootstrapURL := baseURL + "/bootstrap/" + token

	return fmt.Sprintf(`/tool fetch url="%s" mode=%s dst-path=noblifi-bootstrap.rsc
/import file-name=noblifi-bootstrap.rsc`, bootstrapURL, fetchMode)
}

func configInstallCommand(token, baseURL string) string {
	baseURL = normalizeProvisioningBaseURL(baseURL)
	fetchMode := provisioningFetchMode(baseURL)
	configURL := baseURL + "/config/" + token

	return fmt.Sprintf(`/tool fetch url="%s" mode=%s dst-path=noblifi-config.rsc
/import file-name=noblifi-config.rsc`, configURL, fetchMode)
}

func hotspotLoginURL(token, baseURL string) string {
	return normalizeProvisioningBaseURL(baseURL) + "/hotspot-login/" + token
}

func legacyRandomToken() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return uuid.NewString()
	}
	return hex.EncodeToString(bytes)
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

func renderOptions(cfg config.Config) portprofiles.RenderOptions {
	return portprofiles.RenderOptions{
		RadiusServer:        cfg.RadiusServer,
		RadiusSecret:        cfg.RadiusSecret,
		RouterIdentity:      cfg.RouterIdentityPrefix + "-Router",
		APIUsername:         cfg.RouterAPIUsername,
		APIPassword:         cfg.RouterAPIPassword,
		HotspotBridge:       cfg.HotspotBridgeName,
		StaffBridge:         cfg.StaffBridgeName,
		POSBridge:           cfg.POSBridgeName,
		CCTVBridge:          cfg.CCTVBridgeName,
		HotspotSubnet:       cfg.HotspotSubnetCIDR,
		HotspotGateway:      cfg.HotspotGatewayCIDR,
		HotspotPool:         cfg.HotspotPoolRange,
		StaffSubnet:         cfg.StaffSubnetCIDR,
		StaffGateway:        cfg.StaffGatewayCIDR,
		StaffPool:           cfg.StaffPoolRange,
		POSSubnet:           cfg.POSSubnetCIDR,
		POSGateway:          cfg.POSGatewayCIDR,
		POSPool:             cfg.POSPoolRange,
		CCTVSubnet:          cfg.CCTVSubnetCIDR,
		CCTVGateway:         cfg.CCTVGatewayCIDR,
		CCTVPool:            cfg.CCTVPoolRange,
		HotspotDNSName:      cfg.HotspotDNSName,
		HotspotPortalName:   cfg.HotspotPortalName,
		WalledGardenHosts:   cfg.HotspotWalledGardenHosts,
		DisableWWWService:   cfg.DisableWWWService,
		EnableAPIService:    cfg.EnableAPIService,
		EnableAPISSLService: cfg.EnableAPISSLService,
	}
}

func (s *Service) renderOptionsForRouter(
	routerID uuid.UUID,
) (portprofiles.RenderOptions, error) {
	// NetworkProfile() now persists the actual users.hotspot_name and derived
	// tenant DNS name into RouterNetworkProfile before returning it.
	profile, err := s.NetworkProfile(routerID, nil, true)
	if err != nil {
		return portprofiles.RenderOptions{}, err
	}

	options := profile.RenderOptions()
	options = ensureNobliFiDHCPOptions(options, s.cfg)

	if strings.TrimSpace(options.HotspotPortalName) == "" {
		return portprofiles.RenderOptions{}, errors.New(
			"router owner hotspot name is missing",
		)
	}

	if strings.TrimSpace(options.HotspotDNSName) == "" {
		return portprofiles.RenderOptions{}, errors.New(
			"router owner hotspot DNS name is missing",
		)
	}

	return options, nil
}

func (s *Service) applyTenantHotspotIdentity(
	routerID uuid.UUID,
	profile *RouterNetworkProfile,
) error {
	if profile == nil {
		return errors.New("network profile is required")
	}

	hotspotName, err := s.repo.HotspotNameForRouter(routerID)
	if err != nil {
		return fmt.Errorf(
			"resolve router owner hotspot name: %w",
			err,
		)
	}

	hotspotName = strings.TrimSpace(hotspotName)
	if hotspotName == "" {
		return errors.New(
			"router owner does not have a hotspot_name; the user must set a hotspot name before provisioning",
		)
	}

	dnsName := tenantHotspotDNSName(hotspotName)
	if dnsName == "" {
		return fmt.Errorf(
			"could not generate a valid hotspot DNS name from user hotspot_name %q",
			hotspotName,
		)
	}

	// These values are deterministic. No router name, claim token, UUID or
	// random value participates in their generation.
	profile.HotspotPortalName = hotspotName
	profile.HotspotDNSName = dnsName

	return nil
}

func ensureNobliFiDHCPOptions(
	options portprofiles.RenderOptions,
	cfg config.Config,
) portprofiles.RenderOptions {
	// Prefer configured values. Fall back to the standard NobliFi HotSpot
	// network so an old or incomplete profile cannot remove DHCP.
	if strings.TrimSpace(options.HotspotBridge) == "" {
		options.HotspotBridge = strings.TrimSpace(cfg.HotspotBridgeName)
	}
	if strings.TrimSpace(options.HotspotBridge) == "" {
		options.HotspotBridge = "br-hotspot"
	}

	if strings.TrimSpace(options.HotspotSubnet) == "" {
		options.HotspotSubnet = strings.TrimSpace(cfg.HotspotSubnetCIDR)
	}
	if strings.TrimSpace(options.HotspotSubnet) == "" {
		options.HotspotSubnet = "10.10.10.0/24"
	}

	if strings.TrimSpace(options.HotspotGateway) == "" {
		options.HotspotGateway = strings.TrimSpace(cfg.HotspotGatewayCIDR)
	}
	if strings.TrimSpace(options.HotspotGateway) == "" {
		options.HotspotGateway = "10.10.10.1/24"
	}

	if strings.TrimSpace(options.HotspotPool) == "" {
		options.HotspotPool = strings.TrimSpace(cfg.HotspotPoolRange)
	}
	if strings.TrimSpace(options.HotspotPool) == "" {
		options.HotspotPool = "10.10.10.10-10.10.10.254"
	}

	return options
}

func (s *Service) normalizeNetworkProfile(profile *RouterNetworkProfile) {
	NormalizeNetworkProfile(profile, s.cfg)
}

func NormalizeNetworkProfile(
	profile *RouterNetworkProfile,
	cfg config.Config,
) {
	if profile == nil {
		return
	}

	if placeholders.Is(profile.RadiusServer) {
		profile.RadiusServer = cfg.RadiusServer
	}
	if placeholders.Is(profile.RadiusSecret) {
		profile.RadiusSecret = cfg.RadiusSecret
	}
	if placeholders.Is(profile.APIPassword) {
		profile.APIPassword = cfg.RouterAPIPassword
	}

	// Ensure old or partially-created profiles still generate a complete
	// NobliFi HotSpot DHCP configuration.
	if strings.TrimSpace(profile.HotspotBridge) == "" {
		profile.HotspotBridge = strings.TrimSpace(cfg.HotspotBridgeName)
	}
	if strings.TrimSpace(profile.HotspotBridge) == "" {
		profile.HotspotBridge = "br-hotspot"
	}

	if strings.TrimSpace(profile.HotspotSubnet) == "" {
		profile.HotspotSubnet = strings.TrimSpace(cfg.HotspotSubnetCIDR)
	}
	if strings.TrimSpace(profile.HotspotSubnet) == "" {
		profile.HotspotSubnet = "10.10.10.0/24"
	}

	if strings.TrimSpace(profile.HotspotGateway) == "" {
		profile.HotspotGateway = strings.TrimSpace(cfg.HotspotGatewayCIDR)
	}
	if strings.TrimSpace(profile.HotspotGateway) == "" {
		profile.HotspotGateway = "10.10.10.1/24"
	}

	if strings.TrimSpace(profile.HotspotPool) == "" {
		profile.HotspotPool = strings.TrimSpace(cfg.HotspotPoolRange)
	}
	if strings.TrimSpace(profile.HotspotPool) == "" {
		profile.HotspotPool = "10.10.10.10-10.10.10.254"
	}

	if strings.TrimSpace(profile.WANMode) == "" {
		profile.WANMode = "dhcp"
	}

	// If a tenant portal name has already been persisted, its DNS name is
	// always derived from that same value. This prevents a stale generic
	// cfg.HotspotDNSName (for example "noblifi") from overriding the tenant.
	if portalName := strings.TrimSpace(profile.HotspotPortalName); portalName != "" {
		if dnsName := tenantHotspotDNSName(portalName); dnsName != "" {
			profile.HotspotDNSName = dnsName
		}
	}

	// These global values are only compatibility fallbacks for profiles that
	// have not yet been tenant-synchronised. NetworkProfile() replaces them
	// with users.hotspot_name before router-specific rendering.
	if strings.TrimSpace(profile.HotspotPortalName) == "" {
		profile.HotspotPortalName = strings.TrimSpace(cfg.HotspotPortalName)
	}
	if strings.TrimSpace(profile.HotspotDNSName) == "" {
		profile.HotspotDNSName = strings.TrimSpace(cfg.HotspotDNSName)
	}
}

func (s *Service) defaultNetworkProfile(routerID uuid.UUID, routerName string) RouterNetworkProfile {
	return RouterNetworkProfile{
		RouterID:            routerID,
		Name:                routerName + " Network Profile",
		RadiusServer:        s.cfg.RadiusServer,
		RadiusSecret:        s.cfg.RadiusSecret,
		RouterIdentity:      s.cfg.RouterIdentityPrefix + "-" + sanitizeIdentity(routerName),
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
		WANMode:             "dhcp",
		DisableWWWService:   s.cfg.DisableWWWService,
		EnableAPIService:    s.cfg.EnableAPIService,
		EnableAPISSLService: s.cfg.EnableAPISSLService,
	}
}

func (p RouterNetworkProfile) RenderOptions() portprofiles.RenderOptions {
	return portprofiles.RenderOptions{
		RadiusServer:        p.RadiusServer,
		RadiusSecret:        p.RadiusSecret,
		RouterIdentity:      p.RouterIdentity,
		APIUsername:         p.APIUsername,
		APIPassword:         p.APIPassword,
		HotspotBridge:       p.HotspotBridge,
		StaffBridge:         p.StaffBridge,
		POSBridge:           p.POSBridge,
		CCTVBridge:          p.CCTVBridge,
		HotspotSubnet:       p.HotspotSubnet,
		HotspotGateway:      p.HotspotGateway,
		HotspotPool:         p.HotspotPool,
		StaffSubnet:         p.StaffSubnet,
		StaffGateway:        p.StaffGateway,
		StaffPool:           p.StaffPool,
		POSSubnet:           p.POSSubnet,
		POSGateway:          p.POSGateway,
		POSPool:             p.POSPool,
		CCTVSubnet:          p.CCTVSubnet,
		CCTVGateway:         p.CCTVGateway,
		CCTVPool:            p.CCTVPool,
		HotspotDNSName:      p.HotspotDNSName,
		HotspotPortalName:   p.HotspotPortalName,
		DisableWWWService:   p.DisableWWWService,
		EnableAPIService:    p.EnableAPIService,
		EnableAPISSLService: p.EnableAPISSLService,
	}
}

func mergeNetworkProfile(profile *RouterNetworkProfile, input RouterNetworkProfile) {
	if input.Name != "" {
		profile.Name = input.Name
	}
	if input.RadiusServer != "" {
		profile.RadiusServer = input.RadiusServer
	}
	if input.RadiusSecret != "" {
		profile.RadiusSecret = input.RadiusSecret
	}
	if input.RouterIdentity != "" {
		profile.RouterIdentity = input.RouterIdentity
	}
	if input.APIUsername != "" {
		profile.APIUsername = input.APIUsername
	}
	if input.APIPassword != "" {
		profile.APIPassword = input.APIPassword
	}
	if input.HotspotBridge != "" {
		profile.HotspotBridge = input.HotspotBridge
	}
	if input.StaffBridge != "" {
		profile.StaffBridge = input.StaffBridge
	}
	if input.POSBridge != "" {
		profile.POSBridge = input.POSBridge
	}
	if input.CCTVBridge != "" {
		profile.CCTVBridge = input.CCTVBridge
	}
	if input.HotspotSubnet != "" {
		profile.HotspotSubnet = input.HotspotSubnet
	}
	if input.HotspotGateway != "" {
		profile.HotspotGateway = input.HotspotGateway
	}
	if input.HotspotPool != "" {
		profile.HotspotPool = input.HotspotPool
	}
	if input.StaffSubnet != "" {
		profile.StaffSubnet = input.StaffSubnet
	}
	if input.StaffGateway != "" {
		profile.StaffGateway = input.StaffGateway
	}
	if input.StaffPool != "" {
		profile.StaffPool = input.StaffPool
	}
	if input.POSSubnet != "" {
		profile.POSSubnet = input.POSSubnet
	}
	if input.POSGateway != "" {
		profile.POSGateway = input.POSGateway
	}
	if input.POSPool != "" {
		profile.POSPool = input.POSPool
	}
	if input.CCTVSubnet != "" {
		profile.CCTVSubnet = input.CCTVSubnet
	}
	if input.CCTVGateway != "" {
		profile.CCTVGateway = input.CCTVGateway
	}
	if input.CCTVPool != "" {
		profile.CCTVPool = input.CCTVPool
	}
	if input.HotspotDNSName != "" {
		profile.HotspotDNSName = input.HotspotDNSName
	}
	if input.HotspotPortalName != "" {
		profile.HotspotPortalName = input.HotspotPortalName
	}
	if input.WANMode != "" {
		profile.WANMode = input.WANMode
	}
	if input.PPPoEUsername != nil {
		profile.PPPoEUsername = input.PPPoEUsername
	}
	if input.PPPoEPassword != nil {
		profile.PPPoEPassword = input.PPPoEPassword
	}
	profile.DisableWWWService = input.DisableWWWService
	profile.EnableAPIService = input.EnableAPIService
	profile.EnableAPISSLService = input.EnableAPISSLService
}

func tenantHotspotDNSName(hotspotName string) string {
	label := sanitizeHotspotDNSLabel(hotspotName)
	if label == "" {
		return ""
	}

	return label + ".login.noblifi.local"
}

func sanitizeHotspotDNSLabel(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))

	var builder strings.Builder
	lastWasHyphen := false

	for _, r := range value {
		isLetter := r >= 'a' && r <= 'z'
		isNumber := r >= '0' && r <= '9'

		if isLetter || isNumber {
			builder.WriteRune(r)
			lastWasHyphen = false
			continue
		}

		// Spaces, underscores and punctuation become one DNS-safe hyphen.
		if builder.Len() > 0 && !lastWasHyphen {
			builder.WriteByte('-')
			lastWasHyphen = true
		}
	}

	label := strings.Trim(builder.String(), "-")

	// A single DNS label cannot exceed 63 octets.
	if len(label) > 63 {
		label = strings.TrimRight(label[:63], "-")
	}

	return label
}

func sanitizeIdentity(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "Router"
	}
	replacer := strings.NewReplacer(" ", "-", "\"", "", "'", "")
	return replacer.Replace(value)
}