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
	"github.com/noblifi/noblifi/backend/internal/portprofiles"
)

type Service struct {
	repo *Repository
	cfg  config.Config
}

func NewService(repo *Repository, cfg config.Config) *Service {
	return &Service{repo: repo, cfg: cfg}
}

type CreateRouterInput struct {
	Name          string `json:"name"`
	SiteName      string `json:"site_name"`
	Model         string `json:"model"`
	ExpectedModel string `json:"expected_model"`
}

func (s *Service) Create(input CreateRouterInput) (Router, error) {
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
	err := s.repo.Create(&router)
	if err != nil {
		return router, err
	}
	return router, nil
}

func (s *Service) List() ([]Router, error) {
	return s.repo.List()
}

func (s *Service) Find(id uuid.UUID) (Router, error) {
	return s.repo.Find(id)
}

func (s *Service) NetworkProfile(routerID uuid.UUID) (RouterNetworkProfile, error) {
	profile, err := s.repo.NetworkProfile(routerID)
	if err == nil {
		s.normalizeNetworkProfile(&profile)
		return profile, nil
	}
	router, findErr := s.repo.Find(routerID)
	if findErr != nil {
		return RouterNetworkProfile{}, findErr
	}
	profile = s.defaultNetworkProfile(routerID, router.Name)
	return profile, s.repo.CreateNetworkProfile(&profile)
}

func (s *Service) UpdateNetworkProfile(routerID uuid.UUID, input RouterNetworkProfile) (RouterNetworkProfile, error) {
	profile, err := s.NetworkProfile(routerID)
	if err != nil {
		return profile, err
	}
	mergeNetworkProfile(&profile, input)
	err = s.repo.SaveNetworkProfile(&profile)
	return profile, err
}

func (s *Service) RegenerateClaimToken(id uuid.UUID) (Router, error) {
	router, err := s.repo.Find(id)
	if err != nil {
		return router, err
	}
	expires := time.Now().Add(time.Duration(s.cfg.ProvisioningTokenTTLHour) * time.Hour)
	router.ClaimToken = randomToken()
	router.ClaimTokenExpiresAt = &expires
	err = s.repo.Save(&router)
	return router, err
}

func (s *Service) SavePortAssignments(routerID uuid.UUID, inputs []portprofiles.Assignment) error {
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
		role := strings.TrimSpace(input.Role)
		if role == "DISABLED" {
			continue
		}
		iface, ok := byName[input.Name()]
		if !ok {
			return fmt.Errorf("interface %s was not discovered on this MikroTik", input.Name())
		}
		if iface.Disabled && (role == "WAN" || role == "HOTSPOT_LAN") {
			return fmt.Errorf("interface %s is disabled and cannot be used for %s", iface.Name, role)
		}
		if isVirtualInterface(iface) && (role == "WAN" || role == "HOTSPOT_LAN") {
			return fmt.Errorf("interface %s is %s and cannot be used for %s; select a physical port like ether1", iface.Name, interfaceType(iface), role)
		}
	}
	return nil
}

func isVirtualInterface(iface RouterInterface) bool {
	typeName := strings.ToLower(interfaceType(iface))
	name := strings.ToLower(iface.Name)
	return strings.Contains(typeName, "bridge") || strings.Contains(name, "bridge") || strings.HasPrefix(name, "br-") || strings.Contains(typeName, "loopback") || strings.Contains(typeName, "tunnel")
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

func (s *Service) SaveRemoteAccess(routerID uuid.UUID, input RemoteAccessInput) (RouterSetupSession, error) {
	method := strings.TrimSpace(input.RemoteAccessMethod)
	if method != "bootstrap" && method != "direct_api" {
		return RouterSetupSession{}, errors.New("remote_access_method must be bootstrap or direct_api")
	}
	router, err := s.repo.Find(routerID)
	if err != nil {
		return RouterSetupSession{}, err
	}
	if method == "direct_api" {
		if input.Host == "" || input.APIPort == 0 || input.Username == "" || input.Password == "" {
			return RouterSetupSession{}, errors.New("host, api_port, username, and password are required for direct API access")
		}
		if err := TestRouterConnection(input.Host, input.APIPort, input.Username, input.Password); err != nil {
			return RouterSetupSession{}, err
		}
		router.ManagementIP = &input.Host
		router.APIUsername = &input.Username
		encrypted := "encrypted-placeholder:" + input.Password
		router.APIPasswordEncrypted = &encrypted
		if err := s.repo.Save(&router); err != nil {
			return RouterSetupSession{}, err
		}
	}
	session, err := s.repo.EnsureSetupSession(routerID)
	if err != nil {
		return session, err
	}
	session.RemoteAccessMethod = &method
	session.CurrentStep = "method"
	return session, s.repo.SaveSetupSession(&session)
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
		assignments = append(assignments, portprofiles.Assignment{InterfaceName: assignment.InterfaceName, Role: assignment.Role})
	}
	if len(assignments) == 0 {
		assignments = portprofiles.DefaultAssignments()
	}
	if err := portprofiles.Validate(assignments); err != nil {
		return ConfigPreview{}, err
	}
	options, err := s.renderOptionsForRouter(routerID)
	if err != nil {
		return ConfigPreview{}, err
	}
	script, err := portprofiles.RenderRouterOSWithOptions(assignments, options)
	if err != nil {
		return ConfigPreview{}, err
	}
	return ConfigPreview{Summary: portprofiles.BuildSummary(assignments), Script: script}, nil
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
		WalledGardenHosts:   cfg.HotspotWalledGardenHosts,
		DisableWWWService:   cfg.DisableWWWService,
		EnableAPIService:    cfg.EnableAPIService,
		EnableAPISSLService: cfg.EnableAPISSLService,
	}
}

func (s *Service) renderOptionsForRouter(routerID uuid.UUID) (portprofiles.RenderOptions, error) {
	profile, err := s.NetworkProfile(routerID)
	if err != nil {
		return portprofiles.RenderOptions{}, err
	}
	return profile.RenderOptions(), nil
}

func (s *Service) normalizeNetworkProfile(profile *RouterNetworkProfile) {
	if isPlaceholderRadiusSecret(profile.RadiusSecret) {
		profile.RadiusSecret = s.cfg.RadiusSecret
	}
}

func isPlaceholderRadiusSecret(value string) bool {
	secret := strings.TrimSpace(value)
	return secret == "" || secret == "CHANGE_ME_RADIUS_SECRET"
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

func sanitizeIdentity(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "Router"
	}
	replacer := strings.NewReplacer(" ", "-", "\"", "", "'", "")
	return replacer.Replace(value)
}
