package provisioning

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/noblifi/noblifi/backend/internal/config"
	"github.com/noblifi/noblifi/backend/internal/portprofiles"
	"github.com/noblifi/noblifi/backend/internal/routers"
)

type Service struct {
	repo *routers.Repository
	cfg  config.Config
}

func NewService(repo *routers.Repository, cfg config.Config) *Service {
	return &Service{repo: repo, cfg: cfg}
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

func (s *Service) ClaimConfig(token, serial string) (string, error) {
	router, err := s.repo.FindByClaimToken(token)
	if err != nil {
		return "", errors.New("invalid claim token")
	}
	if router.ClaimTokenExpiresAt != nil && router.ClaimTokenExpiresAt.Before(time.Now()) {
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
	return portprofiles.RenderRouterOSWithOptions(assignments, s.renderOptionsForRouter(router))
}

func (s *Service) renderOptionsForRouter(router routers.Router) portprofiles.RenderOptions {
	if router.NetworkProfile != nil {
		return router.NetworkProfile.RenderOptions()
	}
	profile, err := s.repo.NetworkProfile(router.ID)
	if err == nil {
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
/tool fetch url=$statusUrl mode=%s keep-result=no

:put "NobliFi router linked. Return to the dashboard and choose automatic or manual setup."`, token, baseURL, fetchMode, fetchMode)
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
