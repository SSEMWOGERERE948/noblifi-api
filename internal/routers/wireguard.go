package routers

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/config"
)

const routerWireGuardInterface = "noblifi-wg"

type WireGuardSetupResponse struct {
	Enabled                bool     `json:"enabled"`
	Ready                  bool     `json:"ready"`
	Issues                 []string `json:"issues"`
	Status                 string   `json:"status"`
	InterfaceName          string   `json:"interface_name"`
	Endpoint               string   `json:"endpoint"`
	EndpointPort           int      `json:"endpoint_port"`
	RouterAddress          string   `json:"router_address"`
	ServerAddress          string   `json:"server_address"`
	RouterPublicKey        string   `json:"router_public_key"`
	MikroTikInstallCommand string   `json:"mikrotik_install_command"`
	MikroTikScript         string   `json:"mikrotik_script"`
	VPSPeerCommand         string   `json:"vps_peer_command"`
	VPSPeerConfig          string   `json:"vps_peer_config"`
	VerificationCommands   string   `json:"verification_commands"`
}

func (s *Service) PrepareWireGuard(routerID uuid.UUID) (WireGuardSetupResponse, error) {
	if issues := wireGuardConfigIssues(s.cfg); len(issues) > 0 {
		return WireGuardSetupResponse{Enabled: s.cfg.WireGuardEnabled, Issues: issues}, errors.New(strings.Join(issues, "; "))
	}

	router, err := s.repo.Find(routerID)
	if err != nil {
		return WireGuardSetupResponse{}, err
	}
	if !routerSupportsWireGuard(router.RouterOSVersion) {
		return WireGuardSetupResponse{}, errors.New("WireGuard requires RouterOS 7; upgrade this MikroTik before installing the tunnel")
	}

	if router.WireGuardTunnelIP == nil || strings.TrimSpace(*router.WireGuardTunnelIP) == "" {
		address, allocErr := s.allocateWireGuardIP()
		if allocErr != nil {
			return WireGuardSetupResponse{}, allocErr
		}
		router.WireGuardTunnelIP = &address
	}

	router.ManagementIP = router.WireGuardTunnelIP
	if router.WireGuardPublicKey == nil || strings.TrimSpace(*router.WireGuardPublicKey) == "" {
		router.WireGuardStatus = "awaiting_router_key"
	}
	if err := s.repo.Save(&router); err != nil {
		return WireGuardSetupResponse{}, err
	}

	profile, err := s.NetworkProfile(routerID)
	if err != nil {
		return WireGuardSetupResponse{}, err
	}
	profile.RadiusServer = s.cfg.WireGuardServerIP
	if err := s.repo.SaveNetworkProfile(&profile); err != nil {
		return WireGuardSetupResponse{}, err
	}

	return s.wireGuardSetupForRouter(router), nil
}

func (s *Service) WireGuardSetup(routerID uuid.UUID) (WireGuardSetupResponse, error) {
	router, err := s.repo.Find(routerID)
	if err != nil {
		return WireGuardSetupResponse{}, err
	}
	return s.wireGuardSetupForRouter(router), nil
}

func (s *Service) wireGuardSetupForRouter(router Router) WireGuardSetupResponse {
	issues := wireGuardConfigIssues(s.cfg)
	response := WireGuardSetupResponse{
		Enabled:       s.cfg.WireGuardEnabled,
		Ready:         len(issues) == 0 && router.WireGuardTunnelIP != nil,
		Issues:        issues,
		Status:        router.WireGuardStatus,
		InterfaceName: routerWireGuardInterface,
		Endpoint:      s.cfg.WireGuardEndpoint,
		EndpointPort:  s.cfg.WireGuardPort,
		ServerAddress: s.cfg.WireGuardServerIP,
	}
	if response.Status == "" {
		response.Status = "disabled"
	}
	if router.WireGuardTunnelIP == nil {
		return response
	}

	response.RouterAddress = strings.TrimSpace(*router.WireGuardTunnelIP)
	if len(issues) == 0 {
		response.MikroTikScript = RenderWireGuardRouterOS(router, s.cfg)
		wireGuardURL := normalizeProvisioningBaseURL(s.cfg.ProvisioningBaseURL) + "/wireguard/" + router.ClaimToken
		response.MikroTikInstallCommand = routerOSFetchImportCommand(wireGuardURL, provisioningFetchMode(wireGuardURL), "noblifi-wireguard.rsc")
	}
	if router.WireGuardPublicKey == nil || strings.TrimSpace(*router.WireGuardPublicKey) == "" {
		return response
	}

	response.RouterPublicKey = strings.TrimSpace(*router.WireGuardPublicKey)
	statusURL := normalizeProvisioningBaseURL(s.cfg.ProvisioningBaseURL) + "/wireguard-status"
	statusPayload := fmt.Sprintf(`{"token":"%s","status":"connected"}`, router.ClaimToken)
	response.VPSPeerCommand = fmt.Sprintf(
		"sudo wg set %s peer %q allowed-ips %s/32\nsudo wg-quick save %s\nping -c 3 -W 3 %s && curl --fail --silent --show-error -X POST %q -H 'Content-Type: application/json' --data %q",
		s.cfg.WireGuardInterface,
		response.RouterPublicKey,
		response.RouterAddress,
		s.cfg.WireGuardInterface,
		response.RouterAddress,
		statusURL,
		statusPayload,
	)
	response.VPSPeerConfig = fmt.Sprintf(
		"[Peer]\n# NobliFi router %s (%s)\nPublicKey = %s\nAllowedIPs = %s/32",
		router.Name,
		router.ID,
		response.RouterPublicKey,
		response.RouterAddress,
	)
	response.VerificationCommands = fmt.Sprintf(
		"sudo wg show %s\nping -c 3 %s",
		s.cfg.WireGuardInterface,
		response.RouterAddress,
	)
	return response
}

func (s *Service) allocateWireGuardIP() (string, error) {
	baseIP, network, err := net.ParseCIDR(strings.TrimSpace(s.cfg.WireGuardSubnetCIDR))
	if err != nil || baseIP.To4() == nil {
		return "", errors.New("NOBLIFI_WIREGUARD_SUBNET must be a valid IPv4 CIDR")
	}
	ones, bits := network.Mask.Size()
	if bits != 32 || ones > 30 {
		return "", errors.New("NOBLIFI_WIREGUARD_SUBNET must contain at least two usable router addresses")
	}

	routers, err := s.repo.List()
	if err != nil {
		return "", err
	}
	used := map[string]bool{strings.TrimSpace(s.cfg.WireGuardServerIP): true}
	for _, router := range routers {
		if router.WireGuardTunnelIP != nil {
			used[strings.TrimSpace(*router.WireGuardTunnelIP)] = true
		}
	}

	base := binary.BigEndian.Uint32(baseIP.To4())
	hostCount := uint64(1) << uint(32-ones)
	lastUsable := uint64(base) + hostCount - 2
	for candidate := uint64(base) + 2; candidate <= lastUsable; candidate++ {
		value := make(net.IP, net.IPv4len)
		binary.BigEndian.PutUint32(value, uint32(candidate))
		address := value.String()
		if !used[address] {
			return address, nil
		}
	}
	return "", errors.New("WireGuard address pool is exhausted")
}

func wireGuardConfigIssues(cfg config.Config) []string {
	issues := make([]string, 0, 4)
	if !cfg.WireGuardEnabled {
		issues = append(issues, "NOBLIFI_WIREGUARD_ENABLED is not true")
	}
	if !validRouterOSEndpoint(cfg.WireGuardEndpoint) {
		issues = append(issues, "NOBLIFI_WIREGUARD_ENDPOINT must be a VPS hostname or IP address")
	}
	if err := ValidateWireGuardPublicKey(cfg.WireGuardPublicKey); err != nil {
		issues = append(issues, "NOBLIFI_WIREGUARD_PUBLIC_KEY must contain the VPS WireGuard public key")
	}
	serverIP := net.ParseIP(strings.TrimSpace(cfg.WireGuardServerIP))
	_, network, err := net.ParseCIDR(strings.TrimSpace(cfg.WireGuardSubnetCIDR))
	if err != nil || serverIP == nil || serverIP.To4() == nil || !network.Contains(serverIP) {
		issues = append(issues, "NOBLIFI_WIREGUARD_SERVER_IP must be an IPv4 address inside NOBLIFI_WIREGUARD_SUBNET")
	}
	if !validInterfaceName(cfg.WireGuardInterface) {
		issues = append(issues, "NOBLIFI_WIREGUARD_INTERFACE contains unsupported characters")
	}
	return issues
}

func ValidateWireGuardConfig(cfg config.Config) error {
	if issues := wireGuardConfigIssues(cfg); len(issues) > 0 {
		return errors.New(strings.Join(issues, "; "))
	}
	return nil
}

func ValidateWireGuardPublicKey(value string) error {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(decoded) != 32 {
		return errors.New("invalid WireGuard public key")
	}
	return nil
}

func validRouterOSEndpoint(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || strings.Contains(value, "://") || strings.ContainsAny(value, " \t\r\n\"'/$") {
		return false
	}
	return true
}

func validInterfaceName(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	for _, ch := range value {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.' {
			continue
		}
		return false
	}
	return true
}

func routerSupportsWireGuard(version *string) bool {
	if version == nil || strings.TrimSpace(*version) == "" {
		return true
	}
	value := strings.TrimPrefix(strings.TrimSpace(*version), "v")
	value = strings.Fields(value)[0]
	majorText := strings.SplitN(value, ".", 2)[0]
	major, err := strconv.Atoi(majorText)
	return err != nil || major >= 7
}

func RenderWireGuardRouterOS(router Router, cfg config.Config) string {
	routerIP := strings.TrimSpace(*router.WireGuardTunnelIP)
	callbackURL := normalizeProvisioningBaseURL(cfg.ProvisioningBaseURL) + "/wireguard-key"
	fetchMode := provisioningFetchMode(callbackURL)

	return fmt.Sprintf(`# NobliFi management tunnel - RouterOS 7+
# This script does not alter WAN, bridges, DHCP, HotSpot ports, or the default route.
:local wgName "%s"
:local claimToken "%s"

:if ([:len [/interface wireguard find where name=$wgName]] = 0) do={
  /interface wireguard add name=$wgName mtu=1420 comment="NobliFi management tunnel"
}

:local wgInterface [/interface wireguard find where name=$wgName]
/interface wireguard set $wgInterface mtu=1420 disabled=no comment="NobliFi management tunnel"

/ip address remove [find where comment="NobliFi WireGuard address"]
/ip address add address=%s/32 interface=$wgName comment="NobliFi WireGuard address"

/interface wireguard peers remove [find where comment="NobliFi VPS"]
/interface wireguard peers add interface=$wgName public-key="%s" endpoint-address="%s" endpoint-port=%d allowed-address=%s/32 persistent-keepalive=%ds comment="NobliFi VPS"

/ip firewall filter remove [find where comment="Allow NobliFi management over WireGuard"]
/ip firewall filter remove [find where comment="Allow NobliFi WireGuard ping"]
:local inputRules [/ip firewall filter find where chain=input]
:if ([:len $inputRules] = 0) do={
  /ip firewall filter add chain=input action=accept in-interface=$wgName src-address=%s/32 protocol=tcp dst-port=8291,8728,8729 comment="Allow NobliFi management over WireGuard"
  /ip firewall filter add chain=input action=accept in-interface=$wgName src-address=%s/32 protocol=icmp comment="Allow NobliFi WireGuard ping"
} else={
  :local firstInputRule [:pick $inputRules 0]
  /ip firewall filter add chain=input action=accept in-interface=$wgName src-address=%s/32 protocol=tcp dst-port=8291,8728,8729 place-before=$firstInputRule comment="Allow NobliFi management over WireGuard"
  /ip firewall filter add chain=input action=accept in-interface=$wgName src-address=%s/32 protocol=icmp place-before=$firstInputRule comment="Allow NobliFi WireGuard ping"
}

:local routerPublicKey [/interface wireguard get $wgInterface public-key]
:local callbackPayload ("{\"token\":\"" . $claimToken . "\",\"public_key\":\"" . $routerPublicKey . "\"}")
/tool fetch url="%s" mode=%s http-method=post http-header-field="Content-Type: application/json" http-data=$callbackPayload keep-result=no

:put ("NobliFi WireGuard public key: " . $routerPublicKey)
:put "Tunnel configured. Return to NobliFi and install the generated VPS peer command."`,
		routerWireGuardInterface,
		router.ClaimToken,
		routerIP,
		cfg.WireGuardPublicKey,
		cfg.WireGuardEndpoint,
		cfg.WireGuardPort,
		cfg.WireGuardServerIP,
		cfg.WireGuardKeepalive,
		cfg.WireGuardServerIP,
		cfg.WireGuardServerIP,
		cfg.WireGuardServerIP,
		cfg.WireGuardServerIP,
		callbackURL,
		fetchMode,
	)
}
