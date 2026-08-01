package routers

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/noblifi/noblifi/backend/internal/config"
)

const (
	routerWireGuardInterface = "noblifi-wg"

	defaultWireGuardAllocationAttempts = 10
	wireGuardAllocationRetryDelay      = 100 * time.Millisecond
)

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

func (s *Service) PrepareWireGuard(
	routerID uuid.UUID,
) (WireGuardSetupResponse, error) {
	cfg := s.wireGuardConfig()
	if issues := wireGuardConfigIssues(cfg); len(issues) > 0 {
		return WireGuardSetupResponse{
			Enabled: cfg.WireGuardEnabled,
			Issues:  issues,
		}, errors.New(strings.Join(issues, "; "))
	}

	router, err := s.repo.Find(routerID)
	if err != nil {
		return WireGuardSetupResponse{}, err
	}

	if !routerSupportsWireGuard(router.RouterOSVersion) {
		return WireGuardSetupResponse{}, errors.New(
			"WireGuard requires RouterOS 7; upgrade this MikroTik before installing the tunnel",
		)
	}

	if router.WireGuardTunnelIP == nil ||
		strings.TrimSpace(*router.WireGuardTunnelIP) == "" {

		err := AllocateWireGuardIPWithRetry(
			s.repo,
			cfg,
			func(candidateIP string) error {
				/*
					Reload the router for every attempt.

					This matters when multiple App Engine instances process
					requests concurrently. A previous attempt or another
					instance may already have assigned an address.
				*/
				current, err := s.repo.Find(routerID)
				if err != nil {
					return err
				}

				/*
					Do not replace an address that another request has already
					successfully assigned to this router.
				*/
				if current.WireGuardTunnelIP != nil &&
					strings.TrimSpace(
						*current.WireGuardTunnelIP,
					) != "" {

					router = current
					return nil
				}

				allocatedIP := normalizeWireGuardAddress(candidateIP)
				if allocatedIP == "" {
					return fmt.Errorf(
						"allocator returned invalid WireGuard address %q",
						candidateIP,
					)
				}

				current.WireGuardTunnelIP = &allocatedIP
				current.ManagementIP = &allocatedIP

				if current.WireGuardPublicKey == nil ||
					strings.TrimSpace(
						*current.WireGuardPublicKey,
					) == "" {
					current.WireGuardStatus =
						"awaiting_router_key"
				}

				/*
					The PostgreSQL unique index is the final authority.

					If another App Engine instance saves the same IP first,
					this save must return SQLSTATE 23505. The allocator then
					retries with the next available address.
				*/
				if err := s.repo.Save(&current); err != nil {
					return err
				}

				router = current
				return nil
			},
			defaultWireGuardAllocationAttempts,
		)
		if err != nil {
			return WireGuardSetupResponse{}, fmt.Errorf(
				"allocate WireGuard tunnel IP: %w",
				err,
			)
		}
	} else {
		normalizedIP := normalizeWireGuardAddress(
			*router.WireGuardTunnelIP,
		)
		if normalizedIP == "" {
			return WireGuardSetupResponse{}, fmt.Errorf(
				"router has invalid WireGuard tunnel IP %q",
				strings.TrimSpace(*router.WireGuardTunnelIP),
			)
		}

		router.WireGuardTunnelIP = &normalizedIP
		router.ManagementIP = &normalizedIP

		if router.WireGuardPublicKey == nil ||
			strings.TrimSpace(
				*router.WireGuardPublicKey,
			) == "" {
			router.WireGuardStatus = "awaiting_router_key"
		}

		if err := s.repo.Save(&router); err != nil {
			return WireGuardSetupResponse{}, err
		}
	}

	profile, err := s.NetworkProfile(routerID)
	if err != nil {
		return WireGuardSetupResponse{}, err
	}

	profile.RadiusServer = cfg.WireGuardServerIP

	if err := s.repo.SaveNetworkProfile(&profile); err != nil {
		return WireGuardSetupResponse{}, err
	}

	return s.wireGuardSetupForRouter(router), nil
}

func (s *Service) WireGuardSetup(
	routerID uuid.UUID,
) (WireGuardSetupResponse, error) {
	router, err := s.repo.Find(routerID)
	if err != nil {
		return WireGuardSetupResponse{}, err
	}

	return s.wireGuardSetupForRouter(router), nil
}

func (s *Service) wireGuardSetupForRouter(
	router Router,
) WireGuardSetupResponse {
	cfg := s.wireGuardConfig()
	issues := wireGuardConfigIssues(cfg)

	response := WireGuardSetupResponse{
		Enabled: cfg.WireGuardEnabled,
		Ready: len(issues) == 0 &&
			router.WireGuardTunnelIP != nil,
		Issues:        issues,
		Status:        router.WireGuardStatus,
		InterfaceName: routerWireGuardInterface,
		Endpoint:      cfg.WireGuardEndpoint,
		EndpointPort:  cfg.WireGuardPort,
		ServerAddress: cfg.WireGuardServerIP,
	}

	if response.Status == "" {
		response.Status = "disabled"
	}

	if router.WireGuardTunnelIP == nil {
		return response
	}

	response.RouterAddress = normalizeWireGuardAddress(
		*router.WireGuardTunnelIP,
	)
	if response.RouterAddress == "" {
		response.Issues = append(
			response.Issues,
			"router has an invalid WireGuard tunnel address",
		)
		response.Ready = false
		return response
	}

	if len(issues) == 0 {
		response.MikroTikScript =
			RenderWireGuardRouterOS(router, cfg)

		wireGuardURL :=
			normalizeProvisioningBaseURL(
				cfg.ProvisioningBaseURL,
			) +
				"/wireguard/" +
				router.ClaimToken

		response.MikroTikInstallCommand =
			routerOSFetchImportCommand(
				wireGuardURL,
				provisioningFetchMode(wireGuardURL),
				"noblifi-wireguard.rsc",
			)
	}

	if router.WireGuardPublicKey == nil ||
		strings.TrimSpace(
			*router.WireGuardPublicKey,
		) == "" {
		return response
	}

	response.RouterPublicKey = strings.TrimSpace(
		*router.WireGuardPublicKey,
	)

	statusURL :=
		normalizeProvisioningBaseURL(
			cfg.ProvisioningBaseURL,
		) + "/wireguard-status"

	statusPayload := fmt.Sprintf(
		`{"token":"%s","status":"connected"}`,
		router.ClaimToken,
	)

	response.VPSPeerCommand = fmt.Sprintf(
		"sudo wg set %s peer %q allowed-ips %s/32\n"+
			"sudo wg-quick save %s\n"+
			"ping -c 3 -W 3 %s && "+
			"curl --fail --silent --show-error "+
			"-X POST %q "+
			"-H 'Content-Type: application/json' "+
			"--data %q",
		cfg.WireGuardInterface,
		response.RouterPublicKey,
		response.RouterAddress,
		cfg.WireGuardInterface,
		response.RouterAddress,
		statusURL,
		statusPayload,
	)

	response.VPSPeerConfig = fmt.Sprintf(
		"[Peer]\n"+
			"# NobliFi router %s (%s)\n"+
			"PublicKey = %s\n"+
			"AllowedIPs = %s/32",
		router.Name,
		router.ID,
		response.RouterPublicKey,
		response.RouterAddress,
	)

	response.VerificationCommands = fmt.Sprintf(
		"sudo wg show %s\nping -c 3 %s",
		cfg.WireGuardInterface,
		response.RouterAddress,
	)

	return response
}

func (s *Service) wireGuardConfig() config.Config {
	cfg := s.cfg
	if s.serverPublicKeyResolver != nil {
		if publicKey, err := s.serverPublicKeyResolver.ActiveServerPublicKey(); err == nil {
			cfg.WireGuardPublicKey = publicKey
		}
	}
	return cfg
}

// AllocateWireGuardIP returns the next currently unused router address.
//
// This function only selects a candidate. It does not guarantee ownership.
// The PostgreSQL unique index must enforce ownership when the router is saved.
func AllocateWireGuardIP(
	repo *Repository,
	cfg config.Config,
) (string, error) {
	if repo == nil {
		return "", errors.New(
			"router repository is required",
		)
	}

	baseIP, network, err := net.ParseCIDR(
		strings.TrimSpace(
			cfg.WireGuardSubnetCIDR,
		),
	)
	if err != nil ||
		baseIP == nil ||
		baseIP.To4() == nil ||
		network == nil ||
		network.IP.To4() == nil {
		return "", errors.New(
			"NOBLIFI_WIREGUARD_SUBNET must be a valid IPv4 CIDR",
		)
	}

	ones, bits := network.Mask.Size()
	if bits != 32 || ones > 30 {
		return "", errors.New(
			"NOBLIFI_WIREGUARD_SUBNET must contain usable router addresses",
		)
	}

	serverIP := net.ParseIP(
		strings.TrimSpace(
			cfg.WireGuardServerIP,
		),
	)
	if serverIP == nil ||
		serverIP.To4() == nil ||
		!network.Contains(serverIP) {
		return "", errors.New(
			"NOBLIFI_WIREGUARD_SERVER_IP must be an IPv4 address inside NOBLIFI_WIREGUARD_SUBNET",
		)
	}

	routers, err := repo.List()
	if err != nil {
		return "", fmt.Errorf(
			"list routers for WireGuard allocation: %w",
			err,
		)
	}

	used := make(
		map[string]struct{},
		len(routers)+3,
	)

	// Reserve the VPS address.
	used[serverIP.To4().String()] = struct{}{}

	// Reserve the network address.
	networkAddress := network.IP.To4().String()
	used[networkAddress] = struct{}{}

	// Reserve the broadcast address.
	broadcastAddress, err :=
		ipv4BroadcastAddress(network)
	if err != nil {
		return "", err
	}
	used[broadcastAddress] = struct{}{}

	/*
		Reserve every address already stored against a router.

		This intentionally treats an existing router assignment as occupied.
		A router reset should keep the same router record and IP while replacing
		only its WireGuard public key.
	*/
	for _, existingRouter := range routers {
		if existingRouter.WireGuardTunnelIP == nil {
			continue
		}

		address := normalizeWireGuardAddress(
			*existingRouter.WireGuardTunnelIP,
		)
		if address == "" {
			continue
		}

		used[address] = struct{}{}
	}

	base := binary.BigEndian.Uint32(
		network.IP.To4(),
	)

	hostCount := uint64(1) << uint(32-ones)

	/*
		The NobliFi allocation convention is:

		10.77.0.1 = VPS
		10.77.0.2 = first MikroTik
		10.77.0.3 = second MikroTik
		...

		Therefore allocation starts at network base + 2.
	*/
	firstCandidate := uint64(base) + 2
	lastCandidate := uint64(base) + hostCount - 2

	for candidate := firstCandidate; candidate <= lastCandidate; candidate++ {

		if candidate > uint64(^uint32(0)) {
			break
		}

		value := make(net.IP, net.IPv4len)

		binary.BigEndian.PutUint32(
			value,
			uint32(candidate),
		)

		address := value.String()

		if _, alreadyUsed := used[address]; alreadyUsed {
			continue
		}

		return address, nil
	}

	return "", errors.New(
		"WireGuard address pool is exhausted",
	)
}

// AllocateWireGuardIPWithRetry selects an address and calls save.
//
// Multiple App Engine instances can calculate the same free candidate.
// The database unique index determines which request wins. A request losing
// that race receives a unique-constraint error and calculates another address.
func AllocateWireGuardIPWithRetry(
	repo *Repository,
	cfg config.Config,
	save func(ip string) error,
	maxAttempts int,
) error {
	if repo == nil {
		return errors.New(
			"router repository is required",
		)
	}

	if save == nil {
		return errors.New(
			"WireGuard allocation save function is required",
		)
	}

	if maxAttempts <= 0 {
		maxAttempts =
			defaultWireGuardAllocationAttempts
	}

	var lastErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		candidateIP, err :=
			AllocateWireGuardIP(repo, cfg)
		if err != nil {
			return err
		}

		err = save(candidateIP)
		if err == nil {
			return nil
		}

		if !isUniqueViolation(err) {
			return fmt.Errorf(
				"save allocated WireGuard IP %s: %w",
				candidateIP,
				err,
			)
		}

		lastErr = err

		if attempt < maxAttempts {
			time.Sleep(
				wireGuardAllocationRetryDelay,
			)
		}
	}

	if lastErr == nil {
		return fmt.Errorf(
			"could not allocate a unique WireGuard tunnel IP after %d attempts",
			maxAttempts,
		)
	}

	return fmt.Errorf(
		"could not allocate a unique WireGuard tunnel IP after %d attempts: %w",
		maxAttempts,
		lastErr,
	)
}

func normalizeWireGuardAddress(
	value string,
) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	/*
		Support both database formats:

		10.77.0.2
		10.77.0.2/32
	*/
	if strings.Contains(value, "/") {
		ip, _, err := net.ParseCIDR(value)
		if err != nil ||
			ip == nil ||
			ip.To4() == nil {
			return ""
		}

		return ip.To4().String()
	}

	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return ""
	}

	return ip.To4().String()
}

func ipv4BroadcastAddress(
	network *net.IPNet,
) (string, error) {
	if network == nil ||
		network.IP == nil ||
		network.IP.To4() == nil {
		return "", errors.New(
			"cannot calculate broadcast address for invalid IPv4 network",
		)
	}

	ones, bits := network.Mask.Size()
	if bits != 32 {
		return "", errors.New(
			"cannot calculate broadcast address for non-IPv4 network",
		)
	}

	base := binary.BigEndian.Uint32(
		network.IP.To4(),
	)

	hostCount := uint64(1) << uint(32-ones)
	broadcast := uint64(base) + hostCount - 1

	if broadcast > uint64(^uint32(0)) {
		return "", errors.New(
			"calculated WireGuard broadcast address is invalid",
		)
	}

	value := make(net.IP, net.IPv4len)

	binary.BigEndian.PutUint32(
		value,
		uint32(broadcast),
	)

	return value.String(), nil
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}

	message := strings.ToLower(err.Error())

	return strings.Contains(
		message,
		"sqlstate 23505",
	) ||
		strings.Contains(
			message,
			"unique constraint",
		) ||
		strings.Contains(
			message,
			"duplicate key",
		) ||
		strings.Contains(
			message,
			"unique violation",
		)
}

func wireGuardConfigIssues(
	cfg config.Config,
) []string {
	issues := make([]string, 0, 4)

	if !cfg.WireGuardEnabled {
		issues = append(
			issues,
			"NOBLIFI_WIREGUARD_ENABLED is not true",
		)
	}

	if !validRouterOSEndpoint(
		cfg.WireGuardEndpoint,
	) {
		issues = append(
			issues,
			"NOBLIFI_WIREGUARD_ENDPOINT must be a VPS hostname or IP address",
		)
	}

	if err := ValidateWireGuardPublicKey(
		cfg.WireGuardPublicKey,
	); err != nil {
		issues = append(
			issues,
			"NOBLIFI_WIREGUARD_PUBLIC_KEY must contain the VPS WireGuard public key",
		)
	}

	serverIP := net.ParseIP(
		strings.TrimSpace(
			cfg.WireGuardServerIP,
		),
	)

	_, network, err := net.ParseCIDR(
		strings.TrimSpace(
			cfg.WireGuardSubnetCIDR,
		),
	)

	if err != nil ||
		serverIP == nil ||
		serverIP.To4() == nil ||
		network == nil ||
		!network.Contains(serverIP) {
		issues = append(
			issues,
			"NOBLIFI_WIREGUARD_SERVER_IP must be an IPv4 address inside NOBLIFI_WIREGUARD_SUBNET",
		)
	}

	if !validInterfaceName(
		cfg.WireGuardInterface,
	) {
		issues = append(
			issues,
			"NOBLIFI_WIREGUARD_INTERFACE contains unsupported characters",
		)
	}

	return issues
}

func ValidateWireGuardConfig(
	cfg config.Config,
) error {
	if issues := wireGuardConfigIssues(cfg); len(issues) > 0 {
		return errors.New(
			strings.Join(issues, "; "),
		)
	}

	return nil
}

func ValidateWireGuardPublicKey(
	value string,
) error {
	decoded, err := base64.StdEncoding.DecodeString(
		strings.TrimSpace(value),
	)
	if err != nil || len(decoded) != 32 {
		return errors.New(
			"invalid WireGuard public key",
		)
	}

	return nil
}

func validRouterOSEndpoint(
	value string,
) bool {
	value = strings.TrimSpace(value)

	if value == "" ||
		strings.Contains(value, "://") ||
		strings.ContainsAny(
			value,
			" \t\r\n\"'/$",
		) {
		return false
	}

	return true
}

func validInterfaceName(
	value string,
) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}

	for _, ch := range value {
		if (ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '_' ||
			ch == '-' ||
			ch == '.' {
			continue
		}

		return false
	}

	return true
}

func routerSupportsWireGuard(
	version *string,
) bool {
	if version == nil ||
		strings.TrimSpace(*version) == "" {
		return true
	}

	value := strings.TrimPrefix(
		strings.TrimSpace(*version),
		"v",
	)

	fields := strings.Fields(value)
	if len(fields) == 0 {
		return true
	}

	value = fields[0]

	majorText := strings.SplitN(
		value,
		".",
		2,
	)[0]

	major, err := strconv.Atoi(majorText)

	return err != nil || major >= 7
}

func RenderWireGuardRouterOS(
	router Router,
	cfg config.Config,
) string {
	routerIP := normalizeWireGuardAddress(
		*router.WireGuardTunnelIP,
	)

	baseURL := normalizeProvisioningBaseURL(
		cfg.ProvisioningBaseURL,
	)

	callbackURL := baseURL + "/wireguard-key"
	statusURL := baseURL + "/wireguard-status"

	fetchMode := provisioningFetchMode(
		callbackURL,
	)

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

:do { /user remove [find where name="%s" comment="NobliFi API management user"] } on-error={}
:do { /user add name="%s" group=full password="%s" comment="NobliFi API management user" } on-error={ :error "NobliFi failed to create API management user" }
:do { /ip service set api disabled=no address=%s/32 } on-error={ :error "NobliFi failed to enable restricted RouterOS API" }

:local routerPublicKey [/interface wireguard get $wgInterface public-key]
:put ("NobliFi WireGuard public key: " . $routerPublicKey)
:local callbackPayload ("{\"claim_token\":\"" . $claimToken . "\",\"public_key\":\"" . $routerPublicKey . "\"}")
:local keyReported false
:for attempt from=1 to=3 do={
  :if (!$keyReported) do={
    :do {
      :local keyResult [/tool fetch url="%s" mode=%s http-method=post http-header-field="Content-Type: application/json" http-data=$callbackPayload output=user as-value idle-timeout=30s duration=1m]
      :if (($keyResult->"status") = "finished") do={
        :set keyReported true
      }
    } on-error={
      :log warning ("NobliFi WireGuard key report attempt " . $attempt . " failed")
    }
    :if (!$keyReported) do={
      :delay 3s
    }
  }
}

:if (!$keyReported) do={
  :error "NobliFi could not register this router WireGuard key with the control plane"
}

:put "NobliFi WireGuard key registered; waiting for xneelo agent"
:local wgPeer [/interface wireguard peers find where interface=$wgName comment="NobliFi VPS"]
:local connected false
:local lastHandshake ""

:for second from=1 to=120 do={
  :do {
    /tool ping address="%s" src-address="%s" interface=$wgName count=1 interval=200ms
  } on-error={}

  :if ([:len $wgPeer] > 0) do={
    :local rx [/interface wireguard peers get [:pick $wgPeer 0] rx]
    :set lastHandshake [/interface wireguard peers get [:pick $wgPeer 0] last-handshake]

    :if (($rx > 0) && ($lastHandshake != "")) do={
      :set connected true
    }
  }

  :if ($connected) do={
    :set second 120
  } else={
    :delay 1s
  }
}

:if ($connected) do={
  :put ("NobliFi WireGuard connected; last-handshake=" . $lastHandshake)
  :local connectedPayload ("{\"claim_token\":\"" . $claimToken . "\",\"status\":\"connected\"}")

  :do {
    /tool fetch url="%s" mode=%s http-method=post http-header-field="Content-Type: application/json" http-data=$connectedPayload keep-result=no
  } on-error={
    :log warning "NobliFi connected status report failed"
  }
} else={
  :local failedPayload ("{\"claim_token\":\"" . $claimToken . "\",\"status\":\"failed\"}")

  :do {
    /tool fetch url="%s" mode=%s http-method=post http-header-field="Content-Type: application/json" http-data=$failedPayload keep-result=no
  } on-error={
    :log warning "NobliFi failed status report failed"
  }

  :error "NobliFi xneelo agent did not establish a WireGuard handshake within 120 seconds"
}`,
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
		routerOSQuotedString(cfg.RouterAPIUsername),
		routerOSQuotedString(cfg.RouterAPIUsername),
		routerOSQuotedString(cfg.RouterAPIPassword),
		cfg.WireGuardServerIP,
		callbackURL,
		fetchMode,
		cfg.WireGuardServerIP,
		routerIP,
		statusURL,
		fetchMode,
		statusURL,
		fetchMode,
	)
}

func routerOSQuotedString(value string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value)
}
