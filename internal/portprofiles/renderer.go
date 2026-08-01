package portprofiles

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/noblifi/noblifi/backend/internal/placeholders"
)

type Summary struct {
	WAN        []string `json:"wan"`
	HotspotLAN []string `json:"hotspot_lan"`
	StaffLAN   []string `json:"staff_lan"`
	POSLAN     []string `json:"pos_lan"`
	CCTVLAN    []string `json:"cctv_lan"`
	Disabled   []string `json:"disabled"`
}

type RenderOptions struct {
	RadiusServer          string
	RadiusSecret          string
	LoginPageURL          string
	HotspotSupportBaseURL string

	// ProvisioningBaseURL must end in /api/v1/provisioning. The claim token is
	// embedded only in the generated RouterOS installer; the xneelo agent token
	// must never be passed to this renderer.
	ProvisioningBaseURL    string
	ProvisioningClaimToken string

	RouterIdentity      string
	APIUsername         string
	APIPassword         string
	HotspotBridge       string
	StaffBridge         string
	POSBridge           string
	CCTVBridge          string
	HotspotSubnet       string
	HotspotGateway      string
	HotspotPool         string
	StaffSubnet         string
	StaffGateway        string
	StaffPool           string
	POSSubnet           string
	POSGateway          string
	POSPool             string
	CCTVSubnet          string
	CCTVGateway         string
	CCTVPool            string
	HotspotDNSName      string
	HotspotPortalName   string
	DisableWWWService   bool
	EnableAPIService    bool
	EnableAPISSLService bool
	WalledGardenHosts   []string

	// WireGuard management tunnel. WireGuardClientIP must be unique per router.
	WireGuardEnabled              bool
	WireGuardEndpoint             string
	WireGuardPort                 int
	WireGuardPublicKey            string
	WireGuardInterface            string
	WireGuardServerIP             string
	WireGuardClientIP             string
	WireGuardKeepalive            int
	WireGuardAgentManaged         bool
	WireGuardHandshakeWaitSeconds int
}

func DefaultAssignments() []Assignment {
	return []Assignment{
		{InterfaceName: "ether1", Role: "WAN"},
		{InterfaceName: "ether2", Role: "HOTSPOT_LAN"},
		{InterfaceName: "ether3", Role: "HOTSPOT_LAN"},
		{InterfaceName: "ether4", Role: "HOTSPOT_LAN"},
		{InterfaceName: "ether5", Role: "STAFF_LAN"},
	}
}

func BuildSummary(assignments []Assignment) Summary {
	summary := Summary{
		WAN:        []string{},
		HotspotLAN: []string{},
		StaffLAN:   []string{},
		POSLAN:     []string{},
		CCTVLAN:    []string{},
		Disabled:   []string{},
	}
	for _, assignment := range assignments {
		name := assignment.Name()
		switch assignment.Role {
		case "WAN":
			summary.WAN = append(summary.WAN, name)
		case "HOTSPOT_LAN":
			summary.HotspotLAN = append(summary.HotspotLAN, name)
		case "STAFF_LAN":
			summary.StaffLAN = append(summary.StaffLAN, name)
		case "POS_LAN":
			summary.POSLAN = append(summary.POSLAN, name)
		case "CCTV_LAN":
			summary.CCTVLAN = append(summary.CCTVLAN, name)
		case "DISABLED":
			summary.Disabled = append(summary.Disabled, name)
		}
	}
	sort.Strings(summary.WAN)
	sort.Strings(summary.HotspotLAN)
	sort.Strings(summary.StaffLAN)
	sort.Strings(summary.POSLAN)
	sort.Strings(summary.CCTVLAN)
	sort.Strings(summary.Disabled)
	return summary
}

func RenderRouterOS(assignments []Assignment) (string, error) {
	return RenderRouterOSWithOptions(assignments, RenderOptions{
		RadiusServer:                  "127.0.0.1",
		RadiusSecret:                  "noblifi",
		LoginPageURL:                  "",
		RouterIdentity:                "NobliFi-Router",
		APIUsername:                   "noblifi-api",
		APIPassword:                   "CHANGE_ME_API_PASSWORD",
		HotspotBridge:                 "br-hotspot",
		StaffBridge:                   "br-staff",
		POSBridge:                     "br-pos",
		CCTVBridge:                    "br-cctv",
		HotspotSubnet:                 "10.10.10.0/24",
		HotspotGateway:                "10.10.10.1/24",
		HotspotPool:                   "10.10.10.10-10.10.10.254",
		StaffSubnet:                   "10.20.20.0/24",
		StaffGateway:                  "10.20.20.1/24",
		StaffPool:                     "10.20.20.10-10.20.20.254",
		POSSubnet:                     "10.30.30.0/24",
		POSGateway:                    "10.30.30.1/24",
		POSPool:                       "10.30.30.10-10.30.30.254",
		CCTVSubnet:                    "10.40.40.0/24",
		CCTVGateway:                   "10.40.40.1/24",
		CCTVPool:                      "10.40.40.10-10.40.40.254",
		HotspotDNSName:                "noblifi.login",
		HotspotPortalName:             "NobliFi WiFi",
		DisableWWWService:             true,
		EnableAPIService:              true,
		EnableAPISSLService:           true,
		WalledGardenHosts:             defaultWalledGardenHosts(),
		WireGuardEnabled:              false,
		WireGuardPort:                 51820,
		WireGuardInterface:            "noblifi-wg",
		WireGuardServerIP:             "10.77.0.1",
		WireGuardKeepalive:            25,
		WireGuardHandshakeWaitSeconds: 120,
	})
}

func RenderRouterOSWithOptions(assignments []Assignment, options RenderOptions) (string, error) {
	// Preserve the legacy renderer contract for installations that have not
	// enabled agent-managed WireGuard yet.
	normalized := withDefaults(options)
	if !normalized.WireGuardEnabled {
		return RenderManagedRouterConfig(assignments, options)
	}

	managementScript, err := RenderManagementBootstrap(options)
	if err != nil {
		return "", err
	}

	managedScript, err := RenderManagedRouterConfig(assignments, options)
	if err != nil {
		return "", err
	}

	return managementScript + "\n" + managedScript, nil
}

// RenderManagementBootstrap renders only the configuration required to create
// and verify the management tunnel. It deliberately does not touch HotSpot LAN
// ports, DHCP, NAT, RADIUS, or captive-portal files. Those are applied later by
// the xneelo agent after the WireGuard peer is reachable.
func RenderManagementBootstrap(options RenderOptions) (string, error) {
	options = withDefaults(options)
	options = withProvisioningContext(options)

	if isPlaceholderAPIPassword(options.APIPassword) {
		return "", fmt.Errorf("NOBLIFI_ROUTER_API_PASSWORD must be set to a real router API password before provisioning")
	}
	if err := validateWireGuardOptions(options); err != nil {
		return "", err
	}
	if !options.WireGuardEnabled {
		return "", fmt.Errorf("WireGuard must be enabled for agent-managed router provisioning")
	}

	var builder strings.Builder
	builder.WriteString("# NobliFi management bootstrap\n")
	builder.WriteString("# Establishes the xneelo WireGuard management path only.\n\n")

	builder.WriteString("# Management identity, user, and RouterOS services\n")
	writeSafe(&builder, fmt.Sprintf(`/system identity set name="%s"`, escape(options.RouterIdentity)), "set identity")
	writeSafe(&builder, fmt.Sprintf(`/user remove [find where name="%s" comment="NobliFi API management user"]`, escape(options.APIUsername)), "cleanup api user")
	writeCritical(&builder, fmt.Sprintf(`/user add name="%s" group=full password="%s" comment="NobliFi API management user"`, escape(options.APIUsername), escape(options.APIPassword)), "add api user")
	writeSafe(&builder, `/ip service set telnet disabled=yes`, "disable telnet")
	writeSafe(&builder, `/ip service set ftp disabled=yes`, "disable ftp")
	if options.DisableWWWService {
		writeSafe(&builder, `/ip service set www disabled=yes`, "disable www")
	}
	// Restrict management before enabling it. There is no period where the API
	// is exposed to arbitrary WAN addresses while the tunnel is being created.
	serverCIDR := routerOSHostRoute(options.WireGuardServerIP)
	writeSafe(&builder, fmt.Sprintf(`/ip service set api disabled=%s address="%s"`, routerOSDisabled(!options.EnableAPIService), escape(serverCIDR)), "set restricted api service")
	writeSafe(&builder, fmt.Sprintf(`/ip service set api-ssl disabled=%s address="%s"`, routerOSDisabled(!options.EnableAPISSLService), escape(serverCIDR)), "set restricted api-ssl service")
	writeCritical(&builder, `:if ([:len [/interface list find where name="LAN"]] = 0) do={ /interface list add name=LAN comment="NobliFi LAN list" }`, "ensure LAN list")
	builder.WriteString("\n")

	writeWireGuardManagement(&builder, options)

	builder.WriteString(`:put "NobliFi management bootstrap completed; xneelo agent will configure HotSpot, RADIUS, DHCP, NAT, and portal files"` + "\n")
	return builder.String(), nil
}

// RenderManagedRouterConfig renders the desired HotSpot/RADIUS/network state
// that the xneelo agent applies over the already-established WireGuard tunnel.
// It intentionally excludes WireGuard creation and the public-key callback.
func RenderManagedRouterConfig(assignments []Assignment, options RenderOptions) (string, error) {
	if err := Validate(assignments); err != nil {
		return "", err
	}

	options = withDefaults(options)
	options = withProvisioningContext(options)

	// For WireGuard installs, RADIUS is carried through the management tunnel.
	// Non-WireGuard/manual installs must keep the explicitly configured public
	// RADIUS address.
	if options.WireGuardEnabled && strings.TrimSpace(options.WireGuardServerIP) != "" {
		options.RadiusServer = strings.TrimSpace(options.WireGuardServerIP)
	}
	if isPlaceholderRadiusServer(options.RadiusServer) {
		return "", fmt.Errorf("agent-managed RADIUS server is %q; set WireGuardServerIP to the xneelo tunnel address, normally 10.77.0.1", options.RadiusServer)
	}
	if isPlaceholderRadiusSecret(options.RadiusSecret) {
		options.RadiusSecret = "noblifi"
	}
	if err := validateLoginPageURL(options.LoginPageURL); err != nil {
		return "", err
	}

	summary := BuildSummary(assignments)
	wan := summary.WAN[0]
	hotspotGateway := strings.Split(options.HotspotGateway, "/")[0]

	var builder strings.Builder
	builder.WriteString("# NobliFi xneelo agent-managed RouterOS configuration\n")
	builder.WriteString("# Applied after the WireGuard management tunnel is reachable.\n\n")

	// Resolve the custom HotSpot directory once and keep both values together.
	builder.WriteString(`:local hotspotHtmlDir "noblifi"` + "\n")
	builder.WriteString(`:local hotspotHtmlPath "noblifi"` + "\n")
	builder.WriteString(`:if ([:len [/file find where name="flash"]] > 0) do={ :set hotspotHtmlDir "flash/noblifi"; :set hotspotHtmlPath "flash/noblifi" }` + "\n\n")

	builder.WriteString("# Replace NobliFi-owned HotSpot, RADIUS, NAT, and LAN state\n")
	writeSafe(&builder, `/ip hotspot remove [find where name="noblifi-hotspot"]`, "cleanup hotspot server")
	writeSafe(&builder, `/ip hotspot user profile remove [find where name="noblifi-voucher-profile"]`, "cleanup hotspot user profile")
	writeSafe(&builder, `/ip hotspot walled-garden remove [find where comment="NobliFi captive portal"]`, "cleanup captive portal walled garden")
	writeSafe(&builder, `/system scheduler remove [find where name="noblifi-hotspot-login-refresh"]`, "cleanup stale hotspot login refresh scheduler")
	writeSafe(&builder, `/system script remove [find where name="noblifi-hotspot-login-refresh-script"]`, "cleanup stale hotspot login refresh script")
	writeSafe(&builder, `/radius remove [find where comment="NobliFi RADIUS"]`, "cleanup radius client")
	writeSafe(&builder, `/ip firewall nat remove [find where comment="NobliFi client NAT"]`, "cleanup nat")

	writeCleanup(&builder, options.HotspotBridge, "dhcp-hotspot", "pool-hotspot", options.HotspotSubnet)
	writeCleanup(&builder, options.StaffBridge, "dhcp-staff", "pool-staff", options.StaffSubnet)
	writeCleanup(&builder, options.POSBridge, "dhcp-pos", "pool-pos", options.POSSubnet)
	writeCleanup(&builder, options.CCTVBridge, "dhcp-cctv", "pool-cctv", options.CCTVSubnet)
	builder.WriteString("\n")

	// The management path is WireGuard, so LAN-port movement can continue even
	// when the operator's local WinBox/WebFig session is interrupted.
	writeWANInternet(&builder, wan)
	writeHotspotNetwork(&builder, options, summary.HotspotLAN, hotspotGateway)
	writeBridge(&builder, options.StaffBridge, summary.StaffLAN, options.StaffGateway, "pool-staff", options.StaffPool, options.StaffSubnet)
	writeBridge(&builder, options.POSBridge, summary.POSLAN, options.POSGateway, "pool-pos", options.POSPool, options.POSSubnet)
	writeBridge(&builder, options.CCTVBridge, summary.CCTVLAN, options.CCTVGateway, "pool-cctv", options.CCTVPool, options.CCTVSubnet)
	writeHotspotServices(&builder, options, hotspotGateway)

	builder.WriteString(`:put "NobliFi agent-managed HotSpot, RADIUS, DHCP, NAT, and captive portal configuration completed"` + "\n")
	return builder.String(), nil
}

func withDefaults(options RenderOptions) RenderOptions {
	defaults := RenderOptions{
		RouterIdentity:                "NobliFi-Router",
		APIUsername:                   "noblifi-api",
		APIPassword:                   "CHANGE_ME_API_PASSWORD",
		HotspotBridge:                 "br-hotspot",
		StaffBridge:                   "br-staff",
		POSBridge:                     "br-pos",
		CCTVBridge:                    "br-cctv",
		HotspotSubnet:                 "10.10.10.0/24",
		HotspotGateway:                "10.10.10.1/24",
		HotspotPool:                   "10.10.10.10-10.10.10.254",
		StaffSubnet:                   "10.20.20.0/24",
		StaffGateway:                  "10.20.20.1/24",
		StaffPool:                     "10.20.20.10-10.20.20.254",
		POSSubnet:                     "10.30.30.0/24",
		POSGateway:                    "10.30.30.1/24",
		POSPool:                       "10.30.30.10-10.30.30.254",
		CCTVSubnet:                    "10.40.40.0/24",
		CCTVGateway:                   "10.40.40.1/24",
		CCTVPool:                      "10.40.40.10-10.40.40.254",
		HotspotDNSName:                "noblifi.login",
		HotspotPortalName:             "NobliFi WiFi",
		DisableWWWService:             true,
		EnableAPIService:              true,
		EnableAPISSLService:           true,
		WalledGardenHosts:             defaultWalledGardenHosts(),
		WireGuardPort:                 51820,
		WireGuardInterface:            "noblifi-wg",
		WireGuardServerIP:             "10.77.0.1",
		WireGuardKeepalive:            25,
		WireGuardHandshakeWaitSeconds: 120,
	}
	if options.RouterIdentity == "" {
		options.RouterIdentity = defaults.RouterIdentity
	}
	if options.APIUsername == "" {
		options.APIUsername = defaults.APIUsername
	}
	if options.APIPassword == "" {
		options.APIPassword = defaults.APIPassword
	}
	if options.HotspotBridge == "" {
		options.HotspotBridge = defaults.HotspotBridge
	}
	if options.StaffBridge == "" {
		options.StaffBridge = defaults.StaffBridge
	}
	if options.POSBridge == "" {
		options.POSBridge = defaults.POSBridge
	}
	if options.CCTVBridge == "" {
		options.CCTVBridge = defaults.CCTVBridge
	}
	if options.HotspotSubnet == "" {
		options.HotspotSubnet = defaults.HotspotSubnet
	}
	if options.HotspotGateway == "" {
		options.HotspotGateway = defaults.HotspotGateway
	}
	if options.HotspotPool == "" {
		options.HotspotPool = defaults.HotspotPool
	}
	if options.StaffSubnet == "" {
		options.StaffSubnet = defaults.StaffSubnet
	}
	if options.StaffGateway == "" {
		options.StaffGateway = defaults.StaffGateway
	}
	if options.StaffPool == "" {
		options.StaffPool = defaults.StaffPool
	}
	if options.POSSubnet == "" {
		options.POSSubnet = defaults.POSSubnet
	}
	if options.POSGateway == "" {
		options.POSGateway = defaults.POSGateway
	}
	if options.POSPool == "" {
		options.POSPool = defaults.POSPool
	}
	if options.CCTVSubnet == "" {
		options.CCTVSubnet = defaults.CCTVSubnet
	}
	if options.CCTVGateway == "" {
		options.CCTVGateway = defaults.CCTVGateway
	}
	if options.CCTVPool == "" {
		options.CCTVPool = defaults.CCTVPool
	}
	options.HotspotDNSName = normalizeHotspotDNSName(options.HotspotDNSName)
	if options.HotspotPortalName == "" {
		options.HotspotPortalName = defaults.HotspotPortalName
	}
	if len(options.WalledGardenHosts) == 0 {
		options.WalledGardenHosts = defaults.WalledGardenHosts
	}
	if options.WireGuardPort == 0 {
		options.WireGuardPort = defaults.WireGuardPort
	}
	if options.WireGuardInterface == "" {
		options.WireGuardInterface = defaults.WireGuardInterface
	}
	if options.WireGuardServerIP == "" {
		options.WireGuardServerIP = defaults.WireGuardServerIP
	}
	if options.WireGuardKeepalive == 0 {
		options.WireGuardKeepalive = defaults.WireGuardKeepalive
	}
	if options.WireGuardHandshakeWaitSeconds == 0 {
		options.WireGuardHandshakeWaitSeconds = defaults.WireGuardHandshakeWaitSeconds
	}
	options.WalledGardenHosts = cleanHosts(options.WalledGardenHosts)
	return options
}

// withProvisioningContext derives the public provisioning API base and router
// claim token from LoginPageURL when the caller did not set them explicitly.
// ClaimConfig already sets LoginPageURL to
// .../api/v1/provisioning/hotspot-login/<token>, so existing callers become
// agent-aware without receiving the private xneelo agent credential.
func withProvisioningContext(options RenderOptions) RenderOptions {
	options.ProvisioningBaseURL = strings.TrimRight(strings.TrimSpace(options.ProvisioningBaseURL), "/")
	options.ProvisioningClaimToken = strings.TrimSpace(options.ProvisioningClaimToken)

	if options.ProvisioningBaseURL == "" || options.ProvisioningClaimToken == "" {
		loginURL := strings.TrimSpace(options.LoginPageURL)
		if parsed, err := url.Parse(loginURL); err == nil && parsed.Scheme != "" && parsed.Host != "" {
			const marker = "/hotspot-login/"
			if index := strings.LastIndex(parsed.Path, marker); index >= 0 {
				if options.ProvisioningBaseURL == "" {
					basePath := strings.TrimRight(parsed.Path[:index], "/")
					options.ProvisioningBaseURL = parsed.Scheme + "://" + parsed.Host + basePath
				}
				if options.ProvisioningClaimToken == "" {
					options.ProvisioningClaimToken = strings.TrimSpace(parsed.Path[index+len(marker):])
				}
			}
		}
	}

	if options.WireGuardEnabled &&
		options.ProvisioningBaseURL != "" &&
		options.ProvisioningClaimToken != "" {
		options.WireGuardAgentManaged = true
	}

	return options
}

func normalizeHotspotDNSName(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimPrefix(value, "https://")
	value = strings.TrimPrefix(value, "http://")

	if slash := strings.Index(value, "/"); slash >= 0 {
		value = value[:slash]
	}

	value = strings.TrimSuffix(value, ".")

	// Accept the short NobliFi value from older provisioning records,
	// but always configure RouterOS with a proper hostname.
	if value == "" || value == "noblifi" {
		return "noblifi.login"
	}

	return value
}

func isPlaceholderRadiusSecret(value string) bool {
	return placeholders.Is(value)
}

func isPlaceholderRadiusServer(value string) bool {
	server := strings.TrimSpace(value)
	return server == "" || server == "127.0.0.1" || strings.EqualFold(server, "localhost") || placeholders.Is(server)
}

func isPlaceholderAPIPassword(value string) bool {
	return placeholders.Is(value)
}

func validateLoginPageURL(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("NOBLIFI_PROVISIONING_BASE_URL produced invalid HotSpot login URL %q", value)
	}
	if parsed.Host == "noblifi-frontend.vercel.app" {
		return fmt.Errorf("NOBLIFI_PROVISIONING_BASE_URL points at the frontend host %q. Set it to the backend API base ending in /api/v1/provisioning, for example https://noblifi.ew.r.appspot.com/api/v1/provisioning", parsed.Host)
	}
	if !strings.Contains(parsed.Path, "/api/v1/provisioning/hotspot-login/") {
		return fmt.Errorf("NOBLIFI_PROVISIONING_BASE_URL produced HotSpot login URL %q, but MikroTik must fetch the backend /api/v1/provisioning/hotspot-login/:token route directly with no redirects", value)
	}
	return nil
}

func validateWireGuardOptions(options RenderOptions) error {
	if !options.WireGuardEnabled {
		return nil
	}

	if strings.TrimSpace(options.WireGuardEndpoint) == "" {
		return fmt.Errorf("NOBLIFI_WIREGUARD_ENDPOINT must be set when WireGuard provisioning is enabled")
	}
	if strings.TrimSpace(options.WireGuardPublicKey) == "" {
		return fmt.Errorf("NOBLIFI_WIREGUARD_PUBLIC_KEY must contain the VPS WireGuard public key")
	}
	if strings.TrimSpace(options.WireGuardClientIP) == "" {
		return fmt.Errorf("WireGuardClientIP must be allocated uniquely for this router; do not reuse 10.77.0.2 on every MikroTik")
	}
	if options.WireGuardPort < 1 || options.WireGuardPort > 65535 {
		return fmt.Errorf("invalid WireGuard port %d", options.WireGuardPort)
	}
	if options.WireGuardKeepalive < 1 || options.WireGuardKeepalive > 65535 {
		return fmt.Errorf("invalid WireGuard keepalive %d", options.WireGuardKeepalive)
	}
	if options.WireGuardHandshakeWaitSeconds < 15 || options.WireGuardHandshakeWaitSeconds > 600 {
		return fmt.Errorf("WireGuard handshake wait must be between 15 and 600 seconds")
	}

	if options.WireGuardAgentManaged {
		baseURL := strings.TrimSpace(options.ProvisioningBaseURL)
		claimToken := strings.TrimSpace(options.ProvisioningClaimToken)
		if baseURL == "" {
			return fmt.Errorf("ProvisioningBaseURL is required for agent-managed WireGuard")
		}
		if claimToken == "" {
			return fmt.Errorf("ProvisioningClaimToken is required for agent-managed WireGuard")
		}
		parsed, err := url.Parse(baseURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("invalid agent provisioning base URL %q", baseURL)
		}
		if !strings.HasSuffix(strings.TrimRight(parsed.Path, "/"), "/api/v1/provisioning") {
			return fmt.Errorf("agent provisioning base URL must end in /api/v1/provisioning")
		}
	}

	return nil
}

func routerOSHostRoute(ip string) string {
	ip = strings.TrimSpace(ip)
	if strings.Contains(ip, "/") {
		return ip
	}
	return ip + "/32"
}

func routerOSDisabled(disabled bool) string {
	if disabled {
		return "yes"
	}
	return "no"
}

func escape(value string) string {
	return strings.ReplaceAll(value, `"`, `\"`)
}

func writeSafe(builder *strings.Builder, command string, label string) {
	builder.WriteString(fmt.Sprintf(":do { %s } on-error={ :put \"NobliFi skipped %s\" }\n", command, escape(label)))
}

func writeCritical(builder *strings.Builder, command string, label string) {
	builder.WriteString(fmt.Sprintf(":do { %s } on-error={ :error \"NobliFi failed %s\" }\n", command, escape(label)))
}

// writeWANDHCPWait polls the WAN DHCP client for up to 20 seconds, waiting
// for status=bound before the rest of the script proceeds. See the comment
// at its call site in RenderRouterOSWithOptions for why this is necessary:
// the WAN dhcp-client is torn down and re-created earlier in this same
// script, and /ip dhcp-client add does not block until a lease is acquired.
// This deliberately warns rather than :error's out on timeout, because a
// genuinely dead WAN link is already caught by the later "verify hotspot
// server" critical checks, and aborting here would duplicate that failure
// mode with a less specific message.
// writeWANInternet resolves the actual Layer-3 WAN interface and configures
// DHCP/interface-list membership without deleting a working factory DHCP
// client. Example: when ether1 belongs to bridgeLocal, wanL3 becomes
// bridgeLocal and all L3 WAN operations use that bridge.
func writeWANInternet(builder *strings.Builder, wanPhysical string) {
	builder.WriteString("# Interface lists and WAN internet\n")

	writeCritical(builder, `:if ([:len [/interface list find where name="WAN"]] = 0) do={ /interface list add name=WAN comment="NobliFi WAN list" }`, "ensure WAN list")
	writeCritical(builder, `:if ([:len [/interface list find where name="LAN"]] = 0) do={ /interface list add name=LAN comment="NobliFi LAN list" }`, "ensure LAN list")

	builder.WriteString(fmt.Sprintf(`:local wanPhysical "%s"`, escape(wanPhysical)) + "\n")
	builder.WriteString(`:local wanL3 $wanPhysical` + "\n")
	builder.WriteString(`:local wanBridgePort [/interface bridge port find where interface=$wanPhysical]` + "\n")
	builder.WriteString(`:if ([:len $wanBridgePort] > 0) do={` + "\n")
	builder.WriteString(`  :set wanL3 [/interface bridge port get [:pick $wanBridgePort 0] bridge]` + "\n")
	builder.WriteString(`  :put ("NobliFi WAN: physical=" . $wanPhysical . " layer3=" . $wanL3 . " (bridge)")` + "\n")
	builder.WriteString(`} else={` + "\n")
	builder.WriteString(`  :put ("NobliFi WAN: physical=" . $wanPhysical . " layer3=" . $wanL3)` + "\n")
	builder.WriteString(`}` + "\n")

	writeSafe(builder, `/interface list member remove [find where list="WAN" comment="NobliFi WAN member"]`, "cleanup legacy WAN member")
	writeSafe(builder, `/interface list member remove [find where list="WAN" comment="NobliFi WAN L3 member"]`, "cleanup WAN L3 member")

	// Layer-3 WAN cannot also be treated as LAN by firewall/interface-list rules.
	writeSafe(builder, `/interface list member remove [find where list="LAN" interface=$wanL3]`, "remove WAN L3 interface from LAN list")
	writeSafe(builder, `/interface list member remove [find where list="LAN" interface=$wanPhysical]`, "remove WAN physical interface from LAN list")

	writeCritical(
		builder,
		`:if ([:len [/interface list member find where list="WAN" interface=$wanL3]] = 0) do={ /interface list member add list=WAN interface=$wanL3 comment="NobliFi WAN L3 member" }`,
		"add WAN L3 member",
	)

	// Remove only NobliFi DHCP clients attached to the wrong interface.
	// A factory/default DHCP client already bound to wanL3 is reused.
	builder.WriteString(`:foreach id in=[/ip dhcp-client find where comment="NobliFi WAN DHCP client"] do={` + "\n")
	builder.WriteString(`  :local existingIface [/ip dhcp-client get $id interface]` + "\n")
	builder.WriteString(`  :if ($existingIface != $wanL3) do={ /ip dhcp-client remove $id }` + "\n")
	builder.WriteString(`}` + "\n")

	builder.WriteString(`:local wanDhcp [/ip dhcp-client find where interface=$wanL3]` + "\n")
	builder.WriteString(`:if ([:len $wanDhcp] = 0) do={` + "\n")
	builder.WriteString(`  /ip dhcp-client add interface=$wanL3 disabled=no add-default-route=yes use-peer-dns=yes use-peer-ntp=yes comment="NobliFi WAN DHCP client"` + "\n")
	builder.WriteString(`} else={` + "\n")
	builder.WriteString(`  :foreach id in=$wanDhcp do={ /ip dhcp-client set $id disabled=no add-default-route=yes use-peer-dns=yes use-peer-ntp=yes }` + "\n")
	builder.WriteString(`  :put ("NobliFi WAN: reusing existing DHCP client on " . $wanL3)` + "\n")
	builder.WriteString(`}` + "\n")

	writeWANDHCPWait(builder)
}

func writeWANDHCPWait(builder *strings.Builder) {
	builder.WriteString(`:local wanBound false` + "\n")
	builder.WriteString(`:for i from=1 to=30 do={` + "\n")
	builder.WriteString(`  :if ([:len [/ip dhcp-client find where interface=$wanL3 status=bound]] > 0) do={ :set wanBound true }` + "\n")
	builder.WriteString(`  :if ($wanBound) do={ :set i 30 } else={ :delay 1s }` + "\n")
	builder.WriteString(`}` + "\n")
	builder.WriteString(`:if (!$wanBound) do={ :put ("NobliFi WARNING: WAN DHCP client on " . $wanL3 . " did not bind within 30s, continuing with existing portal if available") } else={ :put ("NobliFi WAN DHCP client on " . $wanL3 . " is bound") }` + "\n")
	builder.WriteString(`:if ([:len [/ip route find where dst-address="0.0.0.0/0" active=yes]] = 0) do={ :put "NobliFi WARNING: no active default route after WAN setup" } else={ :put "NobliFi WAN default route is active" }` + "\n")
	builder.WriteString("\n")
}

func writeCleanup(builder *strings.Builder, bridge string, dhcpServer string, pool string, subnet string) {
	if bridge == "" {
		return
	}
	writeSafe(builder, fmt.Sprintf("/ip dhcp-server remove [find name=\"%s\"]", dhcpServer), "cleanup dhcp server")
	writeSafe(builder, fmt.Sprintf("/ip dhcp-server network remove [find address=\"%s\"]", escape(subnet)), "cleanup dhcp network")
	writeSafe(builder, fmt.Sprintf("/ip address remove [find interface=%s]", bridge), "cleanup bridge address")
	writeSafe(builder, fmt.Sprintf("/ip pool remove [find name=\"%s\"]", pool), "cleanup address pool")
	writeSafe(builder, fmt.Sprintf("/interface bridge port remove [find bridge=%s]", bridge), "cleanup bridge ports")
	writeSafe(builder, fmt.Sprintf("/interface bridge remove [find name=%s]", bridge), "cleanup bridge")
}

func writeHotspotNetwork(builder *strings.Builder, options RenderOptions, interfaces []string, hotspotGateway string) {
	builder.WriteString("# HotSpot bridge, DHCP, and client addressing\n")

	writeCritical(
		builder,
		fmt.Sprintf(`:if ([:len [/interface bridge find where name="%s"]] = 0) do={ /interface bridge add name="%s" protocol-mode=rstp comment="NobliFi HotSpot bridge" }`, escape(options.HotspotBridge), escape(options.HotspotBridge)),
		"ensure hotspot bridge",
	)

	// Firewall/NAT classification must include the L3 bridge itself, not only
	// its physical member ports.
	writeSafe(builder, fmt.Sprintf(`/interface list member remove [find where list="WAN" interface="%s"]`, escape(options.HotspotBridge)), "remove hotspot bridge from WAN list")
	writeCritical(
		builder,
		fmt.Sprintf(`:if ([:len [/interface list member find where list="LAN" interface="%s"]] = 0) do={ /interface list member add list=LAN interface="%s" comment="NobliFi HotSpot L3 LAN" }`, escape(options.HotspotBridge), escape(options.HotspotBridge)),
		"add hotspot bridge to LAN list",
	)

	for _, iface := range interfaces {
		writeSafe(builder, fmt.Sprintf(`/interface bridge port remove [find where interface="%s"]`, escape(iface)), "cleanup hotspot bridge port")
		writeCritical(
			builder,
			fmt.Sprintf(`:if ([:len [/interface bridge port find where bridge="%s" interface="%s"]] = 0) do={ /interface bridge port add bridge="%s" interface="%s" comment="NobliFi HotSpot port" }`, escape(options.HotspotBridge), escape(iface), escape(options.HotspotBridge), escape(iface)),
			"add hotspot bridge port",
		)

		writeSafe(builder, fmt.Sprintf(`/interface list member remove [find where list="LAN" interface="%s"]`, escape(iface)), "cleanup LAN list member")
		writeSafe(builder, fmt.Sprintf(`:if ([:len [/interface list member find where list="LAN" interface="%s"]] = 0) do={ /interface list member add list=LAN interface="%s" comment="NobliFi LAN member" }`, escape(iface), escape(iface)), "add LAN list member")
	}

	writeCritical(
		builder,
		fmt.Sprintf(`:if ([:len [/interface bridge port find where bridge="%s"]] = 0) do={ :error "No HotSpot LAN ports were added to %s" }`, escape(options.HotspotBridge), escape(options.HotspotBridge)),
		"verify hotspot bridge ports",
	)

	writeCritical(
		builder,
		fmt.Sprintf(`:if ([:len [/ip address find where interface="%s" address="%s"]] = 0) do={ /ip address add address="%s" interface="%s" comment="NobliFi HotSpot gateway" } else={ /ip address set [find where interface="%s" address="%s"] comment="NobliFi HotSpot gateway" }`, escape(options.HotspotBridge), escape(options.HotspotGateway), escape(options.HotspotGateway), escape(options.HotspotBridge), escape(options.HotspotBridge), escape(options.HotspotGateway)),
		"ensure hotspot gateway",
	)

	writeCritical(
		builder,
		fmt.Sprintf(`:if ([:len [/ip pool find where name="pool-hotspot"]] = 0) do={ /ip pool add name=pool-hotspot ranges=%s comment="NobliFi HotSpot pool" } else={ /ip pool set [find where name="pool-hotspot"] ranges=%s comment="NobliFi HotSpot pool" }`, options.HotspotPool, options.HotspotPool),
		"ensure hotspot pool",
	)

	writeCritical(
		builder,
		fmt.Sprintf(`:if ([:len [/ip dhcp-server find where name="dhcp-hotspot"]] = 0) do={ /ip dhcp-server add name=dhcp-hotspot interface="%s" address-pool=pool-hotspot lease-time=1h disabled=no } else={ /ip dhcp-server set [find where name="dhcp-hotspot"] interface="%s" address-pool=pool-hotspot lease-time=1h disabled=no }`, escape(options.HotspotBridge), escape(options.HotspotBridge)),
		"ensure hotspot dhcp",
	)

	writeCritical(
		builder,
		fmt.Sprintf(`:if ([:len [/ip dhcp-server network find where address="%s"]] = 0) do={ /ip dhcp-server network add address="%s" gateway="%s" dns-server="%s" } else={ /ip dhcp-server network set [find where address="%s"] gateway="%s" dns-server="%s" }`, escape(options.HotspotSubnet), escape(options.HotspotSubnet), escape(hotspotGateway), escape(hotspotGateway), escape(options.HotspotSubnet), escape(hotspotGateway), escape(hotspotGateway)),
		"ensure hotspot dhcp network",
	)

	builder.WriteString("\n")
}

// writeWireGuardManagement creates the MikroTik side of the NobliFi management
// tunnel. It is intentionally idempotent: once RouterOS generates a WireGuard
// keypair, rerunning provisioning preserves the interface and its private key.
//
// IMPORTANT: the VPS must also register this router's generated public key with
// AllowedIPs=<WireGuardClientIP>/32. That server-side peer registration cannot be
// completed by this renderer alone because the public key does not exist until
// RouterOS creates the interface.
func writeWireGuardManagement(builder *strings.Builder, options RenderOptions) {
	if !options.WireGuardEnabled {
		return
	}

	iface := options.WireGuardInterface
	clientCIDR := routerOSHostRoute(options.WireGuardClientIP)
	serverCIDR := routerOSHostRoute(options.WireGuardServerIP)

	builder.WriteString("# NobliFi WireGuard management tunnel\n")

	// Preserve the interface itself so RouterOS keeps the generated private key.
	writeCritical(
		builder,
		fmt.Sprintf(
			`:if ([:len [/interface wireguard find where name="%s"]] = 0) do={ /interface wireguard add name="%s" comment="NobliFi management tunnel" }`,
			escape(iface), escape(iface),
		),
		"ensure WireGuard interface",
	)
	writeCritical(
		builder,
		fmt.Sprintf(`/interface wireguard set [find where name="%s"] disabled=no comment="NobliFi management tunnel"`, escape(iface)),
		"enable WireGuard interface",
	)

	// Keep exactly one NobliFi-owned tunnel address and explicitly enable it.
	writeCritical(
		builder,
		fmt.Sprintf(
			`:if ([:len [/ip address find where interface="%s" address="%s"]] = 0) do={ /ip address remove [find where interface="%s" comment="NobliFi WireGuard address"]; /ip address add address="%s" interface="%s" disabled=no comment="NobliFi WireGuard address" } else={ /ip address set [find where interface="%s" address="%s"] disabled=no comment="NobliFi WireGuard address" }`,
			escape(iface), escape(clientCIDR), escape(iface), escape(clientCIDR), escape(iface), escape(iface), escape(clientCIDR),
		),
		"ensure WireGuard client address",
	)

	// Upsert the single NobliFi-owned VPS peer. Do not remove the local
	// WireGuard interface because that would rotate the router private key.
	builder.WriteString(fmt.Sprintf(`:local noblifiWGPeer [/interface wireguard peers find where interface="%s" comment="NobliFi VPS"]`, escape(iface)) + "\n")
	builder.WriteString(`:if ([:len $noblifiWGPeer] = 0) do={` + "\n")
	builder.WriteString(fmt.Sprintf(
		`  /interface wireguard peers add interface="%s" public-key="%s" endpoint-address="%s" endpoint-port=%d allowed-address="%s" persistent-keepalive=%ds disabled=no comment="NobliFi VPS"`,
		escape(iface), escape(options.WireGuardPublicKey), escape(options.WireGuardEndpoint), options.WireGuardPort, escape(serverCIDR), options.WireGuardKeepalive,
	) + "\n")
	builder.WriteString(fmt.Sprintf(`  :set noblifiWGPeer [/interface wireguard peers find where interface="%s" comment="NobliFi VPS"]`, escape(iface)) + "\n")
	builder.WriteString(`} else={` + "\n")
	builder.WriteString(fmt.Sprintf(
		`  /interface wireguard peers set [:pick $noblifiWGPeer 0] public-key="%s" endpoint-address="%s" endpoint-port=%d allowed-address="%s" persistent-keepalive=%ds disabled=no comment="NobliFi VPS"`,
		escape(options.WireGuardPublicKey), escape(options.WireGuardEndpoint), options.WireGuardPort, escape(serverCIDR), options.WireGuardKeepalive,
	) + "\n")
	builder.WriteString(`}` + "\n")

	writeCritical(
		builder,
		fmt.Sprintf(
			`:local configuredWGServerKey [/interface wireguard peers get [:pick $noblifiWGPeer 0] public-key]; :if ($configuredWGServerKey != "%s") do={ :error "WireGuard VPS public key mismatch" }`,
			escape(options.WireGuardPublicKey),
		),
		"verify WireGuard VPS public key",
	)

	// Allowed-address selects the peer, but RouterOS still requires an explicit
	// host route to the VPS management address.
	writeSafe(builder, `/ip route remove [find where comment="NobliFi VPS WireGuard"]`, "cleanup WireGuard VPS route")
	writeSafe(
		builder,
		fmt.Sprintf(`/ip route remove [find where dst-address="%s" gateway="%s"]`, escape(serverCIDR), escape(iface)),
		"cleanup duplicate WireGuard VPS route",
	)
	writeCritical(
		builder,
		fmt.Sprintf(`/ip route add dst-address="%s" gateway="%s" distance=1 disabled=no comment="NobliFi VPS WireGuard"`, escape(serverCIDR), escape(iface)),
		"add WireGuard VPS route",
	)

	writeCritical(
		builder,
		fmt.Sprintf(`:if ([:len [/interface list member find where list="LAN" interface="%s"]] = 0) do={ /interface list member add list=LAN interface="%s" comment="NobliFi WireGuard LAN" }`, escape(iface), escape(iface)),
		"add WireGuard interface to LAN list",
	)
	writeSafe(
		builder,
		`/ip firewall filter remove [find where comment="NobliFi WireGuard management input"]`,
		"cleanup WireGuard management firewall rule",
	)
	writeCritical(
		builder,
		fmt.Sprintf(`:local noblifiInputRules [/ip firewall filter find where chain=input]; :if ([:len $noblifiInputRules] = 0) do={ /ip firewall filter add chain=input action=accept in-interface="%s" src-address="%s" comment="NobliFi WireGuard management input" } else={ :local noblifiFirstInputRule [:pick $noblifiInputRules 0]; /ip firewall filter add chain=input action=accept in-interface="%s" src-address="%s" place-before=$noblifiFirstInputRule comment="NobliFi WireGuard management input" }`, escape(iface), escape(serverCIDR), escape(iface), escape(serverCIDR)),
		"allow VPS management traffic over WireGuard",
	)
	writeCritical(
		builder,
		fmt.Sprintf(`:if ([:len [/ip route find where dst-address="%s" gateway="%s" active=yes]] = 0) do={ :error "NobliFi WireGuard route is not active" }`, escape(serverCIDR), escape(iface)),
		"verify WireGuard VPS route",
	)

	builder.WriteString(fmt.Sprintf(`:local noblifiWGPublicKey [/interface wireguard get [find where name="%s"] public-key]`, escape(iface)) + "\n")
	builder.WriteString(`:if ([:len $noblifiWGPublicKey] = 0) do={ :error "NobliFi could not read the MikroTik WireGuard public key" }` + "\n")

	if options.WireGuardAgentManaged {
		keyURL := strings.TrimRight(options.ProvisioningBaseURL, "/") + "/wireguard-key"
		statusURL := strings.TrimRight(options.ProvisioningBaseURL, "/") + "/wireguard-status"
		claimToken := escape(options.ProvisioningClaimToken)

		builder.WriteString("# Register the router key so App Engine queues an xneelo agent job\n")
		builder.WriteString(fmt.Sprintf(`:local noblifiWGKeyURL "%s"`, escape(keyURL)) + "\n")
		builder.WriteString(fmt.Sprintf(`:local noblifiWGStatusURL "%s"`, escape(statusURL)) + "\n")
		builder.WriteString(fmt.Sprintf(`:local noblifiWGKeyPayload ("{\"claim_token\":\"%s\",\"public_key\":\"" . $noblifiWGPublicKey . "\"}")`, claimToken) + "\n")
		builder.WriteString(`:local noblifiWGKeyReported false` + "\n")
		builder.WriteString(`:for attempt from=1 to=3 do={` + "\n")
		builder.WriteString(`  :if (!$noblifiWGKeyReported) do={` + "\n")
		builder.WriteString(`    :do {` + "\n")
		builder.WriteString(`      :local reportResult [/tool fetch url=$noblifiWGKeyURL http-method=post http-header-field="Content-Type: application/json" http-data=$noblifiWGKeyPayload output=user as-value idle-timeout=30s duration=1m]` + "\n")
		builder.WriteString(`      :if (($reportResult->"status") = "finished") do={ :set noblifiWGKeyReported true }` + "\n")
		builder.WriteString(`    } on-error={ :log warning ("NobliFi WireGuard key report attempt " . $attempt . " failed") }` + "\n")
		builder.WriteString(`    :if (!$noblifiWGKeyReported) do={ :delay 3s }` + "\n")
		builder.WriteString(`  }` + "\n")
		builder.WriteString(`}` + "\n")
		builder.WriteString(`:if (!$noblifiWGKeyReported) do={ :error "NobliFi could not register this router WireGuard key with the control plane" }` + "\n")
		builder.WriteString(`:put "NobliFi WireGuard key registered; waiting for xneelo agent"` + "\n")

		waitSeconds := options.WireGuardHandshakeWaitSeconds
		builder.WriteString(`:local noblifiWGHandshake false` + "\n")
		builder.WriteString(`:local noblifiWGLastHandshake ""` + "\n")
		builder.WriteString(fmt.Sprintf(`:for second from=1 to=%d do={`+"\n", waitSeconds))
		builder.WriteString(fmt.Sprintf(`  :do { /tool ping address="%s" src-address="%s" interface="%s" count=1 interval=200ms } on-error={}`, escape(options.WireGuardServerIP), escape(options.WireGuardClientIP), escape(iface)) + "\n")
		builder.WriteString(`  :if ([:len $noblifiWGPeer] > 0) do={` + "\n")
		builder.WriteString(`    :local noblifiWGRx [/interface wireguard peers get [:pick $noblifiWGPeer 0] rx]` + "\n")
		builder.WriteString(`    :set noblifiWGLastHandshake [/interface wireguard peers get [:pick $noblifiWGPeer 0] last-handshake]` + "\n")
		builder.WriteString(`    :if (($noblifiWGRx > 0) && ($noblifiWGLastHandshake != "")) do={ :set noblifiWGHandshake true }` + "\n")
		builder.WriteString(`  }` + "\n")
		builder.WriteString(fmt.Sprintf(`  :if ($noblifiWGHandshake) do={ :set second %d } else={ :delay 1s }`, waitSeconds) + "\n")
		builder.WriteString(`}` + "\n")

		builder.WriteString(`:if ($noblifiWGHandshake) do={` + "\n")
		builder.WriteString(`  :put ("NobliFi WireGuard handshake detected; last-handshake=" . $noblifiWGLastHandshake)` + "\n")
		builder.WriteString(fmt.Sprintf(`  :local connectedPayload "{\"claim_token\":\"%s\",\"status\":\"connected\"}"`, claimToken) + "\n")
		builder.WriteString(`  :local connectedReported false` + "\n")
		builder.WriteString(`  :for attempt from=1 to=3 do={` + "\n")
		builder.WriteString(`    :if (!$connectedReported) do={` + "\n")
		builder.WriteString(`      :do {` + "\n")
		builder.WriteString(`        :local statusResult [/tool fetch url=$noblifiWGStatusURL http-method=post http-header-field="Content-Type: application/json" http-data=$connectedPayload output=user as-value idle-timeout=30s duration=1m]` + "\n")
		builder.WriteString(`        :if (($statusResult->"status") = "finished") do={ :set connectedReported true }` + "\n")
		builder.WriteString(`      } on-error={ :log warning ("NobliFi connected status report attempt " . $attempt . " failed") }` + "\n")
		builder.WriteString(`      :if (!$connectedReported) do={ :delay 3s }` + "\n")
		builder.WriteString(`    }` + "\n")
		builder.WriteString(`  }` + "\n")
		builder.WriteString(`  :if (!$connectedReported) do={ :log warning "NobliFi WireGuard is connected, but the backend status update failed" }` + "\n")
		builder.WriteString(`} else={` + "\n")
		builder.WriteString(fmt.Sprintf(`  :local failedPayload "{\"claim_token\":\"%s\",\"status\":\"failed\"}"`, claimToken) + "\n")
		builder.WriteString(`  :for attempt from=1 to=3 do={` + "\n")
		builder.WriteString(`    :do { /tool fetch url=$noblifiWGStatusURL http-method=post http-header-field="Content-Type: application/json" http-data=$failedPayload output=user as-value idle-timeout=30s duration=1m } on-error={ :log warning ("NobliFi failed status report attempt " . $attempt . " failed") }` + "\n")
		builder.WriteString(`    :delay 2s` + "\n")
		builder.WriteString(`  }` + "\n")
		builder.WriteString(fmt.Sprintf(`  :error "NobliFi xneelo agent did not establish a WireGuard handshake within %d seconds"`, waitSeconds) + "\n")
		builder.WriteString(`}` + "\n")
	} else {
		builder.WriteString(`:put "NobliFi WARNING: agent-managed WireGuard is disabled because the provisioning base URL or router token is missing"` + "\n")
	}

	// Test tunneled IP reachability with the exact source/interface used by RADIUS.
	builder.WriteString(fmt.Sprintf(`:do { :local wgReplies [/tool ping address="%s" src-address="%s" interface="%s" count=3 interval=500ms]; :if ($wgReplies = 0) do={ :put "NobliFi WARNING: WireGuard handshake exists, but the VPS tunnel IP did not answer ping" } else={ :put ("NobliFi WireGuard tunnel ping replies=" . $wgReplies) } } on-error={ :put "NobliFi WARNING: WireGuard tunnel ping test failed" }`, escape(options.WireGuardServerIP), escape(options.WireGuardClientIP), escape(iface)) + "\n")
	builder.WriteString(fmt.Sprintf(`:put ("NobliFi WireGuard ready: client=%s server=%s public-key=" . $noblifiWGPublicKey)`, escape(options.WireGuardClientIP), escape(options.WireGuardServerIP)) + "\n")
	builder.WriteString("\n")
}

// writeHotspotSupportFiles clones the default RouterOS HotSpot support files
// into the NobliFi custom HTML directory without relying on "/file copy".
// Some RouterOS builds do not expose that command. These support files are
// small text assets, so their contents can be cloned with /file get + /file add.
// login.html and index.html are deliberately excluded because NobliFi owns and
// fetches those two custom pages separately.
// writeHotspotSupportFiles copies the RouterOS default HotSpot support files
// into the resolved NobliFi directory. Existing destination files are never
// deleted before their replacement contents have been read successfully.
func writeHotspotSupportFiles(builder *strings.Builder, supportBaseURL string) {
	supportBaseURL = strings.TrimRight(strings.TrimSpace(supportBaseURL), "/")

	builder.WriteString("# Prepare HotSpot support files for captive-portal redirects\n")
	builder.WriteString(`:local noblifiSupportFiles {"rlogin.html";"redirect.html";"alogin.html";"flogin.html";"error.html";"errors.txt";"logout.html";"flogout.html";"status.html";"fstatus.html";"rstatus.html";"radvert.html";"md5.js";"api.json"}` + "\n")
	builder.WriteString(`:foreach f in=$noblifiSupportFiles do={` + "\n")
	builder.WriteString(`  :local src ("hotspot/" . $f)` + "\n")
	builder.WriteString(`  :local dst ($hotspotHtmlPath . "/" . $f)` + "\n")
	builder.WriteString(`  :if ([:len [/file find where name=$src]] > 0) do={` + "\n")
	builder.WriteString(`    :do {` + "\n")
	builder.WriteString(`      :local data [/file get [find where name=$src] contents]` + "\n")
	builder.WriteString(`      :if ([:len $data] > 0) do={` + "\n")
	builder.WriteString(`        :if ([:len [/file find where name=$dst]] > 0) do={` + "\n")
	builder.WriteString(`          /file set [find where name=$dst] contents=$data` + "\n")
	builder.WriteString(`        } else={` + "\n")
	builder.WriteString(`          /file add name=$dst contents=$data` + "\n")
	builder.WriteString(`        }` + "\n")
	builder.WriteString(`        :put ("NobliFi support file ready: " . $f)` + "\n")
	builder.WriteString(`      } else={` + "\n")
	builder.WriteString(`        :put ("NobliFi WARNING: support file is empty: " . $src)` + "\n")
	builder.WriteString(`      }` + "\n")
	builder.WriteString(`    } on-error={ :put ("NobliFi WARNING: could not clone support file " . $src) }` + "\n")
	builder.WriteString(`  } else={` + "\n")
	if supportBaseURL != "" {
		builder.WriteString(`    :local fallbackURL ""` + "\n")
		writeHotspotSupportFetchFallback(builder, supportBaseURL, "flogout.html")
		writeHotspotSupportFetchFallback(builder, supportBaseURL, "fstatus.html")
		writeHotspotSupportFetchFallback(builder, supportBaseURL, "rstatus.html")
		builder.WriteString(`    :if ([:len $fallbackURL] > 0) do={` + "\n")
		builder.WriteString(`      :do {` + "\n")
		builder.WriteString(`        :local fallbackResult [/tool fetch url=$fallbackURL output=user as-value idle-timeout=30s duration=1m]` + "\n")
		builder.WriteString(`        :if (($fallbackResult->"status") = "finished") do={` + "\n")
		builder.WriteString(`          :local fallbackData ($fallbackResult->"data")` + "\n")
		builder.WriteString(`          :if ([:len $fallbackData] > 0) do={` + "\n")
		builder.WriteString(`            :if ([:len [/file find where name=$dst]] > 0) do={` + "\n")
		builder.WriteString(`              /file set [find where name=$dst] contents=$fallbackData` + "\n")
		builder.WriteString(`            } else={` + "\n")
		builder.WriteString(`              /file add name=$dst contents=$fallbackData` + "\n")
		builder.WriteString(`            }` + "\n")
		builder.WriteString(`            :put ("NobliFi support file ready: " . $f . " (NobliFi captive portal)")` + "\n")
		builder.WriteString(`          } else={` + "\n")
		builder.WriteString(`            :put ("NobliFi WARNING: NobliFi support file is empty: " . $fallbackURL)` + "\n")
		builder.WriteString(`          }` + "\n")
		builder.WriteString(`        }` + "\n")
		builder.WriteString(`      } on-error={ :put ("NobliFi WARNING: could not fetch NobliFi support file " . $fallbackURL) }` + "\n")
		builder.WriteString(`    } else={` + "\n")
		builder.WriteString(`      :put ("NobliFi WARNING: default HotSpot support file missing: " . $src)` + "\n")
		builder.WriteString(`    }` + "\n")
	} else {
		builder.WriteString(`    :put ("NobliFi WARNING: default HotSpot support file missing: " . $src)` + "\n")
	}
	builder.WriteString(`  }` + "\n")
	builder.WriteString(`}` + "\n")
	builder.WriteString("\n")
}

func writeHotspotSupportFetchFallback(builder *strings.Builder, baseURL, name string) {
	builder.WriteString(fmt.Sprintf(`    :if ($f = "%s") do={ :set fallbackURL "%s/%s" }`, escape(name), escape(baseURL), escape(name)) + "\n")
}

func writeHotspotPortalRefreshScript(builder *strings.Builder, options RenderOptions) {
	loginURL := escape(options.LoginPageURL)

	writeSafe(builder, `/system scheduler remove [find where name="noblifi-hotspot-login-refresh"]`, "cleanup hotspot login refresh scheduler")
	writeSafe(builder, `/system script remove [find where name="noblifi-hotspot-login-refresh-script"]`, "cleanup hotspot login refresh script")

	builder.WriteString(`/system script add name="noblifi-hotspot-login-refresh-script" policy=ftp,read,write,test source={` + "\n")
	builder.WriteString(`:local hotspotHtmlDir "noblifi"` + "\n")
	builder.WriteString(`:local hotspotHtmlPath "noblifi"` + "\n")
	builder.WriteString(`:if ([:len [/file find where name="flash"]] > 0) do={ :set hotspotHtmlDir "flash/noblifi"; :set hotspotHtmlPath "flash/noblifi" }` + "\n")
	builder.WriteString(`:if ([:len [/file find where name=$hotspotHtmlPath]] = 0) do={ /file make-directory $hotspotHtmlPath }` + "\n")
	builder.WriteString(`:local portalData ""` + "\n")
	builder.WriteString(`:local portalFetched false` + "\n")
	builder.WriteString(`:for i from=1 to=3 do={` + "\n")
	builder.WriteString(`  :if (!$portalFetched) do={` + "\n")
	builder.WriteString(`    :do {` + "\n")
	builder.WriteString(fmt.Sprintf(`      :local r [/tool fetch url="%s" output=user as-value idle-timeout=30s duration=1m]`, loginURL) + "\n")
	builder.WriteString(`      :if (($r->"status") = "finished") do={` + "\n")
	builder.WriteString(`        :local d ($r->"data")` + "\n")
	builder.WriteString(`        :if ([:len $d] > 0) do={ :set portalData $d; :set portalFetched true }` + "\n")
	builder.WriteString(`      }` + "\n")
	builder.WriteString(`    } on-error={ :log warning ("NobliFi portal refresh fetch attempt " . $i . " failed") }` + "\n")
	builder.WriteString(`    :if (!$portalFetched) do={ :delay 3s }` + "\n")
	builder.WriteString(`  }` + "\n")
	builder.WriteString(`}` + "\n")
	builder.WriteString(`:if ($portalFetched) do={` + "\n")
	builder.WriteString(`  :local loginFile ($hotspotHtmlPath . "/login.html")` + "\n")
	builder.WriteString(`  :local indexFile ($hotspotHtmlPath . "/index.html")` + "\n")
	builder.WriteString(`  :if ([:len [/file find where name=$loginFile]] > 0) do={ /file set [find where name=$loginFile] contents=$portalData } else={ /file add name=$loginFile contents=$portalData }` + "\n")
	builder.WriteString(`  :if ([:len [/file find where name=$indexFile]] > 0) do={ /file set [find where name=$indexFile] contents=$portalData } else={ /file add name=$indexFile contents=$portalData }` + "\n")
	builder.WriteString(`  :local rloginFile ($hotspotHtmlPath . "/rlogin.html")` + "\n")
	builder.WriteString(`  :local redirectFile ($hotspotHtmlPath . "/redirect.html")` + "\n")
	builder.WriteString(`  :if (([:len [/file find where name=$rloginFile]] > 0) || ([:len [/file find where name=$redirectFile]] > 0)) do={` + "\n")
	builder.WriteString(`    /ip hotspot profile set [find where name="noblifi-hotspot-profile"] html-directory=$hotspotHtmlDir html-directory-override=""` + "\n")
	builder.WriteString(`  }` + "\n")
	builder.WriteString(`  :log info ("NobliFi portal refresh succeeded: " . $hotspotHtmlDir)` + "\n")
	builder.WriteString(`} else={` + "\n")
	builder.WriteString(`  :log warning "NobliFi portal refresh failed; existing live portal preserved"` + "\n")
	builder.WriteString(`}` + "\n")
	builder.WriteString("}\n")

	writeCritical(
		builder,
		`/system scheduler add name="noblifi-hotspot-login-refresh" interval=10m on-event="noblifi-hotspot-login-refresh-script" policy=ftp,read,write,test comment="NobliFi HotSpot login refresh"`,
		"schedule hotspot login refresh",
	)
}

func writeHotspotRestart(builder *strings.Builder) {
	builder.WriteString("# Ensure HotSpot is enabled without clearing active sessions\n")
	writeCritical(builder, `/ip hotspot enable [find where name="noblifi-hotspot"]`, "ensure hotspot enabled")
	builder.WriteString("\n")
}

func writeHotspotServices(builder *strings.Builder, options RenderOptions, hotspotGateway string) {
	hotspotDNSName := normalizeHotspotDNSName(options.HotspotDNSName)
	loginPageURL := strings.TrimSpace(options.LoginPageURL)

	builder.WriteString("# DNS, NAT, RADIUS, and HotSpot service setup\n")

	// 1. Server profile.
	writeCritical(
		builder,
		`:if ([:len [/ip hotspot profile find where name="noblifi-hotspot-profile"]] = 0) do={ /ip hotspot profile add name="noblifi-hotspot-profile" }`,
		"create hotspot server profile",
	)

	writeCritical(
		builder,
		fmt.Sprintf(`/ip hotspot profile set [find where name="noblifi-hotspot-profile"] hotspot-address=%s`, hotspotGateway),
		"set hotspot profile address",
	)

	writeCritical(
		builder,
		fmt.Sprintf(`/ip hotspot profile set [find where name="noblifi-hotspot-profile"] dns-name="%s"`, escape(hotspotDNSName)),
		"set hotspot profile dns name",
	)

	writeCritical(
		builder,
		fmt.Sprintf(`:local configuredDNS [/ip hotspot profile get [find where name="noblifi-hotspot-profile"] dns-name]; :if ($configuredDNS != "%s") do={ :error ("HotSpot DNS name mismatch. RouterOS returned " . $configuredDNS) }`, escape(hotspotDNSName)),
		"verify hotspot profile dns name",
	)

	writeCritical(builder, `/ip hotspot profile set [find where name="noblifi-hotspot-profile"] use-radius=yes`, "enable radius on hotspot profile")
	writeCritical(builder, `/ip hotspot profile set [find where name="noblifi-hotspot-profile"] radius-accounting=yes`, "enable hotspot radius accounting")
	writeCritical(builder, `/ip hotspot profile set [find where name="noblifi-hotspot-profile"] radius-interim-update=5m`, "set hotspot radius interim update")
	writeCritical(builder, `/ip hotspot profile set [find where name="noblifi-hotspot-profile"] login-by=http-chap,http-pap`, "configure hotspot login methods")

	// Do not reset html-directory to "hotspot" merely because LoginPageURL is
	// temporarily empty. If a working custom portal already exists, preserve it.
	if loginPageURL == "" {
		builder.WriteString(`:local existingCustomLogin ($hotspotHtmlPath . "/login.html")` + "\n")
		builder.WriteString(`:local existingCustomRLogin ($hotspotHtmlPath . "/rlogin.html")` + "\n")
		builder.WriteString(`:local existingCustomRedirect ($hotspotHtmlPath . "/redirect.html")` + "\n")
		builder.WriteString(`:local existingCustomLoginReady false` + "\n")
		builder.WriteString(`:if ([:len [/file find where name=$existingCustomLogin]] > 0) do={ :local existingCustomLoginSize [/file get [find where name=$existingCustomLogin] size]; :if ($existingCustomLoginSize > 0) do={ :set existingCustomLoginReady true } }` + "\n")
		builder.WriteString(`:if (($existingCustomLoginReady) && (([:len [/file find where name=$existingCustomRLogin]] > 0) || ([:len [/file find where name=$existingCustomRedirect]] > 0))) do={` + "\n")
		builder.WriteString(`  /ip hotspot profile set [find where name="noblifi-hotspot-profile"] html-directory=$hotspotHtmlDir html-directory-override=""` + "\n")
		builder.WriteString(`  :put ("NobliFi: preserved existing custom HotSpot portal at " . $hotspotHtmlDir)` + "\n")
		builder.WriteString(`} else={` + "\n")
		builder.WriteString(`  /ip hotspot profile set [find where name="noblifi-hotspot-profile"] html-directory=hotspot html-directory-override=""` + "\n")
		builder.WriteString(`  :put "NobliFi: custom portal URL unavailable; using RouterOS default HotSpot portal"` + "\n")
		builder.WriteString(`}` + "\n")
	}

	writeCritical(
		builder,
		`:if ([:len [/ip hotspot profile find where name="noblifi-hotspot-profile"]] = 0) do={ :error "noblifi-hotspot-profile was not created" }`,
		"verify hotspot server profile creation",
	)

	// 2. DNS.
	writeCritical(builder, `/ip dns set allow-remote-requests=yes`, "enable dns forwarding")

	// 3. FastTrack must not bypass HotSpot/simple-queue processing.
	writeSafe(builder, `/ip firewall filter disable [find where action=fasttrack-connection]`, "disable FastTrack for HotSpot shaping")

	// 4. NAT.
	writeCritical(builder, `/ip firewall nat remove [find where comment="NobliFi client NAT"]`, "cleanup nat")
	writeCritical(builder, `/ip firewall nat add chain=srcnat out-interface-list=WAN action=masquerade comment="NobliFi client NAT"`, "add nat")

	// 5. RADIUS.
	writeCritical(builder, `/radius remove [find where comment="NobliFi RADIUS"]`, "cleanup radius client")

	radiusCommand := fmt.Sprintf(
		`/radius add service=hotspot address=%s secret="%s" authentication-port=1812 accounting-port=1813 timeout=3s comment="NobliFi RADIUS"`,
		options.RadiusServer,
		escape(options.RadiusSecret),
	)
	if options.WireGuardEnabled {
		radiusCommand = fmt.Sprintf(
			`/radius add service=hotspot address=%s src-address=%s secret="%s" authentication-port=1812 accounting-port=1813 timeout=3s comment="NobliFi RADIUS"`,
			options.RadiusServer,
			options.WireGuardClientIP,
			escape(options.RadiusSecret),
		)
	}
	writeCritical(builder, radiusCommand, "add radius client")
	writeCritical(builder, `/radius incoming set accept=yes`, "enable radius incoming")

	// 6. Ensure custom directory. This resolves to "noblifi" on routers without
	// a visible flash filesystem and "flash/noblifi" on routers that have one.
	writeSafe(
		builder,
		`:if ([:len [/file find where name=$hotspotHtmlPath]] = 0) do={ /file make-directory $hotspotHtmlPath }`,
		"ensure hotspot html directory",
	)

	if loginPageURL != "" {
		writeHotspotSupportFiles(builder, options.HotspotSupportBaseURL)
	}

	// 7. Voucher user profile.
	writeCritical(
		builder,
		`:if ([:len [/ip hotspot user profile find where name="noblifi-voucher-profile"]] = 0) do={ /ip hotspot user profile add name="noblifi-voucher-profile" }`,
		"ensure hotspot user profile",
	)
	writeCritical(
		builder,
		`/ip hotspot user profile set [find where name="noblifi-voucher-profile"] shared-users=1 keepalive-timeout=2m status-autorefresh=1m`,
		"configure hotspot user profile",
	)

	// 8. HotSpot server.
	writeCritical(
		builder,
		fmt.Sprintf(`:if ([:len [/ip hotspot find where name="noblifi-hotspot"]] = 0) do={ /ip hotspot add name="noblifi-hotspot" interface="%s" address-pool=pool-hotspot profile="noblifi-hotspot-profile" disabled=no }`, escape(options.HotspotBridge)),
		"ensure hotspot server",
	)
	writeCritical(
		builder,
		fmt.Sprintf(`/ip hotspot set [find where name="noblifi-hotspot"] interface="%s" address-pool=pool-hotspot profile="noblifi-hotspot-profile" disabled=no`, escape(options.HotspotBridge)),
		"enable hotspot server",
	)

	// 9. Walled garden.
	for _, host := range options.WalledGardenHosts {
		writeSafe(
			builder,
			fmt.Sprintf(`/ip hotspot walled-garden remove [find where dst-host=%s comment="NobliFi captive portal"]`, host),
			"cleanup captive portal walled garden host",
		)
		writeSafe(
			builder,
			fmt.Sprintf(`/ip hotspot walled-garden add dst-host=%s comment="NobliFi captive portal"`, host),
			"add captive portal walled garden",
		)
	}

	// 10. Install/refresh the custom portal transactionally.
	if loginPageURL != "" {
		builder.WriteString("# Transactional NobliFi portal download\n")
		builder.WriteString(`:local noblifiPortalData ""` + "\n")
		builder.WriteString(`:local noblifiPortalFetched false` + "\n")
		builder.WriteString(`:for i from=1 to=3 do={` + "\n")
		builder.WriteString(`  :if (!$noblifiPortalFetched) do={` + "\n")
		builder.WriteString(`    :put ("NobliFi portal download attempt " . $i . " of 3")` + "\n")
		builder.WriteString(`    :do {` + "\n")
		builder.WriteString(fmt.Sprintf(`      :local fetchResult [/tool fetch url="%s" output=user as-value idle-timeout=30s duration=1m]`, escape(loginPageURL)) + "\n")
		builder.WriteString(`      :if (($fetchResult->"status") = "finished") do={` + "\n")
		builder.WriteString(`        :local fetchedData ($fetchResult->"data")` + "\n")
		builder.WriteString(`        :if ([:len $fetchedData] > 0) do={ :set noblifiPortalData $fetchedData; :set noblifiPortalFetched true }` + "\n")
		builder.WriteString(`      }` + "\n")
		builder.WriteString(`    } on-error={ :put ("NobliFi WARNING: portal download attempt " . $i . " failed") }` + "\n")
		builder.WriteString(`    :if (!$noblifiPortalFetched) do={ :delay 3s }` + "\n")
		builder.WriteString(`  }` + "\n")
		builder.WriteString(`}` + "\n")

		builder.WriteString(`:local hotspotLoginFile ($hotspotHtmlPath . "/login.html")` + "\n")
		builder.WriteString(`:local hotspotIndexFile ($hotspotHtmlPath . "/index.html")` + "\n")

		// Never touch the live files until the fetch has completed successfully.
		builder.WriteString(`:if ($noblifiPortalFetched) do={` + "\n")
		builder.WriteString(`  :if ([:len [/file find where name=$hotspotLoginFile]] > 0) do={ /file set [find where name=$hotspotLoginFile] contents=$noblifiPortalData } else={ /file add name=$hotspotLoginFile contents=$noblifiPortalData }` + "\n")
		builder.WriteString(`  :if ([:len [/file find where name=$hotspotIndexFile]] > 0) do={ /file set [find where name=$hotspotIndexFile] contents=$noblifiPortalData } else={ /file add name=$hotspotIndexFile contents=$noblifiPortalData }` + "\n")
		builder.WriteString(`  :put ("NobliFi portal files updated at " . $hotspotHtmlDir)` + "\n")
		builder.WriteString(`} else={` + "\n")
		builder.WriteString(`  :put "NobliFi WARNING: new portal download failed; existing live portal was not deleted"` + "\n")
		builder.WriteString(`}` + "\n")

		// Select custom pages only if the files required to service /login and
		// initial captive-portal redirect requests actually exist.
		builder.WriteString(`:local hotspotRLoginFile ($hotspotHtmlPath . "/rlogin.html")` + "\n")
		builder.WriteString(`:local hotspotRedirectFile ($hotspotHtmlPath . "/redirect.html")` + "\n")
		builder.WriteString(`:local customPortalReady false` + "\n")
		builder.WriteString(`:if ([:len [/file find where name=$hotspotLoginFile]] > 0) do={` + "\n")
		builder.WriteString(`  :local hotspotLoginSize [/file get [find where name=$hotspotLoginFile] size]` + "\n")
		builder.WriteString(`  :if (($hotspotLoginSize > 0) && (([:len [/file find where name=$hotspotRLoginFile]] > 0) || ([:len [/file find where name=$hotspotRedirectFile]] > 0))) do={ :set customPortalReady true }` + "\n")
		builder.WriteString(`}` + "\n")
		builder.WriteString(`:if ($customPortalReady) do={` + "\n")
		builder.WriteString(`  /ip hotspot profile set [find where name="noblifi-hotspot-profile"] html-directory=$hotspotHtmlDir html-directory-override=""` + "\n")
		builder.WriteString(`  :put ("NobliFi custom HotSpot portal active at " . $hotspotHtmlDir)` + "\n")
		builder.WriteString(`} else={` + "\n")
		builder.WriteString(`  :if ([:len [/file find where name="hotspot/login.html"]] > 0) do={` + "\n")
		builder.WriteString(`    /ip hotspot profile set [find where name="noblifi-hotspot-profile"] html-directory=hotspot html-directory-override=""` + "\n")
		builder.WriteString(`    :put "NobliFi WARNING: custom portal incomplete; safely falling back to RouterOS default portal"` + "\n")
		builder.WriteString(`  } else={` + "\n")
		builder.WriteString(`    :error "Neither NobliFi custom portal nor RouterOS default HotSpot login.html is available"` + "\n")
		builder.WriteString(`  }` + "\n")
		builder.WriteString(`}` + "\n")

		// Refresh is also transactional: a timeout leaves the current live page
		// untouched instead of truncating/removing it.
		writeHotspotPortalRefreshScript(builder, options)
	}

	// Apply the selected HTML directory immediately and force clients to request
	// a fresh captive-portal session instead of retaining a stale 404/cookie.
	writeHotspotRestart(builder)

	// 11. Final verification.
	writeCritical(
		builder,
		fmt.Sprintf(`:if ([:len [/ip dhcp-server find where name="dhcp-hotspot" interface="%s" disabled=no]] = 0) do={ :error "NobliFi HotSpot DHCP is not enabled on %s" }`, escape(options.HotspotBridge), escape(options.HotspotBridge)),
		"verify hotspot dhcp",
	)

	if options.WireGuardEnabled {
		serverCIDR := routerOSHostRoute(options.WireGuardServerIP)
		writeCritical(
			builder,
			fmt.Sprintf(`:if ([:len [/ip route find where dst-address="%s" gateway="%s" active=yes]] = 0) do={ :error "NobliFi WireGuard route is missing or inactive" }`, escape(serverCIDR), escape(options.WireGuardInterface)),
			"final WireGuard route verification",
		)
		writeCritical(
			builder,
			fmt.Sprintf(`:if ([:len [/interface wireguard peers find where interface="%s" comment="NobliFi VPS" disabled=no]] = 0) do={ :error "NobliFi WireGuard VPS peer is missing or disabled" }`, escape(options.WireGuardInterface)),
			"final WireGuard peer verification",
		)
		writeCritical(
			builder,
			`:if ([:len [/ip firewall filter find where comment="NobliFi WireGuard management input" disabled=no]] = 0) do={ :error "NobliFi WireGuard management firewall rule is missing" }`,
			"final WireGuard firewall verification",
		)
	}

	writeCritical(
		builder,
		`:if ([:len [/interface list member find where list="WAN" interface=$wanL3]] = 0) do={ :error ("Resolved WAN L3 interface is not in WAN list: " . $wanL3) }`,
		"verify WAN L3 interface list membership",
	)

	writeCritical(
		builder,
		fmt.Sprintf(`:if ([:len [/interface list member find where list="LAN" interface="%s"]] = 0) do={ :error "NobliFi HotSpot bridge is not in LAN interface list" }`, escape(options.HotspotBridge)),
		"verify hotspot bridge LAN membership",
	)

	writeCritical(builder, `:if ([:len [/radius find where comment="NobliFi RADIUS"]] = 0) do={ :error "NobliFi RADIUS client is missing" }`, "verify radius client")
	writeCritical(builder, `:if ([:len [/ip firewall nat find where comment="NobliFi client NAT"]] = 0) do={ :error "NobliFi client NAT is missing" }`, "verify nat")
	writeCritical(builder, `:if ([:len [/ip hotspot profile find where name="noblifi-hotspot-profile"]] = 0) do={ :error "NobliFi HotSpot server profile is missing" }`, "verify hotspot server profile")

	writeCritical(
		builder,
		fmt.Sprintf(`:local finalDNS [/ip hotspot profile get [find where name="noblifi-hotspot-profile"] dns-name]; :if ($finalDNS != "%s") do={ :error ("Final HotSpot DNS verification failed. RouterOS returned " . $finalDNS) }`, escape(hotspotDNSName)),
		"final hotspot dns verification",
	)

	writeCritical(
		builder,
		fmt.Sprintf(`:if ([:len [/ip hotspot find where name="noblifi-hotspot" interface="%s" disabled=no]] = 0) do={ :error "NobliFi HotSpot server is not enabled on %s" }`, escape(options.HotspotBridge), escape(options.HotspotBridge)),
		"verify hotspot server",
	)

	// Hard 404 prevention: validate the login page in the directory the profile
	// will actually use, not merely the directory we intended to use.
	writeCritical(
		builder,
		`:local finalHtmlDir [/ip hotspot profile get [find where name="noblifi-hotspot-profile"] html-directory]; :local finalLoginFile ($finalHtmlDir . "/login.html"); :if ([:len [/file find where name=$finalLoginFile]] = 0) do={ :error ("HotSpot login.html missing from active HTML directory: " . $finalHtmlDir) }; :local finalLoginSize [/file get [find where name=$finalLoginFile] size]; :if ($finalLoginSize = 0) do={ :error ("HotSpot login.html is empty in active HTML directory: " . $finalHtmlDir) }`,
		"verify active hotspot login file",
	)

	writeCritical(
		builder,
		`:local finalHtmlDir [/ip hotspot profile get [find where name="noblifi-hotspot-profile"] html-directory]; :local finalRLogin ($finalHtmlDir . "/rlogin.html"); :local finalRedirect ($finalHtmlDir . "/redirect.html"); :if (([:len [/file find where name=$finalRLogin]] = 0) && ([:len [/file find where name=$finalRedirect]] = 0)) do={ :error ("HotSpot redirect support files missing from active HTML directory: " . $finalHtmlDir) }`,
		"verify active hotspot redirect files",
	)

	builder.WriteString(`:local finalHotspotDNS [/ip hotspot profile get [find where name="noblifi-hotspot-profile"] dns-name]` + "\n")
	builder.WriteString(`:local finalHotspotDir [/ip hotspot profile get [find where name="noblifi-hotspot-profile"] html-directory]` + "\n")
	builder.WriteString(`:put ("NobliFi: HotSpot provisioning verified. DNS=" . $finalHotspotDNS . " HTML=" . $finalHotspotDir)` + "\n")
	builder.WriteString("\n")
}

func writeBridge(builder *strings.Builder, bridge string, interfaces []string, address string, pool string, ranges string, subnet string) {
	if len(interfaces) == 0 {
		return
	}

	role := strings.TrimPrefix(bridge, "br-")
	gateway := strings.Split(address, "/")[0]

	builder.WriteString(fmt.Sprintf("# %s bridge, DHCP, and client addressing\n", strings.ToUpper(role)))

	writeSafe(
		builder,
		fmt.Sprintf(`:if ([:len [/interface bridge find where name="%s"]] = 0) do={ /interface bridge add name="%s" protocol-mode=rstp comment="NobliFi %s bridge" }`, escape(bridge), escape(bridge), escape(role)),
		"ensure bridge",
	)

	writeSafe(builder, fmt.Sprintf(`/interface list member remove [find where list="WAN" interface="%s"]`, escape(bridge)), "remove bridge from WAN list")
	writeSafe(
		builder,
		fmt.Sprintf(`:if ([:len [/interface list member find where list="LAN" interface="%s"]] = 0) do={ /interface list member add list=LAN interface="%s" comment="NobliFi %s L3 LAN" }`, escape(bridge), escape(bridge), escape(role)),
		"add bridge to LAN list",
	)

	for _, iface := range interfaces {
		writeSafe(builder, fmt.Sprintf(`/interface bridge port remove [find where interface="%s"]`, escape(iface)), "cleanup bridge port")
		writeSafe(
			builder,
			fmt.Sprintf(`:if ([:len [/interface bridge port find where bridge="%s" interface="%s"]] = 0) do={ /interface bridge port add bridge="%s" interface="%s" comment="NobliFi %s port" }`, escape(bridge), escape(iface), escape(bridge), escape(iface), escape(role)),
			"add bridge port",
		)
		writeSafe(builder, fmt.Sprintf(`/interface list member remove [find where list="LAN" interface="%s"]`, escape(iface)), "cleanup LAN list member")
		writeSafe(builder, fmt.Sprintf(`:if ([:len [/interface list member find where list="LAN" interface="%s"]] = 0) do={ /interface list member add list=LAN interface="%s" comment="NobliFi LAN member" }`, escape(iface), escape(iface)), "add LAN list member")
	}

	writeSafe(builder, fmt.Sprintf(`:if ([:len [/ip address find where interface="%s" address="%s"]] = 0) do={ /ip address add address=%s interface="%s" comment="NobliFi %s gateway" } else={ /ip address set [find where interface="%s" address="%s"] comment="NobliFi %s gateway" }`, escape(bridge), escape(address), address, escape(bridge), escape(role), escape(bridge), escape(address), escape(role)), "ensure bridge gateway")
	writeSafe(builder, fmt.Sprintf(`:if ([:len [/ip pool find where name="%s"]] = 0) do={ /ip pool add name=%s ranges=%s comment="NobliFi %s pool" } else={ /ip pool set [find where name="%s"] ranges=%s comment="NobliFi %s pool" }`, pool, pool, ranges, escape(role), pool, ranges, escape(role)), "ensure address pool")
	writeSafe(builder, fmt.Sprintf(`:if ([:len [/ip dhcp-server find where name="dhcp-%s"]] = 0) do={ /ip dhcp-server add name=dhcp-%s interface="%s" address-pool=%s lease-time=1h disabled=no } else={ /ip dhcp-server set [find where name="dhcp-%s"] interface="%s" address-pool=%s lease-time=1h disabled=no }`, role, role, escape(bridge), pool, role, escape(bridge), pool), "ensure dhcp server")
	writeSafe(builder, fmt.Sprintf(`:if ([:len [/ip dhcp-server network find where address="%s"]] = 0) do={ /ip dhcp-server network add address="%s" gateway="%s" dns-server="%s" } else={ /ip dhcp-server network set [find where address="%s"] gateway="%s" dns-server="%s" }`, escape(subnet), escape(subnet), escape(gateway), escape(gateway), escape(subnet), escape(gateway), escape(gateway)), "ensure dhcp network")

	builder.WriteString("\n")
}

func defaultWalledGardenHosts() []string {
	// Do not whitelist captive-portal detection endpoints such as
	// captive.apple.com, connectivitycheck.gstatic.com or msftconnecttest.com.
	// If those probes bypass authentication, phones/computers may conclude that
	// Internet access is already available and never open the login assistant.
	return []string{
		"noblifi-frontend.vercel.app",
		"noblifi.ew.r.appspot.com",
		"noblifi.uc.r.appspot.com",
	}
}

func cleanHosts(hosts []string) []string {
	seen := map[string]bool{}
	cleaned := make([]string, 0, len(hosts))
	for _, host := range hosts {
		host = strings.ToLower(strings.TrimSpace(host))
		host = strings.TrimPrefix(host, "https://")
		host = strings.TrimPrefix(host, "http://")
		if slash := strings.Index(host, "/"); slash >= 0 {
			host = host[:slash]
		}
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		cleaned = append(cleaned, host)
	}
	return cleaned
}
