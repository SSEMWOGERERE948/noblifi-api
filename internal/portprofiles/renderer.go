package portprofiles

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/noblifi/noblifi/backend/internal/placeholders"
)

type Summary struct {
	WAN        []string `json:"wan"`
	HotspotLAN []string `json:"hotspot_lan"`
	FreeLAN    []string `json:"free_lan"`
	StaffLAN   []string `json:"staff_lan"`
	POSLAN     []string `json:"pos_lan"`
	CCTVLAN    []string `json:"cctv_lan"`
	Disabled   []string `json:"disabled"`
}

type RenderOptions struct {
	RadiusServer string
	RadiusSecret string

	// Tenant-scoped captive portal endpoints.
	//
	// LoginPageURL remains the required entry point for backwards compatibility.
	// StatusPageURL and LogoutPageURL may be supplied explicitly. When omitted,
	// they are derived from LoginPageURL using the NobliFi portal URL convention.
	LoginPageURL  string
	StatusPageURL string
	LogoutPageURL string

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
}

func DefaultAssignments() []Assignment {
	return []Assignment{
		{InterfaceName: "ether1", Role: "WAN"},
		{InterfaceName: "ether2", Role: "HOTSPOT_LAN"},
		{InterfaceName: "ether3", Role: "HOTSPOT_LAN"},
		{InterfaceName: "ether4", Role: "HOTSPOT_LAN"},
		{InterfaceName: "ether5", Role: "FREE_LAN"},
	}
}

func BuildSummary(assignments []Assignment) Summary {
	summary := Summary{
		WAN:        []string{},
		HotspotLAN: []string{},
		FreeLAN:    []string{},
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
		case "FREE_LAN":
			summary.FreeLAN = append(summary.FreeLAN, name)
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
	sort.Strings(summary.FreeLAN)
	sort.Strings(summary.StaffLAN)
	sort.Strings(summary.POSLAN)
	sort.Strings(summary.CCTVLAN)
	sort.Strings(summary.Disabled)
	return summary
}

func RenderRouterOS(assignments []Assignment) (string, error) {
	return RenderRouterOSWithOptions(assignments, RenderOptions{
		RadiusServer:        "127.0.0.1",
		RadiusSecret:        "noblifi",
		LoginPageURL:        "",
		RouterIdentity:      "NobliFi-Router",
		APIUsername:         "noblifi-api",
		APIPassword:         "CHANGE_ME_API_PASSWORD",
		HotspotBridge:       "br-hotspot",
		StaffBridge:         "br-staff",
		POSBridge:           "br-pos",
		CCTVBridge:          "br-cctv",
		HotspotSubnet:       "10.10.10.0/24",
		HotspotGateway:      "10.10.10.1/24",
		HotspotPool:         "10.10.10.10-10.10.10.254",
		StaffSubnet:         "10.20.20.0/24",
		StaffGateway:        "10.20.20.1/24",
		StaffPool:           "10.20.20.10-10.20.20.254",
		POSSubnet:           "10.30.30.0/24",
		POSGateway:          "10.30.30.1/24",
		POSPool:             "10.30.30.10-10.30.30.254",
		CCTVSubnet:          "10.40.40.0/24",
		CCTVGateway:         "10.40.40.1/24",
		CCTVPool:            "10.40.40.10-10.40.40.254",
		HotspotDNSName:      "login",
		HotspotPortalName:   "NobliFi WiFi",
		DisableWWWService:   true,
		EnableAPIService:    true,
		EnableAPISSLService: true,
		WalledGardenHosts:   defaultWalledGardenHosts(),
	})
}

func RenderRouterOSWithOptions(assignments []Assignment, options RenderOptions) (string, error) {
	if err := Validate(assignments); err != nil {
		return "", err
	}
	options = withDefaults(options)

	// RouterOS /ip dhcp-server network requires a canonical network CIDR.
	// A profile value such as 10.10.10.1/24 is therefore normalized to
	// 10.10.10.0/24 before the RouterOS script is generated.
	var networkErr error
	options.HotspotSubnet, networkErr = canonicalNetworkCIDR(options.HotspotSubnet)
	if networkErr != nil {
		return "", fmt.Errorf("invalid HotSpot subnet: %w", networkErr)
	}
	options.StaffSubnet, networkErr = canonicalNetworkCIDR(options.StaffSubnet)
	if networkErr != nil {
		return "", fmt.Errorf("invalid Staff subnet: %w", networkErr)
	}
	options.POSSubnet, networkErr = canonicalNetworkCIDR(options.POSSubnet)
	if networkErr != nil {
		return "", fmt.Errorf("invalid POS subnet: %w", networkErr)
	}
	options.CCTVSubnet, networkErr = canonicalNetworkCIDR(options.CCTVSubnet)
	if networkErr != nil {
		return "", fmt.Errorf("invalid CCTV subnet: %w", networkErr)
	}

	if err := validateGatewayInSubnet(options.HotspotGateway, options.HotspotSubnet); err != nil {
		return "", fmt.Errorf("invalid HotSpot gateway: %w", err)
	}
	if err := validateGatewayInSubnet(options.StaffGateway, options.StaffSubnet); err != nil {
		return "", fmt.Errorf("invalid Staff gateway: %w", err)
	}
	if err := validateGatewayInSubnet(options.POSGateway, options.POSSubnet); err != nil {
		return "", fmt.Errorf("invalid POS gateway: %w", err)
	}
	if err := validateGatewayInSubnet(options.CCTVGateway, options.CCTVSubnet); err != nil {
		return "", fmt.Errorf("invalid CCTV gateway: %w", err)
	}
	if isPlaceholderRadiusServer(options.RadiusServer) {
		return "", fmt.Errorf("NOBLIFI_RADIUS_SERVER is %q, but MikroTik routers cannot use localhost, empty values, or setup placeholders for RADIUS. Set it to the public IP or DNS name of the VM/server running NobliFi RADIUS, for example 154.65.105.14, and make sure UDP ports 1812 and 1813 are reachable from the router", options.RadiusServer)
	}
	if isPlaceholderRadiusSecret(options.RadiusSecret) {
		options.RadiusSecret = "noblifi"
	}
	if isPlaceholderAPIPassword(options.APIPassword) {
		return "", fmt.Errorf("NOBLIFI_ROUTER_API_PASSWORD must be set to a real router API password before provisioning")
	}

	summary := BuildSummary(assignments)
	wan := summary.WAN[0]
	hotspotGateway := strings.Split(options.HotspotGateway, "/")[0]

	var builder strings.Builder
	builder.WriteString("# NobliFi generated RouterOS configuration\n")
	builder.WriteString("# Import this file with: /import file-name=noblifi-config.rsc\n\n")
	builder.WriteString("# Connection-preserving NobliFi installation\n")
	builder.WriteString(":put \"============================================================\"\n")
	builder.WriteString(":put \"NobliFi SAFE INSTALL: preserving current management session\"\n")
	builder.WriteString(":put \"WAN DHCP, management services and existing bridges will NOT be torn down\"\n")
	builder.WriteString(":put \"============================================================\"\n")

	// Remove only obsolete captive-portal files owned by NobliFi. Do not remove
	// WAN DHCP, bridges, IP addresses, HotSpot services or management services
	// here; those are updated in place below so the admin session stays alive.
	writeSafe(&builder, "/file remove [find name=\"noblifi/login.html\"]", "cleanup legacy root hotspot login file")
	writeSafe(&builder, "/file remove [find name=\"noblifi/status.html\"]", "cleanup legacy root hotspot status file")
	writeSafe(&builder, "/file remove [find name=\"noblifi/logout.html\"]", "cleanup legacy root hotspot logout file")
	builder.WriteString("\n")

	builder.WriteString("# Management and router services - preserve the active admin session\n")
	writeSafe(&builder, fmt.Sprintf("/system identity set name=\"%s\"", escape(options.RouterIdentity)), "set identity")

	// Upsert the NobliFi API management user. Never remove it first because a
	// live API/automation session could be using it during provisioning.
	builder.WriteString(fmt.Sprintf(`:local noblifiApiUser [/user find where name=%q]`+"\n", options.APIUsername))
	builder.WriteString(fmt.Sprintf(`:if ([:len $noblifiApiUser] = 0) do={ :do { /user add name=%q group=full password=%q comment="NobliFi API management user" } on-error={ :error "NobliFi failed to create API management user" } } else={ :foreach u in=$noblifiApiUser do={ :do { /user set $u group=full password=%q comment="NobliFi API management user" } on-error={ :error "NobliFi failed to update API management user" } } }`+"\n", options.APIUsername, options.APIPassword, options.APIPassword))

	// Do not disable www, www-ssl, ssh, winbox, telnet or any other management
	// service during provisioning. A user may be running this import from one of
	// those services. Only enable the API services NobliFi explicitly requires.
	builder.WriteString(":put \"NobliFi SAFE INSTALL: preserving WebFig/WinBox/SSH management services\"\n")
	if options.EnableAPIService {
		writeSafe(&builder, "/ip service set api disabled=no", "enable api service")
	}
	if options.EnableAPISSLService {
		writeSafe(&builder, "/ip service set api-ssl disabled=no", "enable api-ssl service")
	}
	builder.WriteString("\n")

	builder.WriteString("# Interface lists and WAN internet - preserve existing WAN lease\n")
	writeSafe(&builder, ":if ([:len [/interface list find name=WAN]] = 0) do={/interface list add name=WAN comment=\"NobliFi WAN list\"}", "ensure WAN list")
	writeSafe(&builder, ":if ([:len [/interface list find name=LAN]] = 0) do={/interface list add name=LAN comment=\"NobliFi LAN list\"}", "ensure LAN list")
	builder.WriteString(fmt.Sprintf(`:if ([:len [/interface list member find where list="WAN" interface=%q]] = 0) do={ :do { /interface list member add list=WAN interface=%q comment="NobliFi WAN member" } on-error={ :error "NobliFi failed to add WAN interface-list member" } }`+"\n", wan, wan))

	// CRITICAL: never remove the current WAN DHCP client during an import.
	// Removing it withdraws the dynamic address/default route and can instantly
	// terminate the terminal/API session used to install NobliFi.
	builder.WriteString(fmt.Sprintf(`:local noblifiWanDhcp [/ip dhcp-client find where interface=%q]`+"\n", wan))
	builder.WriteString(fmt.Sprintf(`:if ([:len $noblifiWanDhcp] = 0) do={ :do { /ip dhcp-client add interface=%q disabled=no add-default-route=yes use-peer-dns=yes comment="NobliFi WAN DHCP client" } on-error={ :error "NobliFi failed to create WAN DHCP client" } } else={ :foreach d in=$noblifiWanDhcp do={ :do { /ip dhcp-client set $d disabled=no add-default-route=yes use-peer-dns=yes } on-error={ :error "NobliFi failed to preserve WAN DHCP client" } } }`+"\n", wan))
	builder.WriteString(":put \"NobliFi SAFE INSTALL: WAN connectivity preserved\"\n\n")

	// Stage the complete HotSpot network and captive portal before moving any
	// physical client-facing ports. This keeps the current management path intact
	// for as long as possible and guarantees portal installation happens first.
	if len(summary.HotspotLAN) > 0 {
		writeHotspotNetwork(&builder, options, summary.HotspotLAN, hotspotGateway)
		writeHotspotServices(&builder, options, hotspotGateway)

		builder.WriteString(":put \"NobliFi SAFE INSTALL: captive portal is fully staged; applying final physical-port roles\"\n")

		// FREE_LAN is the installer/management safety port and must never join
		// br-hotspot. Keep it outside the captive portal.
		if len(summary.FreeLAN) > 0 {
			writeFreeLAN(&builder, options, summary.FreeLAN)
		}

		// This is intentionally the final connectivity-changing step.
		writeHotspotPortAssignments(&builder, options, summary.HotspotLAN)

		// The DHCP server was staged earlier on br-hotspot. Now that the
		// selected physical client ports are actually members of br-hotspot,
		// explicitly re-assert the DHCP bindings and verify that the service is
		// enabled. This is non-destructive and does not remove leases.
		writeHotspotDHCPFinalization(&builder, options)

		writeHotspotVerification(&builder, options, summary.HotspotLAN)
	} else {
		builder.WriteString("# No HOTSPOT_LAN ports selected; captive portal not installed\n")
		builder.WriteString(":put \"NobliFi captive portal skipped: no HotSpot ports selected\"\n\n")
	}

	return builder.String(), nil
}
func withDefaults(options RenderOptions) RenderOptions {
	defaults := RenderOptions{
		RouterIdentity:      "NobliFi-Router",
		APIUsername:         "noblifi-api",
		APIPassword:         "CHANGE_ME_API_PASSWORD",
		HotspotBridge:       "br-hotspot",
		StaffBridge:         "br-staff",
		POSBridge:           "br-pos",
		CCTVBridge:          "br-cctv",
		HotspotSubnet:       "10.10.10.0/24",
		HotspotGateway:      "10.10.10.1/24",
		HotspotPool:         "10.10.10.10-10.10.10.254",
		StaffSubnet:         "10.20.20.0/24",
		StaffGateway:        "10.20.20.1/24",
		StaffPool:           "10.20.20.10-10.20.20.254",
		POSSubnet:           "10.30.30.0/24",
		POSGateway:          "10.30.30.1/24",
		POSPool:             "10.30.30.10-10.30.30.254",
		CCTVSubnet:          "10.40.40.0/24",
		CCTVGateway:         "10.40.40.1/24",
		CCTVPool:            "10.40.40.10-10.40.40.254",
		HotspotDNSName:      "login",
		HotspotPortalName:   "NobliFi WiFi",
		DisableWWWService:   true,
		EnableAPIService:    true,
		EnableAPISSLService: true,
		WalledGardenHosts:   defaultWalledGardenHosts(),
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
	if options.HotspotDNSName == "" {
		options.HotspotDNSName = defaults.HotspotDNSName
	}
	if options.HotspotPortalName == "" {
		options.HotspotPortalName = defaults.HotspotPortalName
	}
	if len(options.WalledGardenHosts) == 0 {
		options.WalledGardenHosts = defaults.WalledGardenHosts
	}
	options.WalledGardenHosts = cleanHosts(options.WalledGardenHosts)
	return options
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

// writeCritical aborts the RouterOS import when a required configuration step
// fails. This prevents a partially configured captive portal from being marked
// installed and allows the configure_router job to retry.
func writeCritical(builder *strings.Builder, command string, message string) {
	builder.WriteString(fmt.Sprintf(":do { %s } on-error={ :error \"%s\" }\n", command, escape(message)))
}

func writeCleanup(builder *strings.Builder, bridge string, dhcpServer string, pool string, subnet string) {
	if bridge == "" {
		return
	}
	writeSafe(builder, fmt.Sprintf("/ip dhcp-server remove [find name=\"%s\"]", dhcpServer), "cleanup dhcp server")
	writeSafe(builder, fmt.Sprintf("/ip dhcp-server network remove [find address=%s]", subnet), "cleanup dhcp network")
	writeSafe(builder, fmt.Sprintf("/ip address remove [find interface=%s]", bridge), "cleanup bridge address")
	writeSafe(builder, fmt.Sprintf("/ip pool remove [find name=\"%s\"]", pool), "cleanup address pool")
	writeSafe(builder, fmt.Sprintf("/interface bridge port remove [find bridge=%s]", bridge), "cleanup bridge ports")
	writeSafe(builder, fmt.Sprintf("/interface bridge remove [find name=%s]", bridge), "cleanup bridge")
}

func canonicalNetworkCIDR(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("subnet is empty")
	}

	_, network, err := net.ParseCIDR(value)
	if err != nil {
		return "", fmt.Errorf("%q is not a valid CIDR", value)
	}

	return network.String(), nil
}

func validateGatewayInSubnet(gatewayCIDR, subnetCIDR string) error {
	gatewayCIDR = strings.TrimSpace(gatewayCIDR)
	if gatewayCIDR == "" {
		return fmt.Errorf("gateway is empty")
	}

	gatewayIP, _, err := net.ParseCIDR(gatewayCIDR)
	if err != nil {
		return fmt.Errorf("%q is not a valid gateway CIDR", gatewayCIDR)
	}

	_, network, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		return fmt.Errorf("%q is not a valid subnet CIDR", subnetCIDR)
	}

	if !network.Contains(gatewayIP) {
		return fmt.Errorf("gateway %s is outside subnet %s", gatewayIP.String(), network.String())
	}

	return nil
}

// writeDHCPNetworkUpsert makes the generated script idempotent.
// If RouterOS already has the same DHCP network, NobliFi updates it instead
// of failing with "network already exists". If it does not exist, NobliFi
// creates it. This also avoids deleting a working network entry merely to
// recreate the same entry during provisioning.
func writeDHCPNetworkUpsert(
	builder *strings.Builder,
	subnet string,
	gateway string,
	comment string,
) {
	builder.WriteString(fmt.Sprintf(
		`:local noblifiDhcpNet [/ip dhcp-server network find where address=%q]`+"\n",
		subnet,
	))
	builder.WriteString(fmt.Sprintf(
		`:if ([:len $noblifiDhcpNet] = 0) do={ :do { /ip dhcp-server network add address=%q gateway=%q dns-server=%q comment=%q } on-error={ :error %q } } else={ :foreach n in=$noblifiDhcpNet do={ :do { /ip dhcp-server network set $n gateway=%q dns-server=%q comment=%q } on-error={ :error %q } } }`+"\n",
		subnet,
		gateway,
		gateway,
		comment,
		"NobliFi failed to create DHCP network "+subnet,
		gateway,
		gateway,
		comment,
		"NobliFi failed to update DHCP network "+subnet,
	))
}

func writeFreeLAN(builder *strings.Builder, options RenderOptions, interfaces []string) {
	if len(interfaces) == 0 {
		return
	}

	builder.WriteString("# FREE_LAN management-safety ports - deliberately outside NobliFi HotSpot\n")
	builder.WriteString(":put \"NobliFi SAFE INSTALL: preserving FREE_LAN as the local management path\"\n")

	for _, iface := range interfaces {
		iface = strings.TrimSpace(iface)
		if iface == "" {
			continue
		}

		builder.WriteString(fmt.Sprintf(
			`:put "NobliFi FREE_LAN: keeping %s outside %s"`+"\n",
			escape(iface),
			escape(options.HotspotBridge),
		))

		// Remove only NobliFi HotSpot membership. We intentionally do not add
		// this interface to br-staff, br-pos, br-cctv, or any other bridge.
		// This leaves the physical port available for local/manual management.
		writeSafe(
			builder,
			fmt.Sprintf(
				`/interface bridge port remove [find where bridge=%q interface=%q]`,
				options.HotspotBridge,
				iface,
			),
			"remove FREE_LAN port from HotSpot bridge",
		)

		// Make sure NobliFi did not leave the port disabled.
		writeSafe(
			builder,
			fmt.Sprintf(`/interface ethernet set [find where name=%q] disabled=no`, iface),
			"enable FREE_LAN physical port",
		)
	}

	builder.WriteString(":put \"NobliFi FREE_LAN configuration complete\"\n\n")
}

func writeHotspotNetwork(builder *strings.Builder, options RenderOptions, interfaces []string, hotspotGateway string) {
	if len(interfaces) == 0 {
		return
	}

	builder.WriteString("# HotSpot bridge, DHCP, and client addressing - non-destructive upsert\n")
	builder.WriteString(":put \"NobliFi SAFE INSTALL: preparing HotSpot bridge/DHCP before moving client ports\"\n")

	writeCritical(
		builder,
		fmt.Sprintf(`:if ([:len [/interface bridge find where name=%q]] = 0) do={ /interface bridge add name=%q protocol-mode=rstp comment="NobliFi HotSpot bridge" }`, options.HotspotBridge, options.HotspotBridge),
		"NobliFi failed to create HotSpot bridge",
	)

	// Upsert gateway address instead of deleting/recreating the bridge.
	builder.WriteString(fmt.Sprintf(`:local noblifiHotspotAddr [/ip address find where interface=%q comment="NobliFi HotSpot gateway"]`+"\n", options.HotspotBridge))
	builder.WriteString(fmt.Sprintf(`:if ([:len $noblifiHotspotAddr] = 0) do={ :do { /ip address add address=%q interface=%q comment="NobliFi HotSpot gateway" } on-error={ :error "NobliFi failed to create HotSpot gateway" } } else={ :foreach a in=$noblifiHotspotAddr do={ :do { /ip address set $a address=%q interface=%q } on-error={ :error "NobliFi failed to update HotSpot gateway" } } }`+"\n", options.HotspotGateway, options.HotspotBridge, options.HotspotGateway, options.HotspotBridge))

	// Upsert DHCP pool.
	builder.WriteString(`:local noblifiHotspotPool [/ip pool find where name="pool-hotspot"]` + "\n")
	builder.WriteString(fmt.Sprintf(`:if ([:len $noblifiHotspotPool] = 0) do={ :do { /ip pool add name=pool-hotspot ranges=%q comment="NobliFi HotSpot pool" } on-error={ :error "NobliFi failed to create HotSpot address pool" } } else={ :foreach p in=$noblifiHotspotPool do={ :do { /ip pool set $p ranges=%q } on-error={ :error "NobliFi failed to update HotSpot address pool" } } }`+"\n", options.HotspotPool, options.HotspotPool))

	// Upsert DHCP server and keep it enabled.
	builder.WriteString(`:local noblifiHotspotDhcp [/ip dhcp-server find where name="dhcp-hotspot"]` + "\n")
	builder.WriteString(fmt.Sprintf(`:if ([:len $noblifiHotspotDhcp] = 0) do={ :do { /ip dhcp-server add name=dhcp-hotspot interface=%q address-pool=pool-hotspot lease-time=1h disabled=no } on-error={ :error "NobliFi failed to create HotSpot DHCP server" } } else={ :foreach d in=$noblifiHotspotDhcp do={ :do { /ip dhcp-server set $d interface=%q address-pool=pool-hotspot lease-time=1h disabled=no } on-error={ :error "NobliFi failed to update HotSpot DHCP server" } } }`+"\n", options.HotspotBridge, options.HotspotBridge))

	writeDHCPNetworkUpsert(
		builder,
		options.HotspotSubnet,
		hotspotGateway,
		"NobliFi HotSpot DHCP network",
	)

	builder.WriteString(`:if ([:len [/ip dhcp-server find where name="dhcp-hotspot" disabled=no]] = 0) do={ :error "NobliFi HotSpot DHCP server was not created or is disabled" }` + "\n")
	builder.WriteString(`:if ([:len [/ip pool find where name="pool-hotspot"]] = 0) do={ :error "NobliFi HotSpot DHCP address pool is missing" }` + "\n")
	builder.WriteString(fmt.Sprintf(`:if ([:len [/ip dhcp-server network find where address=%q]] = 0) do={ :error "NobliFi HotSpot DHCP network is missing" }`+"\n", options.HotspotSubnet))
	builder.WriteString(":put \"NobliFi DHCP READY: server=dhcp-hotspot interface=" + escape(options.HotspotBridge) + " pool=pool-hotspot\"\n")
	builder.WriteString(":put \"NobliFi HotSpot bridge and DHCP prepared without dropping management connectivity\"\n\n")
}

// writeHotspotPortAssignments is deliberately called only after the full
// captive portal, RADIUS, DHCP, scheduler and HotSpot server have been created.
// Moving a physical interface between bridges changes its Layer-2 path. By
// deferring this to the final stage, the installation itself completes first.
func writeHotspotPortAssignments(builder *strings.Builder, options RenderOptions, interfaces []string) {
	if len(interfaces) == 0 {
		return
	}

	builder.WriteString("# Final HotSpot physical-port assignment\n")
	builder.WriteString(":put \"NobliFi FINAL NETWORK STEP: attaching selected HotSpot ports to br-hotspot\"\n")
	builder.WriteString(":put \"Management safety: remain connected through FREE_LAN, WAN or WireGuard while ports are moved\"\n")

	for _, iface := range interfaces {
		iface = strings.TrimSpace(iface)
		if iface == "" {
			continue
		}

		// If already in the correct bridge, do nothing. This avoids needless
		// link/L2 changes on repeat provisioning runs.
		builder.WriteString(fmt.Sprintf(`:if ([:len [/interface bridge port find where bridge=%q interface=%q]] = 0) do={ `, options.HotspotBridge, iface))
		builder.WriteString(fmt.Sprintf(`:do { /interface bridge port remove [find where interface=%q] } on-error={}; `, iface))
		builder.WriteString(fmt.Sprintf(`:do { /interface bridge port add bridge=%q interface=%q comment="NobliFi HotSpot port" } on-error={ :error "NobliFi failed to attach %s to HotSpot bridge" } }`+"\n", options.HotspotBridge, iface, escape(iface)))

		builder.WriteString(fmt.Sprintf(`:if ([:len [/interface list member find where list="LAN" interface=%q]] = 0) do={ :do { /interface list member add list=LAN interface=%q comment="NobliFi LAN member" } on-error={} }`+"\n", iface, iface))
	}

	builder.WriteString(":put \"NobliFi selected HotSpot ports attached\"\n\n")
}

func writeHotspotDHCPFinalization(builder *strings.Builder, options RenderOptions) {
	builder.WriteString("# Final NobliFi HotSpot DHCP activation\n")
	builder.WriteString(":put \"NobliFi DHCP FINALIZATION: activating DHCP on br-hotspot after client ports are attached\"\n")

	builder.WriteString(`:local noblifiFinalDhcp [/ip dhcp-server find where name="dhcp-hotspot"]` + "\n")
	builder.WriteString(`:if ([:len $noblifiFinalDhcp] = 0) do={ :error "NobliFi DHCP finalization failed: dhcp-hotspot does not exist" }` + "\n")

	builder.WriteString(fmt.Sprintf(
		`:foreach d in=$noblifiFinalDhcp do={ :do { /ip dhcp-server set $d interface=%q address-pool=pool-hotspot disabled=no } on-error={ :error "NobliFi DHCP finalization failed while enabling dhcp-hotspot" } }`+"\n",
		options.HotspotBridge,
	))

	builder.WriteString(`:if ([:len [/ip dhcp-server find where name="dhcp-hotspot" disabled=no]] = 0) do={ :error "NobliFi DHCP finalization failed: dhcp-hotspot is disabled" }` + "\n")
	builder.WriteString(fmt.Sprintf(
		`:if ([:len [/ip address find where interface=%q address=%q]] = 0) do={ :error "NobliFi DHCP finalization failed: HotSpot gateway address is missing" }`+"\n",
		options.HotspotBridge,
		options.HotspotGateway,
	))
	builder.WriteString(`:if ([:len [/ip pool find where name="pool-hotspot"]] = 0) do={ :error "NobliFi DHCP finalization failed: pool-hotspot is missing" }` + "\n")

	builder.WriteString(":put \"NobliFi DHCP ACTIVE: hotspot clients can now request addresses\"\n\n")
}

func writeHotspotServices(builder *strings.Builder, options RenderOptions, hotspotGateway string) {
	builder.WriteString("# DNS, NAT, RADIUS, and HotSpot captive portal setup\n")
	builder.WriteString(":put \"============================================================\"\n")
	builder.WriteString(":put \"NobliFi CAPTIVE PORTAL INSTALLATION STARTED\"\n")
	builder.WriteString(":put \"Target directory: /flash/noblifi\"\n")
	builder.WriteString(":put \"============================================================\"\n")

	// RouterOS can disable HotSpot and Fetch through device-mode. Detect the
	// HotSpot restriction early so provisioning fails with a useful message.
	builder.WriteString(":local hotspotDeviceModeAllowed true\n")
	builder.WriteString(`:do { :local dm [/system/device-mode get hotspot]; :if ($dm = false) do={ :set hotspotDeviceModeAllowed false } } on-error={}` + "\n")
	builder.WriteString(`:if (!$hotspotDeviceModeAllowed) do={ :error "NobliFi HotSpot is disabled by RouterOS device-mode; enable hotspot=yes and physically confirm the device-mode change" }` + "\n")

	builder.WriteString(":put \"[1/12] Configuring DNS and NAT...\"\n")
	writeSafe(builder, "/ip dns set allow-remote-requests=yes", "enable dns forwarding")
	builder.WriteString(`:if ([:len [/ip firewall nat find where comment="NobliFi client NAT"]] = 0) do={ :do { /ip firewall nat add chain=srcnat out-interface-list=WAN action=masquerade comment="NobliFi client NAT" } on-error={ :error "NobliFi failed to create client NAT" } }` + "\n")

	builder.WriteString(":put \"[2/12] Configuring RADIUS client...\"\n")
	builder.WriteString(`:local noblifiRadius [/radius find where comment="NobliFi RADIUS"]` + "\n")
	builder.WriteString(fmt.Sprintf(`:if ([:len $noblifiRadius] = 0) do={ :do { /radius add service=hotspot address=%q secret=%q authentication-port=1812 accounting-port=1813 timeout=3s comment="NobliFi RADIUS" } on-error={ :error "NobliFi failed to create RADIUS client" } } else={ :foreach r in=$noblifiRadius do={ :do { /radius set $r service=hotspot address=%q secret=%q authentication-port=1812 accounting-port=1813 timeout=3s } on-error={ :error "NobliFi failed to update RADIUS client" } } }`+"\n", options.RadiusServer, options.RadiusSecret, options.RadiusServer, options.RadiusSecret))
	writeSafe(builder, "/radius incoming set accept=yes", "enable radius incoming")
	builder.WriteString(":put \"NobliFi RADIUS client configured\"\n")

	// NobliFi portal files must be persistent. On RouterBOARD devices exposing
	// the flash disk, anything outside flash may live only in RAM and disappear
	// after a reboot. RouterOS creates directories with:
	//
	//   /file add name=/flash/<directory> type=directory
	//
	// Do not use `/file make-directory`; it is not the RouterOS file command.
	builder.WriteString(":put \"[3/12] Preparing persistent captive portal directory /flash/noblifi...\"\n")
	builder.WriteString(`:if ([:len [/file find where name="flash"]] = 0) do={ :error "NobliFi requires persistent flash storage but /flash was not found" }` + "\n")

	// File-list lookup names do not include the leading slash, while the full
	// path used to create the directory and by html-directory does.
	builder.WriteString(`:local hotspotDirLookup "flash/noblifi"` + "\n")
	builder.WriteString(`:local hotspotDir "/flash/noblifi"` + "\n")
	builder.WriteString(`:local hotspotLoginFile "flash/noblifi/login.html"` + "\n")
	builder.WriteString(`:local hotspotStatusFile "flash/noblifi/status.html"` + "\n")
	builder.WriteString(`:local hotspotLogoutFile "flash/noblifi/logout.html"` + "\n")

	writeCritical(
		builder,
		`:if ([:len [/file find where name=$hotspotDirLookup]] = 0) do={ /file add name="/flash/noblifi" type=directory }`,
		"NobliFi failed to create /flash/noblifi HotSpot directory",
	)

	builder.WriteString(`:if ([:len [/file find where name=$hotspotDirLookup]] = 0) do={ :error "NobliFi /flash/noblifi directory is still missing after creation" }` + "\n")
	builder.WriteString(":put \"[3/12] OK - /flash/noblifi directory is ready\"\n")

	// Create local supporting servlet files first. They make the portal usable
	// even before dedicated tenant status/logout endpoints are available.
	// login.html itself is always fetched from the tenant-scoped backend URL.
	builder.WriteString(":put \"[4/12] Installing RouterOS captive portal support files...\"\n")
	writeStaticHotspotFile(
		builder,
		"/flash/noblifi/status.html",
		"flash/noblifi/status.html",
		`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>NobliFi</title></head><body><h2>Connected to NobliFi</h2><p>Your internet session is active.</p><p><a href="/logout">Disconnect</a></p></body></html>`,
		"status.html",
	)
	writeStaticHotspotFile(
		builder,
		"/flash/noblifi/logout.html",
		"flash/noblifi/logout.html",
		`<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>NobliFi</title></head><body><h2>Disconnected</h2><p>Your NobliFi session has ended.</p><p><a href="/login">Connect again</a></p></body></html>`,
		"logout.html",
	)
	writeStaticHotspotFile(
		builder,
		"/flash/noblifi/redirect.html",
		"flash/noblifi/redirect.html",
		`<!doctype html><html><head><meta http-equiv="refresh" content="0;url=/login"></head><body><a href="/login">Continue</a></body></html>`,
		"redirect.html",
	)
	writeStaticHotspotFile(
		builder,
		"/flash/noblifi/rlogin.html",
		"flash/noblifi/rlogin.html",
		`<!doctype html><html><head><meta http-equiv="refresh" content="0;url=/login"></head><body><a href="/login">Continue</a></body></html>`,
		"rlogin.html",
	)
	writeStaticHotspotFile(
		builder,
		"/flash/noblifi/fstatus.html",
		"flash/noblifi/fstatus.html",
		`<!doctype html><html><head><meta http-equiv="refresh" content="0;url=/login"></head><body><a href="/login">Login</a></body></html>`,
		"fstatus.html",
	)
	writeStaticHotspotFile(
		builder,
		"/flash/noblifi/flogout.html",
		"flash/noblifi/flogout.html",
		`<!doctype html><html><head><meta http-equiv="refresh" content="0;url=/login"></head><body><a href="/login">Login</a></body></html>`,
		"flogout.html",
	)
	writeStaticHotspotFile(
		builder,
		"/flash/noblifi/alogin.html",
		"flash/noblifi/alogin.html",
		`<!doctype html><html><head><meta http-equiv="refresh" content="0;url=/status"></head><body><a href="/status">Continue</a></body></html>`,
		"alogin.html",
	)

	builder.WriteString(":put \"[5/12] Creating NobliFi voucher profile...\"\n")
	builder.WriteString(`:if ([:len [/ip hotspot user profile find where name="noblifi-voucher-profile"]] = 0) do={ :do { /ip hotspot user profile add name=noblifi-voucher-profile } on-error={ :error "NobliFi failed to create HotSpot voucher profile" } }` + "\n")
	writeCritical(builder, "/ip hotspot user profile set noblifi-voucher-profile shared-users=1", "NobliFi failed to set HotSpot shared-users")
	writeCritical(builder, "/ip hotspot user profile set noblifi-voucher-profile keepalive-timeout=2m", "NobliFi failed to set HotSpot keepalive")
	writeCritical(builder, "/ip hotspot user profile set noblifi-voucher-profile status-autorefresh=1m", "NobliFi failed to set HotSpot status refresh")

	builder.WriteString(":put \"[6/12] Creating HotSpot server profile...\"\n")

	// Create the profile with the smallest possible valid command first.
	// Do not put dns-name/login-by/html-directory/use-radius in one command:
	// if one property is rejected by a RouterOS build, the entire profile
	// creation would fail and the installation would stop before LAN ports
	// are attached and DHCP becomes reachable.
	builder.WriteString(`:local noblifiHotspotProfile [/ip hotspot profile find where name="noblifi-hotspot-profile"]` + "\n")
	builder.WriteString(fmt.Sprintf(
		`:if ([:len $noblifiHotspotProfile] = 0) do={ :do { /ip hotspot profile add name="noblifi-hotspot-profile" hotspot-address=%q } on-error={ :error "NobliFi failed to create base HotSpot server profile" } }`+"\n",
		hotspotGateway,
	))
	builder.WriteString(`:set noblifiHotspotProfile [/ip hotspot profile find where name="noblifi-hotspot-profile"]` + "\n")
	builder.WriteString(`:if ([:len $noblifiHotspotProfile] = 0) do={ :error "NobliFi HotSpot profile does not exist after base creation" }` + "\n")
	builder.WriteString(":put \"[6/12] OK - base HotSpot profile exists\"\n")

	// Apply required properties individually so an error identifies the exact
	// setting instead of collapsing everything into a generic profile failure.
	builder.WriteString(":put \"      setting hotspot-address...\"\n")
	builder.WriteString(fmt.Sprintf(
		`:foreach p in=$noblifiHotspotProfile do={ :do { /ip hotspot profile set $p hotspot-address=%q } on-error={ :error "NobliFi failed to set HotSpot profile hotspot-address" } }`+"\n",
		hotspotGateway,
	))

	builder.WriteString(":put \"      enabling RADIUS authentication...\"\n")
	builder.WriteString(
		`:foreach p in=$noblifiHotspotProfile do={ :do { /ip hotspot profile set $p use-radius=yes } on-error={ :error "NobliFi failed to enable RADIUS on HotSpot profile" } }` + "\n",
	)

	// Prefer CHAP + PAP. If a RouterOS build rejects the combined list, fall
	// back to PAP so the voucher portal can still authenticate through RADIUS.
	builder.WriteString(":put \"      setting HotSpot login method...\"\n")
	builder.WriteString(
		`:foreach p in=$noblifiHotspotProfile do={ :do { /ip hotspot profile set $p login-by=http-chap,http-pap } on-error={ :do { /ip hotspot profile set $p login-by=http-pap } on-error={ :error "NobliFi failed to set HotSpot login method" } } }` + "\n",
	)

	// The HotSpot DNS name is tenant-specific and required. NobliFi derives it
	// from the router owner's HotspotName, for example:
	//
	//   "Mukama WiFi" -> "mukama-wifi.login"
	//
	// Do not silently continue with an empty DNS name because that hides a
	// broken tenant/profile mapping and prevents the expected branded HotSpot
	// hostname from appearing in RouterOS.
	if strings.TrimSpace(options.HotspotDNSName) == "" {
		builder.WriteString(`:error "NobliFi HotSpot DNS name is empty; owner hotspot name was not resolved"` + "\n")
		return
	}

	builder.WriteString(fmt.Sprintf(
		":put \"      setting tenant HotSpot DNS name: %s...\"\n",
		escape(options.HotspotDNSName),
	))
	builder.WriteString(fmt.Sprintf(
		`:foreach p in=$noblifiHotspotProfile do={ :do { /ip hotspot profile set $p dns-name=%q } on-error={ :error "NobliFi failed to set tenant HotSpot DNS name" } }`+"\n",
		options.HotspotDNSName,
	))
	builder.WriteString(`:local noblifiProfileDNS [/ip hotspot profile get [find where name="noblifi-hotspot-profile"] dns-name]` + "\n")
	builder.WriteString(fmt.Sprintf(
		`:if ($noblifiProfileDNS != %q) do={ :error "NobliFi HotSpot DNS verification failed" }`+"\n",
		options.HotspotDNSName,
	))
	builder.WriteString(fmt.Sprintf(
		":put \"      OK - HotSpot DNS name set to %s\"\n",
		escape(options.HotspotDNSName),
	))

	builder.WriteString(":put \"      setting persistent HTML directory...\"\n")
	// Official RouterOS syntax uses /flash/<dir>. Some hardware/RouterOS
	// combinations expose the same path without the leading slash in setters,
	// so use the documented form first and a compatibility fallback second.
	builder.WriteString(
		`:foreach p in=$noblifiHotspotProfile do={ :do { /ip hotspot profile set $p html-directory="/flash/noblifi" } on-error={ :do { /ip hotspot profile set $p html-directory="flash/noblifi" } on-error={ :error "NobliFi failed to set HotSpot HTML directory to flash/noblifi" } } }` + "\n",
	)

	builder.WriteString(":put \"      enabling RADIUS accounting...\"\n")
	builder.WriteString(
		`:foreach p in=$noblifiHotspotProfile do={ :do { /ip hotspot profile set $p radius-accounting=yes } on-error={ :error "NobliFi failed to enable HotSpot RADIUS accounting" } }` + "\n",
	)
	builder.WriteString(
		`:foreach p in=$noblifiHotspotProfile do={ :do { /ip hotspot profile set $p radius-interim-update=5m } on-error={ :error "NobliFi failed to set HotSpot RADIUS interim update" } }` + "\n",
	)

	builder.WriteString(":put \"[6/12] OK - HotSpot server profile configured\"\n")

	builder.WriteString(":put \"[7/12] Configuring captive portal walled garden...\"\n")
	for _, host := range options.WalledGardenHosts {
		writeSafe(
			builder,
			fmt.Sprintf(`:if ([:len [/ip hotspot walled-garden find where dst-host=%q comment="NobliFi captive portal"]] = 0) do={ /ip hotspot walled-garden add dst-host=%q comment="NobliFi captive portal" }`, host, host),
			"add captive portal walled garden",
		)
	}

	loginURL := strings.TrimSpace(options.LoginPageURL)
	if loginURL == "" {
		builder.WriteString(":error \"NobliFi captive portal login URL is missing\"\n")
		return
	}

	// login.html is mandatory and tenant-scoped.
	builder.WriteString(":put \"[8/12] Downloading tenant login.html -> /flash/noblifi/login.html...\"\n")
	writeCritical(
		builder,
		fmt.Sprintf(
			`/tool fetch url=%q mode=%s dst-path="flash/noblifi/login.html" idle-timeout=30s duration=1m`,
			loginURL,
			portalFetchMode(loginURL),
		),
		"NobliFi failed to download tenant captive portal login page",
	)
	builder.WriteString(":put \"[8/12] OK - tenant login.html downloaded\"\n")

	// status.html/logout.html already have local fallbacks. If dedicated backend
	// URLs exist, replace those fallbacks, but a missing optional endpoint must
	// never prevent the HotSpot server from being installed.
	statusURL := strings.TrimSpace(options.StatusPageURL)
	if statusURL != "" {
		builder.WriteString(":put \"[9/12] Downloading tenant status.html -> /flash/noblifi/status.html...\"\n")
		writeSafe(
			builder,
			fmt.Sprintf(
				`/tool fetch url=%q mode=%s dst-path="flash/noblifi/status.html" idle-timeout=30s duration=1m`,
				statusURL,
				portalFetchMode(statusURL),
			),
			"download tenant captive portal status page",
		)
	}

	logoutURL := strings.TrimSpace(options.LogoutPageURL)
	if logoutURL != "" {
		builder.WriteString(":put \"[9/12] Downloading tenant logout.html -> /flash/noblifi/logout.html...\"\n")
		writeSafe(
			builder,
			fmt.Sprintf(
				`/tool fetch url=%q mode=%s dst-path="flash/noblifi/logout.html" idle-timeout=30s duration=1m`,
				logoutURL,
				portalFetchMode(logoutURL),
			),
			"download tenant captive portal logout page",
		)
	}

	// Refresh login.html periodically so tenant branding and packages update.
	builder.WriteString(":put \"[10/12] Installing captive portal refresh scheduler...\"\n")

	refreshCommand := fmt.Sprintf(
		`/tool fetch url="%s" mode=%s dst-path="flash/noblifi/login.html" idle-timeout=30s duration=1m`,
		escape(loginURL),
		portalFetchMode(loginURL),
	)

	if statusURL != "" {
		refreshCommand += fmt.Sprintf(
			`; /tool fetch url="%s" mode=%s dst-path="flash/noblifi/status.html" idle-timeout=30s duration=1m`,
			escape(statusURL),
			portalFetchMode(statusURL),
		)
	}
	if logoutURL != "" {
		refreshCommand += fmt.Sprintf(
			`; /tool fetch url="%s" mode=%s dst-path="flash/noblifi/logout.html" idle-timeout=30s duration=1m`,
			escape(logoutURL),
			portalFetchMode(logoutURL),
		)
	}

	builder.WriteString(`:local noblifiPortalScheduler [/system scheduler find where name="noblifi-hotspot-portal-refresh"]` + "\n")
	builder.WriteString(fmt.Sprintf(`:if ([:len $noblifiPortalScheduler] = 0) do={ :do { /system scheduler add name=noblifi-hotspot-portal-refresh interval=10m on-event=%q comment="NobliFi tenant HotSpot portal refresh" } on-error={ :error "NobliFi failed to create portal refresh scheduler" } } else={ :foreach s in=$noblifiPortalScheduler do={ :do { /system scheduler set $s interval=10m on-event=%q disabled=no comment="NobliFi tenant HotSpot portal refresh" } on-error={ :error "NobliFi failed to update portal refresh scheduler" } } }`+"\n", refreshCommand, refreshCommand))

	builder.WriteString(":put \"[11/12] Creating and enabling NobliFi HotSpot server...\"\n")
	builder.WriteString(`:local noblifiHotspotServer [/ip hotspot find where name="noblifi-hotspot"]` + "\n")
	builder.WriteString(fmt.Sprintf(`:if ([:len $noblifiHotspotServer] = 0) do={ :do { /ip hotspot add name=noblifi-hotspot interface=%q address-pool=pool-hotspot profile=noblifi-hotspot-profile disabled=no } on-error={ :error "NobliFi failed to create HotSpot server" } } else={ :foreach h in=$noblifiHotspotServer do={ :do { /ip hotspot set $h interface=%q address-pool=pool-hotspot profile=noblifi-hotspot-profile disabled=no } on-error={ :error "NobliFi failed to update HotSpot server" } } }`+"\n", options.HotspotBridge, options.HotspotBridge))

	builder.WriteString(":put \"[12/12] Captive portal installation completed\"\n")
	builder.WriteString(":put \"Files installed under /flash/noblifi:\"\n")
	builder.WriteString(":put \"  - login.html\"\n")
	builder.WriteString(":put \"  - status.html\"\n")
	builder.WriteString(":put \"  - logout.html\"\n")
	builder.WriteString(":put \"  - redirect.html\"\n")
	builder.WriteString(":put \"  - rlogin.html\"\n")
	builder.WriteString(":put \"  - fstatus.html\"\n")
	builder.WriteString(":put \"  - flogout.html\"\n")
	builder.WriteString(":put \"  - alogin.html\"\n")
	builder.WriteString(":put \"No reboot is required.\"\n")
	builder.WriteString(":put \"============================================================\"\n\n")
}

func writeStaticHotspotFile(
	builder *strings.Builder,
	createPath string,
	lookupPath string,
	contents string,
	label string,
) {
	builder.WriteString(fmt.Sprintf(":put \"      installing %s...\"\n", escape(label)))

	writeSafe(
		builder,
		fmt.Sprintf(
			`:if ([:len [/file find where name=%q]] = 0) do={ /file add name=%q type=file }`,
			lookupPath,
			createPath,
		),
		"create "+label,
	)

	writeSafe(
		builder,
		fmt.Sprintf(
			`/file set [find where name=%q] contents=%q`,
			lookupPath,
			contents,
		),
		"write "+label,
	)

	builder.WriteString(fmt.Sprintf(":put \"      OK - %s installed\"\n", escape(label)))
}

func portalFetchMode(rawURL string) string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(rawURL)), "https://") {
		return "https"
	}
	return "http"
}

func writeHotspotVerification(builder *strings.Builder, options RenderOptions, interfaces []string) {
	builder.WriteString("# Verify selected HotSpot ports and persistent captive portal before success\n")
	builder.WriteString(":put \"NobliFi verification: checking HotSpot bridge, DHCP, server and portal files...\"\n")

	builder.WriteString(fmt.Sprintf(
		`:if ([:len [/interface bridge find where name=%q]] = 0) do={ :error "NobliFi HotSpot bridge missing after configuration" }`+"\n",
		options.HotspotBridge,
	))

	for _, iface := range interfaces {
		builder.WriteString(fmt.Sprintf(
			`:if ([:len [/interface bridge port find where bridge=%q interface=%q]] = 0) do={ :error "NobliFi HotSpot port %s is not on the HotSpot bridge" }`+"\n",
			options.HotspotBridge,
			iface,
			escape(iface),
		))
	}

	builder.WriteString(`:if ([:len [/ip dhcp-server find where name="dhcp-hotspot" disabled=no]] = 0) do={ :error "NobliFi HotSpot DHCP server missing or disabled" }` + "\n")
	builder.WriteString(`:if ([:len [/ip hotspot profile find where name="noblifi-hotspot-profile"]] = 0) do={ :error "NobliFi HotSpot profile missing" }` + "\n")
	builder.WriteString(`:if ([:len [/ip hotspot find where name="noblifi-hotspot" disabled=no]] = 0) do={ :error "NobliFi HotSpot server missing or disabled" }` + "\n")

	builder.WriteString(`:if ([:len [/file find where name="flash/noblifi"]] = 0) do={ :error "NobliFi persistent /flash/noblifi directory missing" }` + "\n")
	builder.WriteString(`:if ([:len [/file find where name="flash/noblifi/login.html"]] = 0) do={ :error "NobliFi tenant captive portal login.html missing from flash" }` + "\n")
	builder.WriteString(`:if ([:len [/file find where name="flash/noblifi/status.html"]] = 0) do={ :error "NobliFi captive portal status.html missing from flash" }` + "\n")
	builder.WriteString(`:if ([:len [/file find where name="flash/noblifi/logout.html"]] = 0) do={ :error "NobliFi captive portal logout.html missing from flash" }` + "\n")

	builder.WriteString(`:local verifyNobliFiDNS [/ip hotspot profile get [find where name="noblifi-hotspot-profile"] dns-name]` + "\n")
	builder.WriteString(fmt.Sprintf(
		`:if ($verifyNobliFiDNS != %q) do={ :error "NobliFi tenant HotSpot DNS name is missing or incorrect" }`+"\n",
		options.HotspotDNSName,
	))

	builder.WriteString(`:local noblifiHtmlDir [/ip hotspot profile get [find where name="noblifi-hotspot-profile"] html-directory]` + "\n")
	builder.WriteString(`:if (($noblifiHtmlDir != "/flash/noblifi") && ($noblifiHtmlDir != "flash/noblifi")) do={ :error "NobliFi HotSpot profile is not using flash/noblifi" }` + "\n")

	builder.WriteString(":put \"NobliFi tenant captive portal verified successfully in /flash/noblifi\"\n")
	builder.WriteString(":put \"NobliFi SAFE INSTALL COMPLETE - WAN and management services were preserved\"\n\n")
}

func writeBridge(builder *strings.Builder, bridge string, interfaces []string, address string, pool string, ranges string, subnet string) {
	if len(interfaces) == 0 {
		return
	}
	role := strings.TrimPrefix(bridge, "br-")
	gateway := strings.Split(address, "/")[0]
	builder.WriteString(fmt.Sprintf("# %s bridge, DHCP, and client addressing\n", strings.ToUpper(role)))
	writeSafe(builder, fmt.Sprintf(":if ([:len [/interface bridge find name=%s]] = 0) do={ /interface bridge add name=%s protocol-mode=rstp comment=\"NobliFi %s bridge\" }", bridge, bridge, role), "ensure bridge")
	for _, iface := range interfaces {
		writeSafe(builder, fmt.Sprintf("/interface bridge port remove [find interface=%s]", iface), "cleanup bridge port")
		writeSafe(builder, fmt.Sprintf(":if ([:len [/interface bridge port find bridge=%s interface=%s]] = 0) do={/interface bridge port add bridge=%s interface=%s comment=\"NobliFi %s port\"}", bridge, iface, bridge, iface, role), "add bridge port")
		writeSafe(builder, fmt.Sprintf("/interface list member remove [find list=LAN interface=%s]", iface), "cleanup LAN list member")
		writeSafe(builder, fmt.Sprintf("/interface list member add list=LAN interface=%s comment=\"NobliFi LAN member\"", iface), "add LAN list member")
	}
	writeSafe(builder, fmt.Sprintf("/ip address add address=%s interface=%s comment=\"NobliFi %s gateway\"", address, bridge, role), "add bridge gateway")
	writeSafe(builder, fmt.Sprintf("/ip pool add name=%s ranges=%s comment=\"NobliFi %s pool\"", pool, ranges, role), "add address pool")
	writeSafe(builder, fmt.Sprintf("/ip dhcp-server add name=dhcp-%s interface=%s address-pool=%s lease-time=1h disabled=no", role, bridge, pool), "add dhcp server")
	writeDHCPNetworkUpsert(
		builder,
		subnet,
		gateway,
		"NobliFi "+role+" DHCP network",
	)
	builder.WriteString("\n")
}

func defaultWalledGardenHosts() []string {
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
		host = strings.TrimSpace(host)
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