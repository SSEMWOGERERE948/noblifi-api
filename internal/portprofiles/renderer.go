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
	StaffLAN   []string `json:"staff_lan"`
	POSLAN     []string `json:"pos_lan"`
	CCTVLAN    []string `json:"cctv_lan"`
	Disabled   []string `json:"disabled"`
}

type RenderOptions struct {
	RadiusServer        string
	RadiusSecret        string
	LoginPageURL        string
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
		HotspotDNSName:      "login.noblifi.local",
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
	builder.WriteString("# Clean previous NobliFi-owned service setup\n")
	writeSafe(&builder, "/ip hotspot remove [find name=\"noblifi-hotspot\"]", "cleanup hotspot server")
	writeSafe(&builder, "/ip hotspot profile remove [find name=\"noblifi-hotspot-profile\"]", "cleanup hotspot profile")
	writeSafe(&builder, "/ip hotspot user profile remove [find name=\"noblifi-voucher-profile\"]", "cleanup hotspot user profile")
	writeSafe(&builder, "/ip hotspot walled-garden remove [find comment=\"NobliFi captive portal\"]", "cleanup captive portal walled garden")
	writeSafe(&builder, "/file remove [find name=\"noblifi/login.html\"]", "cleanup legacy hotspot login file")
	writeSafe(&builder, "/file remove [find name=\"flash/noblifi/login.html\"]", "cleanup persistent hotspot login file")
	writeSafe(&builder, "/radius remove [find comment=\"NobliFi RADIUS\"]", "cleanup radius client")
	writeSafe(&builder, "/ip firewall nat remove [find comment=\"NobliFi client NAT\"]", "cleanup nat")
	writeSafe(&builder, fmt.Sprintf("/ip dhcp-client remove [find interface=%s]", wan), "cleanup wan dhcp client")
	writeCleanup(&builder, options.HotspotBridge, "dhcp-hotspot", "pool-hotspot", options.HotspotSubnet)
	writeCleanup(&builder, options.StaffBridge, "dhcp-staff", "pool-staff", options.StaffSubnet)
	writeCleanup(&builder, options.POSBridge, "dhcp-pos", "pool-pos", options.POSSubnet)
	writeCleanup(&builder, options.CCTVBridge, "dhcp-cctv", "pool-cctv", options.CCTVSubnet)
	builder.WriteString("\n")

	builder.WriteString("# Management and router services\n")
	writeSafe(&builder, fmt.Sprintf("/system identity set name=\"%s\"", escape(options.RouterIdentity)), "set identity")
	writeSafe(&builder, fmt.Sprintf("/user remove [find name=%s comment=\"NobliFi API management user\"]", options.APIUsername), "cleanup api user")
	writeSafe(&builder, fmt.Sprintf("/user add name=%s group=full password=\"%s\" comment=\"NobliFi API management user\"", options.APIUsername, escape(options.APIPassword)), "add api user")
	writeSafe(&builder, "/ip service set telnet disabled=yes", "disable telnet")
	writeSafe(&builder, "/ip service set ftp disabled=yes", "disable ftp")
	if options.DisableWWWService {
		writeSafe(&builder, "/ip service set www disabled=yes", "disable www")
	}
	writeSafe(&builder, fmt.Sprintf("/ip service set api disabled=%s", routerOSDisabled(!options.EnableAPIService)), "set api service")
	writeSafe(&builder, fmt.Sprintf("/ip service set api-ssl disabled=%s", routerOSDisabled(!options.EnableAPISSLService)), "set api-ssl service")
	builder.WriteString("\n")

	builder.WriteString("# Interface lists and WAN internet\n")
	writeSafe(&builder, ":if ([:len [/interface list find name=WAN]] = 0) do={/interface list add name=WAN comment=\"NobliFi WAN list\"}", "ensure WAN list")
	writeSafe(&builder, ":if ([:len [/interface list find name=LAN]] = 0) do={/interface list add name=LAN comment=\"NobliFi LAN list\"}", "ensure LAN list")
	writeSafe(&builder, fmt.Sprintf("/interface list member remove [find list=WAN interface=%s]", wan), "cleanup WAN list member")
	writeSafe(&builder, fmt.Sprintf("/interface list member add list=WAN interface=%s comment=\"NobliFi WAN member\"", wan), "add WAN list member")
	writeSafe(&builder, fmt.Sprintf("/ip dhcp-client add interface=%s disabled=no comment=\"NobliFi WAN DHCP client\"", wan), "add WAN dhcp client")
	builder.WriteString("\n")

	// Apply selected port roles and bridge/DHCP configuration first.
	if len(summary.HotspotLAN) > 0 {
		writeHotspotNetwork(&builder, options, summary.HotspotLAN, hotspotGateway)
	}

	writeBridge(&builder, options.StaffBridge, summary.StaffLAN, options.StaffGateway, "pool-staff", options.StaffPool, options.StaffSubnet)
	writeBridge(&builder, options.POSBridge, summary.POSLAN, options.POSGateway, "pool-pos", options.POSPool, options.POSSubnet)
	writeBridge(&builder, options.CCTVBridge, summary.CCTVLAN, options.CCTVGateway, "pool-cctv", options.CCTVPool, options.CCTVSubnet)

	// Install the captive portal only after all selected port roles are complete.
	if len(summary.HotspotLAN) > 0 {
		writeHotspotServices(&builder, options, hotspotGateway)
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
		HotspotDNSName:      "login.noblifi.local",
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

func writeHotspotNetwork(builder *strings.Builder, options RenderOptions, interfaces []string, hotspotGateway string) {
	if len(interfaces) == 0 {
		return
	}

	builder.WriteString("# HotSpot bridge, DHCP, and client addressing\n")
	writeCritical(
		builder,
		fmt.Sprintf(`:if ([:len [/interface bridge find where name=%q]] = 0) do={ /interface bridge add name=%q protocol-mode=rstp comment="NobliFi HotSpot bridge" }`, options.HotspotBridge, options.HotspotBridge),
		"NobliFi failed to create HotSpot bridge",
	)

	for _, iface := range interfaces {
		writeSafe(builder, fmt.Sprintf("/interface bridge port remove [find where interface=%q]", iface), "cleanup hotspot bridge port")
		writeCritical(
			builder,
			fmt.Sprintf(`:if ([:len [/interface bridge port find where bridge=%q interface=%q]] = 0) do={ /interface bridge port add bridge=%q interface=%q comment="NobliFi HotSpot port" }`, options.HotspotBridge, iface, options.HotspotBridge, iface),
			"NobliFi failed to add "+iface+" to HotSpot bridge",
		)
		writeSafe(builder, fmt.Sprintf("/interface list member remove [find where list=LAN interface=%q]", iface), "cleanup LAN list member")
		writeSafe(builder, fmt.Sprintf(`/interface list member add list=LAN interface=%q comment="NobliFi LAN member"`, iface), "add LAN list member")
	}

	writeCritical(
		builder,
		fmt.Sprintf(`/ip address add address=%q interface=%q comment="NobliFi HotSpot gateway"`, options.HotspotGateway, options.HotspotBridge),
		"NobliFi failed to configure HotSpot gateway",
	)
	writeCritical(
		builder,
		fmt.Sprintf(`/ip pool add name=pool-hotspot ranges=%q comment="NobliFi HotSpot pool"`, options.HotspotPool),
		"NobliFi failed to create HotSpot address pool",
	)
	writeCritical(
		builder,
		fmt.Sprintf("/ip dhcp-server add name=dhcp-hotspot interface=%q address-pool=pool-hotspot lease-time=1h disabled=no", options.HotspotBridge),
		"NobliFi failed to create HotSpot DHCP server",
	)
	writeDHCPNetworkUpsert(
		builder,
		options.HotspotSubnet,
		hotspotGateway,
		"NobliFi HotSpot DHCP network",
	)
	builder.WriteString(":put \"NobliFi HotSpot bridge and DHCP configured\"\n\n")
}

func writeHotspotServices(builder *strings.Builder, options RenderOptions, hotspotGateway string) {
	builder.WriteString("# DNS, NAT, RADIUS, and HotSpot captive portal setup\n")

	// RouterOS 7 device-mode can explicitly disable HotSpot. Detect that case
	// and fail loudly instead of silently skipping profile/server creation.
	builder.WriteString(":local hotspotDeviceModeAllowed true\n")
	builder.WriteString(`:do { :local dm [/system/device-mode get hotspot]; :if ($dm = false) do={ :set hotspotDeviceModeAllowed false } } on-error={}` + "\n")
	builder.WriteString(`:if (!$hotspotDeviceModeAllowed) do={ :error "NobliFi HotSpot is disabled by RouterOS device-mode; enable hotspot=yes and physically confirm the device-mode change" }` + "\n")

	writeSafe(builder, "/ip dns set allow-remote-requests=yes", "enable dns forwarding")
	writeSafe(builder, `/ip firewall nat add chain=srcnat out-interface-list=WAN action=masquerade comment="NobliFi client NAT"`, "add nat")

	writeCritical(
		builder,
		fmt.Sprintf(`/radius add service=hotspot address=%q secret=%q authentication-port=1812 accounting-port=1813 timeout=3s comment="NobliFi RADIUS"`, options.RadiusServer, options.RadiusSecret),
		"NobliFi failed to configure RADIUS",
	)
	writeSafe(builder, "/radius incoming set accept=yes", "enable radius incoming")
	builder.WriteString(":put \"NobliFi RADIUS client configured\"\n")

	// Some MikroTik models expose persistent storage as flash/, while others
	// use the root file store. Resolve the correct HotSpot HTML directory at
	// RouterOS runtime instead of hard-coding one model's filesystem layout.
	builder.WriteString(`:local hotspotDir "noblifi"` + "\n")
	builder.WriteString(`:if ([:len [/file find where name="flash"]] > 0) do={ :set hotspotDir "flash/noblifi" }` + "\n")
	builder.WriteString(`:local hotspotLoginFile ($hotspotDir . "/login.html")` + "\n")
	writeCritical(
		builder,
		`:if ([:len [/file find where name=$hotspotDir]] = 0) do={ /file make-directory $hotspotDir }`,
		"NobliFi failed to create HotSpot HTML directory",
	)

	writeCritical(builder, "/ip hotspot user profile add name=noblifi-voucher-profile", "NobliFi failed to create HotSpot voucher profile")
	writeCritical(builder, "/ip hotspot user profile set noblifi-voucher-profile shared-users=1", "NobliFi failed to set HotSpot shared-users")
	writeCritical(builder, "/ip hotspot user profile set noblifi-voucher-profile keepalive-timeout=2m", "NobliFi failed to set HotSpot keepalive")
	writeCritical(builder, "/ip hotspot user profile set noblifi-voucher-profile status-autorefresh=1m", "NobliFi failed to set HotSpot status refresh")

	writeCritical(
		builder,
		fmt.Sprintf(
			"/ip hotspot profile add name=noblifi-hotspot-profile hotspot-address=%q dns-name=%q use-radius=yes login-by=http-chap,http-pap html-directory=$hotspotDir",
			hotspotGateway,
			options.HotspotDNSName,
		),
		"NobliFi failed to create HotSpot server profile",
	)
	writeCritical(builder, "/ip hotspot profile set noblifi-hotspot-profile radius-accounting=yes", "NobliFi failed to enable RADIUS accounting")
	writeCritical(builder, "/ip hotspot profile set noblifi-hotspot-profile radius-interim-update=5m", "NobliFi failed to set RADIUS interim update")

	for _, host := range options.WalledGardenHosts {
		writeSafe(
			builder,
			fmt.Sprintf(`/ip hotspot walled-garden add dst-host=%q comment="NobliFi captive portal"`, host),
			"add captive portal walled garden",
		)
	}

	loginURL := strings.TrimSpace(options.LoginPageURL)
	if loginURL == "" {
		builder.WriteString(":error \"NobliFi captive portal login URL is missing\"\n")
		return
	}

	mode := "http"
	if strings.HasPrefix(strings.ToLower(loginURL), "https://") {
		mode = "https"
	}

	// LoginPageURL is claim-token scoped. The backend endpoint resolves:
	// claim token -> router -> owner -> owner's hotspot name + active packages.
	writeCritical(
		builder,
		fmt.Sprintf(
			"/tool fetch url=%q mode=%s dst-path=$hotspotLoginFile idle-timeout=30s duration=1m",
			loginURL,
			mode,
		),
		"NobliFi failed to download tenant captive portal login page",
	)
	writeCritical(
		builder,
		`/ip hotspot profile set noblifi-hotspot-profile html-directory=$hotspotDir`,
		"NobliFi failed to set HotSpot HTML directory",
	)

	writeSafe(builder, "/system scheduler remove [find where name=noblifi-hotspot-login-refresh]", "cleanup hotspot login refresh")
	refreshCommand := fmt.Sprintf(
		`:local d "noblifi"; :if ([:len [/file find where name="flash"]] > 0) do={ :set d "flash/noblifi" }; /tool fetch url="%s" mode=%s dst-path=($d . "/login.html") idle-timeout=30s duration=1m`,
		escape(loginURL),
		mode,
	)
	writeSafe(
		builder,
		fmt.Sprintf(`/system scheduler add name=noblifi-hotspot-login-refresh interval=10m on-event=%q comment="NobliFi tenant HotSpot login refresh"`, refreshCommand),
		"schedule hotspot login refresh",
	)

	writeCritical(
		builder,
		fmt.Sprintf("/ip hotspot add name=noblifi-hotspot interface=%q address-pool=pool-hotspot profile=noblifi-hotspot-profile disabled=no", options.HotspotBridge),
		"NobliFi failed to create HotSpot server",
	)

	builder.WriteString(":put \"NobliFi tenant captive portal installed\"\n\n")
}

func writeHotspotVerification(builder *strings.Builder, options RenderOptions, interfaces []string) {
	builder.WriteString("# Verify selected HotSpot ports and captive portal before success\n")

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
	builder.WriteString(`:local verifyHotspotDir "noblifi"` + "\n")
	builder.WriteString(`:if ([:len [/file find where name="flash"]] > 0) do={ :set verifyHotspotDir "flash/noblifi" }` + "\n")
	builder.WriteString(`:local verifyLoginFile ($verifyHotspotDir . "/login.html")` + "\n")
	builder.WriteString(`:if ([:len [/file find where name=$verifyLoginFile]] = 0) do={ :error "NobliFi tenant captive portal login.html missing" }` + "\n")
	builder.WriteString(":put \"NobliFi tenant captive portal verified successfully\"\n\n")
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
