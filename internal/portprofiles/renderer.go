package portprofiles

import (
	"fmt"
	"sort"
	"strings"
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
	if strings.TrimSpace(options.RadiusServer) == "" {
		options.RadiusServer = "127.0.0.1"
	}
	if isPlaceholderRadiusSecret(options.RadiusSecret) {
		options.RadiusSecret = "noblifi"
	}
	options = withDefaults(options)

	summary := BuildSummary(assignments)
	wan := summary.WAN[0]
	hotspotGateway := strings.Split(options.HotspotGateway, "/")[0]

	var builder strings.Builder
	builder.WriteString("# NobliFi generated RouterOS configuration\n")
	builder.WriteString("# Import this file with: /import file-name=noblifi-config.rsc\n\n")
	builder.WriteString("# Clean previous NobliFi-owned service setup\n")
	builder.WriteString(fmt.Sprintf("/ip hotspot remove [find name=\"noblifi-hotspot\"]\n"))
	builder.WriteString(fmt.Sprintf("/ip hotspot profile remove [find name=\"noblifi-hotspot-profile\"]\n"))
	builder.WriteString(fmt.Sprintf("/ip hotspot user profile remove [find name=\"noblifi-voucher-profile\"]\n"))
	builder.WriteString("/ip hotspot walled-garden remove [find comment=\"NobliFi captive portal\"]\n")
	builder.WriteString("/radius remove [find comment=\"NobliFi RADIUS\"]\n")
	builder.WriteString("/ip firewall nat remove [find comment=\"NobliFi client NAT\"]\n")
	builder.WriteString(fmt.Sprintf("/ip dhcp-client remove [find interface=%s]\n", wan))
	writeCleanup(&builder, options.HotspotBridge, "dhcp-hotspot", "pool-hotspot", options.HotspotSubnet)
	writeCleanup(&builder, options.StaffBridge, "dhcp-staff", "pool-staff", options.StaffSubnet)
	writeCleanup(&builder, options.POSBridge, "dhcp-pos", "pool-pos", options.POSSubnet)
	writeCleanup(&builder, options.CCTVBridge, "dhcp-cctv", "pool-cctv", options.CCTVSubnet)
	builder.WriteString("\n")

	builder.WriteString("# Management and router services\n")
	builder.WriteString(fmt.Sprintf("/system identity set name=\"%s\"\n", escape(options.RouterIdentity)))
	builder.WriteString(fmt.Sprintf("/user remove [find name=%s comment=\"NobliFi API management user\"]\n", options.APIUsername))
	builder.WriteString(fmt.Sprintf("/user add name=%s group=full password=\"%s\" comment=\"NobliFi API management user\"\n", options.APIUsername, escape(options.APIPassword)))
	builder.WriteString("/ip service set telnet disabled=yes\n")
	builder.WriteString("/ip service set ftp disabled=yes\n")
	if options.DisableWWWService {
		builder.WriteString("/ip service set www disabled=yes\n")
	}
	builder.WriteString(fmt.Sprintf("/ip service set api disabled=%s\n", routerOSDisabled(!options.EnableAPIService)))
	builder.WriteString(fmt.Sprintf("/ip service set api-ssl disabled=%s\n\n", routerOSDisabled(!options.EnableAPISSLService)))

	builder.WriteString("# Interface lists and WAN internet\n")
	builder.WriteString(":if ([:len [/interface list find name=WAN]] = 0) do={/interface list add name=WAN comment=\"NobliFi WAN list\"}\n")
	builder.WriteString(":if ([:len [/interface list find name=LAN]] = 0) do={/interface list add name=LAN comment=\"NobliFi LAN list\"}\n")
	builder.WriteString(fmt.Sprintf("/interface list member remove [find list=WAN interface=%s]\n", wan))
	builder.WriteString(fmt.Sprintf("/interface list member add list=WAN interface=%s comment=\"NobliFi WAN member\"\n", wan))
	builder.WriteString(fmt.Sprintf("/ip dhcp-client add interface=%s disabled=no comment=\"NobliFi WAN DHCP client\"\n\n", wan))

	writeBridge(&builder, options.StaffBridge, summary.StaffLAN, options.StaffGateway, "pool-staff", options.StaffPool, options.StaffSubnet)

	builder.WriteString("# HotSpot bridge, DHCP, and client addressing\n")
	builder.WriteString(fmt.Sprintf("/interface bridge add name=%s protocol-mode=rstp comment=\"NobliFi HotSpot bridge\"\n", options.HotspotBridge))
	for _, iface := range summary.HotspotLAN {
		builder.WriteString(fmt.Sprintf("/interface bridge port remove [find interface=%s]\n", iface))
		builder.WriteString(fmt.Sprintf(":if ([:len [/interface bridge port find bridge=%s interface=%s]] = 0) do={/interface bridge port add bridge=%s interface=%s comment=\"NobliFi HotSpot port\"}\n", options.HotspotBridge, iface, options.HotspotBridge, iface))
		builder.WriteString(fmt.Sprintf("/interface list member remove [find list=LAN interface=%s]\n", iface))
		builder.WriteString(fmt.Sprintf("/interface list member add list=LAN interface=%s comment=\"NobliFi LAN member\"\n", iface))
	}
	builder.WriteString(fmt.Sprintf("/ip address add address=%s interface=%s comment=\"NobliFi HotSpot gateway\"\n", options.HotspotGateway, options.HotspotBridge))
	builder.WriteString(fmt.Sprintf("/ip pool add name=pool-hotspot ranges=%s comment=\"NobliFi HotSpot pool\"\n", options.HotspotPool))
	builder.WriteString(fmt.Sprintf("/ip dhcp-server add name=dhcp-hotspot interface=%s address-pool=pool-hotspot lease-time=1h disabled=no\n", options.HotspotBridge))
	builder.WriteString(fmt.Sprintf("/ip dhcp-server network add address=%s gateway=%s dns-server=%s\n\n", options.HotspotSubnet, hotspotGateway, hotspotGateway))

	writeBridge(&builder, options.POSBridge, summary.POSLAN, options.POSGateway, "pool-pos", options.POSPool, options.POSSubnet)
	writeBridge(&builder, options.CCTVBridge, summary.CCTVLAN, options.CCTVGateway, "pool-cctv", options.CCTVPool, options.CCTVSubnet)

	builder.WriteString("# DNS, NAT, RADIUS, and HotSpot service setup\n")
	builder.WriteString("/ip dns set allow-remote-requests=yes\n")
	builder.WriteString("/ip firewall nat add chain=srcnat out-interface-list=WAN action=masquerade comment=\"NobliFi client NAT\"\n")
	builder.WriteString(fmt.Sprintf("/radius add service=hotspot address=%s secret=\"%s\" authentication-port=1812 accounting-port=1813 timeout=3s comment=\"NobliFi RADIUS\"\n", options.RadiusServer, escape(options.RadiusSecret)))
	builder.WriteString("/radius incoming set accept=yes\n")
	builder.WriteString("/ip hotspot user profile add name=noblifi-voucher-profile\n")
	builder.WriteString("/ip hotspot user profile set noblifi-voucher-profile shared-users=1\n")
	builder.WriteString("/ip hotspot user profile set noblifi-voucher-profile keepalive-timeout=2m\n")
	builder.WriteString("/ip hotspot user profile set noblifi-voucher-profile status-autorefresh=1m\n")
	builder.WriteString(fmt.Sprintf("/ip hotspot profile add name=noblifi-hotspot-profile hotspot-address=%s dns-name=%s use-radius=yes login-by=http-chap,http-pap\n", hotspotGateway, options.HotspotDNSName))
	builder.WriteString("/ip hotspot profile set noblifi-hotspot-profile radius-accounting=yes\n")
	builder.WriteString("/ip hotspot profile set noblifi-hotspot-profile radius-interim-update=5m\n")
	for _, host := range options.WalledGardenHosts {
		builder.WriteString(fmt.Sprintf("/ip hotspot walled-garden add dst-host=%s action=allow comment=\"NobliFi captive portal\"\n", host))
	}
	builder.WriteString(fmt.Sprintf("/ip hotspot add name=noblifi-hotspot interface=%s address-pool=pool-hotspot profile=noblifi-hotspot-profile disabled=no\n", options.HotspotBridge))
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
	if len(options.WalledGardenHosts) == 0 {
		options.WalledGardenHosts = defaults.WalledGardenHosts
	}
	options.WalledGardenHosts = cleanHosts(options.WalledGardenHosts)
	return options
}

func isPlaceholderRadiusSecret(value string) bool {
	secret := strings.TrimSpace(value)
	return secret == "" || secret == "CHANGE_ME_RADIUS_SECRET"
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

func writeCleanup(builder *strings.Builder, bridge string, dhcpServer string, pool string, subnet string) {
	if bridge == "" {
		return
	}
	builder.WriteString(fmt.Sprintf("/ip dhcp-server remove [find name=\"%s\"]\n", dhcpServer))
	builder.WriteString(fmt.Sprintf("/ip dhcp-server network remove [find address=%s]\n", subnet))
	builder.WriteString(fmt.Sprintf("/ip address remove [find interface=%s]\n", bridge))
	builder.WriteString(fmt.Sprintf("/ip pool remove [find name=\"%s\"]\n", pool))
	builder.WriteString(fmt.Sprintf("/interface bridge port remove [find bridge=%s]\n", bridge))
	builder.WriteString(fmt.Sprintf("/interface bridge remove [find name=%s]\n", bridge))
}

func writeBridge(builder *strings.Builder, bridge string, interfaces []string, address string, pool string, ranges string, subnet string) {
	if len(interfaces) == 0 {
		return
	}
	role := strings.TrimPrefix(bridge, "br-")
	gateway := strings.Split(address, "/")[0]
	builder.WriteString(fmt.Sprintf("# %s bridge, DHCP, and client addressing\n", strings.ToUpper(role)))
	builder.WriteString(fmt.Sprintf("/interface bridge add name=%s protocol-mode=rstp comment=\"NobliFi %s bridge\"\n", bridge, role))
	for _, iface := range interfaces {
		builder.WriteString(fmt.Sprintf("/interface bridge port remove [find interface=%s]\n", iface))
		builder.WriteString(fmt.Sprintf(":if ([:len [/interface bridge port find bridge=%s interface=%s]] = 0) do={/interface bridge port add bridge=%s interface=%s comment=\"NobliFi %s port\"}\n", bridge, iface, bridge, iface, role))
		builder.WriteString(fmt.Sprintf("/interface list member remove [find list=LAN interface=%s]\n", iface))
		builder.WriteString(fmt.Sprintf("/interface list member add list=LAN interface=%s comment=\"NobliFi LAN member\"\n", iface))
	}
	builder.WriteString(fmt.Sprintf("/ip address add address=%s interface=%s comment=\"NobliFi %s gateway\"\n", address, bridge, role))
	builder.WriteString(fmt.Sprintf("/ip pool add name=%s ranges=%s comment=\"NobliFi %s pool\"\n", pool, ranges, role))
	builder.WriteString(fmt.Sprintf("/ip dhcp-server add name=dhcp-%s interface=%s address-pool=%s lease-time=1h disabled=no\n", role, bridge, pool))
	builder.WriteString(fmt.Sprintf("/ip dhcp-server network add address=%s gateway=%s dns-server=%s\n\n", subnet, gateway, gateway))
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
