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
}

func DefaultAssignments() []Assignment {
	return []Assignment{
		{InterfaceName: "ether1", Role: "WAN"},
		{InterfaceName: "ether2", Role: "HOTSPOT_LAN"},
		{InterfaceName: "ether3", Role: "HOTSPOT_LAN"},
		{InterfaceName: "ether4", Role: "STAFF_LAN"},
		{InterfaceName: "ether5", Role: "DISABLED"},
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
		RadiusSecret:        "CHANGE_ME_RADIUS_SECRET",
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
	})
}

func RenderRouterOSWithOptions(assignments []Assignment, options RenderOptions) (string, error) {
	if err := Validate(assignments); err != nil {
		return "", err
	}
	if strings.TrimSpace(options.RadiusServer) == "" {
		options.RadiusServer = "127.0.0.1"
	}
	if strings.TrimSpace(options.RadiusSecret) == "" {
		options.RadiusSecret = "CHANGE_ME_RADIUS_SECRET"
	}
	options = withDefaults(options)

	summary := BuildSummary(assignments)
	wan := summary.WAN[0]

	var builder strings.Builder
	builder.WriteString("# NobliFi generated RouterOS configuration\n")
	builder.WriteString(fmt.Sprintf("/system identity set name=\"%s\"\n\n", escape(options.RouterIdentity)))
	builder.WriteString(fmt.Sprintf("/user add name=%s group=full password=\"%s\" comment=\"NobliFi API management user\"\n", options.APIUsername, escape(options.APIPassword)))
	builder.WriteString("/ip/service set telnet disabled=yes\n")
	builder.WriteString("/ip/service set ftp disabled=yes\n")
	if options.DisableWWWService {
		builder.WriteString("/ip/service set www disabled=yes\n")
	}
	builder.WriteString(fmt.Sprintf("/ip/service set api disabled=%s\n", routerOSDisabled(!options.EnableAPIService)))
	builder.WriteString(fmt.Sprintf("/ip/service set api-ssl disabled=%s\n\n", routerOSDisabled(!options.EnableAPISSLService)))
	builder.WriteString("/interface/list add name=WAN\n")
	builder.WriteString("/interface/list add name=LAN\n")
	builder.WriteString(fmt.Sprintf("/interface/list/member add list=WAN interface=%s\n", wan))
	builder.WriteString(fmt.Sprintf("/ip/dhcp-client add interface=%s disabled=no\n\n", wan))

	builder.WriteString(fmt.Sprintf("/interface/bridge add name=%s protocol-mode=rstp\n", options.HotspotBridge))
	for _, iface := range summary.HotspotLAN {
		builder.WriteString(fmt.Sprintf("/interface/bridge/port add bridge=%s interface=%s\n", options.HotspotBridge, iface))
		builder.WriteString(fmt.Sprintf("/interface/list/member add list=LAN interface=%s\n", iface))
	}
	builder.WriteString(fmt.Sprintf("/ip/address add address=%s interface=%s\n", options.HotspotGateway, options.HotspotBridge))
	builder.WriteString(fmt.Sprintf("/ip/pool add name=pool-hotspot ranges=%s\n", options.HotspotPool))
	builder.WriteString(fmt.Sprintf("/ip/dhcp-server add name=dhcp-hotspot interface=%s address-pool=pool-hotspot disabled=no\n", options.HotspotBridge))
	hotspotGateway := strings.Split(options.HotspotGateway, "/")[0]
	builder.WriteString(fmt.Sprintf("/ip/dhcp-server/network add address=%s gateway=%s dns-server=%s\n", options.HotspotSubnet, hotspotGateway, hotspotGateway))
	builder.WriteString("\n")

	writeBridge(&builder, options.StaffBridge, summary.StaffLAN, options.StaffGateway, "pool-staff", options.StaffPool, options.StaffSubnet)
	writeBridge(&builder, options.POSBridge, summary.POSLAN, options.POSGateway, "pool-pos", options.POSPool, options.POSSubnet)
	writeBridge(&builder, options.CCTVBridge, summary.CCTVLAN, options.CCTVGateway, "pool-cctv", options.CCTVPool, options.CCTVSubnet)

	builder.WriteString("# NAT for client internet access\n")
	builder.WriteString("/ip/firewall/nat add chain=srcnat out-interface-list=WAN action=masquerade comment=\"NobliFi client NAT\"\n\n")
	builder.WriteString("# RADIUS + HotSpot service setup\n")
	builder.WriteString(fmt.Sprintf("/radius add service=hotspot address=%s secret=\"%s\" authentication-port=1812 accounting-port=1813 timeout=3s comment=\"NobliFi RADIUS\"\n", options.RadiusServer, escape(options.RadiusSecret)))
	builder.WriteString("/radius incoming set accept=yes\n")
	builder.WriteString(fmt.Sprintf("/ip/hotspot/profile add name=noblifi-hotspot-profile hotspot-address=%s dns-name=%s use-radius=yes radius-accounting=yes radius-interim-update=5m login-by=http-chap,http-pap comment=\"NobliFi HotSpot profile\"\n", hotspotGateway, options.HotspotDNSName))
	builder.WriteString(fmt.Sprintf("/ip/hotspot add name=noblifi-hotspot interface=%s address-pool=pool-hotspot profile=noblifi-hotspot-profile disabled=no comment=\"NobliFi HotSpot server\"\n", options.HotspotBridge))
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
	return options
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

func writeBridge(builder *strings.Builder, bridge string, interfaces []string, address string, pool string, ranges string, subnet string) {
	if len(interfaces) == 0 {
		return
	}
	builder.WriteString(fmt.Sprintf("/interface/bridge add name=%s protocol-mode=rstp\n", bridge))
	for _, iface := range interfaces {
		builder.WriteString(fmt.Sprintf("/interface/bridge/port add bridge=%s interface=%s\n", bridge, iface))
		builder.WriteString(fmt.Sprintf("/interface/list/member add list=LAN interface=%s\n", iface))
	}
	builder.WriteString(fmt.Sprintf("/ip/address add address=%s interface=%s\n", address, bridge))
	builder.WriteString(fmt.Sprintf("/ip/pool add name=%s ranges=%s\n", pool, ranges))
	builder.WriteString(fmt.Sprintf("/ip/dhcp-server add name=dhcp-%s interface=%s address-pool=%s disabled=no\n", strings.TrimPrefix(bridge, "br-"), bridge, pool))
	gateway := strings.Split(address, "/")[0]
	builder.WriteString(fmt.Sprintf("/ip/dhcp-server/network add address=%s gateway=%s dns-server=%s\n\n", subnet, gateway, gateway))
}
