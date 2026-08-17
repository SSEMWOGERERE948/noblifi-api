# NobliFi generated RouterOS configuration
# Import this file with: /import file-name=noblifi-config.rsc

:local radiusServer "CHANGE_ME_RADIUS_SERVER_IP"
:local radiusSecret "CHANGE_ME_RADIUS_SECRET"
:if ($radiusServer = "CHANGE_ME_RADIUS_SERVER_IP") do={ :error "Set radiusServer at the top of noblifi-config.rsc to your NobliFi/RADIUS server IP before importing." }
:if ($radiusSecret = "CHANGE_ME_RADIUS_SECRET") do={ :error "Set radiusSecret at the top of noblifi-config.rsc before importing." }

# Clean previous NobliFi-owned service setup
/ip hotspot remove [find name="noblifi-hotspot"]
/ip hotspot profile remove [find name="noblifi-hotspot-profile"]
/ip hotspot user profile remove [find name="noblifi-voucher-profile"]
/radius remove [find comment="NobliFi RADIUS"]
/ip firewall nat remove [find comment="NobliFi client NAT"]
/ip dhcp-client remove [find interface=ether1 comment="NobliFi WAN DHCP client"]
/ip dhcp-server remove [find name="dhcp-hotspot"]
/ip dhcp-server network remove [find address=10.10.10.0/24 comment~"NobliFi"]
/ip address remove [find interface=br-hotspot comment~"NobliFi"]
/ip pool remove [find name="pool-hotspot"]
/interface bridge port remove [find bridge=br-hotspot]
/interface bridge remove [find name=br-hotspot comment~"NobliFi"]
/ip dhcp-server remove [find name="dhcp-staff"]
/ip dhcp-server network remove [find address=10.20.20.0/24 comment~"NobliFi"]
/ip address remove [find interface=br-staff comment~"NobliFi"]
/ip pool remove [find name="pool-staff"]
/interface bridge port remove [find bridge=br-staff]
/interface bridge remove [find name=br-staff comment~"NobliFi"]
/ip dhcp-server remove [find name="dhcp-pos"]
/ip dhcp-server network remove [find address=10.30.30.0/24 comment~"NobliFi"]
/ip address remove [find interface=br-pos comment~"NobliFi"]
/ip pool remove [find name="pool-pos"]
/interface bridge port remove [find bridge=br-pos]
/interface bridge remove [find name=br-pos comment~"NobliFi"]
/ip dhcp-server remove [find name="dhcp-cctv"]
/ip dhcp-server network remove [find address=10.40.40.0/24 comment~"NobliFi"]
/ip address remove [find interface=br-cctv comment~"NobliFi"]
/ip pool remove [find name="pool-cctv"]
/interface bridge port remove [find bridge=br-cctv]
/interface bridge remove [find name=br-cctv comment~"NobliFi"]

# Management and router services
/system identity set name="NobliFi-Test"
/user remove [find name=noblifi-api comment="NobliFi API management user"]
/user add name=noblifi-api group=full password="CHANGE_ME_API_PASSWORD" comment="NobliFi API management user"
/ip service set telnet disabled=yes
/ip service set ftp disabled=yes
/ip service set www disabled=yes
/ip service set api disabled=no
/ip service set api-ssl disabled=no

# Interface lists and WAN internet
:if ([:len [/interface list find name=WAN]] = 0) do={/interface list add name=WAN comment="NobliFi WAN list"}
:if ([:len [/interface list find name=LAN]] = 0) do={/interface list add name=LAN comment="NobliFi LAN list"}
/interface list member remove [find list=WAN interface=ether1]
/interface list member add list=WAN interface=ether1 comment="NobliFi WAN member"
/ip dhcp-client add interface=ether1 disabled=no comment="NobliFi WAN DHCP client"

# HotSpot bridge, DHCP, and client addressing
/interface bridge add name=br-hotspot protocol-mode=rstp comment="NobliFi HotSpot bridge"
/interface bridge port remove [find interface=ether2]
:if ([:len [/interface bridge port find bridge=br-hotspot interface=ether2]] = 0) do={/interface bridge port add bridge=br-hotspot interface=ether2 comment="NobliFi HotSpot port"}
/interface list member remove [find list=LAN interface=ether2]
/interface list member add list=LAN interface=ether2 comment="NobliFi LAN member"
/interface bridge port remove [find interface=ether3]
:if ([:len [/interface bridge port find bridge=br-hotspot interface=ether3]] = 0) do={/interface bridge port add bridge=br-hotspot interface=ether3 comment="NobliFi HotSpot port"}
/interface list member remove [find list=LAN interface=ether3]
/interface list member add list=LAN interface=ether3 comment="NobliFi LAN member"
/interface bridge port remove [find interface=ether4]
:if ([:len [/interface bridge port find bridge=br-hotspot interface=ether4]] = 0) do={/interface bridge port add bridge=br-hotspot interface=ether4 comment="NobliFi HotSpot port"}
/interface list member remove [find list=LAN interface=ether4]
/interface list member add list=LAN interface=ether4 comment="NobliFi LAN member"
/ip address add address=10.10.10.1/24 interface=br-hotspot comment="NobliFi HotSpot gateway"
/ip pool add name=pool-hotspot ranges=10.10.10.10-10.10.10.254 comment="NobliFi HotSpot pool"
/ip dhcp-server add name=dhcp-hotspot interface=br-hotspot address-pool=pool-hotspot lease-time=1h disabled=no comment="NobliFi HotSpot DHCP"
/ip dhcp-server network add address=10.10.10.0/24 gateway=10.10.10.1 dns-server=10.10.10.1 comment="NobliFi HotSpot DHCP network"

# Staff management bridge, DHCP, and client addressing
# Keep ether5 out of HotSpot so you have a recovery/management port.
/interface bridge add name=br-staff protocol-mode=rstp comment="NobliFi Staff management bridge"
/interface bridge port remove [find interface=ether5]
:if ([:len [/interface bridge port find bridge=br-staff interface=ether5]] = 0) do={/interface bridge port add bridge=br-staff interface=ether5 comment="NobliFi Staff management port"}
/interface list member remove [find list=LAN interface=ether5]
/interface list member add list=LAN interface=ether5 comment="NobliFi management LAN member"
/ip address add address=10.20.20.1/24 interface=br-staff comment="NobliFi Staff management gateway"
/ip pool add name=pool-staff ranges=10.20.20.10-10.20.20.254 comment="NobliFi Staff management pool"
/ip dhcp-server add name=dhcp-staff interface=br-staff address-pool=pool-staff lease-time=1h disabled=no comment="NobliFi Staff management DHCP"
/ip dhcp-server network add address=10.20.20.0/24 gateway=10.20.20.1 dns-server=10.20.20.1 comment="NobliFi Staff management DHCP network"

# DNS, NAT, RADIUS, and HotSpot service setup
/ip dns set allow-remote-requests=yes
/ip firewall nat add chain=srcnat out-interface-list=WAN action=masquerade comment="NobliFi client NAT"
/radius add service=hotspot address=$radiusServer secret=$radiusSecret authentication-port=1812 accounting-port=1813 timeout=3s comment="NobliFi RADIUS"
/radius incoming set accept=yes
/ip hotspot user profile add name=noblifi-voucher-profile shared-users=1 keepalive-timeout=2m status-autorefresh=1m transparent-proxy=no comment="NobliFi voucher profile"
/ip hotspot profile add name=noblifi-hotspot-profile hotspot-address=10.10.10.1 dns-name=login.noblifi.local use-radius=yes radius-accounting=yes radius-interim-update=5m login-by=http-chap,http-pap comment="NobliFi HotSpot profile"
/ip hotspot add name=noblifi-hotspot interface=br-hotspot address-pool=pool-hotspot profile=noblifi-hotspot-profile disabled=no comment="NobliFi HotSpot server"
