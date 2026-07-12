# NobliFi recovery: make ether5 a non-HotSpot management port.
# Paste through WinBox MAC connection, serial console, or any remaining router access.

/ip hotspot disable [find]

/interface bridge port remove [find interface=ether5]
:if ([:len [/interface bridge find name=br-staff]] = 0) do={ /interface bridge add name=br-staff protocol-mode=rstp comment="NobliFi recovery management bridge" }
/interface bridge port add bridge=br-staff interface=ether5 comment="NobliFi recovery management port"

/ip address remove [find comment="NobliFi recovery management gateway"]
/ip address add address=10.20.20.1/24 interface=br-staff comment="NobliFi recovery management gateway"

/ip pool remove [find name=pool-staff-recovery]
/ip pool add name=pool-staff-recovery ranges=10.20.20.10-10.20.20.254

/ip dhcp-server remove [find name=dhcp-staff-recovery]
/ip dhcp-server add name=dhcp-staff-recovery interface=br-staff address-pool=pool-staff-recovery lease-time=1h disabled=no
/ip dhcp-server network remove [find address=10.20.20.0/24]
/ip dhcp-server network add address=10.20.20.0/24 gateway=10.20.20.1 dns-server=10.20.20.1

/ip service set www disabled=no
/ip service set api disabled=no
/ip service set winbox disabled=no

:put "Recovery complete. Plug into ether5 and browse to http://10.20.20.1 or use WinBox."
