# NobliFi WireGuard setup

WireGuard is used only for VPS-to-MikroTik management and RADIUS traffic. The
generated configuration does not move customer internet traffic into the VPN,
change the default route, or attach physical ports to a bridge.

## 1. Prepare the VPS

Use a Debian or Ubuntu VPS with a public IPv4 address. From the backend folder:

```bash
chmod +x scripts/setup-wireguard-vps.sh
sudo NOBLIFI_WIREGUARD_SERVER_IP=10.77.0.1 \
  NOBLIFI_WIREGUARD_SUBNET=10.77.0.0/24 \
  NOBLIFI_WIREGUARD_PORT=51820 \
  ./scripts/setup-wireguard-vps.sh
```

Allow inbound UDP `51820` in the VPS provider firewall. Do not expose RADIUS
UDP `1812` and `1813` publicly; the installer allows them only on `wg0` when
UFW is active.

## 2. Configure the Go backend

Copy the public key printed by the installer into the backend environment:

```dotenv
NOBLIFI_WIREGUARD_ENABLED=true
NOBLIFI_WIREGUARD_ENDPOINT=vpn.example.com
NOBLIFI_WIREGUARD_PORT=51820
NOBLIFI_WIREGUARD_PUBLIC_KEY=PASTE_VPS_PUBLIC_KEY
NOBLIFI_WIREGUARD_INTERFACE=wg0
NOBLIFI_WIREGUARD_SERVER_IP=10.77.0.1
NOBLIFI_WIREGUARD_SUBNET=10.77.0.0/24
NOBLIFI_WIREGUARD_KEEPALIVE=25
NOBLIFI_RADIUS_SERVER=10.77.0.1
```

The process that opens the RouterOS API and RADIUS UDP sockets must run on the
VPS, or on another host that is joined to this WireGuard network. App Engine
and Vercel cannot directly reach `10.77.0.0/24` or accept RADIUS UDP traffic.

## 3. Add a router

1. Register the MikroTik so NobliFi reads its actual RouterOS version and ports.
2. Open **Remote Access**, select **WireGuard VPS**, and prepare the tunnel.
3. Run the generated `/tool fetch` and `/import` commands on RouterOS 7.
4. Wait for NobliFi to receive the MikroTik public key.
5. Run the generated peer command on the VPS.

The VPS command pings the assigned router tunnel address before marking the
tunnel connected. Inspect live handshakes with:

```bash
sudo wg show wg0
```

Each MikroTik receives a unique address from `NOBLIFI_WIREGUARD_SUBNET` and is
registered in RADIUS by that stable tunnel address.
