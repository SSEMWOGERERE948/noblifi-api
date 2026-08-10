# NobliFi WireGuard Agent

## Architecture

Dashboard creates a router, the backend allocates a unique WireGuard client IP, and the MikroTik reports its interface public key to `/api/v1/provisioning/wireguard-key`. The backend queues a WireGuard job. The xneelo agent polls `/api/v1/internal/wireguard/jobs/claim`, updates `wg0`, persists `/etc/wireguard/wg0.conf`, verifies runtime state, and reports completion.

The agent also owns scheduled telemetry for WireGuard-managed routers. App
Engine and hosted GitHub Actions cannot route to private `10.77.0.x` tunnel
addresses, so CPU load, uptime, memory, interface state, and active HotSpot
users must be collected from the VPS side of the tunnel and submitted back to
the control plane.

## Key Direction

The MikroTik interface public key from `/interface wireguard print` is stored on the VPS as the peer `PublicKey`.

The VPS interface public key from `wg show wg0 public-key` is stored on the MikroTik as the remote peer `PublicKey`.

Do not use the MikroTik remote peer key as the VPS peer key.

## Backend Environment

Set:

```bash
NOBLIFI_WIREGUARD_ENABLED=true
NOBLIFI_WIREGUARD_SUBNET=10.77.0.0/24
NOBLIFI_WIREGUARD_SERVER_IP=10.77.0.1
NOBLIFI_WIREGUARD_ENDPOINT=154.65.105.14
NOBLIFI_WIREGUARD_PORT=51820
NOBLIFI_WIREGUARD_PUBLIC_KEY=<VPS_INTERFACE_PUBLIC_KEY>
NOBLIFI_REMOTE_ACCESS_HOST=vpn.your-domain.example
NOBLIFI_REMOTE_WEB_PORT_BASE=21000
NOBLIFI_REMOTE_WINBOX_PORT_BASE=22000
NOBLIFI_AGENT_TOKEN=<long-random-secret>
NOBLIFI_AGENT_ID=xneelo-wg-agent-01
```

## Agent Installation

Configure WireGuard first. Run from the `backend` directory so the script can update `app.yaml` with the same `NOBLIFI_AGENT_TOKEN` written to `/etc/noblifi/vps-agent.env`:

```bash
sudo ./scripts/setup-wireguard-vps.sh
```

If `app.yaml` is not available on the VPS, the script prints the `NOBLIFI_AGENT_TOKEN` line to add under `env_variables`.

Build and install the agent:

```bash
cd backend
go build -o noblifi-vps-agent ./cmd/noblifi-vps-agent
sudo install -m 0755 noblifi-vps-agent /usr/local/bin/noblifi-vps-agent
sudo mkdir -p /etc/noblifi /etc/wireguard/backups
sudo editor /etc/noblifi/vps-agent.env
sudo install -m 0644 deploy/systemd/noblifi-vps-agent.service /etc/systemd/system/noblifi-vps-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now noblifi-vps-agent.service
```

## Agent Environment

```bash
NOBLIFI_CONTROL_PLANE_URL=https://api.example.com/api/v1
NOBLIFI_AGENT_TOKEN=<same backend token>
NOBLIFI_AGENT_ID=xneelo-wg-agent-01
NOBLIFI_WIREGUARD_INTERFACE=wg0
NOBLIFI_WIREGUARD_CONFIG=/etc/wireguard/wg0.conf
NOBLIFI_WIREGUARD_BACKUP_DIR=/etc/wireguard/backups
NOBLIFI_AGENT_TELEMETRY_INTERVAL=2m
```

## Telemetry Scheduler

The VPS agent should run a fixed-interval scheduler, defaulting to
`NOBLIFI_AGENT_TELEMETRY_INTERVAL=2m`.

On each run:

1. Fetch targets with `GET /api/v1/internal/routers/telemetry-targets`.
2. For each target, connect to `router_ip:api_port` with the returned API
   credentials over WireGuard.
3. Read:
   - `/system/resource/print`
   - `/system/identity/print`
   - `/interface/print`
   - `/ip/hotspot/active/print`
4. Submit the snapshot to `POST /api/v1/internal/routers/:id/telemetry`.

If collection fails for one router, the agent should submit the same endpoint
with an `error` value. The backend records that error without clearing the last
good CPU, uptime, or user count.

Hosted GitHub Actions are not suitable for this scheduler because they run
outside the WireGuard network. A self-hosted GitHub runner on the VPS would
work, but it is operationally equivalent to running the scheduler in the agent
and adds another moving part.

## Database Migration

Apply `migrations/002_wireguard_control_plane.sql` to production, or run the Go service AutoMigrate during deployment.

## Provisioning Sequence

1. Router is created.
2. Backend allocates or reuses a WireGuard client IP.
3. MikroTik install script creates/reuses its WireGuard interface.
4. MikroTik reports its interface public key.
5. Backend queues `upsert_peer`.
6. Agent applies and verifies the peer.
7. Backend stores the RADIUS NAS row for the router tunnel IP.

## Remote Access URLs

When VPN remote access is enabled for a router, the backend assigns public
ports from `NOBLIFI_REMOTE_WEB_PORT_BASE` and `NOBLIFI_REMOTE_WINBOX_PORT_BASE`.
The VPS agent listens on those ports and forwards traffic through WireGuard to
the router:

```text
http://<NOBLIFI_REMOTE_ACCESS_HOST>:<remote_web_port>/webfig/
<NOBLIFI_REMOTE_ACCESS_HOST>:<remote_winbox_port>
```

Only the VPS agent needs public listener ports. The MikroTik stays reachable
through its private WireGuard tunnel IP.

## Troubleshooting

```bash
sudo systemctl status noblifi-vps-agent
sudo journalctl -u noblifi-vps-agent -f
sudo wg show wg0
sudo wg-quick strip /etc/wireguard/wg0.conf
```

Agent logs are JSON and never include private keys or agent tokens. Rotate the agent token by updating `NOBLIFI_AGENT_TOKEN` in backend and `/etc/noblifi/vps-agent.env`, then restarting both services.
