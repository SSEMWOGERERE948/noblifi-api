# NobliFi WireGuard Agent

## Architecture

Dashboard creates a router, the backend allocates a unique WireGuard client IP, and the MikroTik reports its interface public key to `/api/v1/provisioning/wireguard-key`. The backend queues a WireGuard job. The xneelo agent polls `/api/v1/internal/wireguard/jobs/claim`, updates `wg0`, persists `/etc/wireguard/wg0.conf`, verifies runtime state, and reports completion.

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
```

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

## Troubleshooting

```bash
sudo systemctl status noblifi-vps-agent
sudo journalctl -u noblifi-vps-agent -f
sudo wg show wg0
sudo wg-quick strip /etc/wireguard/wg0.conf
```

Agent logs are JSON and never include private keys or agent tokens. Rotate the agent token by updating `NOBLIFI_AGENT_TOKEN` in backend and `/etc/noblifi/vps-agent.env`, then restarting both services.
