#!/usr/bin/env bash
set -euo pipefail

WG_INTERFACE="${NOBLIFI_WIREGUARD_INTERFACE:-wg0}"
WG_SERVER_IP="${NOBLIFI_WIREGUARD_SERVER_IP:-10.77.0.1}"
WG_SUBNET="${NOBLIFI_WIREGUARD_SUBNET:-10.77.0.0/24}"
WG_PREFIX="${WG_SUBNET##*/}"
WG_ADDRESS="${NOBLIFI_WIREGUARD_SERVER_ADDRESS:-${WG_SERVER_IP}/${WG_PREFIX}}"
WG_PORT="${NOBLIFI_WIREGUARD_PORT:-51820}"
WG_DIR="/etc/wireguard"
WG_CONFIG="${WG_DIR}/${WG_INTERFACE}.conf"
WG_PRIVATE_KEY="${WG_DIR}/${WG_INTERFACE}.key"
WG_PUBLIC_KEY="${WG_DIR}/${WG_INTERFACE}.public"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this script as root: sudo ./scripts/setup-wireguard-vps.sh" >&2
  exit 1
fi

if ! command -v wg >/dev/null 2>&1; then
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "WireGuard is missing and this installer currently supports Debian/Ubuntu VPS hosts." >&2
    exit 1
  fi
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard
fi

install -d -m 700 "${WG_DIR}"
umask 077

if [[ -e "${WG_CONFIG}" ]]; then
  EXISTING_PRIVATE_KEY="$(awk -F '=' '/^[[:space:]]*PrivateKey[[:space:]]*=/{gsub(/[[:space:]]/, "", $2); print $2; exit}' "${WG_CONFIG}")"
  if [[ -z "${EXISTING_PRIVATE_KEY}" ]]; then
    echo "Could not read PrivateKey from existing ${WG_CONFIG}. No changes were made." >&2
    exit 1
  fi
  printf '%s\n' "${EXISTING_PRIVATE_KEY}" >"${WG_PRIVATE_KEY}"
  echo "Keeping existing ${WG_CONFIG}; no existing peers were changed."
else
  wg genkey >"${WG_PRIVATE_KEY}"
  PRIVATE_KEY="$(<"${WG_PRIVATE_KEY}")"
  cat >"${WG_CONFIG}" <<EOF
[Interface]
Address = ${WG_ADDRESS}
ListenPort = ${WG_PORT}
PrivateKey = ${PRIVATE_KEY}
SaveConfig = true
EOF
  chmod 600 "${WG_CONFIG}"
fi

wg pubkey <"${WG_PRIVATE_KEY}" >"${WG_PUBLIC_KEY}"

systemctl enable --now "wg-quick@${WG_INTERFACE}"

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
  ufw allow "${WG_PORT}/udp"
  ufw allow in on "${WG_INTERFACE}" to any port 1812 proto udp
  ufw allow in on "${WG_INTERFACE}" to any port 1813 proto udp
fi

echo
echo "WireGuard VPS is running on ${WG_INTERFACE}."
echo "Public key: $(<"${WG_PUBLIC_KEY}")"
echo "Set NOBLIFI_WIREGUARD_PUBLIC_KEY to that value."
echo "Set NOBLIFI_WIREGUARD_ENDPOINT to this VPS public IP or DNS name."
echo "Allow UDP ${WG_PORT} in the VPS provider firewall."
