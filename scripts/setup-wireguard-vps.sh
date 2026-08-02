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
NOBLIFI_DIR="/etc/noblifi"
AGENT_ENV="${NOBLIFI_AGENT_ENV:-${NOBLIFI_DIR}/vps-agent.env}"
APP_YAML="${NOBLIFI_APP_YAML:-app.yaml}"

generate_agent_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 48
    return
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import secrets; print(secrets.token_urlsafe(48))'
    return
  fi
  echo "openssl or python3 is required to generate NOBLIFI_AGENT_TOKEN" >&2
  exit 1
}

read_env_value() {
  local key="$1"
  local file="$2"
  if [[ -f "${file}" ]]; then
    awk -F '=' -v key="${key}" '$1 == key {print substr($0, length(key) + 2); exit}' "${file}"
  fi
  return 0
}

set_env_value() {
  local key="$1"
  local value="$2"
  local file="$3"
  local tmp

  install -d -m 700 "$(dirname "${file}")"
  tmp="$(mktemp)"
  if [[ -f "${file}" ]]; then
    awk -F '=' -v key="${key}" -v value="${value}" '
      BEGIN { found = 0 }
      $1 == key { print key "=" value; found = 1; next }
      { print }
      END { if (!found) print key "=" value }
    ' "${file}" >"${tmp}"
  else
    printf '%s=%s\n' "${key}" "${value}" >"${tmp}"
  fi
  install -m 600 "${tmp}" "${file}"
  rm -f "${tmp}"
}

set_env_default() {
  local key="$1"
  local value="$2"
  local file="$3"
  if [[ -z "$(read_env_value "${key}" "${file}")" ]]; then
    set_env_value "${key}" "${value}" "${file}"
  fi
}

set_app_yaml_agent_token() {
  local file="$1"
  local token="$2"
  local tmp

  if [[ ! -f "${file}" ]]; then
    return 1
  fi

  tmp="$(mktemp)"
  if grep -Eq '^[[:space:]]*NOBLIFI_AGENT_TOKEN:' "${file}"; then
    awk -v token="${token}" '
      /^[[:space:]]*NOBLIFI_AGENT_TOKEN:/ {
        print "  NOBLIFI_AGENT_TOKEN: \"" token "\""
        next
      }
      { print }
    ' "${file}" >"${tmp}"
  elif grep -Eq '^[[:space:]]*env_variables:[[:space:]]*$' "${file}"; then
    awk -v token="${token}" '
      {
        print
        if (!done && $0 ~ /^[[:space:]]*env_variables:[[:space:]]*$/) {
          print "  # Must match /etc/noblifi/vps-agent.env on the xneelo VPS."
          print "  NOBLIFI_AGENT_TOKEN: \"" token "\""
          done = 1
        }
      }
    ' "${file}" >"${tmp}"
  else
    cat "${file}" >"${tmp}"
    {
      echo
      echo "env_variables:"
      echo "  # Must match /etc/noblifi/vps-agent.env on the xneelo VPS."
      echo "  NOBLIFI_AGENT_TOKEN: \"${token}\""
    } >>"${tmp}"
  fi

  cat "${tmp}" >"${file}"
  rm -f "${tmp}"
  return 0
}

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

AGENT_TOKEN="${NOBLIFI_AGENT_TOKEN:-$(read_env_value NOBLIFI_AGENT_TOKEN "${AGENT_ENV}")}"
if [[ -z "${AGENT_TOKEN}" || "${AGENT_TOKEN}" == "replace-with-a-long-random-agent-token" || "${AGENT_TOKEN}" == "REPLACE_WITH_XNEELO_AGENT_TOKEN" ]]; then
  AGENT_TOKEN="$(generate_agent_token)"
fi
set_env_value NOBLIFI_AGENT_TOKEN "${AGENT_TOKEN}" "${AGENT_ENV}"
set_env_default NOBLIFI_CONTROL_PLANE_URL "${NOBLIFI_CONTROL_PLANE_URL:-https://api.example.com/api/v1}" "${AGENT_ENV}"
set_env_default NOBLIFI_AGENT_ID "${NOBLIFI_AGENT_ID:-xneelo-wg-agent-01}" "${AGENT_ENV}"
set_env_default NOBLIFI_WIREGUARD_INTERFACE "${WG_INTERFACE}" "${AGENT_ENV}"
set_env_default NOBLIFI_WIREGUARD_CONFIG "${WG_CONFIG}" "${AGENT_ENV}"
set_env_default NOBLIFI_WIREGUARD_LOCK "${NOBLIFI_WIREGUARD_LOCK:-/run/lock/noblifi-wireguard.lock}" "${AGENT_ENV}"
set_env_default NOBLIFI_WIREGUARD_BACKUP_DIR "${NOBLIFI_WIREGUARD_BACKUP_DIR:-/etc/wireguard/backups}" "${AGENT_ENV}"
set_env_default NOBLIFI_AGENT_POLL_INTERVAL "${NOBLIFI_AGENT_POLL_INTERVAL:-5s}" "${AGENT_ENV}"
set_env_default NOBLIFI_AGENT_RECONCILE_INTERVAL "${NOBLIFI_AGENT_RECONCILE_INTERVAL:-5m}" "${AGENT_ENV}"

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
if set_app_yaml_agent_token "${APP_YAML}" "${AGENT_TOKEN}"; then
  echo "Updated ${APP_YAML} with NOBLIFI_AGENT_TOKEN."
else
  echo "Add this to backend app.yaml env_variables:"
  echo "  NOBLIFI_AGENT_TOKEN: \"${AGENT_TOKEN}\""
fi
echo "Set NOBLIFI_CONTROL_PLANE_URL in ${AGENT_ENV} before starting the agent."
echo "Allow UDP ${WG_PORT} in the VPS provider firewall."
