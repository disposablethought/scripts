#!/bin/bash
# Debian 12 VPS initial setup
# - Creates user mholmes, installs SSH keys from GitHub user disposablethought
# - SSH on 22, no root login, no password auth
# - UFW: deny all inbound; prefer Tailscale if detected, else use SSH_ALLOWED_CIDR
# - Fail2ban enabled
# - Unattended upgrades enabled and configured
# - Safe UFW bring-up to avoid lockout

set -euo pipefail

### VARIABLES ###
NEW_USER="mholmes"
GITHUB_USER="disposablethought"      # pulls keys from https://github.com/<user>.keys
SSH_ALLOWED_CIDR="100.81.0.0/24"      # desired policy when not using Tailscale
ENABLE_UNATTENDED_UPGRADES="yes"
##################

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "Run as root (sudo -i)."
    exit 1
  fi
}

pkg() { apt-get install -y --no-install-recommends "$@"; }
msg() { echo -e "\n[+] $*"; }
warn() { echo -e "\n[!] $*" >&2; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

tailscale_up() {
  # Tailscale considered "up" if tailscaled is active and tailscale0 is up
  if have_cmd systemctl && systemctl is-active --quiet tailscaled 2>/dev/null; then
    ip link show dev tailscale0 2>/dev/null | grep -q "state UP" && return 0
  fi
  return 0 # treat as success if interface exists but systemctl absent
}

get_client_ip() {
  # If invoked over SSH, SSH_CONNECTION is "client_ip client_port server_ip server_port"
  if [[ -n "${SSH_CONNECTION-}" ]]; then
    set -- ${SSH_CONNECTION}
    printf "%s" "$1"
    return 0
  fi
  return 1
}

require_root

msg "Updating and upgrading packages"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get -y full-upgrade

msg "Installing base tools"
pkg sudo ufw fail2ban curl ca-certificates vim gnupg

if [[ "${ENABLE_UNATTENDED_UPGRADES}" == "yes" ]]; then
  msg "Installing unattended-upgrades"
  pkg unattended-upgrades apt-listchanges

  msg "Configuring APT periodic tasks"
  cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

  msg "Configuring unattended-upgrades policy"
  cat >/etc/apt/apt.conf.d/50unattended-upgrades <<'EOF'
// Automatically upgrade packages from these repositories
Unattended-Upgrade::Origins-Pattern {
        "origin=Debian,codename=${distro_codename},label=Debian-Security";
        "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
        "origin=Debian,codename=${distro_codename},label=Debian";
        "origin=Debian,codename=${distro_codename}-updates,label=Debian";
};

// Do not reboot automatically on kernel updates
Unattended-Upgrade::Automatic-Reboot "false";

// Remove packages that are no longer required
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";

// Minimal mail reporting to root if MTA present
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::MailOnlyOnError "true";

// Allow immediate upgrades
Unattended-Upgrade::InstallOnShutdown "false";
EOF

  systemctl enable --now unattended-upgrades.service || true
fi

# Optional common tools
apt-get install -y btop iotop iftop neovim dnsutils
timedatectl set-timezone America/Regina

# Make nvim the default for vi/vim (non-interactive)
update-alternatives --install /usr/bin/vim vim /usr/bin/nvim 60
update-alternatives --set vim /usr/bin/nvim
update-alternatives --install /usr/bin/vi vi /usr/bin/nvim 60
update-alternatives --set vi /usr/bin/nvim

msg "Creating user: ${NEW_USER} and adding to sudo"
if ! id -u "${NEW_USER}" >/dev/null 2>&1; then
  adduser --disabled-password --gecos "" "${NEW_USER}"
fi
usermod -aG sudo "${NEW_USER}"

USER_HOME="/home/${NEW_USER}"
SSH_DIR="${USER_HOME}/.ssh"
AUTH_KEYS="${SSH_DIR}/authorized_keys"

msg "Fetching GitHub public keys for ${GITHUB_USER}"
install -d -m 700 -o "${NEW_USER}" -g "${NEW_USER}" "${SSH_DIR}"
touch "${AUTH_KEYS}"
chmod 600 "${AUTH_KEYS}"

TMP_KEYS="$(mktemp)"
if curl -fsSL "https://github.com/${GITHUB_USER}.keys" -o "${TMP_KEYS}"; then
  if [[ -s "${TMP_KEYS}" ]]; then
    sort -u "${TMP_KEYS}" "${AUTH_KEYS}" | \
      grep -E '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp[0-9]+) ' > "${AUTH_KEYS}.new" || true
    mv "${AUTH_KEYS}.new" "${AUTH_KEYS}"
    chown -R "${NEW_USER}:${NEW_USER}" "${SSH_DIR}"
    rm -f "${TMP_KEYS}"
    msg "Installed $(wc -l < "${AUTH_KEYS}") key(s) to ${AUTH_KEYS}"
  else
    rm -f "${TMP_KEYS}"
    warn "No keys found at https://github.com/${GITHUB_USER}.keys"
    warn "Aborting for safety. Update GITHUB_USER or add a key manually."
    exit 2
  fi
else
  warn "Failed to fetch GitHub keys for ${GITHUB_USER}"
  exit 2
fi

msg "Hardening SSH (port 22, key-only, no root login)"
SSHD="/etc/ssh/sshd_config"
[[ -f "${SSHD}.bak" ]] || cp "${SSHD}" "${SSHD}.bak"

ensure_sshd_opt() {
  local key="$1" val="$2"
  if grep -qiE "^[#[:space:]]*${key}\b" "${SSHD}"; then
    sed -i -E "s|^[#[:space:]]*${key}\b.*|${key} ${val}|I" "${SSHD}"
  else
    echo "${key} ${val}" >> "${SSHD}"
  fi
}

ensure_sshd_opt "Port" "22"
ensure_sshd_opt "PermitRootLogin" "no"
ensure_sshd_opt "PasswordAuthentication" "no"
ensure_sshd_opt "KbdInteractiveAuthentication" "no"
ensure_sshd_opt "ChallengeResponseAuthentication" "no"
ensure_sshd_opt "PubkeyAuthentication" "yes"
ensure_sshd_opt "PermitEmptyPasswords" "no"
ensure_sshd_opt "AuthorizedKeysFile" ".ssh/authorized_keys"
ensure_sshd_opt "UsePAM" "yes"
# Optionally restrict to one user:
# ensure_sshd_opt "AllowUsers" "${NEW_USER}"

systemctl restart ssh

msg "Configuring UFW safely (deny all inbound; allow SSH appropriately)"
# Always manage v6 too; harmless if unused
sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw || true

# Reset and set base policy
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

SAFE_TMP_OPENED="no"

# Try to detect Tailscale and prefer it if up
if tailscale_up && ip -o link show tailscale0 >/dev/null 2>&1; then
  msg "Tailscale detected and up; allowing SSH only on tailscale0 from 100.64.0.0/10"
  ufw allow in on tailscale0 from 100.64.0.0/10 to any port 22 proto tcp
else
  # Not on Tailscale path right now — avoid lockout
  CLIENT_IP=""
  if CLIENT_IP="$(get_client_ip)"; then
    msg "Temporarily allowing your current client IP ${CLIENT_IP}/32 on port 22"
    ufw allow from "${CLIENT_IP}" to any port 22 proto tcp
    SAFE_TMP_OPENED="yes"
  else
    warn "Could not determine client IP (not running via SSH?)."
    warn "Temporarily allowing 22/tcp from anywhere to avoid lockout."
    ufw allow 22/tcp
    SAFE_TMP_OPENED="yes"
  fi

  # Now add your desired steady-state rule
  msg "Adding steady-state SSH allow from ${SSH_ALLOWED_CIDR}"
  ufw allow from "${SSH_ALLOWED_CIDR}" to any port 22 proto tcp
fi

ufw --force enable
ufw status verbose

# If we opened a temporary hole, close it now that the steady-state rule exists
if [[ "${SAFE_TMP_OPENED}" == "yes" ]]; then
  # Delete any broad 22/tcp rule and the specific client /32 if present
  # This is best-effort cleanup; won't fail the script if the rule isn't found
  ufw delete allow 22/tcp 2>/dev/null || true
  if [[ -n "${CLIENT_IP-}" ]]; then
    ufw delete allow from "${CLIENT_IP}" to any port 22 proto tcp 2>/dev/null || true
  fi
  ufw reload
  msg "Temporary SSH allow removed; UFW tightened to steady-state policy."
fi

msg "Enabling and starting fail2ban"
systemctl enable --now fail2ban

msg "Summary"
echo "  - User: ${NEW_USER} (sudo)"
echo "  - Keys: https://github.com/${GITHUB_USER}.keys"
echo "  - SSH: port 22, root disabled, password auth disabled"
if tailscale_up && ip -o link show tailscale0 >/dev/null 2>&1; then
  echo "  - UFW: inbound denied; SSH allowed only on tailscale0 from 100.64.0.0/10"
else
  echo "  - UFW: inbound denied; SSH allowed from ${SSH_ALLOWED_CIDR}"
fi
if [[ "${ENABLE_UNATTENDED_UPGRADES}" == "yes" ]]; then
  echo "  - Unattended upgrades: enabled (daily, no auto reboot)"
fi
echo
echo "If you need wider SSH access temporarily (from console):"
echo "  ufw allow 22/tcp   # then tighten back down as needed"
