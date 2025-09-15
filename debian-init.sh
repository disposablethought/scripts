#!/bin/bash
# Debian 12 VPS initial setup
# - Creates user mholmes, installs SSH keys from GitHub user disposablethought
# - SSH on 22, no root login, no password auth
# - UFW: deny all inbound, allow SSH only from 10.81.0.0/24
# - Fail2ban enabled
# - Unattended upgrades enabled and configured

set -euo pipefail

### VARIABLES ###
NEW_USER="mholmes"
GITHUB_USER="disposablethought"      # pulls keys from https://github.com/<user>.keys
SSH_ALLOWED_CIDR="10.81.0.0/24"      # only this CIDR can reach SSH
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

  # Configure allowed origins and safe behaviors for Debian 12 (bookworm)
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

  # Ensure the systemd timer is active
  systemctl enable --now unattended-upgrades.service || true
fi

# install common tools
sudo apt install btop iotop iftop neovim -y

sudo timedatectl set-timezone America/Regina

# setup neovim as default editor for vi/vim
sudo update-alternatives --install /usr/bin/vim vim /usr/bin/nvim 60
sudo update-alternatives --config vim
sudo update-alternatives --install /usr/bin/vim vim /usr/bin/nvim 60
sudo update-alternatives --config vim
sudo update-alternatives --install /usr/bin/vi vi /usr/bin/nvim 60
sudo update-alternatives --config vi

msg "Creating user: ${NEW_USER} and adding to sudo"
if ! id -u "${NEW_USER}" >/dev/null 2>&1; then
  adduser --disabled-password --gecos "" "${NEW_USER}"
fi
usermod -aG sudo "${NEW_USER}"

USER_HOME="/home/${NEW_USER}"
SSH_DIR="${USER_HOME}/.ssh"
AUTH_KEYS="${SSH_DIR}/authorized_keys"

msg "Fetching GitHub public keys for ${GITHUB_USER}"
mkdir -p "${SSH_DIR}"
chmod 700 "${SSH_DIR}"
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
    echo "No keys found at https://github.com/${GITHUB_USER}.keys" >&2
    echo "Aborting for safety. Update GITHUB_USER or add a key manually." >&2
    exit 2
  fi
else
  echo "Failed to fetch GitHub keys for ${GITHUB_USER}" >&2
  exit 2
fi

msg "Hardening SSH (port 22, key-only, no root login)"
SSHD="/etc/ssh/sshd_config"
[[ -f "${SSHD}.bak" ]] || cp "${SSHD}" "${SSHD}.bak"

ensure_sshd_opt() {
  local key="$1" val="$2"
  if grep -qiE "^[#\s]*${key}\b" "${SSHD}"; then
    sed -i -E "s|^[#\s]*${key}\b.*|${key} ${val}|I" "${SSHD}"
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
# Optionally restrict to only this user:
# ensure_sshd_opt "AllowUsers" "${NEW_USER}"

systemctl restart ssh

msg "Configuring UFW (deny all inbound; allow SSH only from ${SSH_ALLOWED_CIDR})"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow from "${SSH_ALLOWED_CIDR}" to any port 22 proto tcp
ufw --force enable
ufw status verbose

msg "Enabling and starting fail2ban"
systemctl enable --now fail2ban

msg "Summary"
echo "  - User: ${NEW_USER} (sudo)"
echo "  - Keys: https://github.com/${GITHUB_USER}.keys"
echo "  - SSH: port 22, root disabled, password auth disabled"
echo "  - UFW: inbound denied; SSH allowed only from ${SSH_ALLOWED_CIDR}"
if [[ "${ENABLE_UNATTENDED_UPGRADES}" == "yes" ]]; then
  echo "  - Unattended upgrades: enabled (daily, security and updates, no auto reboot)"
fi
echo
echo "If you need wider SSH access temporarily (from console):"
echo "  ufw delete allow from ${SSH_ALLOWED_CIDR} to any port 22 proto tcp"
echo "  ufw allow 22/tcp"
