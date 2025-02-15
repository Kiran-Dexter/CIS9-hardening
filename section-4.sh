#!/bin/bash
# remediate_section4.sh - Remediation for Section 4 controls:
# Firewall configuration (4.1.x, 4.2.x, 4.3.x),
# SSH configuration (5.1.x),
# Sudo configuration (5.2.x),
# and PAM/Password Policy (5.3.x, 5.4.x).
#
# Before making changes, this script backs up the affected file (with a timestamp)
# and logs all actions to remediation_section4.log in the present working directory.
# Interactive prompts allow you to confirm or skip each remediation.
#
# Some controls (e.g. detailed PAM/password policies and certain firewall settings)
# require manual remediation. You’ll be prompted accordingly.

LOGFILE="./remediation_section4.log"
timestamp=$(date +%Y%m%d%H%M%S)

#############################################
# Helper Functions
#############################################

backup_file() {
  local file="$1"
  if [ -f "$file" ]; then
    cp "$file" "${file}.bak.${timestamp}"
    echo "Backup of $file created as ${file}.bak.${timestamp}" | tee -a "$LOGFILE"
  fi
}

log_action() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOGFILE"
}

prompt_user() {
  read -p "$1 [Y/n]: " choice
  case "$choice" in 
    [Nn]*) return 1 ;;
    *) return 0 ;;
  esac
}

# Remediation for config directives (for SSH/sudo)
remediate_config_directive() {
  local file="$1"
  local directive="$2"   # e.g. "AllowTcpForwarding"
  local desired="$3"     # e.g. "no"
  local control="$4"
  local description="$5"
  log_action "$control: $description"
  backup_file "$file"
  if grep -qi "^$directive" "$file"; then
    local current
    current=$(grep -i "^$directive" "$file" | head -n 1)
    if echo "$current" | grep -qi "$desired"; then
      log_action "$directive already set to $desired in $file."
    else
      if prompt_user "$directive is currently '$current'. Update to '$directive $desired'?"; then
        sed -i.bak."${timestamp}" "s/^$directive.*/$directive $desired/I" "$file"
        log_action "Updated $directive to $desired in $file."
      else
        log_action "User skipped remediation for $directive."
      fi
    fi
  else
    if prompt_user "$directive not found in $file. Append '$directive $desired'?"; then
      echo "$directive $desired" >> "$file"
      log_action "Appended '$directive $desired' to $file."
    else
      log_action "User skipped appending $directive in $file."
    fi
  fi
}

#############################################
# Group A: Firewall Configuration (4.1.x - 4.3.x)
#############################################

# 4.1.1: Ensure nftables is installed
remediate_nftables_installed() {
  log_action "4.1.1: Ensure nftables is installed"
  if command -v nft &>/dev/null; then
    log_action "nftables is installed."
  else
    if prompt_user "nftables is not installed. Install it now?"; then
      if command -v yum &>/dev/null; then
        yum install -y nftables && log_action "Installed nftables via yum."
      elif command -v apt-get &>/dev/null; then
        apt-get update && apt-get install -y nftables && log_action "Installed nftables via apt-get."
      else
        log_action "Package manager not recognized. Please install nftables manually."
      fi
    else
      log_action "User skipped installation of nftables."
    fi
  fi
}

# 4.1.2: Ensure a single firewall configuration utility is in use (Manual)
remediate_single_firewall_utility() {
  log_action "4.1.2: Ensure a single firewall configuration utility is in use"
  log_action "Manual remediation required. Please verify that only one firewall utility is in use."
  prompt_user "Press Y if you have manually remediated this" && log_action "User confirmed manual remediation for 4.1.2."
}

# 4.2.1: Ensure firewalld drops unnecessary services and ports (Manual)
remediate_firewalld_drop_services() {
  log_action "4.2.1: Ensure firewalld drops unnecessary services and ports"
  log_action "Manual remediation required. Please review your firewalld configuration."
  prompt_user "Press Y if you have manually remediated this" && log_action "User confirmed manual remediation for 4.2.1."
}

# 4.2.2: Ensure firewalld loopback traffic is configured (Manual)
remediate_firewalld_loopback() {
  log_action "4.2.2: Ensure firewalld loopback traffic is configured"
  log_action "Manual remediation required. Please review your firewalld configuration."
  prompt_user "Press Y if you have manually remediated this" && log_action "User confirmed manual remediation for 4.2.2."
}

# 4.3.1: Ensure nftables base chains exist
remediate_nftables_base_chains() {
  log_action "4.3.1: Ensure nftables base chains exist"
  # Check if table ip filter exists and contains base chains.
  if nft list table ip filter &>/dev/null; then
    if nft list chain ip filter input | grep -qi "policy" && nft list chain ip filter output | grep -qi "policy"; then
      log_action "Base chains in table ip filter exist."
    else
      if prompt_user "Base chains not fully configured. Create default base chains in ip filter?"; then
        # Create table if needed and default chains with drop policy.
        nft add table ip filter 2>/dev/null
        nft add chain ip filter input { type filter hook input priority 0 \; policy drop \; } 2>/dev/null
        nft add chain ip filter forward { type filter hook forward priority 0 \; policy drop \; } 2>/dev/null
        nft add chain ip filter output { type filter hook output priority 0 \; policy accept \; } 2>/dev/null
        log_action "Created default base chains in table ip filter."
      else
        log_action "User skipped remediation for nftables base chains."
      fi
    fi
  else
    if prompt_user "Table ip filter does not exist. Create table and base chains?"; then
      nft add table ip filter && \
      nft add chain ip filter input { type filter hook input priority 0 \; policy drop \; } && \
      nft add chain ip filter forward { type filter hook forward priority 0 \; policy drop \; } && \
      nft add chain ip filter output { type filter hook output priority 0 \; policy accept \; }
      log_action "Created table ip filter with default base chains."
    else
      log_action "User skipped creation of table ip filter and base chains."
    fi
  fi
}

# 4.3.2: Ensure nftables established connections are configured
remediate_nftables_established() {
  log_action "4.3.2: Ensure nftables established connections are configured"
  # Check if rule accepting established, related connections exists
  if nft list ruleset | grep -qi "ct state established,related accept"; then
    log_action "Rule for established, related connections found."
  else
    if prompt_user "No rule for established, related connections found. Add rule to accept them?"; then
      nft add rule ip filter input ct state established,related accept && log_action "Added rule to accept established, related connections."
    else
      log_action "User skipped remediation for established connections rule."
    fi
  fi
}

# 4.3.3: Ensure nftables default deny firewall policy (Manual)
remediate_nftables_default_deny() {
  log_action "4.3.3: Ensure nftables default deny firewall policy"
  log_action "Manual remediation required. Please ensure the default policy for your input chains is set to deny."
  prompt_user "Press Y if you have manually remediated this" && log_action "User confirmed manual remediation for 4.3.3."
}

# 4.3.4: Ensure nftables loopback traffic is configured
remediate_nftables_loopback() {
  log_action "4.3.4: Ensure nftables loopback traffic is configured"
  if nft list ruleset | grep -qi "iif lo accept"; then
    log_action "Loopback traffic rule found in nftables."
  else
    if prompt_user "No rule for loopback traffic found. Add rule 'iif lo accept'?"; then
      nft add rule ip filter input iif lo accept && log_action "Added rule to accept loopback traffic."
    else
      log_action "User skipped remediation for loopback traffic rule."
    fi
  fi
}

#############################################
# Group B: SSH Configuration (5.1.x)
#############################################

# 5.1.1: Ensure permissions on /etc/ssh/sshd_config are configured (600)
remediate_sshd_config_perms() {
  log_action "5.1.1: Ensure permissions on /etc/ssh/sshd_config are configured"
  local file="/etc/ssh/sshd_config"
  if [ -f "$file" ]; then
    local perm
    perm=$(stat -c %a "$file")
    if [ "$perm" -eq 600 ]; then
      log_action "$file already has 600 permissions."
    else
      if prompt_user "Permissions on $file are $perm. Set to 600?"; then
        backup_file "$file"
        chmod 600 "$file" && log_action "Set $file permissions to 600."
      else
        log_action "User skipped remediation for $file permissions."
      fi
    fi
  else
    log_action "$file not found. Manual remediation required."
  fi
}

# 5.1.2: Ensure permissions on SSH private host key files are configured (600)
remediate_ssh_private_keys() {
  log_action "5.1.2: Ensure permissions on SSH private host key files are configured"
  for key in /etc/ssh/ssh_host_*_key; do
    [ -e "$key" ] || continue
    local perm
    perm=$(stat -c %a "$key")
    if [ "$perm" -eq 600 ]; then
      log_action "$key already has 600 permissions."
    else
      if prompt_user "Permissions on $key are $perm. Set to 600?"; then
        backup_file "$key"
        chmod 600 "$key" && log_action "Set $key permissions to 600."
      else
        log_action "User skipped remediation for $key."
      fi
    fi
  done
}

# 5.1.3: Ensure permissions on SSH public host key files are configured (644)
remediate_ssh_public_keys() {
  log_action "5.1.3: Ensure permissions on SSH public host key files are configured"
  for key in /etc/ssh/ssh_host_*_key.pub; do
    [ -e "$key" ] || continue
    local perm
    perm=$(stat -c %a "$key")
    if [ "$perm" -eq 644 ]; then
      log_action "$key already has 644 permissions."
    else
      if prompt_user "Permissions on $key are $perm. Set to 644?"; then
        backup_file "$key"
        chmod 644 "$key" && log_action "Set $key permissions to 644."
      else
        log_action "User skipped remediation for $key."
      fi
    fi
  done
}

# 5.1.4, 5.1.5, 5.1.6, 5.1.7, 5.1.15 are marked as manual remediation.
remediate_ssh_manual() {
  local control="$1"
  local description="$2"
  log_action "$control: $description requires manual remediation."
  prompt_user "Press Y if you have manually remediated $description" && log_action "User confirmed manual remediation for $control."
}

# 5.1.10: Ensure sshd DisableForwarding is enabled (AllowTcpForwarding no)
remediate_sshd_disable_forwarding() {
  remediate_config_directive "/etc/ssh/sshd_config" "AllowTcpForwarding" "no" "5.1.10" "Ensure sshd DisableForwarding is enabled"
}

# 5.1.11: Ensure sshd GSSAPIAuthentication is disabled
remediate_sshd_gssapiauth() {
  remediate_config_directive "/etc/ssh/sshd_config" "GSSAPIAuthentication" "no" "5.1.11" "Ensure sshd GSSAPIAuthentication is disabled"
}

# 5.1.13: Ensure sshd IgnoreRhosts is enabled
remediate_sshd_ignorerhosts() {
  remediate_config_directive "/etc/ssh/sshd_config" "IgnoreRhosts" "yes" "5.1.13" "Ensure sshd IgnoreRhosts is enabled"
}

# 5.1.19: Ensure sshd PermitEmptyPasswords is disabled
remediate_sshd_emptypassword() {
  remediate_config_directive "/etc/ssh/sshd_config" "PermitEmptyPasswords" "no" "5.1.19" "Ensure sshd PermitEmptyPasswords is disabled"
}

# 5.1.20: Ensure sshd PermitRootLogin is disabled
remediate_sshd_rootlogin() {
  remediate_config_directive "/etc/ssh/sshd_config" "PermitRootLogin" "no" "5.1.20" "Ensure sshd PermitRootLogin is disabled"
}

# 5.1.22: Ensure sshd UsePAM is enabled
remediate_sshd_usepam() {
  remediate_config_directive "/etc/ssh/sshd_config" "UsePAM" "yes" "5.1.22" "Ensure sshd UsePAM is enabled"
}

#############################################
# Group C: Sudo Configuration (5.2.x)
#############################################

# 5.2.1: Ensure sudo is installed
remediate_sudo_installed() {
  log_action "5.2.1: Ensure sudo is installed"
  if command -v sudo &>/dev/null; then
    log_action "sudo is installed."
  else
    log_action "sudo is not installed. Please install sudo manually."
  fi
}

# 5.2.2: Ensure sudo commands use pty (Defaults use_pty)
remediate_sudo_use_pty() {
  remediate_config_directive "/etc/sudoers" "Defaults\s*use_pty" "Defaults use_pty" "5.2.2" "Ensure sudo commands use pty"
}

# 5.2.3: Ensure sudo log file exists (e.g., /var/log/sudo.log)
remediate_sudo_log_file() {
  log_action "5.2.3: Ensure sudo log file exists"
  local logfile="/var/log/sudo.log"
  if [ -f "$logfile" ]; then
    log_action "$logfile exists."
  else
    if prompt_user "$logfile does not exist. Create an empty log file?"; then
      touch "$logfile" && chmod 600 "$logfile" && log_action "Created $logfile with permissions 600."
    else
      log_action "User skipped creation of $logfile."
    fi
  fi
}

# 5.2.4: Ensure users must provide password for escalation (no NOPASSWD in sudoers)
remediate_sudo_password_required() {
  log_action "5.2.4: Ensure users must provide password for escalation"
  if grep -q "NOPASSWD" /etc/sudoers; then
    if prompt_user "NOPASSWD directive found in /etc/sudoers. Remove it?"; then
      backup_file "/etc/sudoers"
      sed -i.bak."${timestamp}" '/NOPASSWD/d' /etc/sudoers && log_action "Removed NOPASSWD from /etc/sudoers."
    else
      log_action "User skipped remediation for NOPASSWD directive."
    fi
  else
    log_action "No NOPASSWD directive found in /etc/sudoers."
  fi
}

# 5.2.5: Ensure re-authentication for privilege escalation is not disabled (Manual)
remediate_sudo_reauth() {
  remediate_config_directive "/etc/sudoers" "Defaults\s*!authenticate" "" "5.2.5" "Ensure re-authentication is not globally disabled"  
  log_action "Manual review required for 5.2.5."
}

# 5.2.6: Ensure sudo authentication timeout is configured correctly (check for timestamp_timeout)
remediate_sudo_timeout() {
  remediate_config_directive "/etc/sudoers" "timestamp_timeout" "timestamp_timeout=5" "5.2.6" "Ensure sudo authentication timeout is configured (set to 5 minutes)"
}

# 5.2.7: Ensure access to the su command is restricted (check /etc/pam.d/su for pam_wheel)
remediate_su_access() {
  log_action "5.2.7: Ensure access to the su command is restricted"
  local file="/etc/pam.d/su"
  if [ -f "$file" ] && grep -qi "pam_wheel.so" "$file"; then
    log_action "pam_wheel is configured in $file."
  else
    if prompt_user "pam_wheel not configured in $file. Add 'auth required pam_wheel.so use_uid'?"; then
      backup_file "$file"
      echo "auth required pam_wheel.so use_uid" >> "$file" && log_action "Appended pam_wheel configuration to $file."
    else
      log_action "User skipped remediation for su access restrictions."
    fi
  fi
}

#############################################
# Group D: PAM & Password Policy (5.3.x and 5.4.x) – Manual
#############################################

remediate_pam_password_manual() {
  log_action "Controls 5.3.x and 5.4.x: PAM and Password Policy settings require manual remediation."
  log_action "Please review and remediate the following manually:"
  log_action "  - Ensure active authselect profile includes pam modules"
  log_action "  - Ensure pam_faillock, pam_pwquality, pam_pwhistory modules are enabled"
  log_action "  - Ensure password lockout, complexity, history, and expiration settings are configured per your policy"
  log_action "  - Ensure root and group root are the only GID 0 entities; root account access and umask settings"
  prompt_user "Press Y if you have manually remediated PAM and Password Policy settings" && log_action "User confirmed manual remediation for PAM/Password Policy."
}

#############################################
# Main Execution: Remediate Section 4
#############################################

echo "Starting remediation for Section 4. All actions are logged to $LOGFILE."
log_action "=== Starting Remediation for Section 4 ==="

# --- Group A: Firewall ---
remediate_nftables_installed
remediate_single_firewall_utility
remediate_firewalld_drop_services
remediate_firewalld_loopback
remediate_nftables_base_chains
remediate_nftables_established
remediate_nftables_default_deny
remediate_nftables_loopback

# --- Group B: SSH Configuration ---
remediate_sshd_config_perms
remediate_ssh_private_keys
remediate_ssh_public_keys
remediate_ssh_manual "5.1.4" "Ensure sshd Ciphers are configured"
remediate_ssh_manual "5.1.5" "Ensure sshd KexAlgorithms are configured"
remediate_ssh_manual "5.1.6" "Ensure sshd MACs are configured"
remediate_ssh_manual "5.1.7" "Ensure sshd access is configured"
remediate_sshd_disable_forwarding
remediate_sshd_gssapiauth
remediate_ssh_manual "5.1.15" "Ensure sshd LogLevel is configured"
remediate_sshd_ignorerhosts
remediate_sshd_emptypassword
remediate_sshd_rootlogin
remediate_sshd_usepam

# --- Group C: Sudo Configuration ---
remediate_sudo_installed
remediate_sudo_use_pty
remediate_sudo_log_file
remediate_sudo_password_required
remediate_sudo_reauth
remediate_sudo_timeout
remediate_su_access

# --- Group D: PAM & Password Policy ---
remediate_pam_password_manual

log_action "=== Completed Remediation for Section 4 ==="
echo "Remediation for Section 4 complete. Please review $LOGFILE for details."
