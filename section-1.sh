#!/bin/bash
# remediate_section1.sh - Remediation script for Section 1 controls.
# This script backs up files, applies changes interactively,
# and logs all actions to a log file in the present working directory.
#
# Controls remediated in this section:
#   1.1.2.5.4   : Ensure noexec option set on /var/tmp partition
#   1.1.2.6.1   : Ensure separate partition exists for /var/log
#   1.1.2.6.2   : Ensure nodev option set on /var/log partition
#   1.1.2.6.3   : Ensure nosuid option set on /var/log partition
#   1.1.2.6.4   : Ensure noexec option set on /var/log partition
#   1.1.2.7.1   : Ensure separate partition exists for /var/log/audit
#   1.1.2.7.2   : Ensure nodev option set on /var/log/audit partition
#   1.1.2.7.3   : Ensure nosuid option set on /var/log/audit partition
#   1.1.2.7.4   : Ensure noexec option set on /var/log/audit partition
#   1.2.1.1     : Ensure GPG keys are configured
#   1.2.1.2     : Ensure gpgcheck is globally activated
#   1.2.1.3     : Ensure repo_gpgcheck is globally activated
#   1.2.1.4     : Ensure package manager repositories are configured
#   1.2.2.1     : Ensure updates, patches, and additional security software are installed
#   1.3.1.1     : Ensure SELinux is installed
#   1.3.1.2     : Ensure SELinux is not disabled in bootloader configuration
#   1.3.1.3     : Ensure SELinux policy is configured
#   1.3.1.4     : Ensure the SELinux mode is not disabled
#   1.3.1.5     : Ensure the SELinux mode is enforcing
#   1.3.1.6     : Ensure no unconfined services exist (manual)
#   1.3.1.7     : Ensure the MCS Translation Service (mcstrans) is not installed
#   1.3.1.8     : Ensure SETroubleshoot is not installed
#   1.4.1       : Ensure bootloader password is set (manual)
#   1.4.2       : Ensure access to bootloader config is configured
#   1.5.1       : Ensure address space layout randomization is enabled
#   1.5.2       : Ensure ptrace_scope is restricted
#   1.6.1       : Ensure system wide crypto policy is not set to legacy
#   1.6.2       : Ensure system wide crypto policy is not set in sshd configuration
#   1.6.3       : Ensure crypto policy disables sha1 (manual)
#   1.6.4       : Ensure crypto policy disables MACs <128 bits (manual)
#   1.6.5       : Ensure crypto policy disables CBC for ssh
#   1.6.6       : Ensure crypto policy disables chacha20-poly1305 for ssh
#   1.6.7       : Ensure crypto policy disables EtM for ssh (manual)
#
# All actions are logged to "remediation.log" in the current directory.

LOGFILE="./remediation.log"
timestamp=$(date +%Y%m%d%H%M%S)

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
  # Prompt with message; return 0 if yes, 1 if no.
  read -p "$1 [Y/n]: " choice
  case "$choice" in 
    [Nn]*) return 1 ;;
    *) return 0 ;;
  esac
}

#############################################
# Remediation Functions for Section 1
#############################################

# 1.1.2.5.4: Remediate /var/tmp noexec option in /etc/fstab
remediate_noexec_var_tmp() {
  log_action "Remediation 1.1.2.5.4: Ensure noexec option set on /var/tmp partition"
  local fstab="/etc/fstab"
  if ! grep -q "[[:space:]]/var/tmp[[:space:]]" "$fstab"; then
    log_action "/var/tmp entry not found in $fstab. Skipping remediation."
    return
  fi
  if grep "[[:space:]]/var/tmp[[:space:]]" "$fstab" | grep -q "noexec"; then
    log_action "noexec already set for /var/tmp. No action needed."
    return
  fi
  if ! prompt_user "Add noexec to /var/tmp entry in $fstab?"; then
    log_action "User skipped remediation for /var/tmp noexec."
    return
  fi
  backup_file "$fstab"
  sed -i.bak."${timestamp}" '/[[:space:]]\/var\/tmp[[:space:]]/ {
    s/\(\S\+\s\+\S\+\s\+\S\+\s\+\)\([^ \t]*\)/\1\2,noexec/
  }' "$fstab" && log_action "Added noexec option to /var/tmp entry."
}

# 1.1.2.6.1: Remediation for separate /var/log partition (manual)
remediate_separate_partition_var_log() {
  log_action "Remediation 1.1.2.6.1: Ensure separate partition exists for /var/log"
  log_action "This requires manual verification. Please ensure /var/log is mounted separately."
  prompt_user "Press Y if you have manually remediated /var/log partition separation" && log_action "User confirmed manual remediation for /var/log partition."
}

# 1.1.2.6.2: Remediate /var/log nodev option in /etc/fstab
remediate_nodev_var_log() {
  log_action "Remediation 1.1.2.6.2: Ensure nodev option set on /var/log partition"
  local fstab="/etc/fstab"
  if ! grep -q "[[:space:]]/var/log[[:space:]]" "$fstab"; then
    log_action "/var/log entry not found in $fstab. Skipping remediation."
    return
  fi
  if grep "[[:space:]]/var/log[[:space:]]" "$fstab" | grep -q "nodev"; then
    log_action "nodev already set for /var/log. No action needed."
    return
  fi
  if ! prompt_user "Add nodev to /var/log entry in $fstab?"; then
    log_action "User skipped remediation for /var/log nodev."
    return
  fi
  backup_file "$fstab"
  sed -i.bak."${timestamp}" '/[[:space:]]\/var\/log[[:space:]]/ {
    s/\(\S\+\s\+\S\+\s\+\S\+\s\+\)\([^ \t]*\)/\1\2,nodev/
  }' "$fstab" && log_action "Added nodev option to /var/log entry."
}

# 1.1.2.6.3: Remediate /var/log nosuid option in /etc/fstab
remediate_nosuid_var_log() {
  log_action "Remediation 1.1.2.6.3: Ensure nosuid option set on /var/log partition"
  local fstab="/etc/fstab"
  if ! grep -q "[[:space:]]/var/log[[:space:]]" "$fstab"; then
    log_action "/var/log entry not found in $fstab. Skipping remediation."
    return
  fi
  if grep "[[:space:]]/var/log[[:space:]]" "$fstab" | grep -q "nosuid"; then
    log_action "nosuid already set for /var/log. No action needed."
    return
  fi
  if ! prompt_user "Add nosuid to /var/log entry in $fstab?"; then
    log_action "User skipped remediation for /var/log nosuid."
    return
  fi
  backup_file "$fstab"
  sed -i.bak."${timestamp}" '/[[:space:]]\/var\/log[[:space:]]/ {
    s/\(\S\+\s\+\S\+\s\+\S\+\s\+\)\([^ \t]*\)/\1\2,nosuid/
  }' "$fstab" && log_action "Added nosuid option to /var/log entry."
}

# 1.1.2.6.4: Remediate /var/log noexec option in /etc/fstab
remediate_noexec_var_log() {
  log_action "Remediation 1.1.2.6.4: Ensure noexec option set on /var/log partition"
  local fstab="/etc/fstab"
  if ! grep -q "[[:space:]]/var/log[[:space:]]" "$fstab"; then
    log_action "/var/log entry not found in $fstab. Skipping remediation."
    return
  fi
  if grep "[[:space:]]/var/log[[:space:]]" "$fstab" | grep -q "noexec"; then
    log_action "noexec already set for /var/log. No action needed."
    return
  fi
  if ! prompt_user "Add noexec to /var/log entry in $fstab?"; then
    log_action "User skipped remediation for /var/log noexec."
    return
  fi
  backup_file "$fstab"
  sed -i.bak."${timestamp}" '/[[:space:]]\/var\/log[[:space:]]/ {
    s/\(\S\+\s\+\S\+\s\+\S\+\s\+\)\([^ \t]*\)/\1\2,noexec/
  }' "$fstab" && log_action "Added noexec option to /var/log entry."
}

# 1.1.2.7.1: Remediation for separate /var/log/audit partition (manual)
remediate_separate_partition_var_log_audit() {
  log_action "Remediation 1.1.2.7.1: Ensure separate partition exists for /var/log/audit"
  log_action "This requires manual remediation. Please ensure /var/log/audit is mounted separately."
  prompt_user "Press Y if you have manually remediated /var/log/audit partition separation" && log_action "User confirmed manual remediation for /var/log/audit partition."
}

# 1.1.2.7.2: Remediate /var/log/audit nodev option in /etc/fstab
remediate_nodev_var_log_audit() {
  log_action "Remediation 1.1.2.7.2: Ensure nodev option set on /var/log/audit partition"
  local fstab="/etc/fstab"
  if ! grep -q "[[:space:]]/var/log/audit[[:space:]]" "$fstab"; then
    log_action "/var/log/audit entry not found in $fstab. Skipping remediation."
    return
  fi
  if grep "[[:space:]]/var/log/audit[[:space:]]" "$fstab" | grep -q "nodev"; then
    log_action "nodev already set for /var/log/audit. No action needed."
    return
  fi
  if ! prompt_user "Add nodev to /var/log/audit entry in $fstab?"; then
    log_action "User skipped remediation for /var/log/audit nodev."
    return
  fi
  backup_file "$fstab"
  sed -i.bak."${timestamp}" '/[[:space:]]\/var\/log\/audit[[:space:]]/ {
    s/\(\S\+\s\+\S\+\s\+\S\+\s\+\)\([^ \t]*\)/\1\2,nodev/
  }' "$fstab" && log_action "Added nodev option to /var/log/audit entry."
}

# 1.1.2.7.3: Remediate /var/log/audit nosuid option in /etc/fstab
remediate_nosuid_var_log_audit() {
  log_action "Remediation 1.1.2.7.3: Ensure nosuid option set on /var/log/audit partition"
  local fstab="/etc/fstab"
  if ! grep -q "[[:space:]]/var/log/audit[[:space:]]" "$fstab"; then
    log_action "/var/log/audit entry not found in $fstab. Skipping remediation."
    return
  fi
  if grep "[[:space:]]/var/log/audit[[:space:]]" "$fstab" | grep -q "nosuid"; then
    log_action "nosuid already set for /var/log/audit. No action needed."
    return
  fi
  if ! prompt_user "Add nosuid to /var/log/audit entry in $fstab?"; then
    log_action "User skipped remediation for /var/log/audit nosuid."
    return
  fi
  backup_file "$fstab"
  sed -i.bak."${timestamp}" '/[[:space:]]\/var\/log\/audit[[:space:]]/ {
    s/\(\S\+\s\+\S\+\s\+\S\+\s\+\)\([^ \t]*\)/\1\2,nosuid/
  }' "$fstab" && log_action "Added nosuid option to /var/log/audit entry."
}

# 1.1.2.7.4: Remediate /var/log/audit noexec option in /etc/fstab
remediate_noexec_var_log_audit() {
  log_action "Remediation 1.1.2.7.4: Ensure noexec option set on /var/log/audit partition"
  local fstab="/etc/fstab"
  if ! grep -q "[[:space:]]/var/log/audit[[:space:]]" "$fstab"; then
    log_action "/var/log/audit entry not found in $fstab. Skipping remediation."
    return
  fi
  if grep "[[:space:]]/var/log/audit[[:space:]]" "$fstab" | grep -q "noexec"; then
    log_action "noexec already set for /var/log/audit. No action needed."
    return
  fi
  if ! prompt_user "Add noexec to /var/log/audit entry in $fstab?"; then
    log_action "User skipped remediation for /var/log/audit noexec."
    return
  fi
  backup_file "$fstab"
  sed -i.bak."${timestamp}" '/[[:space:]]\/var\/log\/audit[[:space:]]/ {
    s/\(\S\+\s\+\S\+\s\+\S\+\s\+\)\([^ \t]*\)/\1\2,noexec/
  }' "$fstab" && log_action "Added noexec option to /var/log/audit entry."
}

# 1.2.1.1: Remediate GPG keys configuration (create directory if missing)
remediate_gpg_keys_configured() {
  log_action "Remediation 1.2.1.1: Ensure GPG keys are configured"
  if [ -d /etc/pki/rpm-gpg ]; then
    log_action "GPG keys directory exists. No remediation needed."
  else
    if ! prompt_user "Directory /etc/pki/rpm-gpg not found. Create it?"; then
      log_action "User skipped creation of /etc/pki/rpm-gpg."
      return
    fi
    mkdir -p /etc/pki/rpm-gpg && log_action "Created /etc/pki/rpm-gpg."
  fi
}

# 1.2.1.2: Remediate gpgcheck in /etc/yum.conf
remediate_gpgcheck() {
  log_action "Remediation 1.2.1.2: Ensure gpgcheck is globally activated"
  local file="/etc/yum.conf"
  if grep -q "^gpgcheck=1" "$file"; then
    log_action "gpgcheck is already set to 1 in $file."
  else
    if ! prompt_user "Set gpgcheck=1 in $file?"; then
      log_action "User skipped remediation for gpgcheck."
      return
    fi
    backup_file "$file"
    if grep -q "^gpgcheck=" "$file"; then
      sed -i.bak."${timestamp}" 's/^gpgcheck=.*/gpgcheck=1/' "$file"
    else
      echo "gpgcheck=1" >> "$file"
    fi
    log_action "Set gpgcheck=1 in $file."
  fi
}

# 1.2.1.3: Remediate repo_gpgcheck in /etc/yum.conf
remediate_repo_gpgcheck() {
  log_action "Remediation 1.2.1.3: Ensure repo_gpgcheck is globally activated"
  local file="/etc/yum.conf"
  if grep -q "^repo_gpgcheck=1" "$file"; then
    log_action "repo_gpgcheck is already set to 1 in $file."
  else
    if ! prompt_user "Set repo_gpgcheck=1 in $file?"; then
      log_action "User skipped remediation for repo_gpgcheck."
      return
    fi
    backup_file "$file"
    if grep -q "^repo_gpgcheck=" "$file"; then
      sed -i.bak."${timestamp}" 's/^repo_gpgcheck=.*/repo_gpgcheck=1/' "$file"
    else
      echo "repo_gpgcheck=1" >> "$file"
    fi
    log_action "Set repo_gpgcheck=1 in $file."
  fi
}

# 1.2.1.4: Check package manager repositories (manual)
remediate_package_repos_configured() {
  log_action "Remediation 1.2.1.4: Ensure package manager repositories are configured"
  if [ -d /etc/yum.repos.d ] && [ "$(ls -A /etc/yum.repos.d/)" ]; then
    log_action "Repository configuration exists in /etc/yum.repos.d."
  else
    log_action "No repository configuration found in /etc/yum.repos.d. This requires manual remediation."
  fi
}

# 1.2.2.1: Remediate updates/patches installation (enable automatic updates)
remediate_updates_installed() {
  log_action "Remediation 1.2.2.1: Ensure updates/patches and security software are installed"
  if systemctl is-active --quiet yum-cron || systemctl is-active --quiet dnf-automatic; then
    log_action "Automatic updates service is active."
  else
    if ! prompt_user "Automatic updates service not active. Enable yum-cron/dnf-automatic?"; then
      log_action "User skipped remediation for automatic updates."
      return
    fi
    if command -v systemctl &>/dev/null; then
      if command -v yum-cron &>/dev/null; then
        systemctl enable --now yum-cron && log_action "Enabled and started yum-cron."
      elif command -v dnf-automatic &>/dev/null; then
        systemctl enable --now dnf-automatic && log_action "Enabled and started dnf-automatic."
      else
        log_action "Neither yum-cron nor dnf-automatic found. Manual remediation required."
      fi
    fi
  fi
}

# 1.3.1.1: Remediate SELinux installation check (manual if missing)
remediate_selinux_installed() {
  log_action "Remediation 1.3.1.1: Ensure SELinux is installed"
  if [ -d /etc/selinux ]; then
    log_action "SELinux appears to be installed."
  else
    log_action "SELinux not found. Manual remediation required."
  fi
}

# 1.3.1.2: Remediate SELinux not disabled in bootloader config
remediate_selinux_not_disabled_in_bootloader() {
  log_action "Remediation 1.3.1.2: Ensure SELinux is not disabled in bootloader configuration"
  local file="/etc/selinux/config"
  if grep -q "^SELINUX=" "$file"; then
    if grep "^SELINUX=disabled" "$file" >/dev/null; then
      if ! prompt_user "SELinux is disabled in $file. Change to enforcing?"; then
        log_action "User skipped remediation for SELinux mode."
        return
      fi
      backup_file "$file"
      sed -i.bak."${timestamp}" 's/^SELINUX=disabled/SELINUX=enforcing/' "$file" && log_action "Set SELINUX=enforcing in $file."
    else
      log_action "SELinux is not disabled in $file."
    fi
  else
    log_action "$file does not contain SELINUX setting. Manual remediation required."
  fi
}

# 1.3.1.3: Remediate SELinux policy configuration (SELINUXTYPE)
remediate_selinux_policy_configured() {
  log_action "Remediation 1.3.1.3: Ensure SELinux policy is configured"
  local file="/etc/selinux/config"
  if grep -q "^SELINUXTYPE=" "$file"; then
    log_action "SELINUXTYPE is set in $file."
  else
    if ! prompt_user "SELINUXTYPE not set in $file. Append SELINUXTYPE=targeted?"; then
      log_action "User skipped remediation for SELINUXTYPE."
      return
    fi
    backup_file "$file"
    echo "SELINUXTYPE=targeted" >> "$file" && log_action "Appended SELINUXTYPE=targeted to $file."
  fi
}

# 1.3.1.4 & 1.3.1.5: Remediate SELinux mode (ensure enforcing)
remediate_selinux_mode_enforcing() {
  log_action "Remediation 1.3.1.5: Ensure the SELinux mode is enforcing"
  local file="/etc/selinux/config"
  if grep -q "^SELINUX=enforcing" "$file"; then
    log_action "SELinux is already enforcing in $file."
  else
    if ! prompt_user "SELinux is not enforcing in $file. Change to enforcing?"; then
      log_action "User skipped remediation for SELinux enforcing mode."
      return
    fi
    backup_file "$file"
    sed -i.bak."${timestamp}" 's/^SELINUX=.*/SELINUX=enforcing/' "$file" && log_action "Set SELINUX=enforcing in $file."
  fi
}

# 1.3.1.6: Unconfined services (manual)
remediate_no_unconfined_services() {
  log_action "Remediation 1.3.1.6: Ensure no unconfined services exist"
  log_action "This requires manual verification. Please review running services for unconfined contexts."
}

# 1.3.1.7: Remediate removal of mcstrans
remediate_mcstrans_not_installed() {
  log_action "Remediation 1.3.1.7: Ensure mcstrans is not installed"
  if rpm -q mcstrans &>/dev/null || dpkg -s mcstrans &>/dev/null; then
    if ! prompt_user "mcstrans is installed. Remove it?"; then
      log_action "User skipped removal of mcstrans."
      return
    fi
    if command -v yum &>/dev/null; then
      yum remove -y mcstrans && log_action "Removed mcstrans."
    elif command -v apt-get &>/dev/null; then
      apt-get remove -y mcstrans && log_action "Removed mcstrans."
    else
      log_action "Unknown package manager. Manual removal required for mcstrans."
    fi
  else
    log_action "mcstrans is not installed."
  fi
}

# 1.3.1.8: Remediate removal of SETroubleshoot
remediate_setroubleshoot_not_installed() {
  log_action "Remediation 1.3.1.8: Ensure SETroubleshoot is not installed"
  if rpm -q setroubleshoot &>/dev/null || dpkg -s setroubleshoot &>/dev/null; then
    if ! prompt_user "SETroubleshoot is installed. Remove it?"; then
      log_action "User skipped removal of SETroubleshoot."
      return
    fi
    if command -v yum &>/dev/null; then
      yum remove -y setroubleshoot && log_action "Removed SETroubleshoot."
    elif command -v apt-get &>/dev/null; then
      apt-get remove -y setroubleshoot && log_action "Removed SETroubleshoot."
    else
      log_action "Unknown package manager. Manual removal required for SETroubleshoot."
    fi
  else
    log_action "SETroubleshoot is not installed."
  fi
}

# 1.4.1: Bootloader password (manual)
remediate_bootloader_password() {
  log_action "Remediation 1.4.1: Ensure bootloader password is set"
  log_action "This must be set manually in the GRUB configuration. Please verify."
}

# 1.4.2: Remediate bootloader config access (set grub.cfg perms to 600)
remediate_bootloader_config_access() {
  log_action "Remediation 1.4.2: Ensure access to bootloader config is configured"
  local file="/boot/grub2/grub.cfg"
  if [ -f "$file" ]; then
    local current_perms
    current_perms=$(stat -c "%a" "$file")
    if [ "$current_perms" -eq 600 ]; then
      log_action "Permissions on $file are already 600."
    else
      if ! prompt_user "Permissions on $file are $current_perms. Change to 600?"; then
        log_action "User skipped remediation for $file permissions."
        return
      fi
      backup_file "$file"
      chmod 600 "$file" && log_action "Set permissions on $file to 600."
    fi
  else
    log_action "$file not found. Manual remediation required."
  fi
}

# 1.5.1: Remediate ASLR (kernel.randomize_va_space=2)
remediate_aslr_enabled() {
  log_action "Remediation 1.5.1: Ensure ASLR is enabled (kernel.randomize_va_space=2)"
  local key="kernel.randomize_va_space"
  local desired="2"
  local current
  current=$(sysctl -n $key 2>/dev/null)
  if [ "$current" == "$desired" ]; then
    log_action "ASLR is already enabled ($key = $desired)."
  else
    if ! prompt_user "$key is $current. Set to $desired?"; then
      log_action "User skipped remediation for ASLR."
      return
    fi
    backup_file "/etc/sysctl.conf"
    if grep -q "^$key" /etc/sysctl.conf; then
      sed -i.bak."${timestamp}" "s/^$key.*/$key = $desired/" /etc/sysctl.conf
    else
      echo "$key = $desired" >> /etc/sysctl.conf
    fi
    sysctl -w $key=$desired && log_action "Set $key to $desired."
  fi
}

# 1.5.2: Remediate ptrace_scope (kernel.yama.ptrace_scope=1)
remediate_ptrace_scope() {
  log_action "Remediation 1.5.2: Ensure ptrace_scope is restricted (kernel.yama.ptrace_scope=1)"
  local key="kernel.yama.ptrace_scope"
  local desired="1"
  local current
  current=$(sysctl -n $key 2>/dev/null)
  if [ "$current" == "$desired" ]; then
    log_action "$key is already set to $desired."
  else
    if ! prompt_user "$key is $current. Set to $desired?"; then
      log_action "User skipped remediation for ptrace_scope."
      return
    fi
    backup_file "/etc/sysctl.conf"
    if grep -q "^$key" /etc/sysctl.conf; then
      sed -i.bak."${timestamp}" "s/^$key.*/$key = $desired/" /etc/sysctl.conf
    else
      echo "$key = $desired" >> /etc/sysctl.conf
    fi
    sysctl -w $key=$desired && log_action "Set $key to $desired."
  fi
}

# 1.6.1: Remediate crypto policy not set to legacy
remediate_crypto_policy_not_legacy() {
  log_action "Remediation 1.6.1: Ensure crypto policy is not set to legacy"
  if command -v update-crypto-policies &>/dev/null; then
    local current_policy
    current_policy=$(update-crypto-policies --show)
    if [[ "$current_policy" == "DEFAULT" || "$current_policy" == "FUTURE" ]]; then
      log_action "Crypto policy is acceptable (current: $current_policy)."
    else
      if ! prompt_user "Crypto policy is $current_policy. Change to DEFAULT?"; then
        log_action "User skipped remediation for crypto policy."
        return
      fi
      update-crypto-policies --set DEFAULT && log_action "Set crypto policy to DEFAULT."
    fi
  else
    log_action "update-crypto-policies command not found. Manual remediation required."
  fi
}

# 1.6.2: Remediate removal of CryptoPolicy directive from sshd_config
remediate_crypto_policy_not_in_sshd() {
  log_action "Remediation 1.6.2: Ensure crypto policy is not set in sshd configuration"
  local file="/etc/ssh/sshd_config"
  if grep -qi "CryptoPolicy" "$file"; then
    if ! prompt_user "CryptoPolicy directive found in $file. Remove it?"; then
      log_action "User skipped remediation for CryptoPolicy directive."
      return
    fi
    backup_file "$file"
    sed -i.bak."${timestamp}" '/CryptoPolicy/d' "$file" && log_action "Removed CryptoPolicy directive from $file."
  else
    log_action "No CryptoPolicy directive found in $file."
  fi
}

# 1.6.3: Crypto policy disables sha1 (manual)
remediate_crypto_policy_disables_sha1() {
  log_action "Remediation 1.6.3: Ensure crypto policy disables SHA1 hash/signature support"
  log_action "Manual remediation required. Please verify your system’s crypto policy."
}

# 1.6.4: Crypto policy disables MACs less than 128 bits (manual)
remediate_crypto_policy_disables_macs_less_128() {
  log_action "Remediation 1.6.4: Ensure crypto policy disables MACs less than 128 bits"
  log_action "Manual remediation required. Please verify your system’s crypto policy."
}

# 1.6.5: Remediate removal of CBC ciphers in sshd_config
remediate_crypto_policy_disables_cbc() {
  log_action "Remediation 1.6.5: Ensure crypto policy disables CBC for ssh"
  local file="/etc/ssh/sshd_config"
  if grep -qi "CBC" "$file"; then
    if ! prompt_user "CBC ciphers found in $file. Remove them?"; then
      log_action "User skipped remediation for CBC ciphers."
      return
    fi
    backup_file "$file"
    sed -i.bak."${timestamp}" '/CBC/d' "$file" && log_action "Removed CBC ciphers from $file."
  else
    log_action "No CBC ciphers found in $file."
  fi
}

# 1.6.6: Remediate removal of chacha20-poly1305 in sshd_config
remediate_crypto_policy_disables_chacha20() {
  log_action "Remediation 1.6.6: Ensure crypto policy disables chacha20-poly1305 for ssh"
  local file="/etc/ssh/sshd_config"
  if grep -qi "chacha20-poly1305" "$file"; then
    if ! prompt_user "chacha20-poly1305 found in $file. Remove it?"; then
      log_action "User skipped remediation for chacha20-poly1305."
      return
    fi
    backup_file "$file"
    sed -i.bak."${timestamp}" '/chacha20-poly1305/d' "$file" && log_action "Removed chacha20-poly1305 from $file."
  else
    log_action "No chacha20-poly1305 ciphers found in $file."
  fi
}

# 1.6.7: Crypto policy disables EtM (manual)
remediate_crypto_policy_disables_etm() {
  log_action "Remediation 1.6.7: Ensure crypto policy disables EtM for ssh"
  log_action "Manual remediation required. Please verify your system’s crypto policy for EtM support."
}

#############################################
# Main Execution: Remediate Section 1
#############################################

echo "Starting remediation for Section 1. All actions are logged to $LOGFILE."
log_action "=== Starting Remediation for Section 1 ==="

remediate_noexec_var_tmp
remediate_separate_partition_var_log
remediate_nodev_var_log
remediate_nosuid_var_log
remediate_noexec_var_log
remediate_separate_partition_var_log_audit
remediate_nodev_var_log_audit
remediate_nosuid_var_log_audit
remediate_noexec_var_log_audit
remediate_gpg_keys_configured
remediate_gpgcheck
remediate_repo_gpgcheck
remediate_package_repos_configured
remediate_updates_installed
remediate_selinux_installed
remediate_selinux_not_disabled_in_bootloader
remediate_selinux_policy_configured
remediate_selinux_mode_enforcing
remediate_no_unconfined_services
remediate_mcstrans_not_installed
remediate_setroubleshoot_not_installed
remediate_bootloader_password
remediate_bootloader_config_access
remediate_aslr_enabled
remediate_ptrace_scope
remediate_crypto_policy_not_legacy
remediate_crypto_policy_not_in_sshd
remediate_crypto_policy_disables_sha1
remediate_crypto_policy_disables_macs_less_128
remediate_crypto_policy_disables_cbc
remediate_crypto_policy_disables_chacha20
remediate_crypto_policy_disables_etm

log_action "=== Completed Remediation for Section 1 ==="
echo "Remediation for Section 1 complete. Please review $LOGFILE for details."
