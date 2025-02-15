#!/bin/bash
# remediate_section3.sh - Remediation script for Section 3 controls.
# This script remediates settings related to IPv6, kernel modules, and sysctl network settings.
# All actions are logged to "remediation_section3.log" in the current directory.
# It backs up configuration files before making changes and prompts the user interactively.
#
# Controls covered:
# 3.1.1 - Ensure IPv6 status is identified
# 3.1.3 - Ensure bluetooth services are not in use
# 3.2.1 - Ensure dccp kernel module is not available
# 3.2.2 - Ensure tipc kernel module is not available
# 3.2.3 - Ensure rds kernel module is not available
# 3.2.4 - Ensure sctp kernel module is not available
# 3.3.1 - Ensure ip forwarding is disabled
# 3.3.2 - Ensure packet redirect sending is disabled
# 3.3.3 - Ensure bogus icmp responses are ignored
# 3.3.4 - Ensure broadcast icmp requests are ignored
# 3.3.5 - Ensure icmp redirects are not accepted
# 3.3.6 - Ensure secure icmp redirects are not accepted
# 3.3.7 - Ensure reverse path filtering is enabled
# 3.3.8 - Ensure source routed packets are not accepted
# 3.3.9 - Ensure suspicious packets are logged
# 3.3.10 - Ensure tcp syn cookies is enabled
# 3.3.11 - Ensure ipv6 router advertisements are not accepted

LOGFILE="./remediation_section3.log"
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

# Remediate a sysctl setting: If the value isn’t as desired, prompt user, backup /etc/sysctl.conf, update it, and apply it immediately.
remediate_sysctl_setting() {
  local key="$1"
  local desired="$2"
  local control="$3"
  local description="$4"
  log_action "$control: $description"
  local current
  current=$(sysctl -n "$key" 2>/dev/null)
  if [ "$current" == "$desired" ]; then
    log_action "$key is already set to $desired."
    return
  fi
  if ! prompt_user "$key is currently $current. Set to $desired?"; then
    log_action "User skipped remediation for $key."
    return
  fi
  backup_file "/etc/sysctl.conf"
  if grep -q "^$key" /etc/sysctl.conf; then
    sed -i.bak."${timestamp}" "s/^$key.*/$key = $desired/" /etc/sysctl.conf
  else
    echo "$key = $desired" >> /etc/sysctl.conf
  fi
  sysctl -w "$key=$desired" && log_action "Set $key to $desired."
}

# Remediate blacklisting a kernel module: If module is loaded, prompt to add a blacklist entry and remove the module.
remediate_blacklist_module() {
  local module="$1"
  local control="$2"
  local description="$3"
  log_action "$control: $description"
  if lsmod | grep -q "^$module"; then
    if prompt_user "$module is loaded. Add to blacklist and remove it?"; then
      local blacklist_file="/etc/modprobe.d/blacklist.conf"
      backup_file "$blacklist_file"
      if ! grep -q "^blacklist $module" "$blacklist_file"; then
        echo "blacklist $module" >> "$blacklist_file"
        log_action "Added 'blacklist $module' to $blacklist_file."
      else
        log_action "$module is already blacklisted in $blacklist_file."
      fi
      rmmod "$module" && log_action "Removed $module kernel module." || log_action "Failed to remove $module. A reboot may be required."
    else
      log_action "User skipped remediation for $module."
    fi
  else
    log_action "$module is not loaded."
  fi
}

#############################################
# Section 3 Remediation Functions
#############################################

# 3.1.1: Ensure IPv6 status is identified
remediate_ipv6_status() {
  log_action "3.1.1: Ensure IPv6 status is identified"
  if lsmod | grep -q "^ipv6"; then
    log_action "IPv6 module is loaded."
  else
    log_action "IPv6 module is not loaded."
  fi
  # This control is informational; you may wish to manually verify further.
  prompt_user "Press Y if you have verified the IPv6 status" && log_action "User confirmed IPv6 status identification." || log_action "IPv6 status identification review complete."
}

# 3.1.3: Ensure bluetooth services are not in use
remediate_bluetooth() {
  log_action "3.1.3: Ensure bluetooth services are not in use"
  if systemctl is-active --quiet bluetooth; then
    if prompt_user "Bluetooth service is active. Stop and disable it?"; then
      systemctl stop bluetooth
      systemctl disable bluetooth
      log_action "Stopped and disabled bluetooth service."
    else
      log_action "User skipped remediation for bluetooth service."
    fi
  else
    log_action "Bluetooth service is not active."
  fi
}

# 3.2.1: Ensure dccp kernel module is not available
remediate_dccp() {
  remediate_blacklist_module "dccp" "3.2.1" "Ensure dccp kernel module is not available"
}

# 3.2.2: Ensure tipc kernel module is not available
remediate_tipc() {
  remediate_blacklist_module "tipc" "3.2.2" "Ensure tipc kernel module is not available"
}

# 3.2.3: Ensure rds kernel module is not available
remediate_rds() {
  remediate_blacklist_module "rds" "3.2.3" "Ensure rds kernel module is not available"
}

# 3.2.4: Ensure sctp kernel module is not available
remediate_sctp() {
  remediate_blacklist_module "sctp" "3.2.4" "Ensure sctp kernel module is not available"
}

# 3.3.1: Ensure ip forwarding is disabled
remediate_ip_forwarding() {
  remediate_sysctl_setting "net.ipv4.ip_forward" "0" "3.3.1" "Ensure ip forwarding is disabled"
}

# 3.3.2: Ensure packet redirect sending is disabled
remediate_send_redirects() {
  remediate_sysctl_setting "net.ipv4.conf.all.send_redirects" "0" "3.3.2" "Ensure packet redirect sending is disabled"
}

# 3.3.3: Ensure bogus icmp responses are ignored
remediate_ignore_bogus_icmp() {
  remediate_sysctl_setting "net.ipv4.icmp_ignore_bogus_error_responses" "1" "3.3.3" "Ensure bogus icmp responses are ignored"
}

# 3.3.4: Ensure broadcast icmp requests are ignored
remediate_ignore_broadcasts() {
  remediate_sysctl_setting "net.ipv4.icmp_echo_ignore_broadcasts" "1" "3.3.4" "Ensure broadcast icmp requests are ignored"
}

# 3.3.5: Ensure icmp redirects are not accepted
remediate_accept_redirects() {
  remediate_sysctl_setting "net.ipv4.conf.all.accept_redirects" "0" "3.3.5" "Ensure icmp redirects are not accepted"
}

# 3.3.6: Ensure secure icmp redirects are not accepted
remediate_secure_redirects() {
  remediate_sysctl_setting "net.ipv4.conf.all.secure_redirects" "0" "3.3.6" "Ensure secure icmp redirects are not accepted"
}

# 3.3.7: Ensure reverse path filtering is enabled
remediate_rp_filter() {
  remediate_sysctl_setting "net.ipv4.conf.all.rp_filter" "1" "3.3.7" "Ensure reverse path filtering is enabled"
}

# 3.3.8: Ensure source routed packets are not accepted
remediate_accept_source_route() {
  remediate_sysctl_setting "net.ipv4.conf.all.accept_source_route" "0" "3.3.8" "Ensure source routed packets are not accepted"
}

# 3.3.9: Ensure suspicious packets are logged
remediate_log_martians() {
  remediate_sysctl_setting "net.ipv4.conf.all.log_martians" "1" "3.3.9" "Ensure suspicious packets are logged"
}

# 3.3.10: Ensure tcp syn cookies is enabled
remediate_tcp_syncookies() {
  remediate_sysctl_setting "net.ipv4.tcp_syncookies" "1" "3.3.10" "Ensure tcp syn cookies is enabled"
}

# 3.3.11: Ensure ipv6 router advertisements are not accepted
remediate_ipv6_accept_ra() {
  remediate_sysctl_setting "net.ipv6.conf.all.accept_ra" "0" "3.3.11" "Ensure ipv6 router advertisements are not accepted"
}

#############################################
# Main Execution: Remediate Section 3
#############################################

echo "Starting remediation for Section 3. All actions are logged to $LOGFILE."
log_action "=== Starting Remediation for Section 3 ==="

remediate_ipv6_status
remediate_bluetooth

remediate_dccp
remediate_tipc
remediate_rds
remediate_sctp

remediate_ip_forwarding
remediate_send_redirects
remediate_ignore_bogus_icmp
remediate_ignore_broadcasts
remediate_accept_redirects
remediate_secure_redirects
remediate_rp_filter
remediate_accept_source_route
remediate_log_martians
remediate_tcp_syncookies
remediate_ipv6_accept_ra

log_action "=== Completed Remediation for Section 3 ==="
echo "Remediation for Section 3 complete. Please review $LOGFILE for details."
