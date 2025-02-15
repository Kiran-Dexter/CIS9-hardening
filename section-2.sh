#!/bin/bash
# remediate_section2.sh - Remediation script for Section 2 controls.
# This script backs up files, applies changes interactively, and logs
# all actions to a log file ("remediation_section2.log") in the current directory.
#
# Controls covered in this section include:
#   File access configuration for /etc/motd, /etc/issue, /etc/issue.net
#   Removal or proper configuration of GNOME Display Manager (GDM) and XDMCP
#   Stopping/disabling various unwanted services (autofs, avahi, dhcp, etc.)
#   Ensuring unwanted client packages are not installed (ftp, ldap, nis, telnet, tftp)
#   Time synchronization configuration
#   Permissions on cron and at configurations
#
# Customize any function as needed for your environment.

LOGFILE="./remediation_section2.log"
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
  # Prompt with message; return 0 if yes, 1 if no.
  read -p "$1 [Y/n]: " choice
  case "$choice" in
    [Nn]*) return 1 ;;
    *) return 0 ;;
  esac
}

check_file_permission() {
  local file="$1"
  local expected="$2"
  if [ ! -e "$file" ]; then
    echo "fail: $file does not exist"
    return 1
  fi
  local perm
  perm=$(stat -c %a "$file")
  if [ "$perm" -eq "$expected" ]; then
    echo "pass"
    return 0
  else
    echo "fail: $file has permissions $perm (expected $expected)"
    return 1
  fi
}

remediate_file_permission() {
  local file="$1"
  local expected="$2"
  log_action "Remediating file permissions for $file (expected: $expected)"
  local result
  result=$(check_file_permission "$file" "$expected")
  if [[ "$result" == pass ]]; then
    log_action "$file already has correct permissions."
    return 0
  fi
  if ! prompt_user "Set permissions of $file to $expected?"; then
    log_action "User skipped changing permissions on $file."
    return 1
  fi
  backup_file "$file"
  chmod "$expected" "$file" && log_action "Set permissions on $file to $expected."
}

#############################################
# Section 2 Remediation Functions
#############################################

# --- 1.7.x: File Access Configuration ---
remediate_motd_access() {
  log_action "1.7.4: Ensure access to /etc/motd is configured"
  remediate_file_permission "/etc/motd" 644
}

remediate_issue_access() {
  log_action "1.7.5: Ensure access to /etc/issue is configured"
  remediate_file_permission "/etc/issue" 644
}

remediate_issue_net_access() {
  log_action "1.7.6: Ensure access to /etc/issue.net is configured"
  remediate_file_permission "/etc/issue.net" 644
}

# --- 1.8.x: Display Manager & XDMCP ---
remediate_remove_gdm() {
  log_action "1.8.1: Ensure GNOME Display Manager is removed"
  if command -v rpm &>/dev/null; then
    if rpm -q gdm &>/dev/null; then
      if prompt_user "GDM is installed. Remove it?"; then
        yum remove -y gdm && log_action "Removed GDM package."
      else
        log_action "User skipped removal of GDM."
      fi
    else
      log_action "GDM is not installed."
    fi
  elif command -v dpkg &>/dev/null; then
    if dpkg -s gdm3 &>/dev/null; then
      if prompt_user "GDM3 is installed. Remove it?"; then
        apt-get remove -y gdm3 && log_action "Removed GDM3 package."
      else
        log_action "User skipped removal of GDM3."
      fi
    else
      log_action "GDM3 is not installed."
    fi
  else
    log_action "Package manager not recognized. Manual remediation required for GDM."
  fi
}

# For the following GDM settings, mark as manual (they usually require dconf edits)
remediate_gdm_manual() {
  local control="$1"
  local description="$2"
  log_action "$control: $description requires manual remediation. Please verify your GDM settings."
  prompt_user "Press Y if you have manually remediated $description" && log_action "User confirmed manual remediation for $control."
}

remediate_gdm_screen_lock_idle() {
  remediate_gdm_manual "1.8.4" "GDM screen locks when the user is idle"
}
remediate_gdm_lock_override() {
  remediate_gdm_manual "1.8.5" "GDM screen locks cannot be overridden"
}
remediate_gdm_auto_mount_disabled() {
  remediate_gdm_manual "1.8.6" "GDM automatic mounting of removable media is disabled"
}
remediate_gdm_auto_mount_not_overridden() {
  remediate_gdm_manual "1.8.7" "GDM disabling automatic mounting is not overridden"
}
remediate_gdm_autorun_enabled() {
  remediate_gdm_manual "1.8.8" "GDM autorun-never is enabled"
}
remediate_gdm_autorun_not_overridden() {
  remediate_gdm_manual "1.8.9" "GDM autorun-never is not overridden"
}

remediate_xdmcp_disabled() {
  log_action "1.8.10: Ensure XDMCP is not enabled"
  local file="/etc/gdm/custom.conf"
  if [ ! -f "$file" ]; then
    log_action "$file not found; assuming XDMCP is not enabled."
    return
  fi
  if grep -A2 "^\[xdmcp\]" "$file" | grep -qi "Enable=true"; then
    if prompt_user "XDMCP appears enabled in $file. Change 'Enable=true' to 'Enable=false'?"; then
      backup_file "$file"
      sed -i.bak."${timestamp}" '/^\[xdmcp\]/,/^\[/ s/^\(Enable=\)true/\1false/i' "$file" && log_action "Updated XDMCP setting in $file."
    else
      log_action "User skipped remediation for XDMCP."
    fi
  else
    log_action "XDMCP already appears disabled in $file."
  fi
}

# --- 2.1.x: Unwanted Services ---
remediate_service_not_in_use() {
  local service="$1"
  local control="$2"
  local description="$3"
  log_action "$control: $description"
  if systemctl is-active --quiet "$service"; then
    if prompt_user "$service is active. Stop and disable it?"; then
      systemctl stop "$service"
      systemctl disable "$service"
      log_action "Stopped and disabled $service."
    else
      log_action "User skipped remediation for $service."
    fi
  else
    log_action "$service is not active. No action needed."
  fi
}

# 2.1.8 and 2.1.21-2.1.22 require manual remediation.
remediate_service_manual() {
  local control="$1"
  local description="$2"
  log_action "$control: $description requires manual remediation."
  prompt_user "Press Y if you have manually remediated $description" && log_action "User confirmed manual remediation for $control."
}

# Remediate 2.1.x services:
remediate_autofs()          { remediate_service_not_in_use "autofs" "2.1.1" "Ensure autofs services are not in use"; }
remediate_avahi()           { remediate_service_not_in_use "avahi-daemon" "2.1.2" "Ensure avahi daemon services are not in use"; }
remediate_dhcp()            { remediate_service_not_in_use "dhcpd" "2.1.3" "Ensure DHCP server services are not in use"; }
remediate_dns_server()      { remediate_service_not_in_use "named" "2.1.4" "Ensure DNS server services are not in use"; }
remediate_dnsmasq()         { remediate_service_not_in_use "dnsmasq" "2.1.5" "Ensure dnsmasq services are not in use"; }
remediate_samba()           { remediate_service_not_in_use "smb" "2.1.6" "Ensure samba file server services are not in use"; }
remediate_ftp_server()      { remediate_service_not_in_use "vsftpd" "2.1.7" "Ensure FTP server services are not in use"; }
remediate_message_access()  { remediate_service_manual "2.1.8" "Ensure message access server services are not in use"; }
remediate_nfs()             { remediate_service_not_in_use "nfs-server" "2.1.9" "Ensure network file system services are not in use"; }
remediate_nis_server()      { remediate_service_not_in_use "ypserv" "2.1.10" "Ensure NIS server services are not in use"; }
remediate_print_server()    { remediate_service_not_in_use "cups" "2.1.11" "Ensure print server services are not in use"; }
remediate_rpcbind()         { remediate_service_not_in_use "rpcbind" "2.1.12" "Ensure rpcbind services are not in use"; }
remediate_rsync()           { remediate_service_not_in_use "rsync" "2.1.13" "Ensure rsync services are not in use"; }
remediate_snmp()            { remediate_service_not_in_use "snmpd" "2.1.14" "Ensure SNMP services are not in use"; }
remediate_telnet_server()   { remediate_service_not_in_use "telnet" "2.1.15" "Ensure telnet server services are not in use"; }
remediate_tftp_server()     { remediate_service_not_in_use "tftp" "2.1.16" "Ensure TFTP server services are not in use"; }
remediate_web_proxy()       { remediate_service_not_in_use "squid" "2.1.17" "Ensure web proxy server services are not in use"; }
remediate_web_server() {
  log_action "2.1.18: Ensure web server services are not in use"
  local active1 active2
  systemctl is-active --quiet httpd && active1=1 || active1=0
  systemctl is-active --quiet nginx && active2=1 || active2=0
  if [ $active1 -eq 1 ] || [ $active2 -eq 1 ]; then
    if prompt_user "One or both web servers (httpd/nginx) are active. Stop and disable them?"; then
      systemctl stop httpd 2>/dev/null; systemctl disable httpd 2>/dev/null
      systemctl stop nginx 2>/dev/null; systemctl disable nginx 2>/dev/null
      log_action "Stopped and disabled active web server(s)."
    else
      log_action "User skipped remediation for web server services."
    fi
  else
    log_action "Web server services are not active."
  fi
}
remediate_xinetd()         { remediate_service_not_in_use "xinetd" "2.1.19" "Ensure xinetd services are not in use"; }
remediate_xwindow() {
  log_action "2.1.20: Ensure X window server services are not in use"
  if pgrep -x "Xorg" &>/dev/null; then
    if prompt_user "Xorg is running. Kill the process?"; then
      pkill Xorg && log_action "Killed Xorg processes."
    else
      log_action "User skipped remediation for X window server."
    fi
  else
    log_action "No X window server processes found."
  fi
}
remediate_mail_transfer()   { remediate_service_manual "2.1.21" "Ensure mail transfer agents are configured for local-only mode"; }
remediate_approved_services() { remediate_service_manual "2.1.22" "Ensure only approved services are listening on a network interface"; }

# --- 2.2.x: Unwanted Clients ---
remediate_package_not_installed() {
  local pkg="$1"
  if command -v rpm &>/dev/null; then
    rpm -q "$pkg" &>/dev/null && return 1 || return 0
  elif command -v dpkg &>/dev/null; then
    dpkg -s "$pkg" &>/dev/null && return 1 || return 0
  else
    return 2
  fi
}

remediate_remove_package() {
  local pkg="$1"
  if remediate_package_not_installed "$pkg"; then
    log_action "$pkg is not installed."
  else
    if prompt_user "$pkg is installed. Remove it?"; then
      if command -v yum &>/dev/null; then
        yum remove -y "$pkg" && log_action "Removed $pkg."
      elif command -v apt-get &>/dev/null; then
        apt-get remove -y "$pkg" && log_action "Removed $pkg."
      else
        log_action "Package manager not recognized. Manual removal required for $pkg."
      fi
    else
      log_action "User skipped removal of $pkg."
    fi
  fi
}

remediate_ftp_client()   { remediate_remove_package "ftp"; }
remediate_ldap_client()  { remediate_remove_package "ldap-utils"; }
remediate_nis_client()   { remediate_remove_package "ypbind"; }
remediate_telnet_client(){ remediate_remove_package "telnet"; }
remediate_tftp_client()  { remediate_remove_package "tftp"; }

# --- 2.3.x: Time Synchronization ---
remediate_time_sync() {
  log_action "2.3.1: Ensure time synchronization is in use"
  if systemctl is-active --quiet ntpd || systemctl is-active --quiet chronyd; then
    log_action "Time synchronization service is active."
  else
    if prompt_user "No time synchronization service is active. Enable chronyd?"; then
      if command -v systemctl &>/dev/null && [ -f /etc/chrony.conf ]; then
        systemctl enable --now chronyd && log_action "Enabled and started chronyd."
      else
        log_action "chronyd not available. Manual remediation required."
      fi
    else
      log_action "User skipped remediation for time synchronization."
    fi
  fi
}

remediate_chrony_configured() {
  log_action "2.3.2: Ensure chrony is configured"
  if [ -f /etc/chrony.conf ]; then
    log_action "/etc/chrony.conf exists."
  else
    log_action "/etc/chrony.conf not found. Manual remediation required."
  fi
}

# --- 2.4.x: Cron & at Permissions ---
remediate_crontab_permission() {
  log_action "2.4.1.2: Ensure permissions on /etc/crontab are configured"
  remediate_file_permission "/etc/crontab" 600
}

remediate_cron_hourly() {
  log_action "2.4.1.3: Ensure permissions on /etc/cron.hourly are configured"
  remediate_file_permission "/etc/cron.hourly" 700
}

remediate_cron_daily() {
  log_action "2.4.1.4: Ensure permissions on /etc/cron.daily are configured"
  remediate_file_permission "/etc/cron.daily" 700
}

remediate_cron_weekly() {
  log_action "2.4.1.5: Ensure permissions on /etc/cron.weekly are configured"
  remediate_file_permission "/etc/cron.weekly" 700
}

remediate_cron_monthly() {
  log_action "2.4.1.6: Ensure permissions on /etc/cron.monthly are configured"
  remediate_file_permission "/etc/cron.monthly" 700
}

remediate_cron_d() {
  log_action "2.4.1.7: Ensure permissions on /etc/cron.d are configured"
  remediate_file_permission "/etc/cron.d" 700
}

remediate_crontab_authorized() {
  log_action "2.4.1.8: Ensure crontab is restricted to authorized users"
  log_action "Manual remediation required for crontab restrictions. Please review /etc/cron.allow and /etc/cron.deny."
  prompt_user "Press Y if you have manually remediated crontab restrictions" && log_action "User confirmed manual remediation for crontab restrictions."
}

remediate_at_authorized() {
  log_action "2.4.2.1: Ensure at is restricted to authorized users"
  log_action "Manual remediation required for at restrictions. Please review /etc/at.allow and /etc/at.deny."
  prompt_user "Press Y if you have manually remediated at restrictions" && log_action "User confirmed manual remediation for at restrictions."
}

#############################################
# Main Execution: Remediate Section 2
#############################################

echo "Starting remediation for Section 2. All actions are logged to $LOGFILE."
log_action "=== Starting Remediation for Section 2 ==="

# File access configuration
remediate_motd_access
remediate_issue_access
remediate_issue_net_access

# Display Manager & XDMCP
remediate_remove_gdm
remediate_gdm_screen_lock_idle
remediate_gdm_lock_override
remediate_gdm_auto_mount_disabled
remediate_gdm_auto_mount_not_overridden
remediate_gdm_autorun_enabled
remediate_gdm_autorun_not_overridden
remediate_xdmcp_disabled

# Unwanted services (2.1.x)
remediate_autofs
remediate_avahi
remediate_dhcp
remediate_dns_server
remediate_dnsmasq
remediate_samba
remediate_ftp_server
remediate_message_access
remediate_nfs
remediate_nis_server
remediate_print_server
remediate_rpcbind
remediate_rsync
remediate_snmp
remediate_telnet_server
remediate_tftp_server
remediate_web_proxy
remediate_web_server
remediate_xinetd
remediate_xwindow
remediate_mail_transfer
remediate_approved_services

# Unwanted clients (2.2.x)
remediate_ftp_client
remediate_ldap_client
remediate_nis_client
remediate_telnet_client
remediate_tftp_client

# Time synchronization (2.3.x)
remediate_time_sync
remediate_chrony_configured

# Cron & at configuration (2.4.x)
remediate_crontab_permission
remediate_cron_hourly
remediate_cron_daily
remediate_cron_weekly
remediate_cron_monthly
remediate_cron_d
remediate_crontab_authorized
remediate_at_authorized

log_action "=== Completed Remediation for Section 2 ==="
echo "Remediation for Section 2 complete. Please review $LOGFILE for details."
