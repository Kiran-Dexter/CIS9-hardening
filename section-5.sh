#!/bin/bash
# remediate_section5.sh - Remediation script for Section 5 controls:
# Journald, rsyslog, and audit configurations.
#
# All actions are logged to remediation_section5.log in the current directory.
# The script makes timestamped backups of files before modifying them,
# and it prompts interactively to confirm changes.
#
# Controls covered include:
#  Journald configuration (6.2.1.x, 6.2.2.x),
#  Rsyslog configuration (6.2.3.x, 6.2.4.1),
#  Auditd and audit rules (6.3.x).
#

LOGFILE="./remediation_section5.log"
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

remediate_config_directive() {
  # Updates a directive in a configuration file.
  # Args: file, directive, desired value, control number, description.
  local file="$1"
  local directive="$2"
  local desired="$3"
  local control="$4"
  local description="$5"
  log_action "$control: $description"
  backup_file "$file"
  if grep -qi "^$directive" "$file"; then
    local current
    current=$(grep -i "^$directive" "$file" | head -n 1)
    if echo "$current" | grep -qi "$desired"; then
      log_action "$directive is already set to $desired in $file."
    else
      if prompt_user "$directive is currently '$current'. Update to '$directive=$desired'?"; then
        sed -i.bak."${timestamp}" "s/^$directive.*/$directive=$desired/I" "$file"
        log_action "Updated $directive to $desired in $file."
      else
        log_action "User skipped remediation for $directive."
      fi
    fi
  else
    if prompt_user "$directive not found in $file. Append '$directive=$desired'?"; then
      echo "$directive=$desired" >> "$file"
      log_action "Appended '$directive=$desired' to $file."
    else
      log_action "User skipped appending $directive in $file."
    fi
  fi
}

#############################################
# Group A: Journald Configuration (6.2.1.x & 6.2.2.x)
#############################################

# 6.2.1.1: Ensure journald service is enabled and active
remediate_journald_enabled() {
  log_action "6.2.1.1: Ensure systemd-journald service is enabled and active"
  if systemctl is-active --quiet systemd-journald; then
    log_action "systemd-journald is active."
  else
    if prompt_user "systemd-journald is not active. Enable and start it?"; then
      systemctl enable --now systemd-journald && log_action "Enabled and started systemd-journald."
    else
      log_action "User skipped remediation for systemd-journald service."
    fi
  fi
}

# 6.2.1.2: Ensure journald log file access is configured
remediate_journald_log_access() {
  log_action "6.2.1.2: Ensure journald log file access is configured"
  # For example, verify permissions on /var/log/journal if it exists.
  if [ -d /var/log/journal ]; then
    local perm
    perm=$(stat -c %a /var/log/journal)
    if [ "$perm" -eq 750 ]; then
      log_action "/var/log/journal permissions are correctly set (750)."
    else
      if prompt_user "Permissions on /var/log/journal are $perm. Set to 750?"; then
        backup_file "/var/log/journal"
        chmod 750 /var/log/journal && log_action "Set /var/log/journal permissions to 750."
      else
        log_action "User skipped remediation for journald log file access."
      fi
    fi
  else
    log_action "/var/log/journal not found; please ensure journald persistent logging is configured if desired."
  fi
}

# 6.2.1.3: Ensure journald log file rotation is configured
remediate_journald_rotation() {
  log_action "6.2.1.3: Ensure journald log file rotation is configured"
  # Check if journald.conf has rotation settings like SystemMaxFileSize.
  local file="/etc/systemd/journald.conf"
  if grep -qi "^SystemMaxFileSize=" "$file"; then
    log_action "journald log rotation (SystemMaxFileSize) is configured."
  else
    if prompt_user "SystemMaxFileSize is not set in $file. Append 'SystemMaxFileSize=50M'?"; then
      backup_file "$file"
      echo "SystemMaxFileSize=50M" >> "$file" && log_action "Appended 'SystemMaxFileSize=50M' to $file."
    else
      log_action "User skipped remediation for journald log rotation."
    fi
  fi
}

# 6.2.2.1.1: Ensure systemd-journal-remote is installed
remediate_journal_remote_installed() {
  log_action "6.2.2.1.1: Ensure systemd-journal-remote is installed"
  if command -v systemd-journal-remote &>/dev/null; then
    log_action "systemd-journal-remote is installed."
  else
    if prompt_user "systemd-journal-remote is not installed. Install it?"; then
      if command -v yum &>/dev/null; then
        yum install -y systemd-journal-remote && log_action "Installed systemd-journal-remote via yum."
      elif command -v apt-get &>/dev/null; then
        apt-get update && apt-get install -y systemd-journal-remote && log_action "Installed systemd-journal-remote via apt-get."
      else
        log_action "Package manager not recognized. Please install systemd-journal-remote manually."
      fi
    else
      log_action "User skipped installation of systemd-journal-remote."
    fi
  fi
}

# 6.2.2.1.2: Ensure systemd-journal-upload authentication is configured (Manual)
remediate_journal_upload_auth() {
  log_action "6.2.2.1.2: Ensure systemd-journal-upload authentication is configured"
  log_action "Manual remediation required. Please verify that authentication is properly configured for journal-upload."
  prompt_user "Press Y if you have manually remediated systemd-journal-upload authentication" && log_action "User confirmed manual remediation for 6.2.2.1.2."
}

# 6.2.2.1.3: Ensure systemd-journal-upload is enabled and active
remediate_journal_upload_enabled() {
  log_action "6.2.2.1.3: Ensure systemd-journal-upload is enabled and active"
  if systemctl is-active --quiet systemd-journal-upload; then
    log_action "systemd-journal-upload is active."
  else
    if prompt_user "systemd-journal-upload is not active. Enable and start it?"; then
      systemctl enable --now systemd-journal-upload && log_action "Enabled and started systemd-journal-upload."
    else
      log_action "User skipped remediation for systemd-journal-upload."
    fi
  fi
}

# 6.2.2.1.4: Ensure systemd-journal-remote service is not in use
remediate_journal_remote_not_used() {
  log_action "6.2.2.1.4: Ensure systemd-journal-remote service is not in use"
  if systemctl is-active --quiet systemd-journal-remote; then
    if prompt_user "systemd-journal-remote is active. Stop and disable it?"; then
      systemctl stop systemd-journal-remote
      systemctl disable systemd-journal-remote
      log_action "Stopped and disabled systemd-journal-remote."
    else
      log_action "User skipped remediation for systemd-journal-remote."
    fi
  else
    log_action "systemd-journal-remote is not active."
  fi
}

# 6.2.2.2: Ensure journald ForwardToSyslog is disabled
remediate_journald_forwardtosyslog() {
  remediate_config_directive "/etc/systemd/journald.conf" "ForwardToSyslog" "no" "6.2.2.2" "Ensure journald ForwardToSyslog is disabled"
}

# 6.2.2.3: Ensure journald Compress is configured
remediate_journald_compress() {
  remediate_config_directive "/etc/systemd/journald.conf" "Compress" "yes" "6.2.2.3" "Ensure journald Compress is configured"
}

# 6.2.2.4: Ensure journald Storage is configured
remediate_journald_storage() {
  remediate_config_directive "/etc/systemd/journald.conf" "Storage" "auto" "6.2.2.4" "Ensure journald Storage is configured (recommended: auto)"
}

#############################################
# Group B: Rsyslog Configuration (6.2.3.x)
#############################################

# 6.2.3.1: Ensure rsyslog is installed
remediate_rsyslog_installed() {
  log_action "6.2.3.1: Ensure rsyslog is installed"
  if command -v rsyslogd &>/dev/null; then
    log_action "rsyslog is installed."
  else
    if prompt_user "rsyslog is not installed. Install it?"; then
      if command -v yum &>/dev/null; then
        yum install -y rsyslog && log_action "Installed rsyslog via yum."
      elif command -v apt-get &>/dev/null; then
        apt-get update && apt-get install -y rsyslog && log_action "Installed rsyslog via apt-get."
      else
        log_action "Package manager not recognized. Install rsyslog manually."
      fi
    else
      log_action "User skipped installation of rsyslog."
    fi
  fi
}

# 6.2.3.2: Ensure rsyslog service is enabled and active
remediate_rsyslog_enabled() {
  log_action "6.2.3.2: Ensure rsyslog service is enabled and active"
  if systemctl is-active --quiet rsyslog; then
    log_action "rsyslog service is active."
  else
    if prompt_user "rsyslog service is not active. Enable and start it?"; then
      systemctl enable --now rsyslog && log_action "Enabled and started rsyslog."
    else
      log_action "User skipped remediation for rsyslog service."
    fi
  fi
}

# 6.2.3.3: Ensure journald is configured to send logs to rsyslog
remediate_journald_to_rsyslog() {
  remediate_config_directive "/etc/systemd/journald.conf" "ForwardToSyslog" "yes" "6.2.3.3" "Ensure journald is configured to send logs to rsyslog"
}

# 6.2.3.4: Ensure rsyslog log file creation mode is configured
remediate_rsyslog_file_mode() {
  log_action "6.2.3.4: Ensure rsyslog log file creation mode is configured"
  local file="/etc/rsyslog.conf"
  # For example, we might expect log files to be created with 0640 permissions.
  if grep -qi "FileCreateMode" "$file"; then
    log_action "FileCreateMode is set in $file."
  else
    if prompt_user "FileCreateMode not set in $file. Append 'module(load=\"imuxsock\" FileCreateMode=\"0640\")'?"; then
      backup_file "$file"
      echo 'module(load="imuxsock" FileCreateMode="0640")' >> "$file"
      log_action "Appended FileCreateMode configuration to $file."
    else
      log_action "User skipped remediation for rsyslog file creation mode."
    fi
  fi
}

# 6.2.3.5: Ensure rsyslog logging is configured (Manual)
remediate_rsyslog_logging() {
  log_action "6.2.3.5: Ensure rsyslog logging is configured"
  log_action "Manual remediation required. Please review your rsyslog.conf and related files."
  prompt_user "Press Y if you have manually remediated rsyslog logging configuration" && log_action "User confirmed manual remediation for 6.2.3.5."
}

# 6.2.3.6: Ensure rsyslog is configured to send logs to a remote log host (Manual)
remediate_rsyslog_remote() {
  log_action "6.2.3.6: Ensure rsyslog is configured to send logs to a remote log host"
  log_action "Manual remediation required. Please verify remote log host configuration in rsyslog."
  prompt_user "Press Y if you have manually remediated remote log host configuration" && log_action "User confirmed manual remediation for 6.2.3.6."
}

# 6.2.3.7: Ensure rsyslog is not configured to receive logs from a remote client
remediate_rsyslog_no_receive() {
  log_action "6.2.3.7: Ensure rsyslog is not configured to receive logs from a remote client"
  # Check for $ModLoad imtcp or similar.
  if grep -qi "imtcp" /etc/rsyslog.conf; then
    if prompt_user "rsyslog appears configured to receive remote logs. Remove imtcp module?"; then
      backup_file "/etc/rsyslog.conf"
      sed -i.bak."${timestamp}" '/imtcp/d' /etc/rsyslog.conf
      log_action "Removed imtcp module from /etc/rsyslog.conf."
    else
      log_action "User skipped remediation for rsyslog receiving remote logs."
    fi
  else
    log_action "rsyslog is not configured to receive remote logs."
  fi
}

# 6.2.3.8: Ensure rsyslog logrotate is configured (Manual)
remediate_rsyslog_logrotate() {
  log_action "6.2.3.8: Ensure rsyslog logrotate is configured"
  log_action "Manual remediation required. Please verify logrotate configuration in /etc/logrotate.d/rsyslog."
  prompt_user "Press Y if you have manually remediated rsyslog logrotate configuration" && log_action "User confirmed manual remediation for 6.2.3.8."
}

#############################################
# Group C: Logfile Access (6.2.4.1)
#############################################

remediate_logfile_access() {
  log_action "6.2.4.1: Ensure access to all logfiles has been configured"
  log_action "Manual remediation required. Please verify permissions and access controls for all logfiles."
  prompt_user "Press Y if you have manually verified logfile access configuration" && log_action "User confirmed manual remediation for 6.2.4.1."
}

#############################################
# Group D: Audit Configuration (6.3.x)
#############################################

# 6.3.1.1: Ensure auditd packages are installed
remediate_auditd_installed() {
  log_action "6.3.1.1: Ensure auditd packages are installed"
  if command -v auditctl &>/dev/null; then
    log_action "auditctl is available, indicating auditd is installed."
  else
    if prompt_user "auditd is not installed. Install auditd?"; then
      if command -v yum &>/dev/null; then
        yum install -y audit && log_action "Installed auditd via yum."
      elif command -v apt-get &>/dev/null; then
        apt-get update && apt-get install -y auditd && log_action "Installed auditd via apt-get."
      else
        log_action "Package manager not recognized. Install auditd manually."
      fi
    else
      log_action "User skipped installation of auditd."
    fi
  fi
}

# 6.3.1.2: Ensure auditing for processes that start prior to auditd is enabled (Manual)
remediate_audit_pre_auditd() {
  log_action "6.3.1.2: Ensure auditing for processes that start prior to auditd is enabled"
  log_action "Manual remediation required. Please verify that kernel auditing parameters (e.g., audit=1) are set."
  prompt_user "Press Y if you have manually remediated pre-auditd auditing" && log_action "User confirmed manual remediation for 6.3.1.2."
}

# 6.3.1.3: Ensure audit_backlog_limit is sufficient
remediate_audit_backlog_limit() {
  log_action "6.3.1.3: Ensure audit_backlog_limit is sufficient"
  local file="/etc/audit/auditd.conf"
  if grep -qi "^backlog_limit" "$file"; then
    log_action "backlog_limit is configured in $file."
  else
    if prompt_user "backlog_limit not set in $file. Append 'backlog_limit = 8192'?"; then
      backup_file "$file"
      echo "backlog_limit = 8192" >> "$file" && log_action "Appended backlog_limit to $file."
    else
      log_action "User skipped remediation for audit_backlog_limit."
    fi
  fi
}

# 6.3.1.4: Ensure auditd service is enabled and active
remediate_auditd_enabled() {
  log_action "6.3.1.4: Ensure auditd service is enabled and active"
  if systemctl is-active --quiet auditd; then
    log_action "auditd is active."
  else
    if prompt_user "auditd is not active. Enable and start auditd?"; then
      systemctl enable --now auditd && log_action "Enabled and started auditd."
    else
      log_action "User skipped remediation for auditd service."
    fi
  fi
}

# 6.3.2.1: Ensure audit log storage size is configured
remediate_audit_log_size() {
  log_action "6.3.2.1: Ensure audit log storage size is configured"
  local file="/etc/audit/auditd.conf"
  if grep -qi "^max_log_file" "$file"; then
    log_action "max_log_file is set in $file."
  else
    if prompt_user "max_log_file not set in $file. Append 'max_log_file = 8' (MB)?"; then
      backup_file "$file"
      echo "max_log_file = 8" >> "$file" && log_action "Appended max_log_file to $file."
    else
      log_action "User skipped remediation for audit log storage size."
    fi
  fi
}

# 6.3.2.2: Ensure audit logs are not automatically deleted
remediate_audit_log_deletion() {
  log_action "6.3.2.2: Ensure audit logs are not automatically deleted"
  local file="/etc/audit/auditd.conf"
  if grep -qi "^max_log_file_action" "$file"; then
    local action
    action=$(grep -i "^max_log_file_action" "$file" | head -n 1)
    if echo "$action" | grep -qi "keep_logs"; then
      log_action "Audit log file action is set to keep_logs."
    else
      if prompt_user "max_log_file_action is not set to 'keep_logs'. Update it?"; then
        backup_file "$file"
        sed -i.bak."${timestamp}" "s/^max_log_file_action.*/max_log_file_action = keep_logs/I" "$file"
        log_action "Updated max_log_file_action to keep_logs in $file."
      else
        log_action "User skipped remediation for audit log deletion settings."
      fi
    fi
  else
    if prompt_user "max_log_file_action not found in $file. Append 'max_log_file_action = keep_logs'?"; then
      backup_file "$file"
      echo "max_log_file_action = keep_logs" >> "$file" && log_action "Appended max_log_file_action to $file."
    else
      log_action "User skipped remediation for audit log deletion settings."
    fi
  fi
}

# 6.3.3.x: Audit rule collection – Due to complexity, mark these as manual
remediate_audit_rules_manual() {
  log_action "6.3.3.x: Audit rule collection controls require manual remediation."
  log_action "Please ensure that your audit rules collect the following events:"
  log_action "  - Changes to system administration scope (sudoers)"
  log_action "  - Actions as another user"
  log_action "  - Modifications to sudo log file, date/time, network settings, privileged commands, etc."
  prompt_user "Press Y if you have manually remediated audit rule collection" && log_action "User confirmed manual remediation for 6.3.3.x."
}

# 6.3.4.x: Audit file and configuration permissions – Automated where possible
remediate_audit_file_permissions() {
  log_action "6.3.4.x: Ensure audit log file directory and file permissions are configured"
  local auditdir="/var/log/audit"
  if [ -d "$auditdir" ]; then
    local perm
    perm=$(stat -c %a "$auditdir")
    if [ "$perm" -eq 700 ]; then
      log_action "$auditdir already has 700 permissions."
    else
      if prompt_user "Permissions on $auditdir are $perm. Set to 700?"; then
        backup_file "$auditdir"
        chmod 700 "$auditdir" && log_action "Set $auditdir permissions to 700."
      else
        log_action "User skipped remediation for $auditdir permissions."
      fi
    fi
  else
    log_action "$auditdir not found. Manual remediation required for audit log directory."
  fi
  local auditlog="$auditdir/audit.log"
  if [ -f "$auditlog" ]; then
    perm=$(stat -c %a "$auditlog")
    if [ "$perm" -eq 600 ]; then
      log_action "$auditlog already has 600 permissions."
    else
      if prompt_user "Permissions on $auditlog are $perm. Set to 600?"; then
        backup_file "$auditlog"
        chmod 600 "$auditlog" && log_action "Set $auditlog permissions to 600."
      else
        log_action "User skipped remediation for $auditlog permissions."
      fi
    fi
  else
    log_action "$auditlog not found. Manual remediation required for audit log file."
  fi
}

#############################################
# Main Execution: Remediate Section 5
#############################################

echo "Starting remediation for Section 5. All actions are logged to $LOGFILE."
log_action "=== Starting Remediation for Section 5 ==="

# --- Group A: Journald & Journal Upload/Remote ---
remediate_journald_enabled
remediate_journald_log_access
remediate_journald_rotation

remediate_journal_remote_installed
remediate_journal_upload_auth
remediate_journal_upload_enabled
remediate_journal_remote_not_used

remediate_journald_forwardtosyslog
remediate_journald_compress
remediate_journald_storage

# --- Group B: Rsyslog ---
remediate_rsyslog_installed
remediate_rsyslog_enabled
remediate_journald_to_rsyslog
remediate_rsyslog_file_mode
remediate_rsyslog_logging
remediate_rsyslog_remote
remediate_rsyslog_no_receive
remediate_rsyslog_logrotate

# --- Group C: Logfile Access ---
remediate_logfile_access

# --- Group D: Audit Configuration ---
remediate_auditd_installed
remediate_audit_pre_auditd
remediate_audit_backlog_limit
remediate_auditd_enabled
remediate_audit_log_size
remediate_audit_log_deletion
remediate_audit_rules_manual
remediate_audit_file_permissions

log_action "=== Completed Remediation for Section 5 ==="
echo "Remediation for Section 5 complete. Please review $LOGFILE for details."
