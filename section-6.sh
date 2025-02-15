#!/bin/bash
# remediate_section7.sh - Remediation script for Section 7 controls:
#  Account and file permission configurations.
#
# Controls covered:
#  7.1.1  Ensure permissions on /etc/passwd are configured (expected: 644)
#  7.1.2  Ensure permissions on /etc/passwd- are configured (expected: 600)
#  7.1.3  Ensure permissions on /etc/group are configured (expected: 644)
#  7.1.4  Ensure permissions on /etc/group- are configured (expected: 600)
#  7.1.5  Ensure permissions on /etc/shadow are configured (expected: 400)
#  7.1.6  Ensure permissions on /etc/shadow- are configured (expected: 600)
#  7.1.7  Ensure permissions on /etc/gshadow are configured (expected: 640)
#  7.1.8  Ensure permissions on /etc/gshadow- are configured (expected: 600)
#  7.1.9  Ensure permissions on /etc/shells are configured (expected: 644)
#  7.1.10 Ensure permissions on /etc/security/opasswd are configured (expected: 600)
#
#  7.1.11 Ensure world writable files and directories are secured       (Manual review)
#  7.1.12 Ensure no files or directories without an owner and a group exist (Manual review)
#  7.1.13 Ensure SUID and SGID files are reviewed                           (Manual review)
#
#  7.2.1  Ensure accounts in /etc/passwd use shadowed passwords             (Check for "x" in password field)
#  7.2.2  Ensure /etc/shadow password fields are not empty                  (Check that the second field is not blank)
#  7.2.8  Ensure local interactive user home directories are configured      (Check home dirs exist)
#  7.2.9  Ensure local interactive user dot files access is configured       (Manual review)
#
# All actions are logged to remediation_section7.log in the current directory.

LOGFILE="./remediation_section7.log"
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

remediate_file_permission() {
  # Remediates file permission if not as expected.
  local file="$1"
  local expected="$2"
  log_action "Remediating permissions for $file (expected: $expected)"
  if [ ! -f "$file" ]; then
    log_action "$file not found. Manual remediation required."
    return
  fi
  local current
  current=$(stat -c %a "$file")
  if [ "$current" -eq "$expected" ]; then
    log_action "$file already has permission $expected."
  else
    if prompt_user "$file has permission $current. Change to $expected?"; then
      backup_file "$file"
      chmod "$expected" "$file" && log_action "Set permissions on $file to $expected."
    else
      log_action "User skipped permission change for $file."
    fi
  fi
}

#############################################
# Section 7 Remediation Functions
#############################################

# 7.1.1: /etc/passwd (expected 644)
remediate_passwd() {
  log_action "7.1.1: Remediate /etc/passwd permissions"
  remediate_file_permission "/etc/passwd" 644
}

# 7.1.2: /etc/passwd- (expected 600)
remediate_passwd_dash() {
  log_action "7.1.2: Remediate /etc/passwd- permissions"
  remediate_file_permission "/etc/passwd-" 600
}

# 7.1.3: /etc/group (expected 644)
remediate_group() {
  log_action "7.1.3: Remediate /etc/group permissions"
  remediate_file_permission "/etc/group" 644
}

# 7.1.4: /etc/group- (expected 600)
remediate_group_dash() {
  log_action "7.1.4: Remediate /etc/group- permissions"
  remediate_file_permission "/etc/group-" 600
}

# 7.1.5: /etc/shadow (expected 400)
remediate_shadow() {
  log_action "7.1.5: Remediate /etc/shadow permissions"
  remediate_file_permission "/etc/shadow" 400
}

# 7.1.6: /etc/shadow- (expected 600)
remediate_shadow_dash() {
  log_action "7.1.6: Remediate /etc/shadow- permissions"
  remediate_file_permission "/etc/shadow-" 600
}

# 7.1.7: /etc/gshadow (expected 640)
remediate_gshadow() {
  log_action "7.1.7: Remediate /etc/gshadow permissions"
  remediate_file_permission "/etc/gshadow" 640
}

# 7.1.8: /etc/gshadow- (expected 600)
remediate_gshadow_dash() {
  log_action "7.1.8: Remediate /etc/gshadow- permissions"
  remediate_file_permission "/etc/gshadow-" 600
}

# 7.1.9: /etc/shells (expected 644)
remediate_shells() {
  log_action "7.1.9: Remediate /etc/shells permissions"
  remediate_file_permission "/etc/shells" 644
}

# 7.1.10: /etc/security/opasswd (expected 600)
remediate_opasswd() {
  log_action "7.1.10: Remediate /etc/security/opasswd permissions"
  remediate_file_permission "/etc/security/opasswd" 600
}

# 7.1.11: World writable files and directories – Manual
remediate_world_writable() {
  log_action "7.1.11: Ensure world writable files and directories are secured"
  log_action "Manual remediation required. Please review and secure world writable files/directories (e.g., using find / -perm -002 -exec ls -ld {} \\;)."
  prompt_user "Press Y if you have manually secured world writable files" && log_action "User confirmed manual remediation for 7.1.11."
}

# 7.1.12: No files or directories without an owner and group – Manual
remediate_no_orphan_files() {
  log_action "7.1.12: Ensure no files or directories without an owner and group exist"
  log_action "Manual remediation required. Use commands like 'find / -nouser -o -nogroup' to identify such files."
  prompt_user "Press Y if you have manually reviewed orphaned files" && log_action "User confirmed manual remediation for 7.1.12."
}

# 7.1.13: SUID and SGID files are reviewed – Manual
remediate_suid_sgid_review() {
  log_action "7.1.13: Ensure SUID and SGID files are reviewed"
  log_action "Manual remediation required. Please review SUID/SGID files using 'find / -perm /6000 -exec ls -ld {} \\;'."
  prompt_user "Press Y if you have manually reviewed SUID/SGID files" && log_action "User confirmed manual remediation for 7.1.13."
}

# 7.2.1: Ensure accounts in /etc/passwd use shadowed passwords
remediate_shadowed_passwords() {
  log_action "7.2.1: Ensure accounts in /etc/passwd use shadowed passwords"
  if grep -q ":[!*]" /etc/passwd; then
    log_action "Found entries in /etc/passwd that may not be using shadowed passwords."
    if prompt_user "Replace non-shadowed entries with 'x'? (Manual review recommended)"; then
      # Note: This is a delicate operation. In production, you'd review these entries carefully.
      sed -i.bak."${timestamp}" 's/:\([^:]*\):/:x:/' /etc/passwd && log_action "Updated /etc/passwd to use shadowed passwords."
    else
      log_action "User skipped remediation for shadowed passwords."
    fi
  else
    log_action "All accounts appear to be using shadowed passwords (password field contains 'x')."
  fi
}

# 7.2.2: Ensure /etc/shadow password fields are not empty
remediate_shadow_fields() {
  log_action "7.2.2: Ensure /etc/shadow password fields are not empty"
  if awk -F: '($2 == "") { print $1 }' /etc/shadow | grep -q .; then
    log_action "Some accounts have empty password fields in /etc/shadow."
    prompt_user "Please review /etc/shadow manually to secure empty password fields. Confirm remediation?" && log_action "User confirmed manual remediation for 7.2.2."
  else
    log_action "All /etc/shadow entries have non-empty password fields."
  fi
}

# 7.2.8: Ensure local interactive user home directories are configured
remediate_user_home_dirs() {
  log_action "7.2.8: Ensure local interactive user home directories are configured"
  while IFS=: read -r username _ uid _ home _; do
    if [ "$uid" -ge 1000 ] && [ "$username" != "nobody" ]; then
      if [ ! -d "$home" ]; then
        log_action "User $username (UID $uid) has no valid home directory: $home"
        if prompt_user "Create home directory $home for $username?"; then
          mkdir -p "$home" && chown "$username":"$username" "$home" && log_action "Created and set ownership for $home."
        else
          log_action "User skipped remediation for $username home directory."
        fi
      else
        log_action "$username's home directory $home exists."
      fi
    fi
  done < /etc/passwd
}

# 7.2.9: Ensure local interactive user dot files access is configured – Manual
remediate_user_dot_files() {
  log_action "7.2.9: Ensure local interactive user dot files access is configured"
  log_action "Manual remediation required. Please review permissions on dotfiles (e.g., ~/.bashrc, ~/.profile) for local users."
  prompt_user "Press Y if you have manually reviewed and secured user dot files" && log_action "User confirmed manual remediation for 7.2.9."
}

#############################################
# Main Execution: Remediate Section 7
#############################################

echo "Starting remediation for Section 7. All actions are logged to $LOGFILE."
log_action "=== Starting Remediation for Section 7 ==="

remediate_passwd
remediate_passwd_dash
remediate_group
remediate_group_dash
remediate_shadow
remediate_shadow_dash
remediate_gshadow
remediate_gshadow_dash
remediate_shells
remediate_opasswd

remediate_world_writable
remediate_no_orphan_files
remediate_suid_sgid_review

remediate_shadowed_passwords
remediate_shadow_fields
remediate_user_home_dirs
remediate_user_dot_files

log_action "=== Completed Remediation for Section 7 ==="
echo "Remediation for Section 7 complete. Please review $LOGFILE for details."
