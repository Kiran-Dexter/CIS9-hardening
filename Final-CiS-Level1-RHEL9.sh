#!/bin/bash

set -euo pipefail

# Global Variables
LOGFILE="/var/log/hardening_$(date +'%Y%m%d_%H%M%S').log"
HTML_REPORT="hardening_report_$(date +'%Y%m%d_%H%M%S').html"
BACKUP_SUFFIX=".bak_$(date +'%Y%m%d_%H%M%S')"
TMP_CHANGES="/tmp/hardening_changes.txt"
> "$LOGFILE"
> "$TMP_CHANGES"

# Trap errors
trap 'echo "An error occurred at line $LINENO. Exiting." | tee -a "$LOGFILE"; exit 1' ERR

# Logging functions
log_info() {
    echo "[INFO] $(date +'%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOGFILE"
    echo "<p>[INFO] $1</p>" >> "$TMP_CHANGES"
}
log_warn() {
    echo "[WARN] $(date +'%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOGFILE"
    echo "<p style='color:orange;'>[WARN] $1</p>" >> "$TMP_CHANGES"
}
log_error() {
    echo "[ERROR] $(date +'%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOGFILE"
    echo "<p style='color:red;'>[ERROR] $1</p>" >> "$TMP_CHANGES"
}

# Ensure the script is run as root.
if [[ "$EUID" -ne 0 ]]; then
    log_error "This script must be run as root."
    exit 1
fi

# Interactive prompt function (yes/no)
prompt_yes_no() {
    local prompt_message="$1"
    while true; do
        read -rp "$prompt_message [y/n]: " answer
        case "$answer" in
            [Yy]* ) return 0 ;;
            [Nn]* ) return 1 ;;
            * ) echo "Please answer yes or no." ;;
        esac
    done
}

# Backup function: makes a backup of the file if it exists.
backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        cp -p "$file" "${file}${BACKUP_SUFFIX}"
        log_info "Backed up $file to ${file}${BACKUP_SUFFIX}"
    else
        log_warn "File $file does not exist; skipping backup."
    fi
}

###############################################################################
# Helper Function: Fix File Permissions, Owner, and Group
###############################################################################
fix_file_permissions() {
    local file="$1"
    local desired_mode="$2"
    local desired_owner="$3"
    local desired_group="$4"
    local control_id="$5"

    if [[ ! -e "$file" ]]; then
        log_warn "$file not found. Skipping control $control_id."
        return
    fi

    current_mode=$(stat -c "%a" "$file")
    current_owner=$(stat -c "%U" "$file")
    current_group=$(stat -c "%G" "$file")

    # Check mode
    if [[ "$current_mode" != "$desired_mode" ]]; then
        if prompt_yes_no "[$control_id] $file does not have mode $desired_mode (current: $current_mode). Set it?"; then
            backup_file "$file"
            chmod "$desired_mode" "$file" && log_info "Set mode of $file to $desired_mode." || log_warn "Failed to set mode of $file."
        else
            log_warn "Skipped setting mode for $file."
        fi
    else
        log_info "$file already has mode $desired_mode."
    fi

    # Check owner
    if [[ "$current_owner" != "$desired_owner" ]]; then
        if prompt_yes_no "[$control_id] $file does not have owner $desired_owner (current: $current_owner). Set it?"; then
            backup_file "$file"
            chown "$desired_owner" "$file" && log_info "Set owner of $file to $desired_owner." || log_warn "Failed to set owner of $file."
        else
            log_warn "Skipped setting owner for $file."
        fi
    else
        log_info "$file already has owner $desired_owner."
    fi

    # Check group
    if [[ "$current_group" != "$desired_group" ]]; then
        if prompt_yes_no "[$control_id] $file does not have group $desired_group (current: $current_group). Set it?"; then
            backup_file "$file"
            chown :"$desired_group" "$file" && log_info "Set group of $file to $desired_group." || log_warn "Failed to set group of $file."
        else
            log_warn "Skipped setting group for $file."
        fi
    else
        log_info "$file already has group $desired_group."
    fi
}

###############################################################################
# 1. Disable Unwanted Kernel Modules (CIS 1.1.1.x)
###############################################################################
disable_kernel_module() {
    local module="$1"
    local conf_file="/etc/modprobe.d/${module}.conf"
    # Check if module is already disabled
    if [[ -f "$conf_file" ]] && grep -q "install ${module} /bin/true" "$conf_file"; then
        log_info "Kernel module '$module' is already disabled in $conf_file. Skipping."
        return
    fi

    if prompt_yes_no "Disable kernel module $module?"; then
        echo "install $module /bin/true" > "$conf_file"
        log_info "Created $conf_file to disable $module"
        # Try to remove the module if it's loaded
        if lsmod | grep -q "$module"; then
            modprobe -r "$module" && log_info "Unloaded $module module" || log_warn "Failed to unload $module module"
        fi
    else
        log_warn "Skipped disabling kernel module $module"
    fi
}

log_info "Starting RHEL 9 Hardening Script..."

for module in cramfs freevxfs hfs hfsplus jffs2 squashfs udf usb-storage; do
    disable_kernel_module "$module"
done

###############################################################################
# 2. Partition and Mount Options (CIS 1.1.2.x)
###############################################################################
update_fstab_options() {
    local mount_point="$1"
    local options="$2"
    if grep -E "\s${mount_point}\s" /etc/fstab >/dev/null; then
        # Check if the desired options are already in the fstab line
        if grep -E "\s${mount_point}\s" /etc/fstab | grep -q "$options"; then
            log_info "Mount options for $mount_point already include $options. Skipping update."
            return
        fi

        if prompt_yes_no "Update mount options for $mount_point to include $options?"; then
            backup_file "/etc/fstab"
            sed -i "s|\(\s${mount_point}\s.*\)defaults|\1defaults,$options|" /etc/fstab
            log_info "Updated $mount_point mount options in /etc/fstab"
        else
            log_warn "Skipped updating mount options for $mount_point"
        fi
    else
        log_warn "$mount_point not found as a separate partition in /etc/fstab. Manual configuration may be required."
    fi
}

# /tmp: Ensure separate partition with nodev,nosuid,noexec
update_fstab_options "/tmp" "nodev,nosuid,noexec"

# /dev/shm: Ensure separate partition with nodev,nosuid,noexec
update_fstab_options "/dev/shm" "nodev,nosuid,noexec"

# /var/tmp: Ensure separate partition with nodev,nosuid,noexec
update_fstab_options "/var/tmp" "nodev,nosuid,noexec"

# /home: Ensure separate partition with nodev
update_fstab_options "/home" "nodev"

# /var: Check if /var is a separate partition
if grep -E "\s/var\s" /etc/fstab >/dev/null; then
    log_info "/var is configured as a separate partition."
else
    log_warn "/var is not configured as a separate partition. Consider manual partitioning for /var."
fi

###############################################################################
# 3. Bootloader Password (CIS 1.3.1)
###############################################################################
if grep -q "password" /etc/grub.d/40_custom; then
    log_info "Bootloader password already configured in /etc/grub.d/40_custom. Skipping."
else
    if prompt_yes_no "Configure bootloader password? (This step is sensitive and might require manual intervention)"; then
        log_info "Please manually configure bootloader password by editing /etc/grub.d/40_custom and regenerating the GRUB config."
    else
        log_warn "Skipped bootloader password configuration."
    fi
fi

###############################################################################
# 4. SELinux Configuration (CIS 1.5.1, 1.5.2, 1.5.3)
###############################################################################
current_selinux_status=$(getenforce)
if [[ "$current_selinux_status" == "Enforcing" ]]; then
    log_info "SELinux is already enforcing. Skipping SELinux configuration."
else
    if prompt_yes_no "Ensure SELinux is installed and set to enforcing mode?"; then
        backup_file "/etc/selinux/config"
        if rpm -q selinux-policy-targeted &>/dev/null; then
            log_info "SELinux policy package is installed."
        else
            dnf install -y selinux-policy-targeted && log_info "Installed selinux-policy-targeted" || log_error "Failed to install selinux-policy-targeted"
        fi
        sed -i "s/^SELINUX=.*/SELINUX=enforcing/" /etc/selinux/config
        setenforce 1 && log_info "Set SELinux to enforcing mode" || log_warn "Failed to set SELinux enforcing; a reboot might be required."
    else
        log_warn "Skipped SELinux configuration."
    fi
fi

###############################################################################
# 5. Message of the Day (MOTD) (CIS 1.7.1)
###############################################################################
motd_text="Authorized access only. All activity may be monitored and recorded."
if grep -Fxq "$motd_text" /etc/motd; then
    log_info "MOTD already configured. Skipping MOTD configuration."
else
    if prompt_yes_no "Configure Message of the Day (MOTD)?"; then
        backup_file "/etc/motd"
        echo "$motd_text" > /etc/motd
        log_info "Updated /etc/motd with custom message."
    else
        log_warn "Skipped MOTD configuration."
    fi
fi

###############################################################################
# 6. Remove xinetd (CIS 2.1.1)
###############################################################################
if prompt_yes_no "Remove xinetd if installed?"; then
    if rpm -q xinetd &>/dev/null; then
        dnf remove -y xinetd && log_info "xinetd removed." || log_warn "Failed to remove xinetd."
    else
        log_info "xinetd is not installed."
    fi
else
    log_warn "Skipped xinetd removal."
fi

###############################################################################
# 7. Time Synchronization (CIS 2.2.1)
###############################################################################
if systemctl is-active chronyd >/dev/null 2>&1; then
    log_info "chronyd is already active. Skipping time synchronization configuration."
else
    if prompt_yes_no "Configure time synchronization using chronyd?"; then
        if rpm -q chrony &>/dev/null; then
            log_info "chrony is already installed."
        else
            dnf install -y chrony && log_info "Installed chrony." || log_error "Failed to install chrony."
        fi
        systemctl enable --now chronyd && log_info "chronyd enabled and running." || log_error "Failed to enable chronyd."
    else
        log_warn "Skipped time synchronization configuration."
    fi
fi

###############################################################################
# 8. Cron Daemon (CIS 2.3.1)
###############################################################################
if systemctl is-active crond >/dev/null 2>&1; then
    log_info "Cron daemon is already active. Skipping cron configuration."
else
    if prompt_yes_no "Ensure cron daemon (crond) is enabled and active?"; then
        systemctl enable --now crond && log_info "Cron daemon enabled and running." || log_error "Failed to enable cron daemon."
    else
        log_warn "Skipped cron daemon configuration."
    fi
fi

###############################################################################
# 9. Firewalld (CIS 3.1.1)
###############################################################################
if systemctl is-active firewalld >/dev/null 2>&1; then
    log_info "firewalld is already active. Skipping firewalld configuration."
else
    if prompt_yes_no "Ensure firewalld is installed and running?"; then
        if rpm -q firewalld &>/dev/null; then
            log_info "firewalld is already installed."
        else
            dnf install -y firewalld && log_info "Installed firewalld." || log_error "Failed to install firewalld."
        fi
        systemctl enable --now firewalld && log_info "firewalld enabled and running." || log_error "Failed to enable firewalld."
    else
        log_warn "Skipped firewalld configuration."
    fi
fi

###############################################################################
# 10. Disable IPv6 (CIS 3.2.1)
###############################################################################
if grep -q "net.ipv6.conf.all.disable_ipv6\s*=\s*1" /etc/sysctl.conf; then
    log_info "IPv6 disable settings already present in /etc/sysctl.conf. Skipping IPv6 disablement."
else
    if prompt_yes_no "Disable IPv6 (if not required)?"; then
        backup_file "/etc/sysctl.conf"
        cat <<EOF >> /etc/sysctl.conf
# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
        sysctl -p && log_info "IPv6 disabled via sysctl." || log_error "Failed to reload sysctl settings."
    else
        log_warn "Skipped IPv6 disablement."
    fi
fi

###############################################################################
# 11. Auditd Configuration (CIS 4.1.1.x & 4.1.2)
###############################################################################
if systemctl is-active auditd >/dev/null 2>&1; then
    log_info "auditd is already active."
    if grep -q "^max_log_file_action\s*=\s*keep_logs" /etc/audit/auditd.conf; then
        log_info "auditd log retention is already configured."
    else
        if prompt_yes_no "Configure auditd log retention (max_log_file_action = keep_logs)?"; then
            backup_file "/etc/audit/auditd.conf"
            sed -i "s/^max_log_file_action.*/max_log_file_action = keep_logs/" /etc/audit/auditd.conf
            log_info "Configured auditd to keep logs."
        else
            log_warn "Skipped auditd log retention configuration."
        fi
    fi
else
    if prompt_yes_no "Ensure auditd is installed, enabled, and logs are not automatically deleted?"; then
        if rpm -q audit &>/dev/null; then
            log_info "auditd is already installed."
        else
            dnf install -y audit && log_info "Installed auditd." || log_error "Failed to install auditd."
        fi
        systemctl enable --now auditd && log_info "auditd enabled and running." || log_error "Failed to enable auditd."
        backup_file "/etc/audit/auditd.conf"
        sed -i "s/^max_log_file_action.*/max_log_file_action = keep_logs/" /etc/audit/auditd.conf
        log_info "Configured auditd to keep logs."
    else
        log_warn "Skipped auditd configuration."
    fi
fi

###############################################################################
# 12. Password Complexity and Reuse (CIS 5.1.1 & 5.3.1)
###############################################################################
# Password Complexity Check
minlen_set=$(grep -E "^\s*minlen\s*=\s*14" /etc/security/pwquality.conf || true)
dcredit_set=$(grep -E "^\s*dcredit\s*=\s*-1" /etc/security/pwquality.conf || true)
ucredit_set=$(grep -E "^\s*ucredit\s*=\s*-1" /etc/security/pwquality.conf || true)
lcredit_set=$(grep -E "^\s*lcredit\s*=\s*-1" /etc/security/pwquality.conf || true)
ocredit_set=$(grep -E "^\s*ocredit\s*=\s*-1" /etc/security/pwquality.conf || true)

if [[ -n "$minlen_set" && -n "$dcredit_set" && -n "$ucredit_set" && -n "$lcredit_set" && -n "$ocredit_set" ]]; then
    log_info "Password complexity settings already configured in /etc/security/pwquality.conf."
else
    if prompt_yes_no "Configure password complexity settings?"; then
        if [[ -f /etc/security/pwquality.conf ]]; then
            backup_file "/etc/security/pwquality.conf"
            sed -i "s/^\s*minlen.*/minlen = 14/" /etc/security/pwquality.conf
            sed -i "s/^\s*dcredit.*/dcredit = -1/" /etc/security/pwquality.conf
            sed -i "s/^\s*ucredit.*/ucredit = -1/" /etc/security/pwquality.conf
            sed -i "s/^\s*lcredit.*/lcredit = -1/" /etc/security/pwquality.conf
            sed -i "s/^\s*ocredit.*/ocredit = -1/" /etc/security/pwquality.conf
            log_info "Updated /etc/security/pwquality.conf for password complexity."
        else
            log_warn "/etc/security/pwquality.conf not found."
        fi
    fi
fi

# Password Reuse Restriction
if grep -q "remember=5" /etc/pam.d/system-auth; then
    log_info "Password reuse restriction already set in /etc/pam.d/system-auth."
else
    if prompt_yes_no "Restrict password reuse? (Update /etc/pam.d/system-auth)"; then
        backup_file "/etc/pam.d/system-auth"
        if grep -q "remember=" /etc/pam.d/system-auth; then
            sed -i "s/remember=[0-9]*/remember=5/" /etc/pam.d/system-auth
        else
            sed -i "/^password.*pam_unix.so/ s/$/ remember=5/" /etc/pam.d/system-auth
        fi
        log_info "Configured password reuse restriction in /etc/pam.d/system-auth."
    fi
fi

###############################################################################
# 13. SSH Configuration (CIS 5.4.1 & 6.2.1)
###############################################################################
# Disable root SSH login
if grep -E "^\s*PermitRootLogin\s+no" /etc/ssh/sshd_config >/dev/null; then
    log_info "Root SSH login already disabled."
else
    if prompt_yes_no "Disable root SSH login?"; then
        backup_file "/etc/ssh/sshd_config"
        sed -i "s/^#\?PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config
        log_info "Disabled root SSH login in /etc/ssh/sshd_config."
        systemctl restart sshd && log_info "sshd restarted." || log_warn "Failed to restart sshd."
    fi
fi

# Additional OpenSSH Hardening
protocol_check=$(grep -E "^\s*Protocol\s+2" /etc/ssh/sshd_config || true)
empty_pw_check=$(grep -E "^\s*PermitEmptyPasswords\s+no" /etc/ssh/sshd_config || true)
x11_check=$(grep -E "^\s*X11Forwarding\s+no" /etc/ssh/sshd_config || true)
maxauth_check=$(grep -E "^\s*MaxAuthTries\s+4" /etc/ssh/sshd_config || true)

if [[ -n "$protocol_check" && -n "$empty_pw_check" && -n "$x11_check" && -n "$maxauth_check" ]]; then
    log_info "Additional OpenSSH hardening measures already applied."
else
    if prompt_yes_no "Apply additional OpenSSH hardening measures?"; then
        backup_file "/etc/ssh/sshd_config"
        sed -i "s/^#\?Protocol.*/Protocol 2/" /etc/ssh/sshd_config
        grep -q "^PermitEmptyPasswords" /etc/ssh/sshd_config || echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
        grep -q "^X11Forwarding" /etc/ssh/sshd_config || echo "X11Forwarding no" >> /etc/ssh/sshd_config
        grep -q "^MaxAuthTries" /etc/ssh/sshd_config || echo "MaxAuthTries 4" >> /etc/ssh/sshd_config
        log_info "Applied additional OpenSSH hardening in /etc/ssh/sshd_config."
        systemctl restart sshd && log_info "sshd restarted after OpenSSH hardening." || log_warn "Failed to restart sshd after hardening."
    fi
fi

###############################################################################
# 14. System-wide Cryptographic Policies (CIS 6.1.1)
###############################################################################
current_crypto=$(update-crypto-policies --show)
if [[ "$current_crypto" == "DEFAULT" ]]; then
    log_info "System-wide crypto policy is already set to DEFAULT."
else
    if prompt_yes_no "Set system-wide cryptographic policy to DEFAULT?"; then
        update-crypto-policies --set DEFAULT && log_info "System-wide crypto policy set to DEFAULT." || log_error "Failed to set crypto policy."
    fi
fi

###############################################################################
# 15. Remove GUI and Disable Graphical Target
###############################################################################
default_target=$(systemctl get-default)
if [[ "$default_target" == "multi-user.target" ]]; then
    log_info "Default target is already multi-user (non-GUI)."
else
    if prompt_yes_no "Set default target to multi-user (text mode only)?"; then
        systemctl set-default multi-user.target && log_info "Default target set to multi-user (non-GUI) mode." || log_warn "Failed to set default target."
    fi
fi

# Check if GUI packages (Server with GUI group) are installed
if dnf group list installed | grep -q "Server with GUI"; then
    if prompt_yes_no "Remove GUI packages?"; then
        dnf groupremove "Server with GUI" -y && log_info "GUI packages removed." || log_warn "Failed to remove GUI packages."
    else
        log_warn "Skipped removal of GUI packages."
    fi
else
    log_info "GUI packages are not installed."
fi

###############################################################################
# 16. Additional File Permission Controls (CIS 6.3.4.x and 7.1.x)
###############################################################################
# 6.3.4 Audit Files & Tools
# 6.3.4.2 - Audit log files mode
# 6.3.4.3 - Audit log files owner
# 6.3.4.4 - Audit log files group owner
fix_file_permissions "/var/log/audit/audit.log" "600" "root" "root" "6.3.4.2-4"

# 6.3.4.5 - Audit configuration files mode
# 6.3.4.6 - Audit configuration files owner
# 6.3.4.7 - Audit configuration files group owner
fix_file_permissions "/etc/audit/auditd.conf" "600" "root" "root" "6.3.4.5-7"

# 6.3.4.8 - Audit tools mode
# 6.3.4.9 - Audit tools owner
# 6.3.4.10 - Audit tools group owner
# (Assuming /sbin/auditctl is the primary audit tool)
fix_file_permissions "/sbin/auditctl" "750" "root" "root" "6.3.4.8-10"

# 7.1 File Permissions on Critical System Files
fix_file_permissions "/etc/passwd" "644" "root" "root" "7.1.1"
fix_file_permissions "/etc/passwd-" "644" "root" "root" "7.1.2"
fix_file_permissions "/etc/group" "644" "root" "root" "7.1.3"
fix_file_permissions "/etc/group-" "644" "root" "root" "7.1.4"
fix_file_permissions "/etc/shadow" "0000" "root" "root" "7.1.5"
fix_file_permissions "/etc/shadow-" "0000" "root" "root" "7.1.6"
fix_file_permissions "/etc/gshadow" "0000" "root" "root" "7.1.7"
fix_file_permissions "/etc/gshadow-" "0000" "root" "root" "7.1.8"

###############################################################################
# 17. Validate Shadowed Passwords (CIS 7.2.1 & 7.2.2)
###############################################################################
check_shadowed_passwords() {
    local issues=0
    while IFS=: read -r username passwd _; do
        if [[ "$passwd" != "x" ]]; then
            log_warn "Account '$username' in /etc/passwd does not use a shadowed password (found: $passwd)."
            issues=1
        fi
    done < /etc/passwd

    if [[ $issues -eq 0 ]]; then
        log_info "All accounts in /etc/passwd use shadowed passwords."
    fi
}

check_shadow_password_fields() {
    local issues=0
    while IFS=: read -r username passwd rest; do
        if [[ -z "$passwd" ]]; then
            log_warn "Account '$username' in /etc/shadow has an empty password field."
            issues=1
        fi
    done < /etc/shadow

    if [[ $issues -eq 0 ]]; then
        log_info "All /etc/shadow password fields are populated."
    fi
}

# 7.2.1 Ensure accounts in /etc/passwd use shadowed passwords
if prompt_yes_no "Verify that all accounts in /etc/passwd use shadowed passwords?"; then
    check_shadowed_passwords
fi

# 7.2.2 Ensure /etc/shadow password fields are not empty
if prompt_yes_no "Verify that no password fields in /etc/shadow are empty?"; then
    check_shadow_password_fields
fi

###############################################################################
# Finalize and Generate HTML Report
###############################################################################
log_info "Hardening actions completed."

generate_html_report() {
    {
        echo "<!DOCTYPE html>"
        echo "<html lang='en'>"
        echo "<head>"
        echo "  <meta charset='UTF-8'>"
        echo "  <meta name='viewport' content='width=device-width, initial-scale=1.0'>"
        echo "  <title>RHEL9 Hardening Report</title>"
        echo "  <style>"
        echo "    body { font-family: Arial, sans-serif; margin: 20px; }"
        echo "    h1 { color: #333; }"
        echo "    pre { background: #f4f4f4; padding: 10px; }"
        echo "  </style>"
        echo "</head>"
        echo "<body>"
        echo "  <h1>RHEL9 Hardening Report</h1>"
        echo "  <p>Date: $(date)</p>"
        echo "  <h2>Actions Performed:</h2>"
        cat "$TMP_CHANGES"
        echo "  <h2>Log File:</h2>"
        echo "  <pre>$(sed 's/</\&lt;/g; s/>/\&gt;/g' "$LOGFILE")</pre>"
        echo "</body>"
        echo "</html>"
    } > "$HTML_REPORT"
}

generate_html_report && log_info "HTML report generated at $HTML_REPORT"

echo "Hardening complete. Please review the HTML report at $HTML_REPORT"
