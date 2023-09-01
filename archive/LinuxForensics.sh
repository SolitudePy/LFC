#!/bin/bash

# Constant Variables
OUTPUT_DIR="/tmp/result"

# Configuration Files
CONFIG_FILES=(
  "/etc/passwd"
  "/etc/passwd-"
  "/etc/group"
  "/etc/group-"
  "/etc/login.defs"
  "/etc/ssh/sshd_config"
  "/etc/sudoers"
  "/etc/sudoers.d"
  "/etc/pam.d"
  "/etc/hosts"
  "/etc/sysctl.conf"
  "/etc/security/limits.conf"
  "/etc/fstab"
  "/etc/exports"
  "/etc/aliases"
  "/etc/rsyslog.conf"
  "/etc/logrotate.conf"
  "/etc/environment"
  "/etc/crontab"
  "/etc/profile"
  "/etc/motd"
  "/etc/ntp.conf"
  "/etc/nsswitch.conf"
  "/etc/audit/audit.rules"
  "/etc/selinux/config"
  "/etc/hosts.allow"
  "/etc/hosts.deny"
  "/etc/init.d"
  "/etc/nginx"
  "/etc/httpd"
  "/etc/mysql"
  "/etc/issue"
  "/etc/cron.d"
  "/etc/cron.daily"
  "/etc/cron.hourly"
  "/etc/cron.monthly"
  "/etc/cron.weekly"
  "/boot/grub2/grub.cfg"
  "/etc/systemd/system"
  "/etc/logrotate.d"
  # Add more configuration files as needed
)

# Create the output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Start time
START_TIME=$(date +%s)

# Copy configuration files
for file in "${CONFIG_FILES[@]}"; do
  if [ -f "$file" ]; then
    # Get the directory path of the file
    dir_path=$(dirname "$file")
    # Create the corresponding directory structure in the output directory
    mkdir -p "$OUTPUT_DIR$dir_path"
    # Copy the file to the output directory with its directory structure
    cp -R "$file" "$OUTPUT_DIR$dir_path"
  elif [ -d "$file" ]; then
    # Check if the directory is empty
    if [ -n "$(find "$file" -mindepth 1 -print -quit)" ]; then
      # Directory is not empty, copy its contents recursively
      cp -R "$file" "$OUTPUT_DIR$file"
    fi
  else
    echo "File or directory does not exist: $file"
  fi
done

# Copy .bash_history, .bashrc, .bash_logout, and .bash_profile of each user
while IFS=: read -r user _ _ _ _ home _; do
  if [ -d "$home" ]; then
    user_output_dir="$OUTPUT_DIR${home}"
    mkdir -p "$user_output_dir"
    cp "${home}/.bash_history" "${user_output_dir}/"
    cp "${home}/.bashrc" "${user_output_dir}/"
    cp "${home}/.bash_logout" "${user_output_dir}/"
    cp "${home}/.bash_profile" "${user_output_dir}/"
  fi
done < /etc/passwd

# System Logs
cp /var/log/* "$OUTPUT_DIR/"
cp /var/log/secure "$OUTPUT_DIR/"
cp /var/log/audit/audit.log "$OUTPUT_DIR/"

# Network Artifacts
cp /etc/sysconfig/network-scripts/ifcfg-* "$OUTPUT_DIR/"
cp /etc/resolv.conf "$OUTPUT_DIR/"

# Cron Jobs
cp -R /var/spool/cron "$OUTPUT_DIR/cron_jobs"

# Firewall Configuration
iptables-save > "$OUTPUT_DIR/iptables_rules.txt"

# System Metadata
uname -a > "$OUTPUT_DIR/system_info.txt"
lshw > "$OUTPUT_DIR/hardware_info.txt"

# Disk Partition Information
fdisk -l > "$OUTPUT_DIR/disk_partitions.txt"

# Rootkit Detection Tools
rkhunter --check --sk > "$OUTPUT_DIR/rkhunter_scan.txt"

# Lsof (List Open Files)
lsof > "$OUTPUT_DIR/open_files.txt"

# End time
END_TIME=$(date +%s)

# Execution time
ELAPSED_TIME=$((END_TIME - START_TIME))
echo "Artifact collection completed in $ELAPSED_TIME seconds. Artifacts saved in $OUTPUT_DIR."
