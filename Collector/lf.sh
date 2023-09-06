#!/bin/bash

# Start time
START_TIME=$(date +%s)

# Constant Variables
OUTPUT_DIR="/tmp/result"
ZIP_DIR="/tmp"
LOGFILE="$OUTPUT_DIR/log_file.log"
SYSTEM_ANALYSIS="$OUTPUT_DIR/System_Analysis"
AV_ANALYSIS_DIR="$OUTPUT_DIR/AV_Analysis"
USER_ANALYSIS_DIR="$OUTPUT_DIR/User_Analysis"
FILE_ANALYSIS_DIR="$OUTPUT_DIR/File_Analysis"
NETWORK_ANALYSIS_DIR="$OUTPUT_DIR/Network_Analysis"
PROCESS_ANALYSIS_DIR="$OUTPUT_DIR/Process_Analysis"

recent_modified_files_threshold=24 # Time threshold in hours for recent modified files.
recent_read_files_threshold=24 # Time threshold in hours for recent read files.
recent_modified_executables_threshold=24 # Time threshold in hours for recent modified/created executable files.
#user=$(whoami)
#history_file="$OUTPUT_DIR/history_$user.txt"

# Array of important configuration Files
SYSTEM_FILES=(
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
  "/etc/sysctl.d"
  "/etc/security/limits.conf"
  "/etc/security/access.conf"
  "/etc/fstab"
  "/etc/exports"
  "/etc/aliases"
  "/etc/rsyslog.conf"
  "/etc/environment"
  "/etc/environment.d"
  "/etc/crontab"
  "/etc/profile"
  "/etc/profile.d"
  "/etc/motd"
  "/etc/ntp.conf"
  "/etc/nsswitch.conf"
  "/etc/audit"
  "/etc/laurel"
  "/etc/audisp"
  "/etc/selinux/config"
  "/etc/hosts.allow"
  "/etc/hosts.deny"
  "/etc/rc.local"
  "/etc/nginx"
  "/etc/httpd"
  "/etc/mysql"
  "/etc/issue"
  "/etc/issue.net"
  "/etc/issue-"
  "/etc/issue.net-"
  "/etc/xdg/autostart"
  "/etc/cron.d"
  "/etc/cron.daily"
  "/etc/cron.hourly"
  "/etc/cron.monthly"
  "/etc/cron.weekly"
  "/etc/inittab"
  "/etc/modprobe.d"
  "/boot/grub2/grub.cfg"
  "/etc/ld.so.conf"
  "/etc/ld.so.conf.d
  "/etc/systemd/system"
  "/usr/lib/systemd/system"
  "/usr/lib/systemd/system-generators"
  "/etc/logrotate.conf"
  "/etc/logrotate.d"
  "/etc/yum.conf"
  "/etc/yum.repos.d"
  "/etc/resolv.conf"
  "/var/spool/cron"
  "/etc/os-release"
  #"/var/log"
  "/var/www"
  # Add more files as needed
  )

# Array of important user related files
USER_CONFIG_FILES=(
      ".bashrc"
      ".bash_profile"
      ".bash_logout"
      ".bash_history"
      ".history"
      ".config/autostart"
      ".ssh/authorized_keys"
      # Add more user-specific configuration files as needed
    )

# Array of important files under /proc/$pid
PROC_PID_FILES=(
    "cmdline"
    "status"
    "stat"
    "maps"
    "exe"
    "comm"
    "environ"
    # Add more files as needed
  )

# Array of important files under /proc excluding the $pid structure
PROC_IMPORTANT_FILES=(
  "/proc/cmdline"
  "/proc/cpuinfo"
  "/proc/meminfo"
  "/proc/version"
  "/proc/modules"
  "/proc/interrupts"
  "/proc/diskstats"
)

create_file_if_output_not_empty() {
    local command="$1"
    local filename="$2"

    local output
    output=$(eval "$command")

    if [ -n "$output" ]; then
        echo "$output" > "$filename"
    fi
}

# Create the output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

echo "$(date +"%Y-%m-%d %H:%M:%S") - ===== Starting System Files Acquisition =====" >> "$LOGFILE"

# Copy configuration files
for file in "${SYSTEM_FILES[@]}"; do
  if [ -f "$file" -a -s "$file" ]; then
    # Get the directory path of the file
    dir_path=$(dirname "$file")

    # Create the corresponding directory structure in the output directory
    mkdir -p "$OUTPUT_DIR$dir_path"

    # Copy the file to the output directory with its directory structure
    cp -R "$file" "$OUTPUT_DIR$dir_path"

  elif [ -d "$file" ]; then

    # Check if the directory is empty
    if [ -n "$(find "$file" -mindepth 1 -print -quit)" ]; then

      # Get the directory path of the file
      dir_path=$(dirname "$file")

      # Create the corresponding directory structure in the output directory
      mkdir -p "$OUTPUT_DIR$dir_path"

      # Directory is not empty, copy its contents recursively
      cp -R "$file" "$OUTPUT_DIR$file"
    fi
  else
    echo "$(date +"%Y-%m-%d %H:%M:%S") - File or directory does not exist/empty: $file" >> "$LOGFILE"
  fi
done

echo "$(date +"%Y-%m-%d %H:%M:%S") - ===== Done System Files Acquisition =====" >> "$LOGFILE"

# This section is part of the configuration files, it was made this way
# since it contains symbolic links and many directories.
# Copy contents of /etc/rc*.d directories while maintaining directory structure
find /etc/rc*.d/ -type d -exec mkdir -p "$OUTPUT_DIR"/{} \;
find /etc/rc*.d/ -type f -exec cp --parents {} "$OUTPUT_DIR" \;

# Copy contents of /etc/init.d directory while maintaining directory structure
find /etc/init.d/ -type d -exec mkdir -p "$OUTPUT_DIR"/{} \;
find /etc/init.d/ -type f -exec cp --parents {} "$OUTPUT_DIR" \;

echo "$(date +"%Y-%m-%d %H:%M:%S") - ===== Starting User Configuration Files Acquisition =====" >> "$LOGFILE"

# Copy user configuration files while maintaining directory structure
while IFS=: read -r user _ _ _ _ home _; do
  if [ -d "$home" ]; then

    # Loops through list of user config files
    for file in "${USER_CONFIG_FILES[@]}"; do
      if [ -e "$home/$file" ]; then
        target_file="$OUTPUT_DIR$home/$file"
        target_dir=$(dirname "$target_file")
        mkdir -p "$target_dir"
        cp "$home/$file" "$target_file"
      else
        echo "$(date +"%Y-%m-%d %H:%M:%S") - File does not exist: $home/$file" >> "$LOGFILE"
      fi
    done
  fi
done < /etc/passwd

echo "$(date +"%Y-%m-%d %H:%M:%S") - ===== Done User Configuration Files Acquisition =====" >> "$LOGFILE"

echo "$(date +"%Y-%m-%d %H:%M:%S") - ===== Starting ProcFS Traversing =====" >> "$LOGFILE"

# Traverse /proc and copy files from each process directory
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
    process_dir="/proc/$pid"

    # Create corresponding process directory in the destination directory
    mkdir -p "$OUTPUT_DIR$process_dir"

    # Copy important artifacts from the process directory
    for artifact in "${PROC_PID_FILES[@]}"; do
        artifact_path="$process_dir/$artifact"

        # Copy artifact to the destination directory
        if [ -f "$artifact_path" ]; then
            cp -p "$artifact_path" "$OUTPUT_DIR$artifact_path"
        fi
    done
done

echo "$(date +"%Y-%m-%d %H:%M:%S") - ===== Done ProcFS Traversing =====" >> "$LOGFILE"

echo "$(date +"%Y-%m-%d %H:%M:%S") - ===== Starting ProcFS Files General Acquisition =====" >> "$LOGFILE"
# Iterate over the important files and copy them while maintaining directory structure
for file in "${PROC_IMPORTANT_FILES[@]}"; do
  source_path="$file"
  target_path="$OUTPUT_DIR/$file"

  # Create the target directory if it doesn't exist
  mkdir -p "$(dirname "$source_path")"

  # Copy the file while preserving directory structure
  cp -R "$source_path" "$target_path"
done

echo "$(date +"%Y-%m-%d %H:%M:%S") - ===== Done ProcFS Files General Acquisition =====" >> "$LOGFILE"

# Execute the 'history' command and save the output to a file
#history > "$history_file"

echo "$(date +"%Y-%m-%d %H:%M:%S") - ===== Starting System Information Acquisition =====" >> "$LOGFILE"

# System Information 
## Create System_Info directory
mkdir -p "$SYSTEM_ANALYSIS"
## Run these commands to collect information
uname -a                                       > "$SYSTEM_ANALYSIS/uname.txt"
uptime                                         > "$SYSTEM_ANALYSIS/uptime.txt"
date                                           > "$SYSTEM_ANALYSIS/date.txt"
timedatectl                                    > "$SYSTEM_ANALYSIS/timedatectl.txt"
hostname                                       > "$SYSTEM_ANALYSIS/hostname.txt"
hostnamectl                                    > "$SYSTEM_ANALYSIS/hostnamectl.txt"
df -h                                          > "$SYSTEM_ANALYSIS/df.txt"
free                                           > "$SYSTEM_ANALYSIS/free.txt"
lscpu                                          > "$SYSTEM_ANALYSIS/lscpu.txt"
lshw -short                                    > "$SYSTEM_ANALYSIS/lshw.txt"
lsusb                                          > "$SYSTEM_ANALYSIS/lsusb.txt"
lspci                                          > "$SYSTEM_ANALYSIS/lspci.txt"
lsscsi -s                                      > "$SYSTEM_ANALYSIS/lsscsi.txt"
rpm -qa                                        > "$SYSTEM_ANALYSIS/installed_packages.txt"
lsmod                                          > "$SYSTEM_ANALYSIS/lsmod.txt"
systemctl list-unit-files --type=service --all > "$SYSTEM_ANALYSIS/services_unit_files.txt"
systemctl list-units --type=service --all      > "$SYSTEM_ANALYSIS/services_units.txt"
systemctl list-timers --all                    > "$SYSTEM_ANALYSIS/timer_units.txt"
fdisk -l                                       > "$SYSTEM_ANALYSIS/fdisk.txt"
env                                            > "$SYSTEM_ANALYSIS/env.txt"

echo "$(date +"%Y-%m-%d %H:%M:%S") - ===== Done System Information Acquisition =====" >> "$LOGFILE"

echo "$(date +"%Y-%m-%d %H:%M:%S") - ===== Starting Process Information Acquisition =====" >> "$LOGFILE"

# Process Information
## Creates Process information directory
mkdir -p "$PROCESS_ANALYSIS_DIR"
## Run these commands to collect information
ps -eo user,pid,comm,args > "$PROCESS_ANALYSIS_DIR/process_list_medium.txt"
ps -eF                    > "$PROCESS_ANALYSIS_DIR/process_list_full.txt"
create_file_if_output_not_empty "ls -alR /proc/*/exe 2> /dev/null | grep deleted" "$PROCESS_ANALYSIS_DIR/process_no_binary_list.txt"

echo "$(date +"%Y-%m-%d %H:%M:%S") - ===== Done Process Information Acquisition =====" >> "$LOGFILE"

echo "$(date +"%Y-%m-%d %H:%M:%S") - ===== Starting Network Information Acquisition =====" >> "$LOGFILE"

# Network Information
## Creates Network information directory
mkdir -p "$NETWORK_ANALYSIS_DIR"
## Run these commands to collect information
ifconfig        > "$NETWORK_ANALYSIS_DIR/ifconfig.txt"
netstat -tunap  > "$NETWORK_ANALYSIS_DIR/netstat.txt"
ip route show   > "$NETWORK_ANALYSIS_DIR/routing_table.txt"
ip neigh show   > "$NETWORK_ANALYSIS_DIR/arp_cache.txt"
ss -tuln        > "$NETWORK_ANALYSIS_DIR/ss.txt"
ss -a -e -i     > "$NETWORK_ANALYSIS_DIR/ss_full.txt"
iptables-save   > "$NETWORK_ANALYSIS_DIR/iptables_rules.txt"

echo "$(date +"%Y-%m-%d %H:%M:%S") - ===== Done Network Information Acquisition =====" >> "$LOGFILE"

echo "$(date +"%Y-%m-%d %H:%M:%S") - ===== Starting Filesystem Information Acquisition =====" >> "$LOGFILE"

# File Information
## Creates File information directory
mkdir -p "$FILE_ANALYSIS_DIR"
## Run these commands to collect information about files
find / -type f -not -path "/proc/*" -not -path "/sys/*" -mmin -$((recent_modified_files_threshold * 60)) -printf "%TY-%Tm-%Td %TH:%TM,%p\n" 2>/dev/null > "$FILE_ANALYSIS_DIR/recent_modified_files.txt"
find / -type f -not -path "/proc/*" -not -path "/sys/*" -amin -$((recent_read_files_threshold * 60)) -printf "%AY-%Am-%Ad %AH:%AM,%p\n" 2>/dev/null > "$FILE_ANALYSIS_DIR/recent_accessed_files.txt"
find / -type f -executable -mmin -$((recent_modified_executables_threshold * 60)) -printf "%TY-%Tm-%Td %TH:%TM,%p\n" 2>/dev/null > "$FILE_ANALYSIS_DIR/recent_modified_executable_files.txt"
find / -type f -executable -print0 2>/dev/null | xargs -0 sha256sum 2>/dev/null > "$FILE_ANALYSIS_DIR/executable_files_sha256.txt"
lsof > "$FILE_ANALYSIS_DIR/open_files.txt"
create_file_if_output_not_empty "find / -type d -name '\.*'" "$FILE_ANALYSIS_DIR/hidden_directories.txt"

echo "$(date +"%Y-%m-%d %H:%M:%S") - ===== Done Filesystem Information Acquisition =====" >> "$LOGFILE"

echo "$(date +"%Y-%m-%d %H:%M:%S") - ===== Starting Security Sensors Information Acquisition =====" >> "$LOGFILE"

# AV & Security Sensors Information
## Creates Security Sensors & AV information directory
mkdir -p "$AV_ANALYSIS_DIR"
# Run these commands to collect security sensors info
sestatus > "$AV_ANALYSIS_DIR/sestatus.txt"

echo "$(date +"%Y-%m-%d %H:%M:%S") - ===== Done Security Sensors Information Acquisition =====" >> "$LOGFILE"

echo "$(date +"%Y-%m-%d %H:%M:%S") - ===== Starting User Information Acquisition =====" >> "$LOGFILE"

# User Information
## Create User_Info directory
mkdir -p "$USER_ANALYSIS_DIR"
# Run these commands to collect user information
last    > "$USER_ANALYSIS_DIR/last.txt"
lastlog > "$USER_ANALYSIS_DIR/lastlog.txt"
who -H  > "$USER_ANALYSIS_DIR/who.txt"
w       > "$USER_ANALYSIS_DIR/w.txt"

echo "$(date +"%Y-%m-%d %H:%M:%S") - ===== Done User Information Acquisition =====" >> "$LOGFILE"

# Rootkit Detection Tools
#rkhunter --check --sk > "$OUTPUT_DIR/rkhunter_scan.txt"

# End time
END_TIME=$(date +%s)

# Execution time
ELAPSED_TIME=$((END_TIME - START_TIME))
echo "$(date +"%Y-%m-%d %H:%M:%S") - Artifact collection completed in $ELAPSED_TIME seconds. Artifacts saved in $OUTPUT_DIR." >> "$LOGFILE"

# zip output directory -v is for verbose
tar -czvf "$ZIP_DIR/results.tar.gz" "$OUTPUT_DIR"

# Delete uncompressed output directory
rm -rf "$OUTPUT_DIR"