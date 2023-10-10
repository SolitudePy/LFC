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
  "/etc/profile"
  "/etc/profile.d"
  "/etc/bashrc"
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
  "/etc/crontab"
  "/etc/anacrontab"
  "/etc/cron.d"
  "/etc/cron.daily"
  "/etc/cron.hourly"
  "/etc/cron.monthly"
  "/etc/cron.weekly"
  "/etc/inittab"
  "/etc/modprobe.d"
  "/etc/grub2.cfg"
  "/etc/grub.d"
  "/etc/default"
  "/boot/grub2/grub.cfg"
  "/etc/ld.so.conf"
  "/etc/ld.so.conf.d"
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
  "/var/www"
  # Add more files as needed
  )

IMPORTANT_LOG_FILES=(
  "/var/log/secure"
  "/var/log/audit"
  "/var/log/boot.log"
  "/var/log/btmp"
  "/var/log/wtmp"
  "/var/log/cron"
  "/var/log/laurel"
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
    "fd"
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

# Array of blacklist paths to not include in the output directory
BLACKLIST_FILE_DESCRIPTORS=(
  "/var/lib/sss/mc/"
  "/run/log/journal/"
)

create_file_if_output_not_empty() {
    # Creates a file only if command has output.
    local command="$1"
    local filename="$2"

    local output
    output=$(eval "$command")

    # Checks if command's output is not empty.
    if [ -n "$output" ]; then
        echo "$output" > "$filename"
    fi
}

write_log() {
  # Writes a log message to a log file.
  local message="$1"
  local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  echo "[$timestamp] - $message" >> "$LOGFILE"
}

check_if_value_in_blacklist() {
    # Checks if a value is in a list or is a match of a value in list.
    local target_path="$1"

    # Loop through the blacklist
    for blacklist_path in "${BLACKLIST_FILE_DESCRIPTORS[@]}"; do
        if [[ "$target_path" == "$blacklist_path" || "$target_path" == "$blacklist_path"* ]]; then
            
            # Target path is in the list
            return 1
        fi
    done

    # Target path is not in the list
    return 0  
}

copy_configuration_files() {
  # Copy configuration files from a list of configuration files.
  for file in "${SYSTEM_FILES[@]}"; do
    if [ -f "$file" -a -s "$file" ]; then
      # Get the directory path of the file
      dir_path=$(dirname "$file")

      # Create the corresponding directory structure in the output directory.
      mkdir -p "$OUTPUT_DIR$dir_path"

      # Copy the file to the output directory with its directory structure.
      cp -p "$file" "$OUTPUT_DIR$dir_path"

    elif [ -d "$file" ]; then

      # Check if the directory is empty.
      if [ -n "$(find "$file" -mindepth 1 -print -quit)" ]; then

        # Get the directory path of the file.
        dir_path=$(dirname "$file")

        # Create the corresponding directory structure in the output directory.
        mkdir -p "$OUTPUT_DIR$dir_path"

        # Directory is not empty, copy its contents recursively
        cp -pR "$file" "$OUTPUT_DIR$file"
      fi
    else
      write_log "File or directory does not exist or empty: $file"
    fi
  done

  # This section is part of the configuration files, it was made this way
  # since it contains symbolic links and many directories.

  # Copy contents of /etc/rc*.d directories while maintaining directory structure
  find /etc/rc*.d/ -type d -exec mkdir -p "$OUTPUT_DIR"/{} \;
  find /etc/rc*.d/ -type f -exec cp --parents {} "$OUTPUT_DIR" \;

  # Copy contents of /etc/init.d directory while maintaining directory structure
  find /etc/init.d/ -type d -exec mkdir -p "$OUTPUT_DIR"/{} \;
  find /etc/init.d/ -type f -exec cp --parents {} "$OUTPUT_DIR" \;
}

copy_user_configuration_files() {
  # Copy user configuration files while maintaining directory structure
  while IFS=: read -r user _ _ _ _ home _; do
    if [ -d "$home" ]; then

      # Loops through list of user config files
      for file in "${USER_CONFIG_FILES[@]}"; do
        if [ -e "$home/$file" ]; then
          target_file="$OUTPUT_DIR$home/$file"
          target_dir=$(dirname "$target_file")
          mkdir -p "$target_dir"
          cp -p "$home/$file" "$target_file"
        else
          write_log "File does not exist: $home/$file"
        fi
      done
    fi
  done < /etc/passwd
}

copy_important_logs() {
    # Copies important logs from a list of log files/directories.
    for file in "${IMPORTANT_LOG_FILES[@]}"; do
        if [ -e "$file" ]; then
            if [ -d "$file" ]; then

                # If it's a directory, copy its contents to the target directory.
                local target_dir="$OUTPUT_DIR$file"
                if [ ! -d "$target_dir" ]; then
                    mkdir -p "$target_dir"
                fi
                cp -R "$file"/* "$target_dir/"
            else

                # Copy individual log file.
                local target_dir="$OUTPUT_DIR$(dirname "$file")"
                mkdir -p "$target_dir"
                cp "$file" "$target_dir"
            fi
        else
          write_log "File does not exist: $file"
        fi    
    done
}

traverse_procfs() {
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
          elif [ -d "$artifact_path" ]; then
              for file in "$artifact_path"/*; do
        
                  # Checks if it's a regular file.
                  if [ -f "$file" ]; then

                    # Create artifact directory only if it contains regular files.
                    mkdir -p "$OUTPUT_DIR$artifact_path"

                    # Get the target file's path from a symbolic link
                    target_path=$(readlink -f "$file")

                    # Checks if original target path is not in blacklist.
                    if check_if_value_in_blacklist "$target_path"; then
                      # Extract the original file name from the path
                      target_filename=$(basename "$target_path")
                      
                      # Copies the file while preserving directory structure and original file name.
                      cp -p "$file" "$OUTPUT_DIR$artifact_path/$target_filename" 2> /dev/null
                    fi
                  fi
              done
              #cp -LR "$artifact_path" "$OUTPUT_DIR$artifact_path"
          fi
      done
  done

  # Iterate over the important files and copy them while maintaining directory structure
  for file in "${PROC_IMPORTANT_FILES[@]}"; do
    source_path="$file"
    target_path="$OUTPUT_DIR/$file"

    # Create the target directory if it doesn't exist
    mkdir -p "$(dirname "$source_path")"

    # Copy the file while preserving directory structure
    cp -pR "$source_path" "$target_path"
  done
}

generate_system_analysis_info(){
  # System Analysis 
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
}

generate_process_analysis_info() {
  # Process Analysis
  ## Creates Process information directory
  mkdir -p "$PROCESS_ANALYSIS_DIR"
  ## Run these commands to collect information
  ps -eo user,pid,comm,args > "$PROCESS_ANALYSIS_DIR/process_list_medium.txt"
  ps -eF                    > "$PROCESS_ANALYSIS_DIR/process_list_full.txt"
  create_file_if_output_not_empty "ls -alR /proc/*/exe 2> /dev/null | grep deleted" "$PROCESS_ANALYSIS_DIR/process_deleted_binary.txt"
}

generate_network_analysis_info() {
  # Network Analysis
  ## Creates Network information directory
  mkdir -p "$NETWORK_ANALYSIS_DIR"
  ## Run these commands to collect information
  ifconfig        > "$NETWORK_ANALYSIS_DIR/ifconfig.txt"
  netstat -tunap  > "$NETWORK_ANALYSIS_DIR/netstat.txt"
  ip route show   > "$NETWORK_ANALYSIS_DIR/routing_table.txt"
  ip neigh show   > "$NETWORK_ANALYSIS_DIR/arp_cache.txt"
  ss -tuln        > "$NETWORK_ANALYSIS_DIR/ss.txt"
  ss -a           > "$NETWORK_ANALYSIS_DIR/ss_full.txt"
  iptables-save   > "$NETWORK_ANALYSIS_DIR/iptables_rules.txt"
}

generate_file_analysis_info() {
  # File Analysis
  ## Creates File information directory
  mkdir -p "$FILE_ANALYSIS_DIR"
  ## Run these commands to collect information about files
  find / -type f -not -path "/proc/*" -not -path "/sys/*" -mmin -$((recent_modified_files_threshold * 60)) -printf "%TY-%Tm-%Td %TH:%TM,%p\n" 2>/dev/null > "$FILE_ANALYSIS_DIR/recent_modified_files.txt"
  find / -type f -not -path "/proc/*" -not -path "/sys/*" -amin -$((recent_read_files_threshold * 60)) -printf "%AY-%Am-%Ad %AH:%AM,%p\n" 2>/dev/null > "$FILE_ANALYSIS_DIR/recent_accessed_files.txt"
  find / -type f -executable -mmin -$((recent_modified_executables_threshold * 60)) -printf "%TY-%Tm-%Td %TH:%TM,%p\n" 2>/dev/null > "$FILE_ANALYSIS_DIR/recent_modified_executable_files.txt"
  find / -type f -executable -print0 2>/dev/null | xargs -0 sha256sum 2>/dev/null > "$FILE_ANALYSIS_DIR/executable_files_sha256.txt"
  lsof > "$FILE_ANALYSIS_DIR/open_files.txt"
  create_file_if_output_not_empty "find / -type d -name '\.*'" "$FILE_ANALYSIS_DIR/hidden_directories.txt"
}

generate_av_analysis_info() {
  # AV & Security Sensors Analysis
  ## Creates Security Sensors & AV information directory
  mkdir -p "$AV_ANALYSIS_DIR"
  # Run these commands to collect security sensors info
  sestatus > "$AV_ANALYSIS_DIR/sestatus.txt"
}

generate_user_analysis_info() {
  # User Analysis
  ## Create User_Info directory
  mkdir -p "$USER_ANALYSIS_DIR"
  # Run these commands to collect user information
  last    > "$USER_ANALYSIS_DIR/last.txt"
  lastlog > "$USER_ANALYSIS_DIR/lastlog.txt"
  who -H  > "$USER_ANALYSIS_DIR/who.txt"
  w       > "$USER_ANALYSIS_DIR/w.txt"

}

# ===================== MAIN =====================

# Deletes former output directory, just in case
rm -rf "$OUTPUT_DIR"

# Create the output directory
mkdir -p "$OUTPUT_DIR"

# This is first due to script activies being logged if not.
# ================================ FILE ANALYSIS ===================================
write_log "===== Starting Filesystem Information Acquisition        ====="
generate_file_analysis_info
write_log "===== Done Filesystem Information Acquisition            ====="

# ================================ SYSTEM FILES ACQUISTION =========================
write_log "===== Starting System Files Acquisition                  ====="
copy_configuration_files
write_log "===== Done System Files Acquisition                      ====="

# ================================ USER FILES ACQUISITION  =========================
write_log "===== Starting User Configuration Files Acquisition      ====="
copy_user_configuration_files
write_log "===== Done User Configuration Files Acquisition          ====="

# ================================ LOG FILES ACQUISITION  ==========================
write_log "===== Starting Log Files Acquisition                     ====="
copy_important_logs
write_log "===== Done Log Files Acquisition                         ====="

# ================================ PROCFS TRAVERSING ===============================
write_log "===== Starting ProcFS Traversing                         ====="
traverse_procfs
write_log "===== Done ProcFS Traversing                             ====="

# ================================ SYSTEM ANALYSIS =================================
write_log "===== Starting System Information Acquisition            ====="
generate_system_analysis_info
write_log "===== Done System Information Acquisition                ====="

# ================================ PROCESS ANALYSIS ================================
write_log "===== Starting Process Information Acquisition           ====="
generate_process_analysis_info
write_log "===== Done Process Information Acquisition               ====="

# ================================ NETWORK ANALYSIS ================================
write_log "===== Starting Network Information Acquisition           ====="
generate_network_analysis_info
write_log "===== Done Network Information Acquisition               ====="

# ================================ AV ANALYSIS =====================================
write_log "===== Starting Security Sensors Information Acquisition  ====="
generate_av_analysis_info
write_log "===== Done Security Sensors Information Acquisition      ====="

# ================================ USER ANALYSIS ==================================
write_log "===== Starting User Information Acquisition              ====="
generate_user_analysis_info
write_log "===== Done User Information Acquisition                  ====="

# End time
END_TIME=$(date +%s)

# Execution time
ELAPSED_TIME=$((END_TIME - START_TIME))
write_log "======================================================================================"
write_log "Artifact collection completed in $ELAPSED_TIME seconds. Artifacts saved in $OUTPUT_DIR."

# zip output directory -v is for verbose
tar -czf "$ZIP_DIR/result.tar.gz" -C "$ZIP_DIR" result

# Delete uncompressed output directory
rm -rf "$OUTPUT_DIR"