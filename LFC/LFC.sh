#!/bin/bash

# Function to display usage information
usage() {
    echo "Usage: $0 [OUTPUT_DIRECTORY] [--no-osquery] [--tcp-stream IP:PORT]"
    echo "  OUTPUT_DIRECTORY: Optional. Directory where forensic artifacts will be collected."
    echo "                    Default: /tmp/result"
    echo "  --no-osquery:     Optional. Skip osquery collection."
    echo "  --tcp-stream:     Optional. Stream tarball to specified IP:PORT over TCP."
    echo "                    Format: IP:PORT (e.g., 192.168.1.100:8080)"
    echo ""
    echo "Examples:"
    echo "  $0             # Use default output directory (/tmp/result) and run osquery"
    echo "  $0 /var/output # Use custom output directory and run osquery"
    echo "  $0 --no-osquery # Use default output directory and skip osquery"
    echo "  $0 /var/output --no-osquery # Use custom output directory and skip osquery"
    echo "  $0 --tcp-stream 192.168.1.100:8080 # Stream artifacts over TCP"
    echo "  $0 /var/output --no-osquery --tcp-stream 10.0.0.5:9999 # Custom dir, no osquery, TCP stream"
    exit 1
}

# Parse command line arguments
SKIP_OSQUERY=false
TEMP_OUTPUT_DIR=""
TCP_STREAM=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
        usage
        ;;
        --no-osquery)
        SKIP_OSQUERY=true
        shift # Remove --no-osquery from processing
        ;;
        --tcp-stream)
        # Next argument should be IP:PORT
        shift
        TCP_STREAM="$1"
        if [[ ! "$TCP_STREAM" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$ ]]; then
            echo "Error: Invalid TCP stream format. Expected IP:PORT (e.g., 192.168.1.100:8080)"
            usage
        fi
        shift
        ;;
        --tcp-stream=*)
        # Handle --tcp-stream=IP:PORT format
        TCP_STREAM="${1#*=}"
        if [[ ! "$TCP_STREAM" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$ ]]; then
            echo "Error: Invalid TCP stream format. Expected IP:PORT (e.g., 192.168.1.100:8080)"
            usage
        fi
        shift
        ;;
        -*)
        echo "Error: Unknown option $1"
        usage
        ;;
        *)
        # If an argument is not a flag, and TEMP_OUTPUT_DIR is not set, it's the output directory
        if [ -z "$TEMP_OUTPUT_DIR" ]; then
            TEMP_OUTPUT_DIR="$1"
        else
            echo "Error: Too many arguments provided: $1"
            usage
        fi
        shift
        ;;
    esac
done

# Set output directory (use argument if provided, otherwise default)
OUTPUT_DIR="${TEMP_OUTPUT_DIR:-/tmp/result}"

# Validate output directory path
if [ -z "$OUTPUT_DIR" ]; then
    echo "Error: Output directory cannot be empty."
    exit 1
fi

# Check if script is running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)."
    echo "Many forensic artifacts require root privileges to access."
    exit 1
fi

# Start time
START_TIME=$(date +%s)

# Constant Variables (derived from OUTPUT_DIR)
ZIP_DIR="$(dirname "$OUTPUT_DIR")"
LOGFILE="$OUTPUT_DIR/log_file.log"
SYSTEM_ANALYSIS="$OUTPUT_DIR/System_Analysis"
AV_ANALYSIS_DIR="$OUTPUT_DIR/AV_Analysis"
USER_ANALYSIS_DIR="$OUTPUT_DIR/User_Analysis"
FILE_ANALYSIS_DIR="$OUTPUT_DIR/File_Analysis"
NETWORK_ANALYSIS_DIR="$OUTPUT_DIR/Network_Analysis"
PROCESS_ANALYSIS_DIR="$OUTPUT_DIR/Process_Analysis"
OSQUERY_ANALYSIS_DIR="$OUTPUT_DIR/osquery" # New directory for osquery results

# osquery settings
OSQUERY_PATH="/usr/bin/osqueryi" # Default path to osqueryi, adjust if needed
OSQUERY_OUTPUT_FORMAT="json" # Output format for osquery: json, csv, etc.

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
  "/etc/cron.allow"
  "/etc/cron.deny"
  "/etc/inittab"
  "/etc/modprobe.d"
  "/etc/grub2.cfg"
  "/etc/grub.d"
  "/etc/default"
  "/boot/grub2/grub.cfg"
  "/etc/ld.so.conf"
  "/etc/ld.so.conf.d"
  "/etc/ld.so.preload"
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
  "/var/log/auth.log"
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
  "$OUTPUT_DIR" # Add output directory to blacklist to avoid recursion if it's under /
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
  local level="$1"
  local message="$2"
  local timestamp
  timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  echo "[$timestamp] [$level] - $message" >> "$LOGFILE"
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

stream_tarball_over_tcp() {
    # Streams tarball over TCP to specified IP:PORT
    # Uses /dev/tcp as primary method, falls back to nc/ncat if available
    local ip_port="$1"
    local tarball_path="$2"
    
    # Extract IP and port from IP:PORT format
    local ip="${ip_port%:*}"
    local port="${ip_port#*:}"
    
    write_log "INFO" "Attempting to stream tarball $tarball_path to $ip:$port"
    
    # Method 1: Try /dev/tcp (built into bash)
    if exec 3<> "/dev/tcp/$ip/$port" 2>/dev/null; then
        write_log "INFO" "Connected using /dev/tcp method"
        if cat "$tarball_path" >&3 2>/dev/null; then
            write_log "INFO" "Successfully streamed tarball using /dev/tcp"
            exec 3>&-  # Close the connection
            return 0
        else
            write_log "ERROR" "Failed to stream data using /dev/tcp"
            exec 3>&-  # Close the connection
        fi
    else
        write_log "WARNING" "/dev/tcp connection failed, trying fallback methods"
    fi
    
    # Method 2: Try netcat (nc)
    if command -v nc >/dev/null 2>&1; then
        write_log "INFO" "Attempting to use nc (netcat)"
        if nc "$ip" "$port" < "$tarball_path" 2>/dev/null; then
            write_log "INFO" "Successfully streamed tarball using nc"
            return 0
        else
            write_log "ERROR" "Failed to stream using nc"
        fi
    fi
    
    # Method 3: Try ncat (from nmap)
    if command -v ncat >/dev/null 2>&1; then
        write_log "INFO" "Attempting to use ncat"
        if ncat "$ip" "$port" < "$tarball_path" 2>/dev/null; then
            write_log "INFO" "Successfully streamed tarball using ncat"
            return 0
        else
            write_log "ERROR" "Failed to stream using ncat"
        fi
    fi
    
    # All methods failed
    write_log "ERROR" "All TCP streaming methods failed. Tarball remains locally at $tarball_path"
    return 1
}

copy_configuration_files() {
  # Copy configuration files from a list of configuration files.
  for file in "${SYSTEM_FILES[@]}"; do
    if [ -f "$file" ] && [ -s "$file" ]; then
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
      write_log "WARNING" "File or directory does not exist or empty: $file"
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
  while IFS=: read -r _ _ _ _ _ home _; do
    if [ -d "$home" ]; then

      # Loops through list of user config files
      for file in "${USER_CONFIG_FILES[@]}"; do
        if [ -e "$home/$file" ]; then
          target_file="$OUTPUT_DIR$home/$file"
          target_dir=$(dirname "$target_file")
          mkdir -p "$target_dir"
          cp -p "$home/$file" "$target_file"
        else
          write_log "WARNING" "File does not exist: $home/$file"
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
                local target_dir
                target_dir="$OUTPUT_DIR$file"
                if [ ! -d "$target_dir" ]; then
                    mkdir -p "$target_dir"
                fi
                cp -R "$file"/* "$target_dir/"
            else

                # Copy individual log file.
                local target_dir
                target_dir="$OUTPUT_DIR$(dirname "$file")"
                mkdir -p "$target_dir"
                cp "$file" "$target_dir"
            fi
        else
          write_log "WARNING" "File does not exist: $file"
        fi    
    done
}

traverse_procfs() {
  # Traverse /proc and copy files from each process directory
  for pid_dir in /proc/[0-9]*; do
    if [ -d "$pid_dir" ]; then # Ensure it's a directory
      pid=$(basename "$pid_dir")
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
    fi
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
  
  # Generate bodyfile first to capture system state before any other file operations
  generate_bodyfile
  
  ## Run these commands to collect information about files
  find / -type f -not -path "/proc/*" -not -path "/sys/*" -mmin -$((recent_modified_files_threshold * 60)) -printf "%TY-%Tm-%Td %TH:%TM,%p\n" 2>/dev/null > "$FILE_ANALYSIS_DIR/recent_modified_files.txt"
  find / -type f -not -path "/proc/*" -not -path "/sys/*" -amin -$((recent_read_files_threshold * 60)) -printf "%AY-%Am-%Ad %AH:%AM,%p\n" 2>/dev/null > "$FILE_ANALYSIS_DIR/recent_accessed_files.txt"
  find / -type f -executable -mmin -$((recent_modified_executables_threshold * 60)) -printf "%TY-%Tm-%Td %TH:%TM,%p\n" 2>/dev/null > "$FILE_ANALYSIS_DIR/recent_modified_executable_files.txt"
  find / -type f -executable -print0 2>/dev/null | xargs -0 sha256sum 2>/dev/null > "$FILE_ANALYSIS_DIR/executable_files_sha256.txt"
  lsof > "$FILE_ANALYSIS_DIR/open_files.txt" 2>/dev/null
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

generate_bodyfile() {
  # Generate bodyfile - a timeline format containing file metadata
  # Format: MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
  
  write_log "INFO" "Generating bodyfile (filesystem timeline)..."
  
  # Create bodyfile in File Analysis directory
  local bodyfile_path="$FILE_ANALYSIS_DIR/bodyfile.txt"
  
  # Add header comment to bodyfile
  {
    echo "# Bodyfile generated on $(date)"
    echo "# Format: MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime"
    echo "# Times are in Unix epoch format"
  } >> "$bodyfile_path"
  
  # Generate bodyfile using find with stat information
  # Exclude /proc, /sys, and other virtual filesystems to avoid errors and reduce noise
  # Use find's -printf to get most information directly, avoiding multiple command calls per file
  find / \( -path "/proc" -o -path "/sys" -o -path "/dev" -o -path "/run" \) -prune -o -type f -printf "0|%p|%i|%M|%U|%G|%s|%A@|%T@|%C@|0\n" 2>/dev/null | \
  sed 's/\\([0-9]\\+\\)\\.[0-9]*/\\1/g' >> "$bodyfile_path"
  
  write_log "INFO" "Bodyfile generated successfully"
}

# ===================== OSQUERY COLLECTION =====================
run_osquery_collection() {
    if [ "$SKIP_OSQUERY" = true ]; then
        write_log "INFO" "Skipping osquery collection as per user request."
        return
    fi

    if ! command -v "$OSQUERY_PATH" &> /dev/null; then
        write_log "WARNING" "osqueryi not found at $OSQUERY_PATH. Skipping osquery collection."
        write_log "WARNING" "Please install osquery or adjust OSQUERY_PATH variable in the script."
        return
    fi

    write_log "INFO" "===== Starting osquery Collection                      ====="
    mkdir -p "$OSQUERY_ANALYSIS_DIR"

    # Declare associative array: "query" => "output filename"
    # Using a simple array for query and filename pairs for broader compatibility (e.g. older bash)
    # Each pair is: "Query string" "output_filename_without_extension"
    local queries_and_files=(
      "SELECT * FROM users;" "users"
      "SELECT * FROM rpm_packages;" "rpm_packages"
      "SELECT p.path, p.name, p.cmdline, p.on_disk, p.uid, u.username, h.md5, h.sha1, h.sha256 FROM processes AS p LEFT JOIN hash AS h ON p.path = h.path LEFT JOIN users AS u ON p.uid = u.uid;" "processes"
      "SELECT * FROM startup_items;" "startup_items"
      "SELECT * FROM systemd_units;" "systemd_units"
      "SELECT * FROM crontab;" "crontab"
      "SELECT * FROM etc_hosts;" "etc_hosts"
      "SELECT * FROM kernel_modules;" "kernel_modules"
      "SELECT * FROM mounts;" "mounts"
      "SELECT * FROM suid_bin;" "suid_bin"
      "SELECT * FROM arp_cache;" "arp_cache"
      "SELECT * FROM yum_sources;" "yum_sources"
      "SELECT * FROM apt_sources;" "apt_sources"
      "SELECT * FROM dns_resolvers;" "dns_resolvers"
      "SELECT DISTINCT p.pid, p.name AS process_name, p.cmdline AS command_line, p.uid AS user_id, u.username AS username, s.local_address, s.local_port, s.remote_address, s.remote_port, s.path FROM process_open_sockets AS s LEFT JOIN processes AS p ON s.pid = p.pid LEFT JOIN users AS u ON p.uid = u.uid;" "process_open_sockets"
      "SELECT DISTINCT o.path AS file, o.pid, p.name AS process_name, p.cmdline, p.uid, u.username FROM process_open_files AS o LEFT JOIN processes AS p ON o.pid = p.pid LEFT JOIN users AS u ON p.uid = u.uid;" "process_open_files"
      "SELECT a.key_file, a.key, a.algorithm, u.uid, u.username FROM users AS u LEFT JOIN authorized_keys AS a ON u.uid = a.uid;" "authorized_keys"
      "SELECT * FROM interface_addresses;" "interface_addresses"
      "SELECT * FROM interface_details;" "interface_details"
      "SELECT * FROM kernel_info;" "kernel_info"
      "SELECT * FROM last;" "last_logins"
      "SELECT * FROM logged_in_users;" "logged_in_users"
      "SELECT * FROM os_version;" "os_version"
      "SELECT * FROM users JOIN shell_history using(uid);" "shell_history"
      "SELECT * FROM system_controls;" "system_controls"
      "SELECT * FROM uptime;" "uptime"
      # Add more queries as needed
    )

    # Loop through and run each query
    i=0
    while [ $i -lt ${#queries_and_files[@]} ]; do
      query="${queries_and_files[$i]}"
      i=$((i + 1))
      filename_base="${queries_and_files[$i]}"
      i=$((i + 1))

      outfile="$OSQUERY_ANALYSIS_DIR/${filename_base}.$OSQUERY_OUTPUT_FORMAT"
      write_log "INFO" "Running osquery: $query -> $outfile"
      # Redirect osqueryi stderr to the main log file
      if echo "$query" | "$OSQUERY_PATH" --"$OSQUERY_OUTPUT_FORMAT" > "$outfile" 2>> "$LOGFILE"; then
        write_log "INFO" "Successfully executed: $query"
      else
        write_log "ERROR" "Error executing osquery: $query. Exit code: $?. Output file $outfile may be empty or incomplete. Check $LOGFILE for osquery error messages."
        # Optionally remove empty/failed output file
        [ ! -s "$outfile" ] && rm -f "$outfile"
      fi
    done
    write_log "INFO" "===== Done osquery Collection                          ====="
}

# ===================== MAIN =====================

# Deletes former output directory, just in case
rm -rf "$OUTPUT_DIR"

# Create the output directory
mkdir -p "$OUTPUT_DIR"

# Run osquery collection first if not skipped
run_osquery_collection

# This is first usually due to script activies being logged if not.
# ================================ FILE ANALYSIS ===================================
write_log "INFO" "===== Starting Filesystem Information Acquisition        ====="
generate_file_analysis_info
write_log "INFO" "===== Done Filesystem Information Acquisition            ====="

# ================================ SYSTEM FILES ACQUISTION =========================
write_log "INFO" "===== Starting System Files Acquisition                  ====="
copy_configuration_files
write_log "INFO" "===== Done System Files Acquisition                      ====="

# ================================ USER FILES ACQUISITION  =========================
write_log "INFO" "===== Starting User Configuration Files Acquisition      ====="
copy_user_configuration_files
write_log "INFO" "===== Done User Configuration Files Acquisition          ====="

# ================================ LOG FILES ACQUISITION  ==========================
write_log "INFO" "===== Starting Log Files Acquisition                     ====="
copy_important_logs
write_log "INFO" "===== Done Log Files Acquisition                         ====="

# ================================ PROCFS TRAVERSING ===============================
write_log "INFO" "===== Starting ProcFS Traversing                         ====="
traverse_procfs
write_log "INFO" "===== Done ProcFS Traversing                             ====="

# ================================ SYSTEM ANALYSIS =================================
write_log "INFO" "===== Starting System Information Acquisition            ====="
generate_system_analysis_info
write_log "INFO" "===== Done System Information Acquisition                ====="

# ================================ PROCESS ANALYSIS ================================
write_log "INFO" "===== Starting Process Information Acquisition           ====="
generate_process_analysis_info
write_log "INFO" "===== Done Process Information Acquisition               ====="

# ================================ NETWORK ANALYSIS ================================
write_log "INFO" "===== Starting Network Information Acquisition           ====="
generate_network_analysis_info
write_log "INFO" "===== Done Network Information Acquisition               ====="

# ================================ AV ANALYSIS =====================================
write_log "INFO" "===== Starting Security Sensors Information Acquisition  ====="
generate_av_analysis_info
write_log "INFO" "===== Done Security Sensors Information Acquisition      ====="

# ================================ USER ANALYSIS ==================================
write_log "INFO" "===== Starting User Information Acquisition              ====="
generate_user_analysis_info
write_log "INFO" "===== Done User Information Acquisition                  ====="

# End time
END_TIME=$(date +%s)

# Execution time
ELAPSED_TIME=$((END_TIME - START_TIME))
write_log "INFO" "======================================================================================"
write_log "INFO" "Artifact collection completed in $ELAPSED_TIME seconds. Artifacts saved in $OUTPUT_DIR."

# Create tar archive of the collected artifacts
OUTPUT_BASENAME=$(basename "$OUTPUT_DIR")
PARENT_DIR=$(dirname "$OUTPUT_DIR")
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
HOSTNAME=$(hostname -s)
TARBALL_FILENAME="lfc_${HOSTNAME}_${TIMESTAMP}.tar.gz"
TARBALL_PATH="$ZIP_DIR/$TARBALL_FILENAME"
tar -czf "$TARBALL_PATH" -C "$PARENT_DIR" "$OUTPUT_BASENAME"

# Delete uncompressed output directory
rm -rf "$OUTPUT_DIR"

# Handle TCP streaming if requested
if [ -n "$TCP_STREAM" ]; then
    # Create a temporary log file for post-processing operations since original log is now archived
    TEMP_LOGFILE="$ZIP_DIR/lfc_tcp_streaming.log"
    
    # Temporarily redirect write_log to the temp log file
    ORIGINAL_LOGFILE="$LOGFILE"
    LOGFILE="$TEMP_LOGFILE"
    
    write_log "INFO" "TCP streaming requested to $TCP_STREAM"
    
    if stream_tarball_over_tcp "$TCP_STREAM" "$TARBALL_PATH"; then
        write_log "INFO" "Successfully streamed tarball over TCP. Removing local copy."
        rm -f "$TARBALL_PATH"
        write_log "INFO" "Forensic artifacts streamed to $TCP_STREAM and local tarball removed."
        echo "Forensic artifacts streamed to $TCP_STREAM and local tarball removed."
        echo "TCP streaming log saved at: $TEMP_LOGFILE"
    else
        write_log "ERROR" "TCP streaming failed. Tarball remains at $TARBALL_PATH"
        write_log "INFO" "Forensic artifacts collection completed. Local tarball saved at $TARBALL_PATH"
        echo "TCP streaming failed. Tarball remains at $TARBALL_PATH"
        echo "TCP streaming log saved at: $TEMP_LOGFILE"
    fi
    
    # Restore original logfile variable (though it won't be used again)
    LOGFILE="$ORIGINAL_LOGFILE"
else
    echo "Forensic artifacts collection completed. Tarball saved at $TARBALL_PATH"
fi