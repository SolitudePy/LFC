# 🕵️ Linux Forensics Collector

## Background

LFC is a comprehensive bash script designed for digital forensics investigators and incident response teams working with Linux systems. This tool automates the collection of critical forensic artifacts from a compromised or suspicious Linux system, providing investigators with a structured dataset for analysis.

This tool is particularly useful for:
- **Incident Response**: Quickly gathering evidence during active incidents
- **Digital Forensics**: Comprehensive artifact collection for legal proceedings
- **Security Auditing**: Baseline system state documentation
- **Threat Hunting**: Proactive search for indicators of compromise

## Learning
For comprehensive learning, you can refer to my Linux Forensics study guide here:
https://github.com/SolitudePy/LinuxForensicsLearn

## Features

- 🚀 **Rapid Execution**: Ensures timely data acquisition during critical incidents.
- 💻 **Comprehensive System Enumeration**: Gathers extensive details about hardware, OS, kernel, installed packages, active services, disk configurations, environment variables, system logs, and user activities.
- ⚙️ **In-depth Process Analysis**: Provides detailed process listings, hierarchical trees, detection of deleted binaries, memory mapping, and file descriptor information, leveraging the `/proc` filesystem.
- 🌐 **Thorough Network Forensics**: Captures network interface configurations, active connections, routing tables, firewall rules, and socket information.
- ⏱️ **Timeline Generation**: Creates a TSK v3 compatible bodyfile for chronological event analysis.
- 🔒 **Executable Integrity Verification**: Performs SHA256 hashing of all executable files to ensure integrity.


## Quick Usage

### Prerequisites
- Root privileges (required for accessing protected files and directories)
- Sufficient disk space for collected artifacts
- Standard Linux utilities (find, ps, netstat, etc.)

### Basic Usage

**Run with default output directory (`/tmp/result`):**
```bash
sudo ./LFC.SH
```

**Run with custom output directory:**
```bash
sudo ./LFC.SH /path/to/output/directory
```

**Display help:**
```bash
./LFC.SH --help
```

### Example Collection Session

```bash
# Navigate to the collector directory
cd /path/to/LinuxForensics/Collector

# Make the script executable (if needed)
chmod +x LFC.SH

# Run the collector with custom output directory
sudo ./LFC.SH /forensics/case-001

# The script will create and populate the directory structure:
# /forensics/case-001/
# ├── log_file.log
# ├── System_Analysis/
# ├── Process_Analysis/
# ├── Network_Analysis/
# ├── File_Analysis/
# │   └── bodyfile.txt (TSK timeline)
# ├── User_Analysis/
# ├── AV_Analysis/
# └── [copied system files and logs]

# After completion, a compressed archive will be created:
# /forensics/case-001.tar.gz

# Extracting results
tar -xzvf /forensics/case-001.tar.gz -C /tmp
```

## License

This project is licensed under the GNU General Public License v3.0. See the `LICENSE` file for details.