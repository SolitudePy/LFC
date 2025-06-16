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
- 🛡️ **Osquery Integration**: Leverages [osquery](https://github.com/osquery/osquery) for flexible and structured system data collection.


## Quick Usage

### Prerequisites
- Root privileges (required for accessing protected files and directories)
- Sufficient disk space for collected artifacts
- Standard Linux utilities (find, ps, netstat, etc.)
- `osquery` (for osquery integration)

### Basic Usage
```
Usage: ./LFC.sh [OUTPUT_DIRECTORY] [--no-osquery]
  OUTPUT_DIRECTORY: Optional. Directory where forensic artifacts will be collected.
                    Default: /tmp/result
  --no-osquery:     Optional. Skip osquery collection.

Examples:
  ./LFC.sh             # Use default output directory (/tmp/result) and run osquery
  ./LFC.sh /var/output # Use custom output directory and run osquery
  ./LFC.sh --no-osquery # Use default output directory and skip osquery
  ./LFC.sh /var/output --no-osquery # Use custom output directory and skip osquery

```

### Example Collection Session

```bash
# Clone & navigate to the collector directory
git clone https://github.com/SolitudePy/LFC.git
cd LFC/LFC

# Make the script executable (if needed)
chmod +x LFC.sh

# Run the collector with custom output directory (includes osquery by default)
# After completion, a compressed archive will be created: 
# /forensics/case-001.tar.gz
sudo ./LFC.sh /forensics/case-001

# Unarchive results
tar -xzvf /forensics/case-001.tar.gz -C /forensics
```

## License

This project is licensed under the GNU General Public License v3.0. See the `LICENSE` file for details.