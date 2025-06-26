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
- 📡 **TCP Streaming**: Stream collected artifacts directly to a remote destination over TCP, eliminating the need for local storage.


## Quick Usage

### Prerequisites
- Root privileges (required for accessing protected files and directories)
- Sufficient disk space for collected artifacts
- Standard Linux utilities (find, ps, netstat, etc.)
- `osqueryi` (for osquery integration, optional)
- Network connectivity (for TCP streaming feature, optional)

### Basic Usage
```
Usage: ./LFC/LFC.sh [OUTPUT_DIRECTORY] [--no-osquery] [--tcp-stream IP:PORT] [--osqueryi-path PATH]
  OUTPUT_DIRECTORY: Optional. Directory where forensic artifacts will be collected.
                    Default: /tmp/lfc_<hostname>_<timestamp>
  --no-osquery:     Optional. Skip osquery collection.
  --tcp-stream:     Optional. Stream tarball to specified IP:PORT over TCP.
                    Format: IP:PORT (e.g., 192.168.1.100:8080)
  --osqueryi-path:  Optional. Path to osqueryi binary.
                    Default: /usr/bin/osqueryi

Examples:
  ./LFC/LFC.sh             # Use default output directory (/tmp/lfc_<hostname>_<timestamp>) and run osquery
  ./LFC/LFC.sh /var/output # Use custom output directory and run osquery
  ./LFC/LFC.sh --no-osquery # Use default output directory and skip osquery
  ./LFC/LFC.sh /var/output --no-osquery # Use custom output directory and skip osquery
  ./LFC/LFC.sh --tcp-stream 192.168.1.100:8080 # Stream artifacts over TCP
  ./LFC/LFC.sh /var/output --no-osquery --tcp-stream 10.0.0.5:9999 # Custom dir, no osquery, TCP stream
  ./LFC/LFC.sh --osqueryi-path /opt/osquery/bin/osqueryi # Use custom osqueryi path
```

### Example Collection Session

```bash
# Clone & navigate to the collector directory
git clone https://github.com/SolitudePy/LFC.git
cd LFC/LFC

# Make the script executable (if needed)
chmod +x LFC.sh

# Standard collection with custom output directory
# After completion, a compressed archive will be created: 
# /var/case-001.tar.gz
sudo ./LFC.sh /var/case-001

# Extract results locally
tar -xzvf /var/case-001.tar.gz -C /var
```

#### Setting up a TCP Listener

On your analysis machine, set up a listener to receive the streamed data:

```bash
# Using netcat to receive the tarball
nc -l -p 8080 > forensic_artifacts.tar.gz

# Or using socat for more advanced options
socat TCP-LISTEN:8080,fork file:forensic_artifacts.tar.gz

# Using Python for a simple HTTP server (alternative approach)
python3 -m http.server 8080
```

#### Integrating osquery
```bash
1. Download the latest release from https://github.com/osquery/osquery
2. Install osquery e.g via rpm
3. Copy osqueryi to your desired location to work standalone along with LFC
```

## License

This project is licensed under the GNU General Public License v3.0. See the `LICENSE` file for details.