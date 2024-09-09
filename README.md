# reeekOn

```
░▒▓███████▓▒░░▒▓████████▓▒░▒▓████████▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓███████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓██████▓▒░ ░▒▓██████▓▒░ ░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓████████▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░

created by: susapr (https://suye.sh)
```

reeekOn is a lightweight Python-based penetration testing framework designed for fast and stealthy network scanning. It automatically scans a list of target IP addresses for open ports, services, versions, and known vulnerabilities. Additionally, `reeekOn` can integrate with Metasploit to automate the exploitation process.

## Features

- **Input from .txt file**: Supply a list of IP addresses in a text file.
- **Folder-based output**: Automatically creates folders for each target IP and subfolders for each open port.
- **Nmap scanning**: Performs quick scans to identify open ports and services while maintaining a low profile.
- **Service Detection**: Identifies the service and version running on each open port.
- **Known Vulnerabilities**: Queries ExploitDB via `searchsploit` for known vulnerabilities associated with the detected services.
- **Metasploit Integration**: Optionally run Metasploit to exploit detected vulnerabilities automatically.

## Installation

To install `reeekOn` on **Kali Linux**, follow these steps:

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/reeekOn.git
    cd reeekOn
    ```

2. Run the `install.sh` script to install dependencies and make `reeekOn` accessible from any location:
    ```bash
    ./install.sh
    ```

This will install `nmap`, `metasploit-framework`, and `exploitdb`, and create a symlink to the tool, so you can run it from any directory.

## Usage

### Basic Usage
1. Prepare a file with the list of IP addresses (one per line):
    ```
    192.168.1.10
    192.168.1.20
    192.168.1.30
    ```

2. Run `reeekOn` to scan the IPs and save results to the current folder:
    ```bash
    ./reeekOn.py -i ips.txt
    ```

3. Optionally, specify an output directory:
    ```bash
    ./reeekOn.py -i ips.txt -o /path/to/output
    ```

4. To enable automatic exploitation with Metasploit:
    ```bash
    ./reeekOn.py -i ips.txt -e
    ```

### Command Line Options

- `-i` or `--input`: Specify the input text file containing the list of IP addresses (required).
- `-o` or `--output`: Specify the output directory. If omitted, the current folder is used.
- `-e` or `--exploit`: Enable automatic exploitation via Metasploit (optional).

## Example Directory Structure

When `reeekOn` runs, it generates the following folder structure for each target IP:

output/
  └── 192.168.1.100/
    ├── 80/ 
    │ ├── 80.txt # Details about port 80 (service, version)
    │ └── vulnerabilities.txt # Vulnerabilities for port 80 service 
    └── 22/ 
      ├── 22.txt # Details about port 22 (service, version) 
      └── vulnerabilities.txt # Vulnerabilities for port 22 service

## Example Output

susapr> cat ips.txt
http://scanme.nmap.org

susapr> reeekOn -i ips.txt -o output

[*] Scanning 45.33.32.156...
[*] Found ssh on port 22/tcp (version: OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0))
[*] Found http? on port 80/tcp (version: Unknown)
[*] Found nping-echo on port 9929/tcp (version: Nping echo)
[*] Found tcpwrapped on port 31337/tcp (version: Unknown)

## Example Workflow

- Step 1: You supply a list of IPs.
- Step 2: The tool scans for open ports and services using `nmap`.
- Step 3: For each open port, it fetches known vulnerabilities using `searchsploit`.
- Step 4: Optionally, you can automate the exploitation phase with Metasploit.

## Upcoming Features

- version control: diff changes in services from past scans of the same IP with alerts
- cron jobs: automated scans based on set intervals or subscription of IP address changes (REST API)
- ExploitDB integration

## Requirements

- **Kali Linux** (or any Linux distribution with `nmap`, `metasploit`, and `searchsploit` installed).
- **Python 3.x**

## Contribution

Feel free to submit issues or pull requests. All contributions are welcome!

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
