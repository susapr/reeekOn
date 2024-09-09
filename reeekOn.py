import os
import subprocess
import argparse
import socket
from urllib.parse import urlparse

# Default Nmap options for stealth scanning
NMAP_OPTIONS = "-sS -T4 --open --min-rate=1000"

# Function to resolve URL to IP
def resolve_url_to_ip(url):
    try:
        # Extract hostname from URL
        hostname = urlparse(url).hostname
        if hostname:
            ip = socket.gethostbyname(hostname)
            return ip
        else:
            raise ValueError("Invalid URL")
    except (socket.error, ValueError) as err:
        print(f"Error resolving URL {url}: {err}")
        return None

# Function to run Nmap scan on the target IP and return open ports and services
def scan_target(ip):
    scan_command = f"nmap {NMAP_OPTIONS} -sV {ip}"
    result = subprocess.check_output(scan_command, shell=True, text=True)
    return result

# Function to process Nmap results and extract open ports, services, and versions
def process_nmap_output(nmap_output):
    services = []
    lines = nmap_output.splitlines()
    for line in lines:
        if "/tcp" in line or "/udp" in line:  # Process only port/service lines
            parts = line.split()
            port = parts[0]
            service = parts[2] if len(parts) > 2 else "Unknown"
            version = ' '.join(parts[3:]) if len(parts) > 3 else "Unknown"
            services.append((port, service, version))
    return services

# Function to sanitize port and service strings for file paths
def sanitize_path(path):
    return path.replace('/', '_').replace(':', '_').replace('(', '_').replace(')', '_')

# Create directories for IP and port folders
def create_ip_folder(ip, base_dir):
    ip_folder = os.path.join(base_dir, ip)
    os.makedirs(ip_folder, exist_ok=True)
    return ip_folder

# Write service information to file
def write_service_info(ip_folder, port, service, version):
    sanitized_port = sanitize_path(port)
    port_folder = os.path.join(ip_folder, sanitized_port)
    os.makedirs(port_folder, exist_ok=True)
    
    info_file = os.path.join(port_folder, f"{sanitized_port}.txt")
    with open(info_file, "w") as f:
        f.write(f"Port: {port}\n")
        f.write(f"Service: {service}\n")
        f.write(f"Version: {version}\n")

# Function to query known vulnerabilities (for now, simulate with searchsploit)
def search_vulnerabilities(service, version):
    # Escape special characters in service and version
    safe_service = sanitize_path(service)
    safe_version = sanitize_path(version)
    
    search_command = f"searchsploit '{safe_service}' '{safe_version}'"
    
    try:
        result = subprocess.check_output(search_command, shell=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running searchsploit: {e}")
        result = ""
    
    return result

def save_vulnerabilities(ip_folder, port, vulnerabilities):
    sanitized_port = sanitize_path(port)
    vuln_file = os.path.join(ip_folder, sanitized_port, "vulnerabilities.txt")
    os.makedirs(os.path.dirname(vuln_file), exist_ok=True)
    with open(vuln_file, "w") as f:
        f.write(vulnerabilities)

def main(url_file, output_dir, auto_exploit):
    # Read URLs from the input file
    with open(url_file, "r") as file:
        urls = [line.strip() for line in file if line.strip()]

    # Base output directory
    output_base = output_dir if output_dir else os.getcwd()

    for url in urls:
        ip = resolve_url_to_ip(url)
        if not ip:
            print(f"Skipping URL {url} due to resolution failure.")
            continue

        print(f"[*] Scanning {ip}...")

        # Create folder for IP
        ip_folder = create_ip_folder(ip, output_base)

        # Perform Nmap scan
        nmap_result = scan_target(ip)

        # Process the scan results to get ports and services
        services = process_nmap_output(nmap_result)

        for port, service, version in services:
            print(f"[*] Found {service} on port {port} (version: {version})")

            # Create folder for each port and save service info
            write_service_info(ip_folder, port, service, version)

            # Search vulnerabilities and save them
            vulnerabilities = search_vulnerabilities(service, version)
            save_vulnerabilities(ip_folder, port, vulnerabilities)

            # Optional: Run exploits with Metasploit if enabled
            if auto_exploit:
                run_metasploit_exploit(ip, port, service)

# Function to run Metasploit exploit
def run_metasploit_exploit(ip, port, service):
    exploit_command = f"msfconsole -x 'use exploit/multi/handler; set RHOST {ip}; set RPORT {port}; exploit'"
    subprocess.call(exploit_command, shell=True)

if __name__ == "__main__":
    reeekOn_ascii = """
    ░▒▓███████▓▒░░▒▓████████▓▒░▒▓████████▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓███████▓▒░  
    ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓██████▓▒░ ░▒▓██████▓▒░ ░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓████████▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░

    created by: susapr (https://suye.sh)
    """
    print(reeekOn_ascii)
    parser = argparse.ArgumentParser(description="Penetration Testing Framework")
    parser.add_argument("-i", "--input", help="Input file with URLs", required=True)
    parser.add_argument("-o", "--output", help="Output directory (default: current)", default=".")
    parser.add_argument("-e", "--exploit", help="Auto exploit with Metasploit", action="store_true")

    args = parser.parse_args()
    main(args.input, args.output, args.exploit)
