#!/usr/bin/env python3
import socket
import concurrent.futures
import sys
import time
import re
from datetime import datetime

# ANSI Color Codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"
UNDERLINE = "\033[4m"

# ASCII Art Banner
LAMIRA_BANNER = f"""
{BLUE}{BOLD}
  _                      _ _        ____                                
 | |    ___   __ _  __ _(_) | ___  / ___|  ___ __ _ _ __  _ __   ___ _ __ 
 | |   / _ \\ / _` |/ _` | | |/ _ \\ \\___ \\ / __/ _` | '_ \\| '_ \\ / _ \\ '__|
 | |__| (_) | (_| | (_| | | |  __/  ___) | (_| (_| | | | | | | |  __/ |   
 |_____\\___/ \\__, |\\__, |_|_|\\___| |____/ \\___\\__,_|_| |_|_| |_|\\___|_|   
             |___/ |___/                                                
{RESET}
{GREEN}Tool Lamira Scanner| Contact: @Black_on2{RESET}
{YELLOW}Telegram Channel: https://t.me/codepyAcademy{RESET}
{BLUE}{'-'*80}{RESET}
"""

# Common ports list (Top 100 TCP ports)
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 
    143, 443, 445, 993, 995, 1723, 3306, 3389, 
    5900, 8080, 8443, 8888, 9000, 9090, 9100
]

# Service-specific probes for enhanced banner grabbing
SERVICE_PROBES = {
    21: b"USER anonymous\r\n",
    22: b"SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10\r\n",
    25: b"EHLO example.com\r\n",
    80: b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n",
    110: b"USER root\r\n",
    143: b"a001 CAPABILITY\r\n",
    443: b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n",
    445: b"\x00",  # SMB null session
    3306: b"\x0a",  # MySQL ping
    3389: b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00",  # RDP
    8080: b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n",
    8443: b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"
}

def display_banner():
    """Display Lamira Scanner banner"""
    print(LAMIRA_BANNER)

def format_port_results(results, scan_time):
    """Format scan results into a detailed report"""
    open_ports = [r for r in results if r['status']]
    closed_ports = [r for r in results if not r['status']]
    
    report = f"\n{CYAN}{BOLD}{'='*80}{RESET}\n"
    report += f"{GREEN}{BOLD}PORT SCAN REPORT{RESET}\n"
    report += f"{CYAN}{'='*80}{RESET}\n"
    report += f"{YELLOW}{BOLD}Target:{RESET} {results[0]['host']}\n"
    report += f"{YELLOW}{BOLD}Scanned ports:{RESET} {len(results)}\n"
    report += f"{YELLOW}{BOLD}Open ports:{RESET} {len(open_ports)}\n"
    report += f"{YELLOW}{BOLD}Closed ports:{RESET} {len(closed_ports)}\n"
    report += f"{YELLOW}{BOLD}Scan duration:{RESET} {scan_time:.2f} seconds\n"
    report += f"{CYAN}{'-'*80}{RESET}\n"
    
    if open_ports:
        report += f"{GREEN}{BOLD}OPEN PORTS:{RESET}\n"
        report += f"{BLUE}{BOLD}{'Port':<8}{'Service':<15}{'Version':<25}{'Banner'}{RESET}\n"
        report += f"{CYAN}{'-'*80}{RESET}\n"
        
        for port in open_ports:
            banner_lines = port['banner'].split('\n')
            first_line = True
            
            for line in banner_lines:
                if first_line:
                    report += f"{GREEN}{port['port']:<8}{port['service']:<15}{port['version']:<25}{line}{RESET}\n"
                    first_line = False
                else:
                    report += f"{' ' * 48}{line}\n"
        report += f"{CYAN}{'-'*80}{RESET}\n"
    
    report += f"\n{YELLOW}{BOLD}SCAN SUMMARY:{RESET}\n"
    report += f"{CYAN}{BOLD}{'-'*40}{RESET}\n"
    report += f"- First open port: {min(p['port'] for p in open_ports) if open_ports else 'N/A'}\n"
    report += f"- Last open port: {max(p['port'] for p in open_ports) if open_ports else 'N/A'}\n"
    
    # Detect potential services
    web_ports = [p for p in open_ports if p['port'] in [80, 443, 8080, 8443]]
    if web_ports:
        report += f"- {BOLD}Web server{RESET} detected on ports: {', '.join(str(p['port']) for p in web_ports)}\n"
    
    db_ports = [p for p in open_ports if p['port'] in [3306, 5432, 27017]]
    if db_ports:
        report += f"- {BOLD}Database{RESET} detected on ports: {', '.join(str(p['port']) for p in db_ports)}\n"
    
    remote_ports = [p for p in open_ports if p['port'] in [22, 3389, 5900]]
    if remote_ports:
        report += f"- {BOLD}Remote access{RESET} services on ports: {', '.join(str(p['port']) for p in remote_ports)}\n"
    
    return report

def grab_banner(sock, port):
    """Enhanced banner grabbing with service-specific probes"""
    try:
        # Set a shorter timeout for banner grabbing
        sock.settimeout(1.5)
        
        # Try to read initial banner (some services send immediately)
        initial = sock.recv(1024)
        
        # If we have a service-specific probe, send it
        if port in SERVICE_PROBES:
            sock.send(SERVICE_PROBES[port])
            response = sock.recv(4096)
            return initial.decode(errors='ignore').strip() + response.decode(errors='ignore').strip()
        
        return initial.decode(errors='ignore').strip()
    except (socket.timeout, ConnectionResetError, OSError):
        return ""
    except Exception as e:
        return f"Banner error: {str(e)}"

def detect_service_version(banner):
    """Extract service version from banner"""
    patterns = {
        r'SSH-(\d+\.\d+-[\w\d._-]+)': 'OpenSSH',
        r'Apache/([\d.]+)': 'Apache HTTP Server',
        r'nginx/([\d.]+)': 'Nginx',
        r'IIS/([\d.]+)': 'Microsoft IIS',
        r'PostgreSQL ([\d.]+)': 'PostgreSQL',
        r'MySQL ([\d.]+)': 'MySQL',
        r'Microsoft FTP Service ([\d.]+)': 'Microsoft FTP',
        r'ProFTPD ([\d.]+)': 'ProFTPD',
        r'vsFTPd ([\d.]+)': 'vsFTPd',
        r'Exchange ([\d.]+)': 'Microsoft Exchange',
        r'OpenSMTPD ([\d.]+)': 'OpenSMTPD',
        r'Postfix': 'Postfix SMTP'
    }
    
    for pattern, service in patterns.items():
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            version = match.group(1) if len(match.groups()) > 0 else 'unknown'
            return service, version
    
    # Try to guess service from common ports if no match
    common_services = {
        '220': 'FTP',
        'SSH': 'SSH',
        'HTTP': 'HTTP',
        'Microsoft': 'SMB',
        'MySQL': 'MySQL',
        'SMTP': 'SMTP'
    }
    
    for keyword, service in common_services.items():
        if keyword in banner:
            return service, 'unknown version'
    
    return 'Unknown', ''

def scan_port(target_ip, port):
    """Scan a single port with enhanced detection"""
    result = {
        'host': target_ip,
        'port': port,
        'service': 'Unknown',
        'version': '',
        'banner': '',
        'status': False
    }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        connection_result = sock.connect_ex((target_ip, port))
        
        if connection_result == 0:
            result['status'] = True
            result['banner'] = grab_banner(sock, port)
            
            # Try to get service name
            try:
                result['service'] = socket.getservbyport(port, 'tcp')
            except OSError:
                pass
                
            # Detect service version
            service, version = detect_service_version(result['banner'])
            if service != 'Unknown':
                result['service'] = service
                result['version'] = version
    except Exception as e:
        result['banner'] = f"Scan error: {str(e)}"
    finally:
        try:
            sock.close()
        except:
            pass
            
    return result

def port_scan(target_host, ports):
    """Perform port scanning with progress tracking"""
    start_time = time.time()
    
    try:
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        print(f"\n{RED}{BOLD}Error: Could not resolve hostname '{target_host}'{RESET}")
        return
    
    print(f"{GREEN}{BOLD}\n[+] Target resolved: {target_ip}{RESET}")
    print(f"{YELLOW}[+] Scanning {len(ports)} ports...{RESET}\n")
    
    results = []
    total_ports = len(ports)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=300) as executor:
        future_to_port = {executor.submit(scan_port, target_ip, port): port for port in ports}
        
        for i, future in enumerate(concurrent.futures.as_completed(future_to_port), 1):
            port = future_to_port[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                results.append({
                    'host': target_ip,
                    'port': port,
                    'service': 'Error',
                    'version': '',
                    'banner': f"Scan failed: {str(e)}",
                    'status': False
                })
            
            # Update progress - FIXED SYNTAX ERROR HERE
            progress = (i/total_ports)*100
            open_count = sum(1 for r in results if r['status'])
            sys.stdout.write(f"\r{MAGENTA}{BOLD}Progress: {i}/{total_ports} ports scanned "
                            f"({progress:.1f}%) | Open: {open_count}{RESET}")
            sys.stdout.flush()
    
    sys.stdout.write("\n")
    scan_time = time.time() - start_time
    print(format_port_results(results, scan_time))

def get_ports_to_scan():
    """Get port range from user with common ports option"""
    print(f"\n{CYAN}{BOLD}Scan Configuration{RESET}")
    print(f"{GREEN}1. Common ports (Top 100)")
    print(f"{GREEN}2. Full port range (1-65535)")
    print(f"{GREEN}3. Custom port range")
    print(f"{GREEN}4. Specific ports (comma separated){RESET}")
    
    choice = input(f"{YELLOW}{BOLD}Enter choice (1-4): {RESET}").strip()
    
    if choice == '1':
        return COMMON_PORTS
    elif choice == '2':
        return list(range(1, 65536))
    elif choice == '3':
        start = int(input("Start port: "))
        end = int(input("End port: "))
        return list(range(start, end + 1))
    elif choice == '4':
        ports = input("Enter ports (comma separated): ")
        return [int(p.strip()) for p in ports.split(',')]
    else:
        print(f"{RED}Invalid choice, using common ports{RESET}")
        return COMMON_PORTS

if __name__ == '__main__':
    display_banner()
    print(f"{YELLOW}{BOLD}Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}\n")
    
    try:
        target_host = input(f"{CYAN}{BOLD}Enter target host: {RESET}").strip()
        if not target_host:
            print(f"{RED}{BOLD}Error: Target host cannot be empty{RESET}")
            sys.exit(1)
            
        ports = get_ports_to_scan()
        port_scan(target_host, ports)
        
    except KeyboardInterrupt:
        print(f"\n{RED}{BOLD}Scan aborted by user{RESET}")
        sys.exit(1)
        
    print(f"\n{GREEN}{BOLD}{'='*80}{RESET}")
    print(f"{YELLOW}{BOLD}Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"{GREEN}{BOLD}   Tool Lamira Scanner      Developed by @Black_on2 | Telegram: https://t.me/codepyAcademy{RESET}")
    print(f"{GREEN}{BOLD}{'='*80}{RESET}")
