#!/usr/bin/env python3
import nmap
import requests
import json

def discover_hosts(network):
    """
    Discover active hosts on a given network using a ping scan.
    """
    scanner = nmap.PortScanner()
    print(f"[+] Scanning network {network} for active hosts...")
    # Ping scan to discover hosts (no port scan)
    scanner.scan(hosts=network, arguments='-sn --disable-arp-ping')
    hosts = list(scanner.all_hosts())
    print(f"    Found hosts: {hosts}")
    return hosts

def scan_host(host):
    """
    Scan a host to detect open ports (with service version detection) and OS.
    """
    scanner = nmap.PortScanner()
    print(f"[+] Scanning host {host} for open ports and OS detection...")
    # Use -sV for version detection and -O for OS detection (requires elevated privileges)
    arguments = '-sV -O'
    scanner.scan(host, arguments=arguments)
    
    host_info = {'ip': host}

    # OS detection: nmap returns a list of possible OS matches.
    os_matches = scanner[host].get('osmatch', [])
    if os_matches:
        # Taking the best match (first one)
        os_match = os_matches[0]
        host_info['os'] = os_match['name']
        host_info['os_accuracy'] = os_match['accuracy']
        host_info['os_version'] = os_match.get('version', '')
    else:
        host_info['os'] = "Unknown"
        host_info['os_version'] = ""
    
    # Collect open TCP ports and associated service info
    services = []
    if 'tcp' in scanner[host]:
        for port, port_info in scanner[host]['tcp'].items():
            if port_info.get('state') == 'open':
                service = {
                    'port': port,
                    'name': port_info.get('name', ''),
                    'product': port_info.get('product', ''),
                    'version': port_info.get('version', '')
                }
                services.append(service)
    host_info['services'] = services
    
    return host_info

def lookup_vulnerabilities(keyword, api_key):
    """
    Lookup vulnerabilities using the NVD API v2.
    The keyword should typically include the service or OS name and its version.
    """
    print(f"[+] Looking up vulnerabilities for '{keyword}' ...")
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    # Using the new parameter 'keywordSearch'
    params = {"keywordSearch": keyword}
    headers = {"apiKey": api_key}
    
    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            # In the v2 API, vulnerabilities are under the 'vulnerabilities' key.
            cve_items = data.get("vulnerabilities", [])
            vulnerabilities = []
            for item in cve_items:
                cve_id = item["cve"]["id"]
                vulnerabilities.append(cve_id)
            return vulnerabilities
        else:
            print(f"    NVD API returned status code: {response.status_code}")
            return []
    except Exception as e:
        print(f"    Error during vulnerability lookup: {e}")
        return []

def generate_report(hosts_info, api_key):
    """
    Generate a text report with host, OS, services, and vulnerabilities.
    """
    report = "\n=== Scan Report ===\n\n"
    for host in hosts_info:
        report += f"Host: {host['ip']}\n"
        report += f"  OS: {host.get('os', 'Unknown')}"
        if host.get('os_version'):
            report += f" (Version: {host['os_version']})"
        report += "\n"
        
        # Vulnerability lookup for OS if version information is available.
        if host.get('os') != "Unknown" and host.get('os_version'):
            os_query = f"{host['os']} {host['os_version']}"
            os_vulns = lookup_vulnerabilities(os_query, api_key)
            if os_vulns:
                report += f"  OS Vulnerabilities: {', '.join(os_vulns)}\n"
            else:
                report += "  OS Vulnerabilities: None found\n"
        else:
            report += "  OS Vulnerabilities: Skipped (insufficient version info)\n"
        
        report += "  Open Services:\n"
        for svc in host.get('services', []):
            svc_line = f"    Port {svc['port']}: {svc['name']}"
            if svc.get('product'):
                svc_line += f" ({svc['product']})"
            if svc.get('version'):
                svc_line += f" v{svc['version']}"
            report += svc_line + "\n"
            
            # Lookup vulnerabilities for the service if version information is available.
            if svc.get('version'):
                svc_query = f"{svc.get('product','')} {svc['version']}".strip()
                vulns = lookup_vulnerabilities(svc_query, api_key)
                if vulns:
                    report += f"      Vulnerabilities: {', '.join(vulns)}\n"
                else:
                    report += "      Vulnerabilities: None found\n"
            else:
                report += "      Vulnerabilities: Skipped (no version info)\n"
        report += "\n"
    return report

def main():
    # Get comma-separated network ranges from the user.
    networks = input("Enter comma-separated networks to scan (e.g., 192.168.1.0/24,10.0.0.0/24): ")
    network_list = [net.strip() for net in networks.split(',')]
    
    # Get the NVD API key from the user.
    api_key = input("Enter your NVD API key: ").strip()
    
    all_hosts_info = []
    
    # Discover hosts and then scan each host in each network.
    for network in network_list:
        hosts = discover_hosts(network)
        for host in hosts:
            host_info = scan_host(host)
            all_hosts_info.append(host_info)
    
    # Generate and print the final report.
    report = generate_report(all_hosts_info, api_key)
    print(report)

if __name__ == "__main__":
    main()
