#!/usr/bin/env python3
import nmap
import requests
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

def discover_hosts(network):
    """
    Discover active hosts on a given network using a ping scan.
    """
    scanner = nmap.PortScanner()
    print(f"[+] Scanning network {network} for active hosts...")
    scanner.scan(hosts=network, arguments='-sn --disable-arp-ping')
    hosts = list(scanner.all_hosts())
    print(f"    Found hosts on {network}: {hosts}")
    return hosts

def scan_host(host):
    """
    Scan a host to detect open ports (with service version detection) and OS.
    """
    scanner = nmap.PortScanner()
    print(f"[+] Scanning host {host} for open ports and OS detection...")
    scanner.scan(host, arguments='-sV -O')
    
    info = {'ip': host}
    # OS detection
    os_matches = scanner[host].get('osmatch', [])
    if os_matches:
        best = os_matches[0]
        info.update({
            'os': best['name'],
            'os_accuracy': best['accuracy'],
            'os_version': best.get('version', '')
        })
    else:
        info.update({'os': 'Unknown', 'os_version': ''})

    # Service/version detection
    services = []
    for port, port_info in scanner[host].get('tcp', {}).items():
        if port_info.get('state') == 'open':
            services.append({
                'port': port,
                'name': port_info.get('name', ''),
                'product': port_info.get('product', ''),
                'version': port_info.get('version', '')
            })
    info['services'] = services
    return info

def lookup_vulnerabilities(keyword, api_key):
    """
    Lookup vulnerabilities using the NVD API v2.
    """
    print(f"[+] Looking up vulnerabilities for '{keyword}' ...")
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": keyword}
    headers = {"apiKey": api_key}
    try:
        resp = requests.get(url, headers=headers, params=params)
        resp.raise_for_status()
        data = resp.json()
        vulns = [item["cve"]["id"] for item in data.get("vulnerabilities", [])]
        return vulns
    except Exception as e:
        print(f"    Vulnerability lookup failed for '{keyword}': {e}")
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

        # OS vulnerabilities
        if host.get('os') != "Unknown" and host.get('os_version'):
            os_query = f"{host['os']} {host['os_version']}"
            os_vulns = lookup_vulnerabilities(os_query, api_key)
            report += f"  OS Vulnerabilities: {', '.join(os_vulns) or 'None found'}\n"
        else:
            report += "  OS Vulnerabilities: Skipped (insufficient info)\n"

        # Service vulnerabilities
        report += "  Open Services:\n"
        for svc in host.get('services', []):
            svc_line = f"    Port {svc['port']}: {svc['name']}"
            if svc.get('product'):
                svc_line += f" ({svc['product']})"
            if svc.get('version'):
                svc_line += f" v{svc['version']}"
            report += svc_line + "\n"

            if svc.get('version'):
                svc_query = f"{svc.get('product','')} {svc['version']}".strip()
                svc_vulns = lookup_vulnerabilities(svc_query, api_key)
                report += f"      Vulnerabilities: {', '.join(svc_vulns) or 'None found'}\n"
            else:
                report += "      Vulnerabilities: Skipped (no version)\n"
        report += "\n"
    return report

def main():
    networks = input("Enter comma-separated networks to scan (e.g., 192.168.1.0/24,10.0.0.0/24): ")
    api_key  = input("Enter your NVD API key: ").strip()
    network_list = [n.strip() for n in networks.split(',')]

    # 1) Discover all hosts in parallel
    all_hosts = []
    with ThreadPoolExecutor(max_workers=min(10, len(network_list))) as pool:
        futures = {pool.submit(discover_hosts, net): net for net in network_list}
        for fut in as_completed(futures):
            try:
                all_hosts.extend(fut.result())
            except Exception as e:
                print(f"Error discovering {futures[fut]}: {e}")

    # 2) Scan each host in parallel
    hosts_info = []
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(scan_host, host): host for host in all_hosts}
        for fut in as_completed(futures):
            host = futures[fut]
            try:
                hosts_info.append(fut.result())
            except Exception as e:
                print(f"Error scanning host {host}: {e}")

    # 3) Print the combined report
    report = generate_report(hosts_info, api_key)
    print(report)

if __name__ == "__main__":
    main()
