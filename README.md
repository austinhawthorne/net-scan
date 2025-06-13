A simple set of scripts that setups one host with "vulnerable" services and another to scan hosts for vulnerabilities.  Used for testing visibility in networks to detect such activity.

Pre-Requisite:  You need to get an NVD API key from here: https://nvd.nist.gov/developers/request-an-api-key

'setup-vuln.py' can be run on a host to setup FTP, SSH, and HTTP services that have certain signatures that match known vulnerabilities.

```
client2:~/net-scan $ python setup-vuln.py 
[SSH] Server running on 0.0.0.0:2222
[FTP] Server running on 0.0.0.0:2121
Dummy vulnerable services are running. Press Ctrl+C to stop.
[HTTP] Server running on 0.0.0.0:8080
```

'scan-network.py' runs from a separate host, on the same subnet or different subnet, to discover all hosts and run scans of each discovered host.  Once the scan is done, it performs a lookup to the National Vulnerability Database (NVD).  Running this script will prompt you for the target network to scan and your NVD API key.

```
client1:~/net-scan $ sudo python scan-network.py 
Enter comma-separated networks to scan (e.g., 192.168.1.0/24,10.0.0.0/24): 10.0.3.0/24
Enter your NVD API key: REDACTED 
[+] Scanning network 10.0.3.0/24 for active hosts...
    Found hosts: ['10.0.3.1', '10.0.3.100', '10.0.3.161', '10.0.3.180']
[+] Scanning host 10.0.3.1 for open ports and OS detection...
[+] Scanning host 10.0.3.100 for open ports and OS detection...
[+] Scanning host 10.0.3.161 for open ports and OS detection...
[+] Scanning host 10.0.3.180 for open ports and OS detection...
[+] Looking up vulnerabilities for 'OpenSSH 9.2p1 Debian 2+deb12u5' ...
[+] Looking up vulnerabilities for 'OpenSSH 9.2p1 Debian 2+deb12u3' ...
[+] Looking up vulnerabilities for 'vsftpd 2.3.4' ...
[+] Looking up vulnerabilities for 'OpenSSH 7.2p2' ...
[+] Looking up vulnerabilities for 'Apache httpd 2.4.49' ...

=== Scan Report ===

Host: 10.0.3.1
  OS: Linux 2.6.32
  OS Vulnerabilities: Skipped (insufficient version info)
  Open Services:
    Port 80: http
      Vulnerabilities: Skipped (no version info)
    Port 443: https
      Vulnerabilities: Skipped (no version info)
    Port 8443: https-alt
      Vulnerabilities: Skipped (no version info)

Host: 10.0.3.100
  OS: Linux 2.6.32
  OS Vulnerabilities: Skipped (insufficient version info)
  Open Services:
    Port 22: ssh (OpenSSH) v9.2p1 Debian 2+deb12u5
      Vulnerabilities: None found

Host: 10.0.3.161
  OS: Unknown
  OS Vulnerabilities: Skipped (insufficient version info)
  Open Services:

Host: 10.0.3.180
  OS: Linux 4.15 - 5.6
  OS Vulnerabilities: Skipped (insufficient version info)
  Open Services:
    Port 22: ssh (OpenSSH) v9.2p1 Debian 2+deb12u3
      Vulnerabilities: None found
    Port 2121: ftp (vsftpd) v2.3.4
      Vulnerabilities: CVE-2011-2523
    Port 2222: ssh (OpenSSH) v7.2p2
      Vulnerabilities: CVE-2016-3115, CVE-2015-8325
    Port 8080: http (Apache httpd) v2.4.49
      Vulnerabilities: None found
```
