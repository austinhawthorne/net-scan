A simple set of scripts that setups one host with "vulnerable" services and another to scan hosts for vulnerabilities.  Used for testing visibility in networks to detect such activity.

'setup-vuln.py' can be run on a host to setup FTP, SSH, and HTTP services that have certain signatures that match known vulnerabilities.

'scan-network.py' runs from a separate host, on the same subnet or different subnet, to discover all hosts and run scans of each discovered host.  Once the scan is done, it performs a lookup to the National Vulnerability Database (NVD).  Running this script will prompt you for the target network to scan and your NVD API key.
