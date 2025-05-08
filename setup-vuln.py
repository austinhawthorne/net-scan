#!/usr/bin/env python3
"""
This script creates dummy vulnerable services for testing purposes.
It opens up three ports with servers that mimic vulnerable software:
  - SSH on port 2222 (banner: OpenSSH_7.2p2)
  - FTP on port 2121 (banner: vsFTPd 2.3.4)
  - HTTP on port 8080 (HTTP header: Apache/2.4.49 (Debian))
  
Use only in a controlled lab environment.
"""

import socket
import threading
import time

def run_ssh_server(host='0.0.0.0', port=2222):
    banner = "SSH-2.0-OpenSSH_7.2p2\r\n"
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((host, port))
    except Exception as e:
        print(f"[SSH] Error binding to {host}:{port} -> {e}")
        return
    server.listen(5)
    print(f"[SSH] Server running on {host}:{port}")
    while True:
        try:
            client, addr = server.accept()
            print(f"[SSH] Connection from {addr}")
            client.sendall(banner.encode())
            client.close()
        except Exception as e:
            print(f"[SSH] Error handling connection: {e}")

def run_ftp_server(host='0.0.0.0', port=2121):
    banner = "220 (vsFTPd 2.3.4)\r\n"
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((host, port))
    except Exception as e:
        print(f"[FTP] Error binding to {host}:{port} -> {e}")
        return
    server.listen(5)
    print(f"[FTP] Server running on {host}:{port}")
    while True:
        try:
            client, addr = server.accept()
            print(f"[FTP] Connection from {addr}")
            client.sendall(banner.encode())
            client.close()
        except Exception as e:
            print(f"[FTP] Error handling connection: {e}")

def run_http_server(host='0.0.0.0', port=8080):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((host, port))
    except Exception as e:
        print(f"[HTTP] Error binding to {host}:{port} -> {e}")
        return
    server.listen(5)
    print(f"[HTTP] Server running on {host}:{port}")
    while True:
        try:
            client, addr = server.accept()
            print(f"[HTTP] Connection from {addr}")
            # Read incoming data (HTTP request)
            _ = client.recv(1024)
            # Respond with a simple HTTP response and a Server header
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Server: Apache/2.4.49 (Debian)\r\n"
                "Content-Length: 0\r\n"
                "\r\n"
            )
            client.sendall(response.encode())
            client.close()
        except Exception as e:
            print(f"[HTTP] Error handling connection: {e}")

def main():
    threads = []
    
    # Create a thread for each server
    ssh_thread = threading.Thread(target=run_ssh_server, args=('0.0.0.0', 2222))
    ftp_thread = threading.Thread(target=run_ftp_server, args=('0.0.0.0', 2121))
    http_thread = threading.Thread(target=run_http_server, args=('0.0.0.0', 8080))
    
    threads.extend([ssh_thread, ftp_thread, http_thread])
    
    for t in threads:
        t.daemon = True  # Allows the program to exit even if threads are still running
        t.start()
    
    print("Dummy vulnerable services are running. Press Ctrl+C to stop.")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down servers.")

if __name__ == "__main__":
    main()
