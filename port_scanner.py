"""
Port Scanner
Checks which common ports are open on a machine you own.
Part of the Cipherora Projects series.

Only scan devices and networks you own or have written permission to test.
Scanning systems you don't own or have permission for may be illegal.
"""

import socket
from datetime import datetime

# A short list of common ports and what they're usually used for.
# A real scanner could check all 65535, but this keeps it fast and readable.
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP (alt)",
}


def scan_port(target, port, timeout=0.5):
    """Try to open a connection to one port. Return True if it's open."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((target, port))
        return result == 0
    finally:
        sock.close()


def scan_target(target, ports=COMMON_PORTS):
    """Scan a list of ports on one target and return the open ones."""
    open_ports = []
    for port, service in ports.items():
        if scan_port(target, port):
            open_ports.append((port, service))
    return open_ports


if __name__ == "__main__":
    print("Port Scanner")
    print("Only scan machines you own or have permission to test.\n")

    target = input("Enter a target to scan (e.g. 127.0.0.1 or localhost): ").strip()
    if not target:
        target = "127.0.0.1"

    print(f"\nScanning {target} ...")
    start = datetime.now()

    open_ports = scan_target(target)

    duration = (datetime.now() - start).total_seconds()

    if open_ports:
        print(f"\nFound {len(open_ports)} open port(s):")
        for port, service in open_ports:
            print(f"  {port}/tcp  open   {service}")
    else:
        print("\nNo open ports found among the common ones checked.")

    print(f"\nScan finished in {duration:.2f} seconds.")
