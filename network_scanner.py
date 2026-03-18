"""
network_scanner.py
------------------
A simple network scanner that:
  1. Pings a range of IP addresses to find live hosts
  2. Scans common ports on each live host
  3. Displays results in a clean, readable table

Usage:
  python network_scanner.py --target 192.168.1.0/24
  python network_scanner.py --target 192.168.1.1 --ports 22,80,443,3389

Author: Your Name
"""

import argparse          # Handles command-line arguments (flags like --target)
import ipaddress         # Lets us work with IP ranges like 192.168.1.0/24
import socket            # Used for connecting to ports (port scanning)
import subprocess        # Used to run the ping command
import concurrent.futures  # Lets us scan multiple hosts at the same time (faster)
from datetime import datetime  # For timestamping the scan report


# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────

# These are the most commonly used ports in networking/security.
# Each entry is: port_number -> service_name
COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    135:  "RPC",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

TIMEOUT = 0.5  # Seconds to wait before giving up on a port connection


# ─────────────────────────────────────────────
# CORE FUNCTIONS
# ─────────────────────────────────────────────

def ping_host(ip: str) -> bool:
    """
    Sends a single ping to an IP address.
    Returns True if the host responds, False if it doesn't.

    Automatically detects Windows vs Linux/Mac and uses the correct flags.
    Falls back to a TCP connection check if ping fails (common on Windows
    where ICMP may be blocked by the firewall).
    """
    import sys
    import platform

    ip_str = str(ip)

    # Detect the OS and build the correct ping command
    if platform.system().lower() == "windows":
        # Windows: -n 1 (one packet), -w 1000 (timeout in milliseconds)
        ping_cmd = ["ping", "-n", "1", "-w", "1000", ip_str]
    else:
        # Linux/Mac: -c 1 (one packet), -W 1 (timeout in seconds)
        ping_cmd = ["ping", "-c", "1", "-W", "1", ip_str]

    try:
        result = subprocess.run(
            ping_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3
        )
        if result.returncode == 0:
            return True
    except Exception:
        pass

    # ── Fallback: TCP probe on common ports ──
    # If ping is blocked (common on Windows), try connecting to a few
    # ports that are almost always open on network devices.
    for port in [80, 443, 22, 445, 135]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            if sock.connect_ex((ip_str, port)) == 0:
                sock.close()
                return True
            sock.close()
        except Exception:
            pass

    return False


def scan_port(ip: str, port: int) -> bool:
    """
    Tries to connect to a specific port on an IP address.
    Returns True if the port is open, False if it's closed or filtered.

    This is a TCP connect scan — the most basic type of port scan.
    """
    try:
        # Create a TCP socket (SOCK_STREAM = TCP)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)  # Don't wait too long for a response

        # connect_ex returns 0 if connection succeeded (port open)
        result = sock.connect_ex((str(ip), port))
        sock.close()
        return result == 0
    except Exception:
        return False


def get_hostname(ip: str) -> str:
    """
    Tries to resolve the hostname for an IP address (reverse DNS lookup).
    Returns the hostname if found, or 'N/A' if not.
    """
    try:
        # gethostbyaddr returns (hostname, alias_list, address_list)
        hostname = socket.gethostbyaddr(str(ip))[0]
        return hostname
    except socket.herror:
        return "N/A"


def scan_host(ip: str, ports_to_scan: list) -> dict | None:
    """
    Full scan of a single host:
      1. First pings it to see if it's alive
      2. If alive, scans all specified ports
      3. Returns a dictionary with the results, or None if host is down

    This function is called in parallel for each IP in the range.
    """
    ip_str = str(ip)

    # Step 1: Check if the host is up
    if not ping_host(ip_str):
        return None  # Host didn't respond — skip it

    # Step 2: Resolve hostname
    hostname = get_hostname(ip_str)

    # Step 3: Scan each port
    open_ports = []
    for port in ports_to_scan:
        if scan_port(ip_str, port):
            # Get the service name if we know it, otherwise just show port number
            service = COMMON_PORTS.get(port, "Unknown")
            open_ports.append((port, service))

    # Return all results for this host
    return {
        "ip": ip_str,
        "hostname": hostname,
        "open_ports": open_ports,
    }


# ─────────────────────────────────────────────
# OUTPUT / DISPLAY FUNCTIONS
# ─────────────────────────────────────────────

def print_banner():
    """Prints a clean header at the start of the scan."""
    print("=" * 60)
    print("           PYTHON NETWORK SCANNER")
    print("           github.com/dsixta")
    print("=" * 60)
    print(f"  Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)


def print_results(results: list, ports_scanned: list):
    """
    Prints the final scan results in a formatted table.
    'results' is a list of host dictionaries from scan_host().
    """
    live_hosts = [r for r in results if r is not None]

    print(f"\n[+] Scan complete. Found {len(live_hosts)} live host(s).\n")

    if not live_hosts:
        print("  No live hosts found. Check your target range.")
        return

    # Print each live host and its open ports
    for host in live_hosts:
        print(f"  Host: {host['ip']}  |  Hostname: {host['hostname']}")

        if host["open_ports"]:
            print(f"  {'PORT':<8} {'SERVICE':<15} STATUS")
            print(f"  {'-'*8} {'-'*15} ------")
            for port, service in host["open_ports"]:
                print(f"  {port:<8} {service:<15} OPEN")
        else:
            print("  No open ports found on scanned range.")

        print()  # Blank line between hosts

    # Summary line
    print("-" * 60)
    print(f"  Ports scanned per host: {len(ports_scanned)}")
    print(f"  Live hosts:             {len(live_hosts)}")
    print(f"  Scan finished:          {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)


# ─────────────────────────────────────────────
# ARGUMENT PARSING (command-line flags)
# ─────────────────────────────────────────────

def parse_arguments():
    """
    Sets up and parses command-line arguments.
    This allows the user to run: python network_scanner.py --target 192.168.1.0/24
    """
    parser = argparse.ArgumentParser(
        description="Simple Network Scanner — finds live hosts and open ports",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Target IP or network range.\nExamples:\n  192.168.1.1\n  192.168.1.0/24"
    )

    parser.add_argument(
        "--ports",
        default=None,
        help="Comma-separated list of ports to scan.\nDefault: scans all common ports.\nExample: --ports 22,80,443"
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Number of parallel threads (default: 50). Higher = faster but noisier."
    )

    return parser.parse_args()


# ─────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────

def main():
    args = parse_arguments()

    print_banner()

    # ── Build the list of IPs to scan ──
    try:
        # ipaddress.ip_network handles both single IPs and CIDR ranges
        network = ipaddress.ip_network(args.target, strict=False)
        ip_list = list(network.hosts()) or [network.network_address]  # .hosts() returns empty for /32; fall back to the address itself
    except ValueError as e:
        print(f"[!] Invalid target: {e}")
        return

    print(f"  Target:  {args.target}")
    print(f"  Hosts:   {len(ip_list)} address(es) to scan")

    # ── Build the list of ports to scan ──
    if args.ports:
        # User specified custom ports — parse the comma-separated list
        try:
            ports_to_scan = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            print("[!] Invalid port list. Use format: --ports 22,80,443")
            return
    else:
        # Default: scan all ports in our COMMON_PORTS dictionary
        ports_to_scan = list(COMMON_PORTS.keys())

    print(f"  Ports:   {len(ports_to_scan)} port(s) per host")
    print(f"  Threads: {args.threads}")
    print("\n  [*] Scanning... (this may take a moment)\n")

    # ── Run the scan in parallel using a thread pool ──
    # ThreadPoolExecutor lets us scan multiple hosts simultaneously
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        # Submit a scan job for each IP address
        future_to_ip = {
            executor.submit(scan_host, ip, ports_to_scan): ip
            for ip in ip_list
        }

        # Collect results as each scan completes
        for future in concurrent.futures.as_completed(future_to_ip):
            result = future.result()
            results.append(result)

            # Show a live update dot for each host scanned
            ip = future_to_ip[future]
            if result:
                print(f"  [+] LIVE: {result['ip']}  ({result['hostname']})")

    # ── Print the final report ──
    print_results(results, ports_to_scan)


# This ensures main() only runs when you execute this file directly,
# not when it's imported as a module by another script.
if __name__ == "__main__":
    main()