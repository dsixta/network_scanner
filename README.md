# 🔍 Network Scanner

A lightweight Python network scanner that discovers live hosts on a network and identifies open ports and running services. Built with core Python libraries — no heavy dependencies required.

---

## 📋 Features

- **Host Discovery** — Pings a full subnet (e.g. `192.168.1.0/24`) to find live devices
- **Port Scanning** — TCP connect scan across 17 common ports per host
- **Service Detection** — Maps open ports to known service names (SSH, HTTP, RDP, etc.)
- **Reverse DNS Lookup** — Resolves hostnames for discovered IPs
- **Multithreaded** — Scans multiple hosts in parallel for speed
- **Custom Targets** — Scan a single IP or a full CIDR range
- **Custom Ports** — Specify your own port list via command-line flag

---

## 🚀 Usage

### Basic scan of a subnet
```bash
python network_scanner.py --target 192.168.1.0/24
```

### Scan a single host
```bash
python network_scanner.py --target 192.168.1.1
```

### Scan specific ports only
```bash
python network_scanner.py --target 192.168.1.0/24 --ports 22,80,443,3389
```

### Adjust thread count for speed
```bash
python network_scanner.py --target 192.168.1.0/24 --threads 100
```

---

## 📦 Requirements

No third-party packages needed. Uses only Python standard library modules:

| Module | Purpose |
|--------|---------|
| `socket` | TCP port connection attempts |
| `subprocess` | Ping execution |
| `ipaddress` | CIDR range parsing |
| `concurrent.futures` | Multithreaded scanning |
| `argparse` | Command-line argument handling |

Python 3.8+ recommended.

---

## 📄 Example Output

```
============================================================
           PYTHON NETWORK SCANNER
           github.com/yourusername
============================================================
  Scan started: 2024-11-15 14:32:01
============================================================
  Target:  192.168.1.0/24
  Hosts:   254 address(es) to scan
  Ports:   17 port(s) per host
  Threads: 50

  [*] Scanning... (this may take a moment)

  [+] LIVE: 192.168.1.1    (router.local)
  [+] LIVE: 192.168.1.15   (N/A)
  [+] LIVE: 192.168.1.42   (desktop.local)

[+] Scan complete. Found 3 live host(s).

  Host: 192.168.1.1  |  Hostname: router.local
  PORT     SERVICE         STATUS
  -------- --------------- ------
  80       HTTP            OPEN
  443      HTTPS           OPEN

  Host: 192.168.1.42  |  Hostname: desktop.local
  PORT     SERVICE         STATUS
  -------- --------------- ------
  22       SSH             OPEN
  3389     RDP             OPEN

------------------------------------------------------------
  Ports scanned per host: 17
  Live hosts:             3
  Scan finished:          2024-11-15 14:32:28
============================================================
```

---

## ⚙️ How It Works

1. **Parse Target** — Converts the input (IP or CIDR) into a list of individual IP addresses using Python's `ipaddress` module
2. **Ping Sweep** — Sends a single ICMP ping to each address using the OS `ping` command
3. **Port Scan** — For live hosts, attempts a TCP connection to each port using `socket.connect_ex()`
4. **Results** — Collects and displays all findings in a structured table

---

## ⚠️ Legal Notice

> Only scan networks and devices you own or have explicit written permission to test. Unauthorized port scanning may violate computer fraud laws in your jurisdiction.

---

## 🛠️ Potential Improvements

- [ ] Export results to CSV or JSON
- [ ] Add UDP scanning support
- [ ] Banner grabbing (detect software versions)
- [ ] OS fingerprinting
- [ ] Integration with CVE database for vulnerability lookups

---

## 📚 Concepts Demonstrated

`TCP/IP` · `ICMP` · `Socket Programming` · `Multithreading` · `CIDR Notation` · `Port Scanning` · `Reverse DNS`
