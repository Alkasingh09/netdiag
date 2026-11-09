# NetDiag – Network Troubleshooting Toolkit

A command-line tool in Python that troubleshoots network connectivity **layer by layer**, the way a network support engineer would. It finds the layer where the fault is, suggests a fix, and records every check in a CSV log you can attach to a ticket.

Standard library only: no installs needed. Works on Windows, Linux and macOS.

## Features

| Command | What it does |
|---|---|
| `diagnose` | Checks the local IP and DHCP, the default gateway, the internet by IP, DNS and the service port in order, and stops at the first failing layer with a suggested fix |
| `ping` | ICMP reachability and average latency |
| `sweep` | Multithreaded ping sweep to find live hosts in a subnet (/22 or smaller) |
| `ports` | TCP check of common service ports (FTP, SSH, Telnet, SMTP, DNS, HTTP, POP3, IMAP, HTTPS, RDP) as OPEN / CLOSED / FILTERED |
| `dns` | Forward lookup (A / AAAA records) or reverse lookup (PTR) |
| `trace` | Traceroute (`tracert` on Windows) with hop count |
| `subnet` | Subnet calculator: network, netmask, wildcard, broadcast, host range, usable hosts |

## How `diagnose` isolates a fault

| Step | Check | If it fails, the fault is in |
|---|---|---|
| 1 | Local IPv4 address assigned (and not 169.254.x.x / APIPA) | Local interface or DHCP |
| 2 | Default gateway answers ping | Local network (cable, Wi-Fi, switch, VLAN) |
| 3 | Public IP (8.8.8.8) answers ping | Routing beyond the gateway, ISP or firewall |
| 4 | Target hostname resolves | DNS |
| 5 | Target TCP port connects | Service down or port blocked by a firewall |

## Usage

```bash
python netdiag.py diagnose
python netdiag.py diagnose --target example.com --port 443
python netdiag.py ping 8.8.8.8 --count 4
python netdiag.py sweep 192.168.1.0/24
python netdiag.py ports 192.168.1.1 --ports 22,80,443
python netdiag.py dns example.com
python netdiag.py dns 8.8.8.8
python netdiag.py trace 8.8.8.8
python netdiag.py subnet 192.168.10.0/26
```

Each run is appended to `netdiag_log.csv` (timestamp, run ID, check, target, status, detail, suggested fix). Use `--log <file>` to choose another file, or `--no-log` to skip logging.

### Sample output

```
Run ND-20261109-035114: diagnosing connectivity to no-such-host.invalid:443

[PASS] Local IP config        192.168.1.23           address assigned
[PASS] Default gateway        192.168.1.1            reply, avg 4.0 ms
[PASS] Internet (by IP)       8.8.8.8                reply, avg 4.0 ms
[FAIL] DNS resolution         no-such-host.invalid   Name or service not known
       -> IP works but names don't: fix DNS server settings, flush cache (ipconfig /flushdns)

Fault isolated at: Layer 7: DNS
```

## Tests

```bash
python -m unittest discover -s tests -v
```

There are 12 unit tests. They cover ping output parsing for Windows and Linux (including Windows "Destination host unreachable" replies, which exit with code 0), default gateway detection from `/proc/net/route` and `ipconfig`, subnet maths, open and closed port detection, DNS lookup and logging.
