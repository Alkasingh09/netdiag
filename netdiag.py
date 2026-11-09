#!/usr/bin/env python3
"""
NetDiag - a small network troubleshooting toolkit.

It checks connectivity layer by layer, the way a support engineer would
(local IP -> gateway -> internet -> DNS -> service port), tells you which
layer is failing with a suggested fix, and records every check in a CSV
log so the issue can be reported or escalated.

Standard library only. Works on Windows, Linux and macOS.

Examples:
    python netdiag.py diagnose                       # full layer-by-layer check
    python netdiag.py diagnose --target example.com --port 443
    python netdiag.py ping 8.8.8.8 --count 4
    python netdiag.py sweep 192.168.1.0/24           # find live hosts
    python netdiag.py ports 192.168.1.1              # common service ports
    python netdiag.py dns example.com
    python netdiag.py trace 8.8.8.8
    python netdiag.py subnet 192.168.10.0/26
"""

import argparse
import csv
import datetime as dt
import ipaddress
import os
import platform
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

SYSTEM = platform.system()          # "Windows", "Linux" or "Darwin"
IS_WIN = SYSTEM == "Windows"
DEFAULT_LOG = "netdiag_log.csv"
MAX_SWEEP_HOSTS = 1024              # keep sweeps to /22 or smaller

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 3389: "RDP",
}

# ---------------------------------------------------------------- output

if IS_WIN:
    os.system("")                   # enables ANSI colours in Windows 10+ terminals

_COLOURS = {"PASS": "\033[92m", "FAIL": "\033[91m", "WARN": "\033[93m", "INFO": "\033[96m"}
_RESET = "\033[0m"


def badge(status):
    text = f"[{status}]"
    if sys.stdout.isatty():
        return f"{_COLOURS.get(status, '')}{text}{_RESET}"
    return text


class Logger:
    """Appends every check to a CSV file so runs can be reviewed or attached to a ticket."""

    FIELDS = ["timestamp", "run_id", "check", "target", "status", "detail", "suggestion"]

    def __init__(self, path=DEFAULT_LOG, enabled=True):
        self.path = path
        self.enabled = enabled
        self.run_id = "ND-" + dt.datetime.now().strftime("%Y%m%d-%H%M%S")

    def record(self, check, target, status, detail="", suggestion=""):
        print(f"{badge(status):<6} {check:<22} {target:<22} {detail}")
        if suggestion and status != "PASS":
            print(f"       -> {suggestion}")
        if not self.enabled:
            return
        new_file = not os.path.exists(self.path)
        with open(self.path, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self.FIELDS)
            if new_file:
                writer.writeheader()
            writer.writerow({
                "timestamp": dt.datetime.now().isoformat(timespec="seconds"),
                "run_id": self.run_id, "check": check, "target": target,
                "status": status, "detail": detail, "suggestion": suggestion,
            })


# ---------------------------------------------------------------- ICMP (ping)

def build_ping_command(host, count=1, timeout=1.0, system=SYSTEM):
    if system == "Windows":
        return ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), host]
    if system == "Darwin":
        return ["ping", "-c", str(count), "-t", str(max(1, int(timeout * count))), host]
    return ["ping", "-c", str(count), "-W", str(max(1, int(timeout))), host]


def parse_ping_output(output, system=SYSTEM):
    """Return (reachable, average_latency_ms or None) from raw ping output."""
    # Windows can exit with code 0 for "Destination host unreachable",
    # so a real reply is only trusted if it contains a TTL value.
    reachable = bool(re.search(r"ttl[=\s]\d+", output, re.IGNORECASE))
    times = [float(t) for t in re.findall(r"time[=<]\s*([\d.]+)\s*ms", output, re.IGNORECASE)]
    latency = round(sum(times) / len(times), 2) if times else None
    return reachable, latency


def ping(host, count=1, timeout=1.0):
    try:
        proc = subprocess.run(build_ping_command(host, count, timeout),
                              capture_output=True, text=True,
                              timeout=timeout * count + 5)
    except FileNotFoundError:
        raise RuntimeError("the 'ping' command is not available on this system")
    except subprocess.TimeoutExpired:
        return False, None
    return parse_ping_output(proc.stdout + proc.stderr)


# ---------------------------------------------------------------- TCP ports

def check_port(host, port, timeout=1.5):
    """Return (state, latency_ms). state is OPEN, CLOSED (refused) or FILTERED (no reply)."""
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "OPEN", round((time.perf_counter() - start) * 1000, 2)
    except ConnectionRefusedError:
        return "CLOSED", None
    except socket.timeout:
        return "FILTERED", None
    except OSError:
        return "UNREACHABLE", None


# ---------------------------------------------------------------- DNS

def dns_lookup(name):
    """Forward lookup for a hostname, reverse (PTR) lookup for an IP address."""
    try:
        ipaddress.ip_address(name)
        hostname, aliases, _ = socket.gethostbyaddr(name)
        return {"type": "reverse", "names": [hostname] + aliases}
    except ValueError:
        pass
    infos = socket.getaddrinfo(name, None)
    v4 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET})
    v6 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET6})
    return {"type": "forward", "ipv4": v4, "ipv6": v6}


# ---------------------------------------------------------------- local configuration

def get_local_ip():
    """IP of the interface used for outbound traffic (UDP connect sends no packets)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return None


def parse_linux_route_table(text):
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) > 2 and fields[1] == "00000000":          # default route
            return socket.inet_ntoa(bytes.fromhex(fields[2])[::-1])
    return None


def parse_windows_ipconfig(text):
    # The gateway line may hold an IPv6 address first, with the IPv4 one on the next line.
    match = re.search(r"Default Gateway[ .]*:((?:\s*[0-9a-fA-F:.%]+\s*\n?)+)", text)
    if not match:
        return None
    for candidate in match.group(1).split():
        try:
            if ipaddress.ip_address(candidate.split("%")[0]).version == 4:
                return candidate
        except ValueError:
            continue
    return None


def get_default_gateway():
    try:
        if SYSTEM == "Linux":
            with open("/proc/net/route") as f:
                return parse_linux_route_table(f.read())
        if IS_WIN:
            out = subprocess.run(["ipconfig"], capture_output=True, text=True).stdout
            return parse_windows_ipconfig(out)
        if SYSTEM == "Darwin":
            out = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True).stdout
            m = re.search(r"gateway:\s*(\S+)", out)
            return m.group(1) if m else None
    except (OSError, subprocess.SubprocessError):
        return None
    return None


# ---------------------------------------------------------------- subnetting

def subnet_info(cidr):
    net = ipaddress.ip_network(cidr, strict=False)
    if net.version == 4 and net.prefixlen <= 30:
        first, last = net.network_address + 1, net.broadcast_address - 1
        usable = net.num_addresses - 2
    else:                                   # /31, /32 and IPv6 have no broadcast to subtract
        first, last = net.network_address, net[-1]
        usable = net.num_addresses
    info = {
        "network": str(net.network_address),
        "prefix": f"/{net.prefixlen}",
        "netmask": str(net.netmask),
        "first_host": str(first),
        "last_host": str(last),
        "usable_hosts": usable,
        "private": net.is_private,
    }
    if net.version == 4:
        info["wildcard"] = str(net.hostmask)
        info["broadcast"] = str(net.broadcast_address)
    return info


def sweep_targets(cidr):
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
    if len(hosts) > MAX_SWEEP_HOSTS:
        raise ValueError(f"{cidr} has {len(hosts)} hosts; limit sweeps to /22 or smaller")
    return [str(h) for h in hosts]


# ---------------------------------------------------------------- commands

def cmd_ping(args, log):
    ok, latency = ping(args.host, args.count, args.timeout)
    if ok:
        log.record("ICMP ping", args.host, "PASS", f"reply, avg {latency} ms")
    else:
        log.record("ICMP ping", args.host, "FAIL", "no reply",
                   "Check the address, cabling/Wi-Fi, or whether a firewall blocks ICMP")


def cmd_sweep(args, log):
    targets = sweep_targets(args.cidr)
    print(f"Sweeping {len(targets)} hosts in {args.cidr} ...")
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(lambda h: (h, *ping(h, 1, args.timeout)), targets))
    live = [(h, lat) for h, ok, lat in results if ok]
    for host, latency in live:
        log.record("Host discovery", host, "PASS", f"alive, {latency} ms")
    log.record("Sweep summary", args.cidr, "INFO", f"{len(live)}/{len(targets)} hosts responded")


def cmd_ports(args, log):
    ports = [int(p) for p in args.ports.split(",")] if args.ports else list(COMMON_PORTS)
    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(pool.map(lambda p: (p, *check_port(args.host, p, args.timeout)), ports))
    for port, state, latency in results:
        name = COMMON_PORTS.get(port, "")
        detail = f"{port}/tcp {name} {state}" + (f" ({latency} ms)" if latency else "")
        status = "PASS" if state == "OPEN" else "WARN" if state == "CLOSED" else "FAIL"
        log.record("TCP port", args.host, status, detail.replace("  ", " "))


def cmd_dns(args, log):
    try:
        res = dns_lookup(args.name)
    except (socket.gaierror, socket.herror) as e:
        log.record("DNS lookup", args.name, "FAIL", str(e),
                   "Check DNS server settings, try 8.8.8.8 or 1.1.1.1, flush the DNS cache")
        return
    if res["type"] == "reverse":
        log.record("Reverse DNS (PTR)", args.name, "PASS", ", ".join(res["names"]))
    else:
        log.record("DNS A record", args.name, "PASS", ", ".join(res["ipv4"]) or "none")
        log.record("DNS AAAA record", args.name, "PASS" if res["ipv6"] else "INFO",
                   ", ".join(res["ipv6"]) or "none")


def cmd_trace(args, log):
    cmd = (["tracert", "-d", "-h", str(args.max_hops), args.host] if IS_WIN
           else ["traceroute", "-n", "-m", str(args.max_hops), args.host])
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=args.max_hops * 6)
    except FileNotFoundError:
        log.record("Traceroute", args.host, "FAIL", f"'{cmd[0]}' not installed")
        return
    except subprocess.TimeoutExpired:
        log.record("Traceroute", args.host, "WARN", "timed out before reaching the host")
        return
    print(proc.stdout)
    hops = [l for l in proc.stdout.splitlines() if re.match(r"\s*\d+\s", l)]
    log.record("Traceroute", args.host, "INFO", f"{len(hops)} hops")


def cmd_subnet(args, log):
    info = subnet_info(args.cidr)
    width = max(len(k) for k in info)
    for key, value in info.items():
        print(f"  {key.replace('_', ' ').title():<{width + 2}} {value}")
    log.record("Subnet calculation", args.cidr, "INFO",
               f"{info['usable_hosts']} usable hosts, mask {info['netmask']}")


def _safe_ping(log, check, host, count, timeout):
    """ping() for diagnose: returns (ok, latency), or None if ping is unavailable."""
    try:
        return ping(host, count, timeout)
    except RuntimeError as e:
        log.record(check, host, "WARN", f"skipped: {e}")
        return None


def cmd_diagnose(args, log):
    """Layer-by-layer check. Stops at the first failing layer and says where the fault is."""
    print(f"Run {log.run_id}: diagnosing connectivity to {args.target}:{args.port}\n")

    # 1. Local IP configuration (Layer 1-3 on this machine)
    local_ip = get_local_ip()
    if not local_ip:
        log.record("Local IP config", "this host", "FAIL", "no usable IPv4 address",
                   "Check cable or Wi-Fi, enable the adapter, then renew DHCP (ipconfig /renew)")
        return conclude(log, "Layer 1-3: local interface")
    if local_ip.startswith("169.254."):
        log.record("Local IP config", local_ip, "FAIL", "APIPA address, DHCP did not respond",
                   "DHCP server unreachable: check the router/DHCP service, then renew the lease")
        return conclude(log, "Layer 3: DHCP / IP addressing")
    log.record("Local IP config", local_ip, "PASS", "address assigned")

    # 2. Default gateway (local network)
    gateway = args.gateway or get_default_gateway()
    if not gateway:
        log.record("Default gateway", "-", "WARN", "could not detect gateway",
                   "Check the adapter's gateway setting, or pass --gateway")
    else:
        result = _safe_ping(log, "Default gateway", gateway, 2, args.timeout)
        ok, latency = result if result else (True, None)
        if result and not ok:
            log.record("Default gateway", gateway, "FAIL", "no reply",
                       "LAN fault: check switch/Wi-Fi link, VLAN and gateway address")
            return conclude(log, "Layer 2-3: local network to gateway")
        if result:
            log.record("Default gateway", gateway, "PASS", f"reply, avg {latency} ms")

    # 3. Internet reachability by IP (routing beyond the gateway)
    result = _safe_ping(log, "Internet (by IP)", args.public_ip, 2, args.timeout)
    if result and not result[0]:
        log.record("Internet (by IP)", args.public_ip, "FAIL", "no reply",
                   "Upstream fault: check WAN link/ISP, routing, or firewall blocking ICMP")
        return conclude(log, "Layer 3: routing beyond the gateway")
    if result:
        log.record("Internet (by IP)", args.public_ip, "PASS", f"reply, avg {result[1]} ms")

    # 4. Name resolution
    try:
        addrs = dns_lookup(args.target)["ipv4"] if not _is_ip(args.target) else [args.target]
        log.record("DNS resolution", args.target, "PASS", ", ".join(addrs[:3]))
    except (socket.gaierror, socket.herror) as e:
        log.record("DNS resolution", args.target, "FAIL", str(e),
                   "IP works but names don't: fix DNS server settings, flush cache (ipconfig /flushdns)")
        return conclude(log, "Layer 7: DNS")

    # 5. Service port
    state, latency = check_port(args.target, args.port, args.timeout + 1)
    if state != "OPEN":
        log.record("Service port", f"{args.target}:{args.port}", "FAIL", state,
                   "Network is fine: service may be down or the port blocked by a firewall/proxy")
        return conclude(log, "Layer 4-7: service / firewall")
    log.record("Service port", f"{args.target}:{args.port}", "PASS", f"open, {latency} ms")
    return conclude(log, None)


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def conclude(log, fault_layer):
    print()
    if fault_layer:
        print(f"Fault isolated at: {fault_layer}")
    else:
        print("All checks passed: the network path and service are healthy.")
    if log.enabled:
        print(f"Results logged to {log.path} under run {log.run_id}")
    return fault_layer


# ---------------------------------------------------------------- CLI

def build_parser():
    p = argparse.ArgumentParser(prog="netdiag", description="Network troubleshooting toolkit")
    p.add_argument("--log", default=DEFAULT_LOG, help="CSV log file (default: %(default)s)")
    p.add_argument("--no-log", action="store_true", help="do not write to the log file")
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("diagnose", help="layer-by-layer connectivity check")
    d.add_argument("--target", default="google.com")
    d.add_argument("--port", type=int, default=443)
    d.add_argument("--public-ip", default="8.8.8.8")
    d.add_argument("--gateway", help="override the detected default gateway")
    d.add_argument("--timeout", type=float, default=1.0)
    d.set_defaults(func=cmd_diagnose)

    s = sub.add_parser("ping", help="ICMP reachability and latency")
    s.add_argument("host")
    s.add_argument("--count", type=int, default=4)
    s.add_argument("--timeout", type=float, default=1.0)
    s.set_defaults(func=cmd_ping)

    s = sub.add_parser("sweep", help="find live hosts in a subnet")
    s.add_argument("cidr")
    s.add_argument("--workers", type=int, default=64)
    s.add_argument("--timeout", type=float, default=1.0)
    s.set_defaults(func=cmd_sweep)

    s = sub.add_parser("ports", help="check common or given TCP ports")
    s.add_argument("host")
    s.add_argument("--ports", help="comma-separated list, e.g. 22,80,443")
    s.add_argument("--timeout", type=float, default=1.5)
    s.set_defaults(func=cmd_ports)

    s = sub.add_parser("dns", help="forward or reverse DNS lookup")
    s.add_argument("name")
    s.set_defaults(func=cmd_dns)

    s = sub.add_parser("trace", help="traceroute to a host")
    s.add_argument("host")
    s.add_argument("--max-hops", type=int, default=20)
    s.set_defaults(func=cmd_trace)

    s = sub.add_parser("subnet", help="subnet calculator")
    s.add_argument("cidr")
    s.set_defaults(func=cmd_subnet)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    log = Logger(args.log, enabled=not args.no_log)
    try:
        args.func(args, log)
    except (ValueError, RuntimeError) as e:
        print(f"Error: {e}")
        return 1
    except KeyboardInterrupt:
        print("\nStopped.")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
