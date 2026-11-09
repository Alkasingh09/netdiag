import os
import socket
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import netdiag  # noqa: E402

WINDOWS_PING_OK = """
Pinging 8.8.8.8 with 32 bytes of data:
Reply from 8.8.8.8: bytes=32 time=14ms TTL=117
Reply from 8.8.8.8: bytes=32 time=16ms TTL=117
"""
WINDOWS_PING_UNREACHABLE = """
Pinging 10.0.0.99 with 32 bytes of data:
Reply from 10.0.0.5: Destination host unreachable.
"""
LINUX_PING_OK = """
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=10.4 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=11.6 ms
"""
LINUX_ROUTE = """Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0101A8C0	0003	0	0	100	00000000	0	0	0
eth0	0001A8C0	00000000	0001	0	0	100	00FFFFFF	0	0	0
"""
IPCONFIG = """
Wireless LAN adapter Wi-Fi:

   IPv4 Address. . . . . . . . . . . : 192.168.1.23
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::1%12
                                       192.168.1.1
"""


class PingParsing(unittest.TestCase):
    def test_windows_reply(self):
        self.assertEqual(netdiag.parse_ping_output(WINDOWS_PING_OK), (True, 15.0))

    def test_windows_unreachable_is_not_success(self):
        self.assertEqual(netdiag.parse_ping_output(WINDOWS_PING_UNREACHABLE), (False, None))

    def test_linux_reply(self):
        self.assertEqual(netdiag.parse_ping_output(LINUX_PING_OK), (True, 11.0))

    def test_command_per_os(self):
        self.assertEqual(netdiag.build_ping_command("h", 2, 1.5, "Windows"), ["ping", "-n", "2", "-w", "1500", "h"])
        self.assertEqual(netdiag.build_ping_command("h", 2, 1.0, "Linux"), ["ping", "-c", "2", "-W", "1", "h"])


class GatewayParsing(unittest.TestCase):
    def test_linux_route_table(self):
        self.assertEqual(netdiag.parse_linux_route_table(LINUX_ROUTE), "192.168.1.1")

    def test_windows_ipconfig_prefers_ipv4(self):
        self.assertEqual(netdiag.parse_windows_ipconfig(IPCONFIG), "192.168.1.1")


class Subnetting(unittest.TestCase):
    def test_slash_26(self):
        info = netdiag.subnet_info("192.168.10.77/26")
        self.assertEqual(info["network"], "192.168.10.64")
        self.assertEqual(info["broadcast"], "192.168.10.127")
        self.assertEqual(info["first_host"], "192.168.10.65")
        self.assertEqual(info["last_host"], "192.168.10.126")
        self.assertEqual(info["usable_hosts"], 62)
        self.assertEqual(info["wildcard"], "0.0.0.63")

    def test_point_to_point_slash_31(self):
        self.assertEqual(netdiag.subnet_info("10.0.0.0/31")["usable_hosts"], 2)

    def test_sweep_limit(self):
        self.assertEqual(len(netdiag.sweep_targets("10.0.0.0/24")), 254)
        with self.assertRaises(ValueError):
            netdiag.sweep_targets("10.0.0.0/16")


class PortsAndDns(unittest.TestCase):
    def test_open_and_closed_ports(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        threading.Thread(target=lambda: server.accept(), daemon=True).start()
        self.assertEqual(netdiag.check_port("127.0.0.1", port)[0], "OPEN")
        server.close()
        self.assertEqual(netdiag.check_port("127.0.0.1", port)[0], "CLOSED")

    def test_forward_lookup_localhost(self):
        self.assertIn("127.0.0.1", netdiag.dns_lookup("localhost")["ipv4"])


class Logging(unittest.TestCase):
    def test_log_written_with_header(self):
        path = os.path.join(tempfile.mkdtemp(), "log.csv")
        log = netdiag.Logger(path)
        log.record("TCP port", "host", "FAIL", "CLOSED", "check firewall")
        with open(path) as f:
            lines = f.read().splitlines()
        self.assertTrue(lines[0].startswith("timestamp,run_id"))
        self.assertIn("check firewall", lines[1])


if __name__ == "__main__":
    unittest.main()
