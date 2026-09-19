"""Opt-in Linux packet integration tests in two disposable network namespaces.

Run: sudo unshare --net -- env DEFENDER_LINUX_TEST=1 python3 -B -m unittest test_defender_linux -v
Never run with DEFENDER_LINUX_TEST=1 outside a fresh network namespace.
"""

import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import unittest

import defender as d
import scanner as s


LOCAL, PEER = "198.18.0.1", "198.18.0.2"
ROOT = Path(__file__).resolve().parent
PEER_CODE = """
import json, socket, sys
mode = sys.argv[1]
if mode == 'tcp':
    with socket.create_connection(('198.18.0.1', 8080), timeout=3) as sock:
        sock.sendall(b'normal TCP still works')
        print(sock.recv(256).decode(), flush=True)
else:
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    sock.settimeout(3)
    print('ready', flush=True)
    for line in sys.stdin:
        try:
            print(json.dumps({'packet': sock.recv(65535).hex()}), flush=True)
        except socket.timeout:
            print(json.dumps({'timeout': True}), flush=True)
"""


@unittest.skipUnless(sys.platform.startswith("linux") and os.environ.get("DEFENDER_LINUX_TEST") == "1",
                     "requires explicit opt-in inside a fresh Linux network namespace")
class LinuxPacketTests(unittest.TestCase):
    @classmethod
    def command(cls, *args):
        return subprocess.run(args, check=True, capture_output=True, text=True, timeout=15).stdout

    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0 or os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
            raise RuntimeError("run as root inside unshare --net, never in the host network namespace")
        # Refuse namespaces with existing interfaces beyond loopback.
        if len(json.loads(cls.command("ip", "-j", "link"))) != 1:
            raise RuntimeError("integration test requires an empty network namespace")
        cls.peer = subprocess.Popen(["unshare", "--net", "--", "sleep", "120"])
        cls.addClassCleanup(cls.stop_peer)
        for _ in range(100):
            if os.readlink(f"/proc/{cls.peer.pid}/ns/net") != os.readlink("/proc/self/ns/net"):
                break
            time.sleep(0.01)
        else:
            raise RuntimeError("peer namespace did not start")
        cls.command("ip", "link", "add", "defense0", "type", "veth", "peer", "name", "scan0")
        cls.command("ip", "link", "set", "scan0", "netns", str(cls.peer.pid))
        cls.command("ip", "address", "add", LOCAL + "/24", "dev", "defense0")
        cls.command("ip", "link", "set", "defense0", "up")
        cls.command("ip", "link", "set", "lo", "up")
        cls.peer_prefix = ["nsenter", "--target", str(cls.peer.pid), "--net", "--"]
        cls.command(*cls.peer_prefix, "ip", "address", "add", PEER + "/24", "dev", "scan0")
        cls.command(*cls.peer_prefix, "ip", "link", "set", "scan0", "up")
        cls.command(*cls.peer_prefix, "ip", "link", "set", "lo", "up")

    @classmethod
    def stop_peer(cls):
        cls.peer.terminate()
        cls.peer.wait(timeout=5)

    def setUp(self):
        self.backend = None
        self.receiver = None
        self.components = []
        self.sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.addCleanup(self.sender.close)
        self.addCleanup(self.cleanup)

    def cleanup(self):
        for component in reversed(self.components):
            component.close()
        if self.backend is not None:
            self.backend.close()
        if self.receiver is not None:
            self.receiver.terminate()
            self.receiver.communicate(timeout=5)

    def start(self, policy=d.Policy()):
        self.backend = d.LinuxDefense(policy)
        self.backend.start()

    def receiver_start(self):
        self.receiver = subprocess.Popen(self.peer_prefix + [sys.executable, "-u", "-c", PEER_CODE, "udp"],
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, text=True)
        self.assertEqual(self.receiver.stdout.readline().strip(), "ready")

    def exchange(self, df=True):
        udp = s.udp_segment(LOCAL, PEER, 12345, 23456, b"defense payload")
        raw = bytearray(s.ip_packet(LOCAL, PEER, 17, udp, 4321, df=df))
        raw[8] = 128
        self.sender.sendto(raw, (PEER, 0))
        self.receiver.stdin.write("receive\n")
        self.receiver.stdin.flush()
        row = json.loads(self.receiver.stdout.readline())
        self.assertNotIn("timeout", row)
        return bytes.fromhex(row["packet"])

    def test_real_ttl_id_checksums_and_restore(self):
        self.receiver_start()
        before = self.exchange()
        self.assertEqual(before[8], 128)
        self.assertEqual(int.from_bytes(before[4:6], "big"), 4321)
        self.start()
        after = self.exchange()
        self.assertEqual(after[8], 64)
        self.assertEqual(after[4:6], b"\0\0")
        self.assertEqual(after[20:], before[20:])
        self.assertEqual(s.checksum(after[:20]), 0)
        fragmentable = self.exchange(df=False)
        self.assertEqual(int.from_bytes(fragmentable[4:6], "big"), 4321)
        self.backend.close()
        restored = self.exchange()
        self.assertEqual(restored[8], 128)
        self.assertEqual(int.from_bytes(restored[4:6], "big"), 4321)

    def test_normal_tcp_connection_survives_optional_probe_filter(self):
        self.start(d.Policy(quiet_probes=True, suppress_rst=True))
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((LOCAL, 8080))
            listener.listen()
            listener.settimeout(5)
            failures = []

            def echo():
                try:
                    with listener.accept()[0] as client:
                        client.settimeout(3)
                        client.sendall(client.recv(256))
                except Exception as error:
                    failures.append(error)

            worker = threading.Thread(target=echo)
            worker.start()
            try:
                reply = self.command(*self.peer_prefix, sys.executable, "-c", PEER_CODE, "tcp")
                self.assertEqual(reply.strip(), "normal TCP still works")
            finally:
                worker.join(timeout=6)
            self.assertEqual(failures, [])

    def test_scope_and_ttl_only(self):
        self.receiver_start()
        self.start(d.Policy(peers=(ipaddress.IPv4Network("192.0.2.1"),)))
        self.assertEqual(self.exchange()[8], 128)
        self.backend.close()
        self.start(d.Policy(ttl=99, mode="ttl-only"))
        raw = self.exchange()
        self.assertEqual(raw[8], 99)
        self.assertEqual(int.from_bytes(raw[4:6], "big"), 4321)

    def test_existing_firewall_table_and_duplicate_instance_preserved(self):
        self.command("nft", "add", "table", "ip", "unrelated_test_table")
        self.start()
        duplicate = d.LinuxDefense(d.Policy())
        with self.assertRaises(OSError):
            duplicate.start()
        duplicate.close()
        self.backend.check()
        self.backend.close()
        self.assertIn("unrelated_test_table", self.command("nft", "list", "tables"))
        self.command("nft", "delete", "table", "ip", "unrelated_test_table")

    def peer_python(self, code, *args):
        return self.command(*self.peer_prefix, sys.executable, "-B", "-c", code, *args)

    def send_syns(self, ports, source=PEER):
        self.peer_python("""
import socket, sys
import scanner as s
source = sys.argv[1]
with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as sock:
    for port in map(int, sys.argv[2:]):
        segment = s.tcp_segment(source, '198.18.0.1', 45000, port, 100, flags=s.SYN)
        sock.sendto(s.ip_packet(source, '198.18.0.1', 6, segment, 123), ('198.18.0.1', 0))
""", source, *map(str, ports))

    def decoy(self):
        decoy = d.DecoyServices(d.Policy(decoy_ports=(8080,), decoy_bind=LOCAL, decoy_banner="220 test decoy"))
        self.components.append(decoy)
        decoy.start()

    def greeting(self):
        return self.peer_python("""
import socket
try:
    with socket.create_connection(('198.18.0.1', 8080), timeout=0.4) as client:
        print(client.recv(128).decode().strip())
except (TimeoutError, ConnectionRefusedError):
    print('blocked')
""").strip()

    def monitor(self, policy):
        monitor = d.LinuxMonitor(policy, self.backend)
        self.components.append(monitor)
        monitor.start()
        return monitor

    def dropped(self, expression):
        rules = self.command("nft", "list", "chain", "ip", d.TABLE, "incoming")
        line = next(row for row in rules.splitlines() if expression in row)
        return int(re.search(r"counter packets (\d+)", line).group(1))

    def test_active_sweep_blocks_then_expires_and_restores_service(self):
        args = d.make_parser().parse_args(["preview", "--active", "--interface", "defense0",
                                          "--threshold", "3", "--block-seconds", "2"])
        policy = d.Policy.from_args(args)
        self.start(policy)
        self.decoy()
        monitor = self.monitor(policy)
        self.assertEqual(self.greeting(), "220 test decoy")
        self.send_syns((8090, 8091, 8092))
        deadline = time.monotonic() + 1.5
        while PEER not in self.command("nft", "list", "set", "ip", d.TABLE, "blocked"):
            monitor.check()
            self.assertLess(time.monotonic(), deadline, "sensor did not install a source block")
            time.sleep(0.03)
        self.assertEqual(self.greeting(), "blocked")
        self.assertGreater(self.dropped("@blocked"), 0)
        time.sleep(2.1)
        monitor.check()
        self.assertEqual(self.greeting(), "220 test decoy")

    def test_kernel_blocks_unusual_probe_before_python_monitor_starts(self):
        self.start(d.Policy(auto_block=True, block_seconds=2))
        self.decoy()
        self.assertEqual(self.greeting(), "220 test decoy")
        self.peer_python("""
import socket
import scanner as s
with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as sock:
    tcp = s.tcp_segment('198.18.0.2', '198.18.0.1', 45000, 8080, 100, flags=0)
    sock.sendto(s.ip_packet('198.18.0.2', '198.18.0.1', 6, tcp, 123), ('198.18.0.1', 0))
""")
        self.assertIn(PEER, self.command("nft", "list", "set", "ip", d.TABLE, "blocked"))
        self.assertEqual(self.greeting(), "blocked")
        time.sleep(2.1)
        self.assertEqual(self.greeting(), "220 test decoy")

    def test_hardened_defeats_standard_fingerprint_battery_on_same_link(self):
        self.decoy()
        code = """
import contextlib, io, json
import scanner as s
args = s.make_parser().parse_args(['scan', '198.18.0.1', '-p', '8080,8081',
                                  '--os-tries', '1', '--retries', '0', '--timeout', '0.2'])
with contextlib.redirect_stdout(io.StringIO()):
    report = s.scan(args)
print(json.dumps({'syn_replies': report['result']['syn_replies'],
                  'responsive': [p['name'] for r in report['fingerprint_rounds']
                                 for p in r['probes'] if p['response']]}))
"""
        before = json.loads(self.peer_python(code))
        self.assertEqual(before["syn_replies"], 6)
        policy = d.Policy.from_args(d.make_parser().parse_args(["preview", "--hardened", "--interface", "any"]))
        self.start(policy)
        # No monitor: the firewall alone must suppress the first fingerprint
        # SYN and the rest of the battery, while normal clients still work.
        self.assertEqual(self.greeting(), "220 test decoy")
        after = json.loads(self.peer_python(code))
        self.assertEqual(after["syn_replies"], 0)
        self.assertEqual(after["responsive"], [])
        self.assertIn(PEER, self.command("nft", "list", "set", "ip", d.TABLE, "blocked"))
        print(f"\nSame-link fingerprint SYN replies: {before['syn_replies']} -> {after['syn_replies']}")

    def test_any_interface_monitor_and_rule_scope(self):
        policy = d.Policy(interface="any", detect=True, auto_block=True, threshold=2)
        self.start(policy)
        monitor = self.monitor(policy)
        self.send_syns((8090, 8091))
        deadline = time.monotonic() + 2
        while PEER not in self.command("nft", "list", "set", "ip", d.TABLE, "blocked"):
            monitor.check()
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.03)
        self.assertGreater(monitor.observed, 0)
        self.assertNotIn("127.0.0.1", monitor.local)

    def test_wrong_vm_interface_has_explicit_route_warning(self):
        self.command("ip", "link", "add", "wrong0", "type", "dummy")
        try:
            self.command("ip", "address", "add", "192.0.2.1/24", "dev", "wrong0")
            self.command("ip", "link", "set", "wrong0", "up")
            policy = d.Policy(interface="wrong0", detect=True, peers=(ipaddress.IPv4Network(PEER),))
            self.start(policy)
            with self.assertLogs(d.LOG, "WARNING") as logs:
                self.monitor(policy)
            self.assertTrue(any("INTERFACE MISMATCH" in row and "defense0" in row for row in logs.output))
        finally:
            self.command("ip", "link", "delete", "wrong0")

    def test_allowlist_exempts_detection_and_static_block(self):
        policy = d.Policy(interface="defense0", detect=True, auto_block=True, threshold=2,
                          trusted=(ipaddress.IPv4Network(PEER),), block_sources=(ipaddress.IPv4Network(PEER),))
        self.start(policy)
        self.decoy()
        monitor = self.monitor(policy)
        self.send_syns((8090, 8091, 8092))
        self.assertEqual(self.greeting(), "220 test decoy")
        monitor.check()
        self.assertNotIn(PEER, self.command("nft", "list", "set", "ip", d.TABLE, "blocked"))

    def test_real_incomplete_handshake_correlation_blocks_half_open_scan(self):
        policy = d.Policy(interface="defense0", detect=True, auto_block=True, threshold=100,
                          handshake_threshold=2)
        self.start(policy)
        self.decoy()
        monitor = self.monitor(policy)
        self.assertEqual(self.greeting(), "220 test decoy")
        time.sleep(0.1)
        self.assertFalse(monitor.detector.incomplete)
        # The peer's kernel resets these raw SYN/SYN-ACK handshakes. Distinct
        # port count stays one, so only handshake correlation can trigger.
        self.send_syns((8080,))
        time.sleep(0.1)
        self.send_syns((8080,))
        deadline = time.monotonic() + 2
        while PEER not in self.command("nft", "list", "set", "ip", d.TABLE, "blocked"):
            monitor.check()
            self.assertLess(time.monotonic(), deadline, "incomplete handshake sensor did not block")
            time.sleep(0.03)
        self.assertEqual(self.greeting(), "blocked")

    def test_abnormal_flag_packets_are_dropped_without_header_rewriting(self):
        self.start(d.Policy(mode="filter-only", filter_flags=True))
        self.peer_python("""
import socket
import scanner as s
with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as sock:
    for flags in (0, s.SYN | s.FIN, s.SYN | s.RST, s.FIN | s.PSH | s.URG):
        tcp = s.tcp_segment('198.18.0.2', '198.18.0.1', 45000, 8080, 100, flags=flags)
        sock.sendto(s.ip_packet('198.18.0.2', '198.18.0.1', 6, tcp, 123), ('198.18.0.1', 0))
""")
        rules = self.command("nft", "list", "chain", "ip", d.TABLE, "incoming")
        self.assertEqual(sum(map(int, re.findall(r"counter packets (\d+)", rules))), 4)
        self.decoy()
        self.assertEqual(self.greeting(), "220 test decoy")
        self.receiver_start()
        self.assertEqual(self.exchange()[8], 128)

    def test_echo_and_legacy_icmp_requests_hit_only_selected_filters(self):
        self.start(d.Policy(block_echo=True, block_legacy_icmp=True))
        self.peer_python("""
import socket, struct
import scanner as s
with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as sock:
    for kind in (8, 13, 17):
        message = bytes([kind, 0, 0, 0]) + b'\\0' * 16
        message = message[:2] + struct.pack('!H', s.checksum(message)) + message[4:]
        sock.sendto(s.ip_packet('198.18.0.2', '198.18.0.1', 1, message, 123), ('198.18.0.1', 0))
""")
        self.assertEqual(self.dropped("echo-request"), 1)
        self.assertEqual(self.dropped("timestamp-request"), 2)

    def test_syn_rate_is_per_source_and_normal_connection_recovers(self):
        self.start(d.Policy(syn_rate=2, syn_burst=2))
        self.send_syns(range(8090, 8098))
        dropped = self.dropped("@syn_rates")
        self.assertGreaterEqual(dropped, 5)
        self.send_syns((8099,), source="198.18.0.3")
        self.assertEqual(self.dropped("@syn_rates"), dropped)
        self.decoy()
        time.sleep(1.1)
        self.assertEqual(self.greeting(), "220 test decoy")

    def test_syn_rate_excess_blocks_source_even_for_repeated_single_port(self):
        policy = d.Policy(auto_block=True, syn_rate=2, syn_burst=2, block_seconds=2)
        self.start(policy)
        self.decoy()
        # No Python monitor, and only one destination port: this must be a
        # kernel rate decision, not a distinct-port alert.
        self.send_syns((8090,) * 6)
        self.assertIn(PEER, self.command("nft", "list", "set", "ip", d.TABLE, "blocked"))
        self.assertEqual(self.greeting(), "blocked")
        self.command(*self.peer_prefix, "ip", "address", "add", "198.18.0.3/24", "dev", "scan0")
        try:
            other = self.peer_python("""
import socket
with socket.create_connection(('198.18.0.1', 8080), timeout=1, source_address=('198.18.0.3', 0)) as client:
    print(client.recv(128).decode().strip())
""")
            self.assertEqual(other.strip(), "220 test decoy")
        finally:
            self.command(*self.peer_prefix, "ip", "address", "delete", "198.18.0.3/24", "dev", "scan0")
        time.sleep(2.1)
        self.assertEqual(self.greeting(), "220 test decoy")

    def test_udp_filter_blocks_only_selected_port_and_preserves_tcp(self):
        self.start(d.Policy(block_echo=True, block_legacy_icmp=True, udp_ports=(33434,)))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as blocked, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as allowed:
            blocked.bind((LOCAL, 33434))
            allowed.bind((LOCAL, 33435))
            blocked.settimeout(0.25)
            allowed.settimeout(1)
            self.peer_python("""
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    for port in (33434, 33435):
        sock.sendto(b'udp test', ('198.18.0.1', port))
""")
            self.assertEqual(allowed.recv(128), b"udp test")
            with self.assertRaises(socket.timeout):
                blocked.recv(128)
        self.assertEqual(self.dropped("udp dport"), 1)
        self.decoy()
        self.assertEqual(self.greeting(), "220 test decoy")

    def test_connection_limit_drops_only_excess_connections(self):
        self.start(d.Policy(connlimit=2))
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((LOCAL, 8080))
            listener.listen(10)
            result = self.peer_python("""
import socket
clients = []
try:
    for _ in range(3):
        try:
            clients.append(socket.create_connection(('198.18.0.1', 8080), timeout=0.3))
            print('connected')
        except TimeoutError:
            print('blocked')
finally:
    for client in clients:
        client.close()
""")
        self.assertEqual(result.splitlines(), ["connected", "connected", "blocked"])
        self.assertGreater(self.dropped("@connections"), 0)

    def test_sigterm_background_cleanup_restores_sysctl_and_rules(self):
        setting = Path("/proc/sys/net/ipv4/tcp_syncookies")
        original = setting.read_text()
        self.addCleanup(setting.write_text, original)
        setting.write_text("0\n")
        process = subprocess.Popen([sys.executable, "-B", "defender.py", "run", "--syn-cookies"],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while setting.read_text().strip() != "1":
                self.assertIsNone(process.poll(), "defender exited during startup")
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.03)
            # Wait for complete startup (monitor is started after sysctl).
            time.sleep(0.2)
            process.terminate()
            _, logs = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 0, logs)
            self.assertIn("ACTIVE", logs)
            self.assertIn("interface=any", logs)
            self.assertIn("STRICT FILTER", logs)
            self.assertEqual(setting.read_text().strip(), "0")
            self.assertNotIn(d.TABLE, self.command("nft", "list", "tables"))
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
