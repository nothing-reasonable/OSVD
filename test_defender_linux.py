"""Opt-in Linux packet integration tests in two disposable network namespaces.

Run: sudo unshare --net -- env DEFENDER_LINUX_TEST=1 python3 -B -m unittest test_defender_linux -v
Never run with DEFENDER_LINUX_TEST=1 outside a fresh network namespace.
"""

import ipaddress
import json
import os
from pathlib import Path
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
        self.sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.addCleanup(self.sender.close)
        self.addCleanup(self.cleanup)

    def cleanup(self):
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


if __name__ == "__main__":
    unittest.main()
