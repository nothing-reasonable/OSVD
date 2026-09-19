"""Offline defense regressions; optional real WinDivert helper tests open no handles."""

import argparse
import ctypes as c
import ipaddress
import os
import queue
import struct
import sys
import time
import unittest
from unittest.mock import Mock, patch

import defender as d
import scanner as s
import windows_transport as w


LOCAL, PEER = "192.0.2.1", "192.0.2.2"


def packet(flags=s.SYN | s.ACK, source=LOCAL, target=PEER, df=True, ttl=128):
    tcp = s.tcp_segment(source, target, 8080, 45000, 123, ack=456,
                        flags=flags, window=64240, options=b"\x02\x04\x05\xb4\x01\x01\x04\x02")
    raw = bytearray(s.ip_packet(source, target, 6, tcp, 4321, df=df))
    raw[8] = ttl
    raw[10:12] = b"\0\0"
    raw[10:12] = struct.pack("!H", s.checksum(raw[:20]))
    return bytes(raw)


class PolicyTests(unittest.TestCase):
    def test_default_preserves_connections_and_all_replies(self):
        args = d.make_parser().parse_args(["preview"])
        policy = d.Policy.from_args(args)
        self.assertIsNone(d.divert_filters(policy)[0])
        self.assertNotIn("drop", d.nft_rules(policy))
        self.assertNotIn("tcp", d.nft_rules(policy))

    def test_peer_validation_and_collapse(self):
        args = d.make_parser().parse_args(["preview", "--peer", "192.0.2.4/24", "--peer", PEER])
        self.assertEqual(d.Policy.from_args(args).peers, (ipaddress.IPv4Network("192.0.2.0/24"),))
        for value in ("::1", "a; drop table", "300.1.1.1"):
            with self.assertRaises(argparse.ArgumentTypeError):
                d.ipv4_network(value)
        for value in ("0", "256", "64.1", "foo"):
            with self.assertRaises(argparse.ArgumentTypeError):
                d.ttl_value(value)
        for value in ("nan", "inf", "-1"):
            with self.assertRaises(argparse.ArgumentTypeError):
                d.duration_value(value)

    def test_normalization_preserves_transport_and_fragment_ids(self):
        original = packet()
        changed = d.normalize_packet(original, d.Policy())
        self.assertEqual(changed[8], 64)
        self.assertEqual(changed[4:6], b"\0\0")
        self.assertEqual(changed[20:], original[20:])
        self.assertEqual(changed[:4], original[:4])
        self.assertEqual(changed[6:8], original[6:8])
        for fragment in (0, 0x2000, 0x2001, 1, 0x6000, 0x4001):
            raw = bytearray(original)
            raw[6:8] = struct.pack("!H", fragment)
            self.assertEqual(d.normalize_packet(raw, d.Policy())[4:6], original[4:6])
        self.assertEqual(d.normalize_packet(original, d.Policy(mode="ttl-only"))[4:6], original[4:6])

    def test_truncated_headers_rejected(self):
        for raw in (b"", b"\x45" * 10, b"\x65" * 20, b"\x4f" * 20, b"\x41" * 20):
            with self.assertRaises(ValueError):
                d.normalize_packet(raw, d.Policy())


class LinuxLifecycleTests(unittest.TestCase):
    def backend(self, results):
        with patch.object(d.shutil, "which", return_value="/usr/sbin/nft"):
            backend = d.LinuxDefense(d.Policy())
        backend.command = Mock(side_effect=results)
        return backend

    def test_checks_then_atomic_install_and_owned_cleanup(self):
        backend = self.backend(["", "", ""])
        with patch.object(d.os, "geteuid", return_value=0, create=True):
            backend.start()
        self.assertTrue(backend.active)
        calls = backend.command.call_args_list
        self.assertEqual(calls[0].args, ("--check", "--file", "-"))
        self.assertEqual(calls[1].args, ("--file", "-"))
        self.assertTrue(calls[1].kwargs["script"].startswith("create table ip portscan_defense\n"))
        self.assertNotIn("flush", calls[1].kwargs["script"])
        backend.close()
        backend.command.assert_called_with("delete", "table", "ip", d.TABLE)

    def test_failed_or_duplicate_install_does_not_remove_existing_table(self):
        for results in ([OSError("exists")], ["", OSError("exists")]):
            backend = self.backend(results)
            with patch.object(d.os, "geteuid", return_value=0, create=True):
                with self.assertRaises(OSError):
                    backend.start()
            backend.close()
            self.assertFalse(backend.active)
            self.assertFalse(any(call.args[0] == "delete" for call in backend.command.call_args_list))


class FakeDriver:
    def __init__(self):
        self.opened, self.closed, self.sent = [], [], []
        self.incoming = queue.Queue()
        self.WinDivertHelperCalcChecksums = Mock(side_effect=self.checksum)
        self.fail_second = False

    def WinDivertOpen(self, expression, layer, priority, flags):
        if self.fail_second and self.opened:
            return c.c_void_p(-1).value
        self.opened.append((expression, layer, priority, flags))
        return len(self.opened)

    def WinDivertGetParam(self, handle, param, value):
        c.cast(value, c.POINTER(c.c_uint64))[0] = 2
        return True

    def WinDivertRecv(self, handle, buffer, capacity, size, address):
        raw = self.incoming.get(timeout=3)
        if raw is None:
            return False
        c.memmove(buffer, raw, len(raw))
        c.cast(size, c.POINTER(c.c_uint32))[0] = len(raw)
        c.cast(address, c.POINTER(w.DivertAddress))[0].flags = 1 << 17
        return True

    def checksum(self, buffer, size, address, flags):
        raw = bytearray(c.string_at(buffer, size))
        raw[10:12] = b"\0\0"
        raw[10:12] = struct.pack("!H", s.checksum(raw[:20]))
        c.memmove(buffer, bytes(raw), size)
        return True

    def WinDivertSend(self, handle, buffer, size, sent, address):
        self.sent.append(c.string_at(buffer, size))
        c.cast(sent, c.POINTER(c.c_uint32))[0] = size
        return True

    def WinDivertShutdown(self, handle, how):
        self.incoming.put(None)
        return True

    def WinDivertClose(self, handle):
        self.closed.append(handle)
        return True


class WindowsLifecycleTests(unittest.TestCase):
    def backend(self, driver, policy=d.Policy()):
        with patch.object(w, "load_library", return_value=driver):
            backend = d.WindowsDefense(policy)
        backend.driver_error = lambda name: OSError(name)
        self.addCleanup(backend.close)
        return backend

    def test_rewrites_reinjects_and_stops_idle_worker(self):
        driver = FakeDriver()
        backend = self.backend(driver)
        backend.start()
        driver.incoming.put(packet())
        deadline = time.monotonic() + 2
        while not driver.sent and time.monotonic() < deadline:
            backend.check()
            time.sleep(0.01)
        self.assertEqual(len(driver.sent), 1)
        self.assertEqual(driver.sent[0][8], 64)
        self.assertEqual(driver.sent[0][4:6], b"\0\0")
        self.assertEqual(s.checksum(driver.sent[0][:20]), 0)
        self.assertEqual(driver.sent[0][20:], packet()[20:])
        backend.close()
        self.assertFalse(backend.thread.is_alive())
        self.assertEqual(driver.closed, [1])
        self.assertEqual(driver.opened[0][3], 0)  # Divert, not sniff/copy.

    def test_partial_start_failure_closes_drop_handle(self):
        driver = FakeDriver()
        driver.fail_second = True
        backend = self.backend(driver, d.Policy(quiet_probes=True))
        with self.assertRaises(OSError):
            backend.start()
        self.assertEqual(driver.closed, [1])
        self.assertEqual(driver.opened[0][3], 2)

    def test_thread_start_failure_closes_all_handles(self):
        driver = FakeDriver()
        backend = self.backend(driver, d.Policy(quiet_probes=True))
        with patch.object(d.threading.Thread, "start", side_effect=RuntimeError("thread unavailable")):
            with self.assertRaisesRegex(RuntimeError, "thread unavailable"):
                backend.start()
        self.assertEqual(driver.closed, [2, 1])

    def test_checksum_failure_is_reported_without_reinjecting(self):
        driver = FakeDriver()
        driver.WinDivertHelperCalcChecksums.side_effect = None
        driver.WinDivertHelperCalcChecksums.return_value = False
        backend = self.backend(driver)
        backend.start()
        driver.incoming.put(packet())
        backend.thread.join(timeout=2)
        with self.assertRaisesRegex(OSError, "CalcChecksums"):
            backend.check()
        self.assertEqual(driver.sent, [])


@unittest.skipUnless(sys.platform == "win32" and os.environ.get("DEFENDER_WINDIVERT_DIR"),
                     "set DEFENDER_WINDIVERT_DIR for offline native filter/checksum tests")
class NativeWindowsFilterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dll = w.load_library(os.environ["DEFENDER_WINDIVERT_DIR"])
        cls.compile = cls.dll.WinDivertHelperCompileFilter
        cls.compile.argtypes = [c.c_char_p, c.c_int, c.c_void_p, c.c_uint32,
                               c.POINTER(c.c_char_p), c.POINTER(c.c_uint32)]
        cls.compile.restype = c.c_int32
        cls.evaluate = cls.dll.WinDivertHelperEvalFilter
        cls.evaluate.argtypes = [c.c_char_p, c.c_void_p, c.c_uint32, c.POINTER(w.DivertAddress)]
        cls.evaluate.restype = c.c_int32

    def matches(self, expression, raw, outbound=False, loopback=False):
        if expression is None:
            return False
        error, position = c.c_char_p(), c.c_uint32()
        self.assertTrue(self.compile(expression.encode(), 0, None, 0, c.byref(error), c.byref(position)),
                        f"{error.value!r} at {position.value}: {expression}")
        address = w.DivertAddress()
        address.flags = (int(outbound) << 17) | (int(loopback) << 18)
        return bool(self.evaluate(expression.encode(), raw, len(raw), c.byref(address)))

    def test_all_probe_packets_remain_allowed_by_default(self):
        policy = d.Policy(peers=(ipaddress.IPv4Network(PEER),))
        drop, rewrite = d.divert_filters(policy)
        for probe in s.standard_probes(PEER, LOCAL, 8080, 8081, 33434):
            self.assertFalse(self.matches(drop, probe.packet))
        self.assertTrue(self.matches(rewrite, packet(), outbound=True))
        self.assertFalse(self.matches(rewrite, packet(target="192.0.2.3"), outbound=True))
        self.assertFalse(self.matches(rewrite, packet(), outbound=True, loopback=True))
        self.assertFalse(self.matches(rewrite, packet(), outbound=False))

    def test_optional_filter_preserves_normal_handshakes_and_pmtu(self):
        drop, _ = d.divert_filters(d.Policy(quiet_probes=True))
        for flags in (s.SYN, s.SYN | s.ECE | s.CWR, s.SYN | s.ACK, s.ACK, s.FIN | s.ACK, s.RST):
            self.assertFalse(self.matches(drop, packet(flags)))
        for flags in (0, s.SYN | s.FIN, s.SYN | s.RST, s.FIN | s.PSH | s.URG):
            self.assertTrue(self.matches(drop, packet(flags)))
        for kind, code, blocked in ((0, 0, True), (3, 3, True), (3, 4, False), (11, 0, False)):
            icmp = struct.pack("!BBHI", kind, code, 0, 0) + b"\0" * 28
            raw = s.ip_packet(LOCAL, PEER, 1, icmp, 123)
            self.assertEqual(self.matches(drop, raw, outbound=True), blocked)
        rst_drop, _ = d.divert_filters(d.Policy(suppress_rst=True))
        self.assertTrue(self.matches(rst_drop, packet(s.RST), outbound=True))
        self.assertFalse(self.matches(rst_drop, packet(s.SYN | s.ACK), outbound=True))

    def test_rewrite_filter_only_selects_changed_headers(self):
        _, rewrite = d.divert_filters(d.Policy())
        self.assertTrue(self.matches(rewrite, packet(ttl=64), outbound=True))
        self.assertFalse(self.matches(rewrite, packet(ttl=64, df=False), outbound=True))
        self.assertFalse(self.matches(rewrite, d.normalize_packet(packet(), d.Policy()), outbound=True))
        _, ttl_only = d.divert_filters(d.Policy(mode="ttl-only"))
        self.assertFalse(self.matches(ttl_only, packet(ttl=64), outbound=True))
        for target in ("224.0.0.251", "239.255.255.250", "255.255.255.255"):
            self.assertFalse(self.matches(rewrite, packet(target=target), outbound=True))

    def test_real_checksum_helper_preserves_fragment_payload(self):
        helper = self.dll.WinDivertHelperCalcChecksums
        helper.argtypes = [c.c_void_p, c.c_uint32, c.POINTER(w.DivertAddress), c.c_uint64]
        helper.restype = c.c_int32
        for fragment in (0x4000, 0, 0x2000, 1):
            raw = bytearray(packet())
            raw[6:8] = struct.pack("!H", fragment)
            raw = d.normalize_packet(raw, d.Policy())
            buffer = c.create_string_buffer(raw)
            address = w.DivertAddress()
            self.assertTrue(helper(buffer, len(raw), c.byref(address), d.checksum_flags(raw)), hex(fragment))
            changed = buffer.raw[:len(raw)]
            self.assertEqual(s.checksum(changed[:20]), 0)
            self.assertEqual(changed[20:], raw[20:])

    def test_real_checksum_helper_repairs_outbound_offloaded_tcp(self):
        helper = self.dll.WinDivertHelperCalcChecksums
        helper.argtypes = [c.c_void_p, c.c_uint32, c.POINTER(w.DivertAddress), c.c_uint64]
        helper.restype = c.c_int32
        raw = bytearray(packet())
        raw[36:38] = b"\0\0"
        raw = d.normalize_packet(raw, d.Policy())
        buffer = c.create_string_buffer(raw)
        address = w.DivertAddress()
        address.flags = 1 << 17
        self.assertTrue(helper(buffer, len(raw), c.byref(address), 0))
        self.assertEqual(buffer.raw[20:len(raw)], packet()[20:])


if __name__ == "__main__":
    unittest.main()
