"""Windows transport regressions, with no driver installation or network scans."""

import ctypes as c
from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import queue
import socket
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import scanner as s
import windows_transport as w


SOURCE, TARGET = "192.0.2.1", "192.0.2.2"


class FakeDriver:
    """Exercise real ctypes buffers and the blocking capture-thread lifecycle."""
    def __init__(self):
        self.incoming = queue.Queue()
        self.sent = []
        self.closed = 0
        self.major = 2
        self.reply = None
        self.send_ok = True

    def WinDivertOpen(self, expression, layer, priority, flags):
        self.opened = (expression, layer, priority, flags)
        return 123

    def WinDivertGetParam(self, handle, param, value):
        c.cast(value, c.POINTER(c.c_uint64))[0] = self.major
        return True

    def WinDivertRecv(self, handle, buffer, capacity, length, address):
        packet = self.incoming.get(timeout=3)
        if packet is None:
            return False
        c.memmove(buffer, packet, len(packet))
        c.cast(length, c.POINTER(c.c_uint32))[0] = len(packet)
        return True

    def WinDivertSend(self, handle, packet, size, length, address):
        self.sent.append((packet, c.cast(address, c.POINTER(w.DivertAddress))[0].flags))
        c.cast(length, c.POINTER(c.c_uint32))[0] = size
        if self.reply:
            self.reply(packet)
        return self.send_ok

    def WinDivertShutdown(self, handle, how):
        self.incoming.put(None)
        return True

    def WinDivertClose(self, handle):
        self.closed += 1
        return True


class WindowsTransportTests(unittest.TestCase):
    def setUp(self):
        self.driver = FakeDriver()
        self.loader = patch.object(w, "load_library", return_value=self.driver)
        self.loader.start()
        self.addCleanup(self.loader.stop)

    def transport(self):
        transport = w.WinDivertTransport(SOURCE, TARGET)
        self.addCleanup(transport.close)
        return transport

    def test_address_abi_and_injection_preserve_all_probe_bytes(self):
        self.assertEqual(c.sizeof(w.DivertAddress), 80)
        self.assertEqual(w.DivertAddress.flags.offset, 8)
        self.assertEqual(w.DivertAddress.data.offset, 16)
        transport = self.transport()
        probes = s.standard_probes(SOURCE, TARGET, 80, 81, 33434)
        for probe in probes:
            transport.send(probe.packet)
        self.assertEqual([row[0] for row in self.driver.sent], [p.packet for p in probes])
        self.assertEqual({row[1] for row in self.driver.sent}, {0x00e20000})

    def test_filter_keeps_router_icmp_loopback_and_normal_delivery(self):
        self.transport()
        expression, layer, priority, flags = self.driver.opened
        self.assertIn(b"(inbound or loopback)", expression)
        self.assertIn(b"ip.DstAddr == 192.0.2.1", expression)
        self.assertIn(b"((tcp and ip.SrcAddr == 192.0.2.2) or icmp)", expression)
        self.assertEqual((layer, priority, flags), (0, 0, 1))

    def test_receive_copies_buffer_and_preserves_arrival_time(self):
        transport = self.transport()
        before = time.monotonic()
        for data in (b"first", b"second"):
            self.driver.incoming.put(data)
        rows = []
        while len(rows) < 2:
            rows.extend(transport.receive(0.2))
            self.assertLess(time.monotonic() - before, 2)
        self.assertEqual([r[0] for r in rows], [b"first", b"second"])
        self.assertTrue(all(before <= r[1] <= time.monotonic() for r in rows))

    def test_silence_and_close_unblock_receiver_without_leaking_thread(self):
        transport = self.transport()
        self.assertEqual(transport.receive(0.01), [])
        transport.close()
        transport.close()
        self.assertFalse(transport.thread.is_alive())
        self.assertEqual(self.driver.closed, 1)

    def test_driver_version_failure_closes_handle(self):
        self.driver.major = 1
        with self.assertRaisesRegex(ValueError, "2.x"):
            self.transport()
        self.assertEqual(self.driver.closed, 1)

    def test_thread_start_failure_closes_handle(self):
        with patch.object(w.threading.Thread, "start", side_effect=RuntimeError("thread failed")):
            with self.assertRaisesRegex(RuntimeError, "thread failed"):
                self.transport()
        self.assertEqual(self.driver.closed, 1)

    def test_capture_failure_is_not_reported_as_filtered_ports(self):
        transport = self.transport()
        with patch.object(w, "driver_error", return_value=OSError("capture failed")):
            self.driver.incoming.put(None)
            transport.thread.join(1)
        with self.assertRaisesRegex(OSError, "capture failed"):
            transport.receive(0)
        with self.assertRaisesRegex(OSError, "capture failed"):
            transport.send(b"packet")

    def test_send_failure_is_not_reported_as_filtered_ports(self):
        transport = self.transport()
        self.driver.send_ok = False
        with patch.object(w, "driver_error", return_value=OSError("send failed")):
            with self.assertRaisesRegex(OSError, "send failed"):
                transport.send(b"packet")

    def test_windows_exchange_matches_reply_and_sends_reset(self):
        # The real WindowsNetwork and inherited scheduler run against a fake DLL.
        with patch.object(s.socket, "socket") as socket_factory:
            socket_factory.return_value.__enter__.return_value.getsockname.return_value = (SOURCE, 1)
            network = s.WindowsNetwork(TARGET)
        self.addCleanup(network.close)
        probe = s.make_probe(SOURCE, TARGET, "scan", 80)
        def reply(packet):
            if s.decode_packet(packet)["flags"] != s.SYN:
                return
            body = s.tcp_segment(TARGET, SOURCE, 80, probe.sport, 100,
                                 (probe.seq + 1) & 0xffffffff, s.SYN | s.ACK)
            self.driver.incoming.put(b"malformed")
            self.driver.incoming.put(s.ip_packet(TARGET, SOURCE, 6, body, 1))
        self.driver.reply = reply
        network.exchange([probe], timeout=0.2, retries=0)
        self.assertEqual(s.port_result(probe)["state"], "open")
        self.assertEqual(probe.attempts, 1)
        self.assertEqual(s.decode_packet(self.driver.sent[-1][0])["flags"], s.RST)

    def test_exchange_silence_retries_then_finishes(self):
        with patch.object(s.socket, "socket") as socket_factory:
            socket_factory.return_value.__enter__.return_value.getsockname.return_value = (SOURCE, 1)
            network = s.WindowsNetwork(TARGET)
        self.addCleanup(network.close)
        probe = s.make_probe(SOURCE, TARGET, "scan", 80)
        network.exchange([probe], timeout=0.01, retries=1)
        self.assertEqual(probe.attempts, 2)
        self.assertEqual(len(self.driver.sent), 2)
        self.assertEqual(s.port_result(probe)["state"], "filtered")

    def test_windows_exchange_matches_icmp_echo_and_router_udp_error(self):
        with patch.object(s.socket, "socket") as socket_factory:
            socket_factory.return_value.__enter__.return_value.getsockname.return_value = (SOURCE, 1)
            network = s.WindowsNetwork(TARGET)
        self.addCleanup(network.close)
        probes = [s.make_probe(SOURCE, TARGET, "IE1", protocol=1),
                  s.make_probe(SOURCE, TARGET, "U1", 33434, protocol=17)]
        def reply(packet):
            sent = s.decode_ip(packet)
            if sent["protocol"] == 1:
                body = b"\0\0\0\0" + sent["payload"][4:]
                sender = TARGET
            else:
                body = b"\x03\x03\0\0\0\0\0\0" + packet[:28]
                sender = "192.0.2.254"
            body = body[:2] + s.struct.pack("!H", s.checksum(body)) + body[4:]
            self.driver.incoming.put(s.ip_packet(sender, SOURCE, 1, body, 1))
        self.driver.reply = reply
        network.exchange(probes, timeout=0.2, retries=0)
        self.assertEqual(probes[0].response["icmp_type"], 0)
        self.assertEqual(probes[1].response["source"], "192.0.2.254")
        # Router errors are associated with the probe but supply no OS evidence.
        self.assertFalse(any(key.startswith("U1.") for key in s.extract_features(probes, TARGET)))


class PlatformTests(unittest.TestCase):
    def test_platform_selection(self):
        for platform, name in (("win32", "WindowsNetwork"), ("linux", "RawNetwork")):
            with self.subTest(platform=platform), patch.object(s.sys, "platform", platform):
                with patch.object(s, name) as network:
                    self.assertIs(s.open_network(TARGET), network.return_value)
        with patch.object(s.sys, "platform", "darwin"):
            with self.assertRaises(ValueError):
                s.open_network(TARGET)

    def test_linux_rejects_windows_option(self):
        with patch.object(s.sys, "platform", "linux"):
            with self.assertRaisesRegex(ValueError, "only used on Windows"):
                s.open_network(TARGET, Path("WinDivert"))

    def test_missing_dll_has_actionable_message(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(w.sys, "platform", "win32"):
            with self.assertRaisesRegex(ValueError, "--windivert-dir"):
                w.load_library(directory)

    def test_ctypes_signatures_and_secure_dll_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "WinDivert.dll"
            path.touch()
            with patch.object(w.sys, "platform", "win32"), patch.object(w.c, "CDLL") as load:
                dll = w.load_library(directory)
            self.assertEqual(load.call_args.args, (str(path.resolve()),))
            self.assertEqual(load.call_args.kwargs, {"use_last_error": True, "winmode": 0x1100})
            self.assertIs(dll.WinDivertOpen.restype, c.c_void_p)
            self.assertEqual(len(dll.WinDivertSend.argtypes), 5)

    def test_windows_option_and_offline_import(self):
        args = s.make_parser().parse_args(["scan", TARGET, "--windivert-dir", "C:/WinDivert/x64"])
        self.assertEqual(args.windivert_dir, Path("C:/WinDivert/x64"))
        with patch.object(w, "load_library") as load:
            s.read_published_database(s.PUBLISHED_DB)
            load.assert_not_called()


@unittest.skipUnless(sys.platform == "win32" and os.getenv("SCANNER_WINDOWS_LIVE_TEST") == "1",
                     "requires Administrator, WinDivert, and SCANNER_WINDOWS_LIVE_TEST=1")
class WindowsLiveTests(unittest.TestCase):
    def test_loopback_scan_save_and_rematch(self):
        with socket.socket() as listener, socket.socket() as closed, tempfile.TemporaryDirectory() as directory:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            closed.bind(("127.0.0.1", 0))
            output = Path(directory) / "scan.json"
            argv = ["scan", "127.0.0.1", "-p", "%d,%d" % (listener.getsockname()[1], closed.getsockname()[1]),
                    "--timeout", "0.5", "--retries", "0", "--os-tries", "1", "-o", str(output)]
            if os.getenv("SCANNER_WINDIVERT_DIR"):
                argv.extend(["--windivert-dir", os.environ["SCANNER_WINDIVERT_DIR"]])
            with redirect_stdout(io.StringIO()):
                report = s.scan(s.make_parser().parse_args(argv))
            states = {row["port"]: row["state"] for row in report["ports"]}
            self.assertEqual(states[listener.getsockname()[1]], "open")
            self.assertEqual(states[closed.getsockname()[1]], "closed")
            self.assertEqual(s.match_report(s.read_report(output), s.read_published_database(s.PUBLISHED_DB)),
                             report["result"])


if __name__ == "__main__":
    unittest.main()
