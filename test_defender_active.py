"""Offline tests for active policy, handshake detection and failure cleanup."""

import argparse
import ipaddress
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import Mock, patch

import defender as d
import scanner as s


LOCAL, PEER = "192.0.2.1", "192.0.2.2"


def observation(flags=d.SYN, port=8080, sport=45000, seq=100, ack=0, outbound=False):
    return dict(source=LOCAL if outbound else PEER, target=PEER if outbound else LOCAL,
                sport=port if outbound else sport, dport=sport if outbound else port,
                seq=seq, ack=ack, flags=flags)


class ActivePolicyTests(unittest.TestCase):
    def policy(self, *options):
        profile = [] if any(flag in options for flag in ("--profile", "--active", "--hardened")) else ["--profile", "normalize"]
        return d.Policy.from_args(d.make_parser().parse_args(["preview", "--platform", "linux", *profile, *options]))

    def test_active_defaults_to_all_interfaces_and_windows_rejects_extensions(self):
        for option in ("--active", "--detect", "--auto-block"):
            self.assertEqual(self.policy(option).interface, "any")
        policy = self.policy("--active", "--interface", "eth0")
        self.assertTrue(policy.detect and policy.auto_block and policy.filter_flags)
        self.assertTrue(policy.block_echo and policy.block_legacy_icmp)
        self.assertEqual(policy.udp_ports, (33434,))
        self.assertEqual(policy.syn_rate, 20)
        with self.assertRaisesRegex(ValueError, "require Linux"):
            d.divert_filters(policy)

    def test_bare_run_is_full_defense_with_explicit_overrides(self):
        with patch.object(d.sys, "platform", "linux"):
            policy = d.Policy.from_args(d.make_parser().parse_args(["run"]))
            self.assertTrue(policy.hardened and policy.detect and policy.auto_block and policy.suppress_rst)
            self.assertEqual(policy.interface, "any")
            self.assertEqual(policy.syn_rate, 20)
            self.assertEqual(policy.min_syn_window, 1024)
            configured = d.Policy.from_args(d.make_parser().parse_args(["run", "--syn-rate", "2", "--syn-burst", "2"]))
            self.assertTrue(configured.auto_block and configured.hardened)
            self.assertEqual((configured.syn_rate, configured.syn_burst), (2, 2))
            minimal = d.Policy.from_args(d.make_parser().parse_args(["run", "--profile", "normalize"]))
            self.assertFalse(minimal.auto_block or minimal.detect or minimal.suppress_rst or minimal.min_syn_window)
        with patch.object(d.sys, "platform", "win32"):
            policy = d.Policy.from_args(d.make_parser().parse_args(["run"]))
            self.assertTrue(policy.quiet_probes and policy.suppress_rst)
            self.assertFalse(policy.linux_only())
            self.assertIn("tcp.Window < 1024", d.divert_filters(policy)[0])

    def test_scope_exemptions_precede_blocking_and_rewrites(self):
        policy = self.policy("--active", "--interface", "eth0", "--allow-peer", "192.0.2.10",
                             "--peer", "192.0.2.0/24", "--block-source", PEER)
        self.assertTrue(policy.protects(PEER))
        for address in ("192.0.2.10", "198.51.100.1", "127.0.0.1", "224.0.0.1", "0.0.0.0"):
            self.assertFalse(policy.protects(address))
        rules = d.nft_rules(policy)
        self.assertLess(rules.index('iifname != "eth0" return'), rules.index("@blocked"))
        self.assertLess(rules.index("ip saddr 192.0.2.10/32 return"), rules.index("@blocked"))
        self.assertIn("ip saddr 192.0.2.0/24 ip saddr 192.0.2.2/32 counter drop", rules)

    def test_independent_flags_and_limits(self):
        rules = d.nft_rules(self.policy("--filter-flags"))
        self.assertIn("counter drop", rules)
        self.assertNotIn("icmp", rules)
        rules = d.nft_rules(self.policy("--block-echo", "--block-udp-port", "33434", "--syn-rate", "2",
                                       "--syn-burst", "2", "--connlimit", "3"))
        self.assertIn("echo-request", rules)
        self.assertIn("udp dport { 33434 }", rules)
        self.assertIn("update @syn_rates { ip saddr limit rate over 2/second burst 2 packets }", rules)
        self.assertIn("ct count over 3", rules)
        self.assertNotIn("fragmentation-needed", rules)
        self.assertNotIn("echo-reply", rules)
        self.assertEqual(self.policy("--active", "--interface", "eth0", "--syn-rate", "0").syn_rate, 0)
        filtering = self.policy("--mode", "filter-only", "--filter-flags")
        self.assertNotIn("ip ttl", d.nft_rules(filtering))
        self.assertNotIn("ip id", d.nft_rules(filtering))
        raw = s.ip_packet(PEER, LOCAL, 17, b"example", 123)
        self.assertEqual(d.normalize_packet(raw, filtering), raw)

    def test_hardened_any_interface_and_immediate_kernel_rules(self):
        policy = self.policy("--hardened", "--interface", "any")
        self.assertTrue(policy.auto_block and policy.detect and policy.quiet_probes and policy.suppress_rst)
        self.assertEqual(policy.min_syn_window, 1024)
        rules = d.nft_rules(policy)
        self.assertNotIn('iifname != "any"', rules)
        self.assertIn("flags dynamic,timeout", rules)
        self.assertIn("tcp window < 1024 add @blocked", rules)
        self.assertIn("ct state invalid counter drop", rules)
        self.assertLess(rules.index("ip saddr @blocked"), rules.index("incoming ip saddr 0.0.0.0/0 tcp flags"))
        self.assertLess(rules.index('comment "kernel-scan-block"'), rules.index('comment "probe-drop"'))
        self.assertEqual(self.policy("--hardened", "--interface", "any", "--min-syn-window", "0").min_syn_window, 0)

    def test_stateless_small_window_filter_is_available_on_windows(self):
        policy = self.policy("--min-syn-window", "1024")
        drop, _ = d.divert_filters(policy)
        self.assertIn("tcp.Window < 1024", drop)
        self.assertIn("!tcp.Ack", drop)

    def test_input_validation(self):
        for value in ("lo", 'eth0";flush ruleset', "eth0\n", "x" * 16):
            with self.assertRaises(argparse.ArgumentTypeError):
                d.interface_value(value)
        with self.assertRaisesRegex(ValueError, "one printable line"):
            self.policy("--decoy-banner", "hello\nworld")


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.detector = d.ActiveDetector(d.Policy(threshold=3, window=10, handshake_timeout=5, handshake_threshold=2))

    def synack(self, now, sport=45000):
        return self.detector.observe(observation(d.SYN | d.ACK, sport=sport, seq=900, ack=101, outbound=True), now, True)

    def test_sweep_counts_distinct_ports_and_expires(self):
        for now in range(5):
            self.assertEqual(self.detector.observe(observation(), now), [])
        self.assertEqual(self.detector.observe(observation(port=8081), 5), [])
        alerts = self.detector.observe(observation(port=8082), 6)
        self.assertEqual(alerts[0]["reason"], "distinct-port SYN sweep")
        self.assertEqual(alerts[0]["count"], 3)
        self.assertEqual(self.detector.observe(observation(port=8083), 7), [])
        self.detector.expire(20)
        self.assertEqual(self.detector.observe(observation(port=8084), 20), [])

    def test_normal_handshake_and_closed_ports_do_not_count_as_incomplete(self):
        self.detector.observe(observation(), 0)
        self.synack(0.1)
        self.detector.observe(observation(d.ACK, seq=101, ack=901), 0.2)
        self.assertFalse(self.detector.pending)
        self.detector.observe(observation(), 1)
        self.detector.observe(observation(d.RST | d.ACK, outbound=True), 1.1, True)
        self.assertFalse(self.detector.pending)
        self.detector.observe(observation(), 2)  # No SYN-ACK; not an open port.
        self.assertEqual(self.detector.expire(10), [])
        self.assertFalse(self.detector.incomplete)

    def test_only_correlated_ack_completes_handshake(self):
        self.detector.observe(observation(), 0)
        self.detector.observe(observation(d.SYN | d.ACK, seq=900, ack=999, outbound=True), 0.1, True)
        self.detector.observe(observation(d.ACK, seq=101, ack=901), 0.2)
        self.assertTrue(self.detector.pending)
        self.synack(0.3)
        self.detector.observe(observation(d.ACK, seq=105, ack=901), 0.4)
        self.assertTrue(self.detector.pending)
        self.detector.observe(observation(d.ACK, seq=101, ack=901), 0.5)
        self.assertFalse(self.detector.pending)

    def test_retransmits_do_not_extend_timeout_and_idle_tick_alerts(self):
        for sport in (45000, 45001):
            self.detector.observe(observation(sport=sport), 0)
            self.synack(0.1, sport)
            self.detector.observe(observation(sport=sport), 4)
        alerts = self.detector.expire(5)
        self.assertEqual([row["reason"] for row in alerts], ["incomplete TCP handshakes"])
        self.assertFalse(self.detector.pending)

    def test_reset_after_synack_counts_as_incomplete(self):
        for sport in (45000, 45001):
            self.detector.observe(observation(sport=sport), 0)
            self.synack(0.1, sport)
            alerts = self.detector.observe(observation(d.RST, sport=sport), 0.2)
        self.assertEqual(alerts[0]["reason"], "incomplete TCP handshakes")

    def test_unusual_flags_and_benign_controls(self):
        for flags in (0, d.SYN | d.FIN, d.SYN | d.RST, d.FIN | d.PSH | d.URG):
            detector = d.ActiveDetector(d.Policy())
            self.assertEqual(detector.observe(observation(flags), 0)[0]["reason"], "unusual TCP flags")
        for flags in (d.SYN, d.SYN | 0xc0, d.ACK, d.FIN | d.ACK, d.RST):
            self.assertFalse(d.ActiveDetector(d.Policy()).observe(observation(flags), 0))

    def test_bounded_state_and_forget(self):
        with patch.object(d, "STATE_LIMIT", 4):
            for sport in range(10):
                self.detector.observe(observation(sport=sport), 0)
            self.assertEqual(len(self.detector.pending), 4)
            self.detector.forget(PEER)
            self.assertFalse(self.detector.pending or self.detector.ports)

    def test_packet_parser_rejects_fragments_and_truncation(self):
        segment = s.tcp_segment(PEER, LOCAL, 45000, 8080, 100, flags=s.SYN)
        raw = s.ip_packet(PEER, LOCAL, 6, segment, 123)
        self.assertEqual(d.tcp_observation(raw), dict(observation(), window=1024))
        for malformed in (b"", raw[:19], raw[:30], raw[:6] + b"\x20\x00" + raw[8:],
                          raw[:6] + b"\x00\x01" + raw[8:]):
            self.assertIsNone(d.tcp_observation(malformed))

    def test_small_window_detector_ignores_established_window_updates(self):
        detector = d.ActiveDetector(d.Policy(min_syn_window=1024))
        self.assertEqual(detector.observe(dict(observation(), window=1), 0)[0]["reason"], "small-window SYN")
        self.assertFalse(detector.observe(dict(observation(d.ACK), window=0), 0.1))
        self.assertFalse(detector.observe(dict(observation(), window=64240), 0.2))


class LifecycleTests(unittest.TestCase):
    def test_block_success_failure_and_scope(self):
        policy = d.Policy(auto_block=True, trusted=(ipaddress.IPv4Network("192.0.2.3"),))
        backend = Mock()
        monitor = d.LinuxMonitor(policy, backend)
        alert = dict(source=PEER, target=LOCAL, reason="distinct-port SYN sweep", count=20)
        with self.assertLogs(d.LOG, "WARNING"):
            monitor.handle_alerts([alert, alert], 10)
        backend.block.assert_called_once_with(PEER)
        self.assertAlmostEqual(monitor.blocked[PEER], 70, places=2)
        monitor.handle_alerts([dict(alert, source="192.0.2.3")], 10)
        self.assertEqual(backend.block.call_count, 1)
        backend.block.side_effect = OSError("nft failed")
        with self.assertRaisesRegex(OSError, "nft failed"):
            monitor.handle_alerts([alert], 71)
        self.assertAlmostEqual(monitor.blocked[PEER], 70, places=2)

    def test_detection_only_does_not_block(self):
        backend = Mock()
        monitor = d.LinuxMonitor(d.Policy(detect=True), backend)
        with self.assertLogs(d.LOG, "WARNING"):
            monitor.handle_alerts([dict(source=PEER, target=LOCAL, reason="unusual TCP flags")], 0)
        backend.block.assert_not_called()

    def test_syncookies_restore_and_external_change(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tcp_syncookies"
            for original, current, expected in (("0", "1", "0"), ("0", "2", "2"), ("1", "1", "1"), ("2", "2", "2")):
                path.write_text(original)
                cookies = d.SynCookies()
                cookies.path = path
                cookies.start()
                self.assertNotEqual(path.read_text().strip(), "0")
                path.write_text(current)
                cookies.close()
                self.assertEqual(path.read_text().strip(), expected)

    def test_partial_monitor_start_failure_removes_firewall_and_restores_cookies(self):
        args = d.make_parser().parse_args(["run", "--active", "--interface", "eth0", "--syn-cookies"])
        backend, cookies, monitor = Mock(), Mock(), Mock()
        monitor.start.side_effect = OSError("cannot bind sensor")
        with patch.object(d.sys, "platform", "linux"), patch.object(d, "LinuxDefense", return_value=backend), \
                patch.object(d, "SynCookies", return_value=cookies), patch.object(d, "LinuxMonitor", return_value=monitor):
            with self.assertRaisesRegex(OSError, "cannot bind"):
                d.run(args, d.Policy.from_args(args))
        for resource in (backend, cookies, monitor):
            resource.close.assert_called_once()

    def test_decoy_binding_failure_releases_prior_listener(self):
        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", 0))
            occupied.listen()
            port = occupied.getsockname()[1]
            service = d.DecoyServices(d.Policy(decoy_ports=(0, port), decoy_bind="127.0.0.1"))
            with self.assertRaises(OSError):
                service.start()
            first = list(service.selector.get_map().values())[0].fileobj
            service.close()
            self.assertEqual(first.fileno(), -1)


if __name__ == "__main__":
    unittest.main()
