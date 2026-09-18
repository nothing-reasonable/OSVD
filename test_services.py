"""Application evidence tests; network tests use temporary loopback listeners."""

from contextlib import contextmanager, redirect_stdout
import copy
import io
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import scanner as s
from test_scanner import battery, matching_fixture, TARGET, tcp_reply


@contextmanager
def serve_once(handler, accept_timeout=3):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(accept_timeout)
    errors = []
    def run():
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(3)
                handler(connection)
        except Exception as error:
            errors.append(error)
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        thread.join(4)
        listener.close()
        if thread.is_alive():
            raise AssertionError("loopback server did not stop")
        if errors:
            raise AssertionError("loopback server failed: %s" % errors)


class BannerTests(unittest.TestCase):
    def test_ssh_platform_and_service_version_are_separate(self):
        row = s.parse_service_banner(b"Welcome\r\nSSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n")
        self.assertEqual((row["service"], row["product"], row["version"]), ("ssh", "OpenSSH", "9.6p1"))
        self.assertEqual(row["os_hints"][0]["family"], "Linux")
        self.assertNotIn("version", row["os_hints"][0])

    def test_openssh_alone_is_not_linux_evidence(self):
        row = s.parse_service_banner(b"SSH-2.0-OpenSSH_9.6p1\r\n")
        self.assertEqual(row["os_hints"], [])

    def test_windows_specific_ssh_product(self):
        row = s.parse_service_banner(b"SSH-2.0-OpenSSH_for_Windows_9.5\r\n")
        self.assertEqual((row["product"], row["version"]), ("OpenSSH_for_Windows", "9.5"))
        self.assertEqual(row["os_hints"][0]["family"], "Windows")

    def test_http_server_product_platform_and_header_case(self):
        row = s.parse_service_banner(b"HTTP/1.1 200 OK\r\nsErVeR: Apache/2.4.62 (Debian)\r\n\r\n")
        self.assertEqual((row["service"], row["product"], row["version"]), ("http", "Apache", "2.4.62"))
        self.assertEqual(row["os_hints"][0]["family"], "Linux")

    def test_iis_version_is_not_windows_version(self):
        row = s.parse_service_banner(b"HTTP/1.0 404 Not Found\r\nServer: Microsoft-IIS/10.0\r\n\r\n")
        self.assertEqual(row["version"], "10.0")
        self.assertEqual(row["os_hints"][0]["family"], "Windows")
        self.assertNotIn("version", row["os_hints"][0])

    def test_http_body_and_hostname_do_not_supply_os_evidence(self):
        row = s.parse_service_banner(b"HTTP/1.1 200 OK\r\nServer: nginx/1.26.0\r\nX-Host: Ubuntu\r\n\r\nServer: Microsoft-IIS/10.0\r\nSSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n")
        self.assertEqual(row["service"], "http")
        self.assertEqual(row["os_hints"], [])
        row = s.parse_service_banner(b"220 ubuntu.example.org ESMTP Postfix\r\n")
        self.assertEqual((row["service"], row["product"], row["os_hints"]), ("smtp", "Postfix", []))

    def test_ftp_pop_and_imap_greetings(self):
        for data, protocol, product in (
                (b"220 (vsFTPd 3.0.5)\r\n", "ftp", "vsFTPd"),
                (b"+OK Dovecot ready.\r\n", "pop3", "Dovecot"),
                (b"* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n", "imap", "Dovecot")):
            with self.subTest(protocol=protocol):
                row = s.parse_service_banner(data)
                self.assertEqual((row["service"], row["product"]), (protocol, product))
                self.assertEqual(row["os_hints"], [])

    def test_arbitrary_text_and_partial_lines_are_unknown(self):
        for data in (b"Ubuntu Windows Linux\r\n", b"SSH-2.0-OpenSSH_9.", b"220 ready\r\n", b"\xff\0\x01"):
            row = s.parse_service_banner(data)
            self.assertEqual(row["service"], "unknown")
            self.assertEqual(row["os_hints"], [])

    def test_byte_limit_does_not_invent_partial_version(self):
        data = b"x" * s.SERVICE_BYTE_LIMIT + b"\nSSH-2.0-OpenSSH_9.6p1 Ubuntu\n"
        self.assertEqual(s.parse_service_banner(data)["service"], "unknown")
        data = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4"
        row = s.parse_service_banner(data)
        self.assertEqual(row["service"], "http")
        self.assertIsNone(row["version"])

    def test_family_corroboration_and_conflicts(self):
        rows = [{"port": 22, **s.parse_service_banner(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu\n")}]
        report = {"services": {"enabled": True, "ports": rows}}
        for stack, status in (({}, "tentative"), ({"family": "Linux"}, "corroborates-stack"),
                              ({"family": "Windows"}, "conflicts-with-stack")):
            with self.subTest(status=status):
                self.assertEqual(s.application_os_assessment(report, stack)["status"], status)
        rows.append({"port": 80, **s.parse_service_banner(b"HTTP/1.0 200 OK\nServer: Microsoft-IIS/10.0\n\n")})
        result = s.application_os_assessment(report, {})
        self.assertEqual(result["status"], "conflicting-banners")
        self.assertIsNone(result["family"])

    def test_banners_do_not_change_stack_score_or_candidate(self):
        report, database = matching_fixture()
        report.update(probe_set=s.PUBLISHED_PROBES)
        original = s.match_report(report, database)
        report["services"] = {"enabled": True, "ports": [{"port": 22,
            **s.parse_service_banner(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu\n")}]}
        result = s.match_report(report, database)
        self.assertEqual(result["ranked"], original["ranked"])
        self.assertEqual(result["candidate"], original["candidate"])
        self.assertEqual(result["application_os"]["status"], "conflicts-with-stack")

    def test_service_selection_is_bounded_and_only_open_ports(self):
        ports = [{"port": p, "state": "open"} for p in (9100, 1234, 80, 22)]
        ports += [{"port": 25, "state": "closed"}, {"port": 443, "state": "filtered"}]
        with patch.object(s, "probe_service", side_effect=lambda target, port, *args: {"port": port}) as probe:
            result = s.collect_services("127.0.0.1", ports, max_ports=2, http_ports=[80])
        self.assertEqual({call.args[1] for call in probe.call_args_list}, {22, 80})
        self.assertEqual(result["excluded_ports"], [9100])
        self.assertEqual(result["unprobed_ports"], [1234])

    def test_printer_and_invalid_host_never_connect(self):
        with patch.object(s.socket, "create_connection") as connect:
            self.assertEqual(s.probe_service("127.0.0.1", 9100)["status"], "skipped")
            with self.assertRaises(ValueError):
                s.probe_service("127.0.0.1", 80, hostname="host\r\nInjected: yes")
            connect.assert_not_called()

    def test_cli_defaults_are_opt_in(self):
        args = s.make_parser().parse_args(["scan", "127.0.0.1"])
        self.assertFalse(args.service_version)
        args = s.make_parser().parse_args(["scan", "127.0.0.1", "-sV", "--http-ports", "12345"])
        self.assertTrue(args.service_version)
        self.assertEqual(args.http_ports, [12345])

    def test_display_escapes_banner_control_characters(self):
        report, db = matching_fixture()
        report.update(target=TARGET, probe_set=s.PUBLISHED_PROBES, features={})
        report["ports"] = [{"port": 22, "state": "open", "reason": "test"},
                           {"port": 81, "state": "closed", "reason": "test"}]
        row = {"port": 22, "transport": "tcp", "status": "identified",
               **s.parse_service_banner(b"SSH-2.0-product\x1b[31m_1.2 Ubuntu\n")}
        report["services"] = {"enabled": True, "ports": [row]}
        report["result"] = s.match_report(report, db)
        output = io.StringIO()
        with redirect_stdout(output):
            s.show_report(report)
        self.assertNotIn("\x1b", output.getvalue())
        self.assertIn("\\u001b", output.getvalue())

    def test_malformed_saved_service_evidence_is_rejected(self):
        report, _ = matching_fixture()
        report.update(format=s.FORMAT, probe_set=s.PUBLISHED_PROBES, features={},
                      implementation_revision=s.IMPLEMENTATION_REVISION)
        for services in ([], {"enabled": True, "ports": [None]},
                         {"enabled": True, "ports": [{"port": 22, "service": "ssh", "status": "identified",
                                                     "transport": "tcp", "os_hints": [None]}]}):
            with self.subTest(services=services), tempfile.TemporaryDirectory() as directory:
                report["services"] = services
                path = Path(directory) / "report.json"
                s.write_json(path, report)
                with self.assertRaises(ValueError):
                    s.read_report(path)


class ApplicationLoopbackTests(unittest.TestCase):
    def test_ssh_on_nonstandard_port_and_offline_rematch(self):
        with serve_once(lambda conn: conn.sendall(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\r\n")) as port:
            row = s.probe_service("127.0.0.1", port, timeout=1)
        self.assertEqual(row["status"], "identified")
        self.assertEqual(row["service"], "ssh")
        report, db = matching_fixture()
        report.update(format=s.FORMAT, probe_set=s.PUBLISHED_PROBES, features={},
                      implementation_revision=s.IMPLEMENTATION_REVISION,
                      services={"enabled": True, "ports": [row]})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            s.write_json(path, report)
            loaded = s.read_report(path)
        self.assertEqual(s.match_report(loaded, db), s.match_report(report, db))

    def test_http_get_on_selected_nonstandard_port(self):
        requests = []
        def handle(connection):
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = connection.recv(2048)
                if not chunk:
                    raise AssertionError("client closed before HTTP request")
                data += chunk
            requests.append(data)
            connection.sendall(b"HTTP/1.1 200 OK\r\nServer: Apache/2.")
            time.sleep(0.01)
            connection.sendall(b"4.62 (Debian)\r\nContent-Length: 0\r\n\r\n")
        with serve_once(handle) as port:
            row = s.probe_service("127.0.0.1", port, timeout=1, hostname="example.test", http_ports=[port])
        self.assertEqual((row["service"], row["version"]), ("http", "2.4.62"))
        self.assertEqual(row["os_hints"][0]["family"], "Linux")
        self.assertIn(b"Host: example.test:", requests[0])
        self.assertEqual(row["probes"], ["NULL", "HTTP GET"])

    def test_silent_service_deadline(self):
        with serve_once(lambda conn: conn.recv(1)) as port:
            started = time.monotonic()
            row = s.probe_service("127.0.0.1", port, timeout=0.15)
            elapsed = time.monotonic() - started
        self.assertEqual(row["status"], "no-banner")
        self.assertLess(elapsed, 1)

    def test_reply_byte_cap(self):
        with serve_once(lambda conn: conn.sendall(b"x" * (s.SERVICE_BYTE_LIMIT + 2048))) as port:
            row = s.probe_service("127.0.0.1", port, timeout=1)
        self.assertLessEqual(len(bytes.fromhex(row["response_hex"])), s.SERVICE_BYTE_LIMIT)
        self.assertEqual(row["status"], "unrecognized")

    def test_connection_refused_keeps_unknown(self):
        with socket.socket() as closed:
            closed.bind(("127.0.0.1", 0))
            row = s.probe_service("127.0.0.1", closed.getsockname()[1], timeout=0.1)
        self.assertEqual(row["status"], "error")
        self.assertEqual(row["os_hints"], [])

    @unittest.skipUnless(shutil.which("openssl"), "TLS fixture generation needs openssl")
    def test_real_self_signed_https(self):
        with tempfile.TemporaryDirectory() as directory:
            key, cert = (str(Path(directory) / name) for name in ("key.pem", "cert.pem"))
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost"],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            def handle(connection):
                with context.wrap_socket(connection, server_side=True) as wrapped:
                    data = b""
                    while b"\r\n\r\n" not in data:
                        chunk = wrapped.recv(2048)
                        if not chunk:
                            raise AssertionError("client closed before HTTPS request")
                        data += chunk
                    wrapped.sendall(b"HTTP/1.0 200 OK\r\nServer: Microsoft-IIS/10.0\r\n\r\n")
            with serve_once(handle) as port:
                row = s.probe_service("127.0.0.1", port, timeout=2, hostname="localhost",
                                      http_ports=[port], tls_ports=[port])
            self.assertEqual((row["transport"], row["service"]), ("tls", "http"))
            self.assertFalse(row["tls_certificate_verified"])
            self.assertEqual(row["os_hints"][0]["family"], "Windows")


class ExistingFingerprintMethodsTests(unittest.TestCase):
    def test_option_order_changes_database_score(self):
        probe = battery()[0]
        probe.response = tcp_reply(probe, options=bytes.fromhex("020405b4040201030307"))
        tests, _ = s.standard_fingerprint([probe], TARGET)
        value = tests["OPS"]["O1"]
        self.assertTrue(value.startswith("M5B4SNW7"))
        _, db = matching_fixture()
        entry = db["entries"][0]
        entry["tests"] = {"OPS": {"O1": value}}
        other = copy.deepcopy(entry)
        other.update(label="Same option values, different order")
        other["tests"]["OPS"]["O1"] = value.replace("SN", "NS")
        db.update(entries=[entry, other], count=2, points={"OPS": {"O1": 20}})
        result = s.published_match({"standard_fingerprint": tests, "ports": []}, db)
        self.assertEqual([row["score"] for row in result["ranked"]], [100, 0])

    def test_icmp_df_behavior_covers_all_four_classes(self):
        for flags, expected in (((False, False), "N"), ((True, False), "S"),
                                ((True, True), "Y"), ((False, True), "O")):
            with self.subTest(expected=expected):
                probes = [p for p in battery() if p.name in ("IE1", "IE2")]
                for p, df in zip(probes, flags):
                    p.response = {"source": TARGET, "protocol": 1, "icmp_type": 0,
                                  "df": df, "code": 0, "ttl": 64, "id": 1}
                tests, _ = s.standard_fingerprint(probes, TARGET)
                self.assertEqual(tests["IE"]["DFI"], expected)

    def test_fragments_are_not_misread_as_complete_tcp_packets(self):
        packet = bytearray(battery()[0].packet)
        for fragment in (b"\x20\0", b"\0\x01"):
            packet[6:8] = fragment
            with self.assertRaisesRegex(ValueError, "fragmented"):
                s.decode_packet(bytes(packet))


@unittest.skipUnless(sys.platform.startswith("linux") and os.getenv("SCANNER_LIVE_TEST") == "1",
                     "requires Linux raw sockets and SCANNER_LIVE_TEST=1")
class RawApplicationWorkflowTests(unittest.TestCase):
    def test_real_scan_with_banner_and_saved_assessment(self):
        with serve_once(lambda conn: conn.sendall(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\r\n"), accept_timeout=20) as port:
            with socket.socket() as closed, tempfile.TemporaryDirectory() as directory:
                closed.bind(("127.0.0.1", 0))
                path = Path(directory) / "scan.json"
                args = s.make_parser().parse_args(["scan", "127.0.0.1", "-p",
                    "%d,%d" % (port, closed.getsockname()[1]), "--os-tries", "1",
                    "--retries", "0", "--timeout", "0.2", "-sV", "-o", str(path)])
                with redirect_stdout(io.StringIO()):
                    report = s.scan(args)
                loaded = s.read_report(path)
                self.assertEqual(report["services"]["ports"][0]["service"], "ssh")
                self.assertEqual(report["result"]["application_os"]["family"], "Linux")
                self.assertEqual(s.match_report(loaded, s.read_published_database(s.PUBLISHED_DB)), report["result"])


if __name__ == "__main__":
    unittest.main()
