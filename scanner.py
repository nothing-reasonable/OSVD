#!/usr/bin/env python3
"""Hand-built IPv4 SYN scanner and OS fingerprinter. Python standard library only."""

import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import random
import re
import select
import socket
import ssl
import statistics
import struct
import sys
import time
import zlib


FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = (1, 2, 4, 8, 16, 32, 64, 128)
RNG = random.SystemRandom()
FORMAT = 1
PROBE_SET = "handmade-v1"
DEFAULT_DB = Path(__file__).with_name("fingerprints.json")
PUBLISHED_DB = Path(__file__).with_name("nmap-os-db")
PUBLISHED_PROBES = "standard-ipv4-v2"
IMPLEMENTATION_REVISION = 2
SERVICE_BYTE_LIMIT = 8192
SERVICE_EXCLUDED_PORTS = frozenset(range(9100, 9108))


# 1. Packet construction and decoding. No packet/scanning libraries are used.

def checksum(data):
    """Internet one's-complement checksum, including odd-length messages."""
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def ip_packet(source, target, protocol, payload, ident, df=True, tos=0):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, tos, 20 + len(payload),
                         ident, 0x4000 if df else 0, 64, protocol, 0,
                         socket.inet_aton(source), socket.inet_aton(target))
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def tcp_segment(source, target, sport, dport, seq, ack=0, flags=SYN,
                window=1024, options=b"", urgent=0):
    options += b"\0" * (-len(options) % 4)
    if len(options) > 40:
        raise ValueError("TCP options exceed 40 bytes")
    header = struct.pack("!HHIIHHHH", sport, dport, seq, ack,
                         ((5 + len(options) // 4) << 12) | flags,
                         window, 0, urgent) + options
    pseudo = socket.inet_aton(source) + socket.inet_aton(target)
    pseudo += struct.pack("!BBH", 0, 6, len(header))
    return header[:16] + struct.pack("!H", checksum(pseudo + header)) + header[18:]


def udp_segment(source, target, sport, dport, payload):
    header = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    pseudo = socket.inet_aton(source) + socket.inet_aton(target)
    pseudo += struct.pack("!BBH", 0, 17, len(header) + len(payload))
    value = checksum(pseudo + header + payload) or 0xffff
    return header[:6] + struct.pack("!H", value) + payload


def echo_message(ident, sequence, code=0, size=120, fill=b"C"):
    body = struct.pack("!BBHHH", 8, code, 0, ident, sequence) + fill * size
    return body[:2] + struct.pack("!H", checksum(body)) + body[4:]


def decode_options(data):
    names, values = [], {}
    offset = 0
    while offset < len(data):
        kind = data[offset]
        if kind in (0, 1):
            names.append("EOL" if kind == 0 else "NOP")
            offset += 1
            if kind == 0:
                break
            continue
        if offset + 2 > len(data):
            raise ValueError("truncated TCP option")
        size = data[offset + 1]
        if size < 2 or offset + size > len(data):
            raise ValueError("invalid TCP option length")
        value = data[offset + 2:offset + size]
        names.append({2: "MSS", 3: "WS", 4: "SACK", 8: "TS"}.get(kind, str(kind)))
        expected = {2: 4, 3: 3, 4: 2, 8: 10}.get(kind)
        if expected is not None and size != expected:
            raise ValueError("invalid known TCP option length")
        if kind == 2:
            values["mss"] = struct.unpack("!H", value)[0]
        elif kind == 3:
            values["ws"] = value[0]
        elif kind == 8:
            values["tsval"], values["tsecr"] = struct.unpack("!II", value)
        offset += size
    return ",".join(names), values


def decode_ip(data, quoted=False):
    """Quoted ICMP packets may contain only the IP header + 8 transport bytes."""
    if len(data) < 20 or data[0] >> 4 != 4:
        raise ValueError("not an IPv4 packet")
    size = (data[0] & 15) * 4
    total, ident, fragment = struct.unpack("!HHH", data[2:8])
    if size < 20 or size > len(data) or total < size:
        raise ValueError("invalid IPv4 length")
    if not quoted and total > len(data):
        raise ValueError("truncated IPv4 packet")
    if fragment & 0x3fff:
        raise ValueError("fragmented IPv4 packet")
    return {"source": socket.inet_ntoa(data[12:16]),
            "target": socket.inet_ntoa(data[16:20]), "ttl": data[8],
            "protocol": data[9], "id": ident, "df": bool(fragment & 0x4000),
            "tos": data[1], "total_length": total, "header_hex": data[:size].hex(),
            "payload": data[size:total]}


def decode_packet(data):
    packet = decode_ip(data)
    body = packet.pop("payload")
    if packet["protocol"] == 6:
        if len(body) < 20:
            raise ValueError("truncated TCP header")
        sport, dport, seq, ack, bits, window, _, urgent = struct.unpack("!HHIIHHHH", body[:20])
        size = (bits >> 12) * 4
        if size < 20 or size > len(body):
            raise ValueError("invalid TCP header length")
        order, values = decode_options(body[20:size])
        packet.update(sport=sport, dport=dport, seq=seq, ack=ack,
                      flags=bits & 0x1ff, reserved=(bits >> 9) & 7,
                      window=window, urgent=urgent, options=order,
                      options_hex=body[20:size].hex(), data_hex=body[size:].hex(), **values)
    elif packet["protocol"] == 1:
        if len(body) < 8:
            raise ValueError("truncated ICMP header")
        kind, code, _, ident, seq = struct.unpack("!BBHHH", body[:8])
        packet.update(icmp_type=kind, code=code, icmp_id=ident, icmp_seq=seq)
        if kind in (3, 11, 12):
            quote = decode_ip(body[8:], quoted=True)
            if len(quote["payload"]) < 8:
                raise ValueError("truncated ICMP transport quote")
            quote["data_hex"] = quote["payload"].hex()
            quote["payload"] = quote["payload"][:8].hex()
            packet["quote"] = quote
            packet["unused"] = struct.unpack("!I", body[4:8])[0]
    return packet


@dataclass
class Probe:
    name: str
    packet: bytes
    protocol: int
    sport: int = 0
    dport: int = 0
    seq: int = 0
    ack: int = 0
    flags: int = 0
    icmp_id: int = 0
    icmp_seq: int = 0
    sent: float = 0
    attempts: int = 0
    response: dict = None
    fingerprint: bool = False
    first_sent: float = 0


def make_probe(source, target, name, dport=0, flags=SYN, window=1024,
               options=b"", df=True, code=0, size=120, tos=0, protocol=6,
               sport=None, urgent=0, ack_value=None, ip_id=None,
               icmp_id=None, icmp_seq=None, fill=b"C", fingerprint=False):
    # Unique sequence/ID tokens let us reject stale and unrelated replies.
    ident = RNG.randrange(1, 65536) if ip_id is None else ip_id
    probe = Probe(name, b"", protocol, sport if sport is not None else RNG.randrange(32768, 61000), dport,
                  RNG.getrandbits(32), RNG.getrandbits(32), flags,
                  RNG.randrange(1, 65536), RNG.randrange(1, 65536))
    probe.fingerprint = fingerprint
    if ack_value is not None:
        probe.ack = ack_value
    if icmp_id is not None:
        probe.icmp_id = icmp_id
    if icmp_seq is not None:
        probe.icmp_seq = icmp_seq
    if protocol == 6:
        body = tcp_segment(source, target, probe.sport, dport, probe.seq,
                           probe.ack if flags & ACK or fingerprint else 0, flags, window, options, urgent)
    elif protocol == 17:
        body = udp_segment(source, target, probe.sport, dport, b"C" * 300)
    else:
        body = echo_message(probe.icmp_id, probe.icmp_seq, code, size, fill)
    probe.packet = ip_packet(source, target, protocol, body, ident, df, tos)
    return probe


def corresponds(probe, response, source, target):
    if response["target"] != source:
        return False
    if response["protocol"] == 6 and probe.protocol == 6:
        if (response["source"], response["sport"], response["dport"]) != (target, probe.dport, probe.sport):
            return False
        if probe.fingerprint and not probe.name.startswith("CLK"):
            # Each standard test owns a unique, locally reserved source port.
            # Nonstandard S/A relationships are evidence, not reasons to discard it.
            return True
        if response["flags"] & ACK:
            consumed = bool(probe.flags & SYN) + bool(probe.flags & FIN)
            return response["ack"] == (probe.seq + consumed) & 0xffffffff
        # A reset answering our ACK copies that ACK into its sequence field.
        return bool(response["flags"] & RST and probe.flags & ACK
                    and response["seq"] == probe.ack)
    if response["protocol"] != 1:
        return False
    if response["icmp_type"] == 0 and probe.protocol == 1:
        return (response["source"], response["icmp_id"], response["icmp_seq"]) == (target, probe.icmp_id, probe.icmp_seq)
    quote = response.get("quote")
    if quote:
        sent = decode_ip(probe.packet)
        if probe.fingerprint and probe.protocol == 17:
            return all(quote[key] == sent[key] for key in ("source", "target", "protocol")) and quote["payload"][:8] == sent["payload"][:4].hex()
        return all(quote[key] == sent[key] for key in ("source", "target", "protocol", "id")) and quote["payload"] == sent["payload"][:8].hex()
    return False


def require_linux():
    if not sys.platform.startswith("linux"):
        raise ValueError("Live scanning needs Linux raw sockets. Run inside a Linux VM or WSL2 with sudo. Offline match/learn/evaluate work on Windows.")


# 2. The event loop sends probes and listens at the same time, without threads.

class RawNetwork:
    def __init__(self, target):
        require_linux()
        self.target = target
        self.sockets = []
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
                route.connect((target, 9))  # Select a route; send no UDP packet.
                self.source = route.getsockname()[0]
            self.sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            self.sockets.append(self.sender)
            self.sender.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self.readers = []
            for protocol in (socket.IPPROTO_TCP, socket.IPPROTO_ICMP):
                receiver = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol)
                self.sockets.append(receiver)
                receiver.bind((self.source, 0))
                receiver.setblocking(False)
                self.readers.append(receiver)
        except OSError:
            self.close()
            raise

    def close(self):
        for sock in self.sockets:
            sock.close()

    def reserve_port(self, protocol=6):
        """Prevent local applications from sharing a fingerprint probe's tuple."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == 6 else socket.SOCK_DGRAM)
        try:
            sock.bind((self.source, 0))
        except BaseException:
            sock.close()
            raise
        self.sockets.append(sock)
        return sock.getsockname()[1]

    def reset(self, probe, response):
        if response["protocol"] == 6 and response["flags"] & (SYN | ACK | RST) == SYN | ACK:
            # Never send an ACK that completes the handshake.
            segment = tcp_segment(self.source, self.target, probe.sport, probe.dport,
                                  response["ack"], flags=RST, window=0)
            self.sender.sendto(ip_packet(self.source, self.target, 6, segment,
                                        RNG.randrange(1, 65536)), (self.target, 0))

    def exchange(self, probes, timeout=1.0, retries=1, parallel=32, delay=0.01, jitter=0):
        pending, index, next_send = [], 0, time.monotonic()
        while index < len(probes) or pending:
            now = time.monotonic()
            if index < len(probes) and len(pending) < parallel and now >= next_send:
                probe = probes[index]
                self.sender.sendto(probe.packet, (self.target, 0))
                probe.sent, probe.attempts = now, 1
                probe.first_sent = now
                pending.append(probe)
                index += 1
                next_send = now + delay + RNG.uniform(0, jitter)
            for probe in pending[:]:
                if now - probe.sent >= timeout:
                    if probe.attempts <= retries:
                        self.sender.sendto(probe.packet, (self.target, 0))
                        probe.sent = now
                        probe.attempts += 1
                    else:
                        pending.remove(probe)
            wait = min([0.05] + [max(0, p.sent + timeout - now) for p in pending])
            if index < len(probes) and len(pending) < parallel:
                wait = min(wait, max(0, next_send - now))
            ready, _, _ = select.select(self.readers, [], [], wait)
            for receiver in ready:
                # Bound work per iteration so unrelated traffic cannot starve timers.
                for _ in range(256):
                    try:
                        data = receiver.recv(65535)
                    except BlockingIOError:
                        break
                    try:
                        response = decode_packet(data)
                    except ValueError:
                        continue
                    for probe in pending:
                        if corresponds(probe, response, self.source, self.target):
                            response["rtt_ms"] = round((time.monotonic() - probe.sent) * 1000, 3)
                            response["received_at"] = time.monotonic()
                            probe.response = response
                            self.reset(probe, response)
                            pending.remove(probe)
                            break
        return probes


def port_result(probe):
    response = probe.response
    state, reason = "filtered", "no reply (filtering, loss, or unreachable host)"
    if response and response["protocol"] == 6:
        flags = response["flags"]
        if flags & (SYN | ACK | RST) == SYN | ACK:
            state, reason = "open", "SYN-ACK"
        elif flags & RST:
            state, reason = "closed", "RST"
        else:
            state, reason = "unknown", "unexpected TCP flags"
    elif response:
        reason = "ICMP type %s code %s from %s" % (response["icmp_type"], response["code"], response["source"])
    return {"port": probe.dport, "state": state, "reason": reason,
            "attempts": probe.attempts, "response": response}


def fingerprint_probes(source, target, open_port, closed_port, udp_port):
    ts = b"\x08\x0a" + struct.pack("!II", 0xffffffff, 0)
    mss = lambda n: b"\x02\x04" + struct.pack("!H", n)
    probes = []
    if open_port is not None:
        for name, window, options in (
            ("SP1", 1, b"\x03\x03\x0a\x01" + mss(1460) + ts + b"\x04\x02"),
            ("SP2", 63, mss(1400) + b"\x03\x03\0\x04\x02" + ts + b"\0"),
            ("SP3", 4, ts + b"\x01\x01\x03\x03\x05\x01" + mss(640)),
        ):
            probes.append(make_probe(source, target, name, open_port, window=window, options=options))
        probes.append(make_probe(source, target, "NP", open_port, flags=0, window=128))
        # The report mentions ECN but omits it from its battery; include it explicitly.
        probes.append(make_probe(source, target, "ECN", open_port, flags=SYN | ECE | CWR,
                                 window=3, options=mss(1460) + b"\x04\x02"))
    if closed_port is not None:
        probes.append(make_probe(source, target, "XP", closed_port,
                                 flags=SYN | FIN | URG | PSH, window=256, df=False))
        probes.append(make_probe(source, target, "AP", closed_port, flags=ACK, window=1024))
    probes.append(make_probe(source, target, "IE1", protocol=1, code=9, size=120, df=True))
    probes.append(make_probe(source, target, "IE2", protocol=1, code=0, size=150, df=False, tos=4))
    probes.append(make_probe(source, target, "U1", udp_port, protocol=17, df=False))
    return probes


def ttl_guess(ttl):
    return next((initial for initial in (32, 64, 128, 255) if initial >= ttl), 255)


def extract_features(probes, target):
    features = {}
    for probe in probes:
        response = probe.response
        if not response or response["source"] != target:
            continue  # Router errors and silence aren't target OS fingerprints.
        if probe.protocol == 6 and response["protocol"] != 6:
            continue
        if probe.name in ("SP1", "SP2", "SP3", "ECN") and response["flags"] & (SYN | ACK | RST) != SYN | ACK:
            continue
        if probe.protocol == 1 and response.get("icmp_type") != 0:
            continue
        if probe.protocol == 17 and (response.get("icmp_type"), response.get("code")) != (3, 3):
            continue
        fields = {"ttl_guess": ttl_guess(response["ttl"]), "df": response["df"]}
        if response["protocol"] == 6:
            for key in ("window", "options", "flags", "reserved", "urgent"):
                fields[key] = response[key]
            fields["ws"] = response.get("ws", -1)
        else:
            fields["code"] = response["code"]
        features.update({probe.name + "." + key: value for key, value in fields.items()})
    return features


def sequence_observations(probes):
    """Record weak sequence evidence for inspection, never use it as version proof."""
    replies = [p.response for p in probes if p.name in ("SP1", "SP2", "SP3")
               and p.response and p.response["protocol"] == 6
               and p.response["flags"] & (SYN | ACK | RST) == SYN | ACK]
    result = {"note": "Only three samples; IP IDs, ISNs and timestamp rates are diagnostics, not matching features."}
    if len(replies) < 3:
        return result
    ids = [r["id"] for r in replies]
    steps = [(b - a) % 65536 for a, b in zip(ids, ids[1:])]
    result["ip_id_pattern"] = ("zero" if not any(ids) else "constant" if not any(steps)
                               else "incrementing" if all(0 < n < 100 for n in steps) else "other")
    seqs = [r["seq"] for r in replies]
    result["isn_deltas"] = [(b - a) % (2**32) for a, b in zip(seqs, seqs[1:])]
    result["isn_gcd"] = math.gcd(*result["isn_deltas"])
    rates = []
    for a, b in zip(replies, replies[1:]):
        elapsed = b["received_at"] - a["received_at"]
        if "tsval" in a and "tsval" in b and elapsed > 0:
            rates.append(((b["tsval"] - a["tsval"]) % (2**32)) / elapsed)
    if rates and all(0 <= value <= 10000 for value in rates):
        result["timestamp_hz_estimate"] = round(statistics.median(rates), 1)
    return result


# 3. Standard IPv4 fingerprints: our probes/decoder/matcher, published data only.

def standard_probes(source, target, open_port, closed_port, udp_port, reserve=None):
    """The documented 16-packet IPv4 battery; bytes must match database tests."""
    timestamp = bytes.fromhex("080AFFFFFFFF00000000")
    mss = lambda value: b"\x02\x04" + struct.pack("!H", value)
    ports = set()
    def port(protocol):
        if reserve:
            return reserve(protocol)
        while True:
            value = RNG.randrange(32768, 61000)
            if value not in ports:
                ports.add(value)
                return value
    def tcp(name, destination, flags, window, options, df=True, **kwargs):
        return make_probe(source, target, name, destination, flags=flags,
                          window=window, options=options, df=df, sport=port(6),
                          fingerprint=True, **kwargs)
    probes = []
    if open_port is not None:
        samples = (
            (1, b"\x03\x03\x0a\x01" + mss(1460) + timestamp + b"\x04\x02"),
            (63, mss(1400) + b"\x03\x03\x00\x04\x02" + timestamp + b"\x00"),
            (4, timestamp + b"\x01\x01\x03\x03\x05\x01" + mss(640)),
            (4, b"\x04\x02" + timestamp + b"\x03\x03\x0a\x00"),
            (16, mss(536) + b"\x04\x02" + timestamp + b"\x03\x03\x0a\x00"),
            (512, mss(265) + b"\x04\x02" + timestamp),
        )
        for number, (window, options) in enumerate(samples, 1):
            probes.append(tcp("S%d" % number, open_port, SYN, window, options, df=False))
    echo_id = RNG.randrange(1, 65535)
    probes.append(make_probe(source, target, "IE1", protocol=1, code=9,
                             size=120, df=True, icmp_id=echo_id, icmp_seq=295, fill=b"\x00", fingerprint=True))
    probes.append(make_probe(source, target, "IE2", protocol=1, code=0,
                             size=150, df=False, tos=4, icmp_id=echo_id + 1, icmp_seq=296,
                             fill=b"\x00", fingerprint=True))
    common = bytes.fromhex("03030A0102040109080AFFFFFFFF000000000402")
    if open_port is not None:
        # Nmap's current sender sets the four-bit reserved field to 8:
        # byte 12 has low nibble 8 (wire mask 0x0800), not NS (0x0100).
        probes.append(tcp("ECN", open_port, SYN | ECE | CWR | 0x800, 3,
                          bytes.fromhex("03030A01020405B404020101"), df=False,
                          urgent=0xf7f5, ack_value=0))
        probes.append(tcp("T2", open_port, 0, 128, common))
        probes.append(tcp("T3", open_port, SYN | FIN | URG | PSH, 256, common, df=False))
        probes.append(tcp("T4", open_port, ACK, 1024, common))
    if closed_port is not None:
        probes.append(tcp("T5", closed_port, SYN, 31337, common, df=False))
        probes.append(tcp("T6", closed_port, ACK, 32768, common))
        probes.append(tcp("T7", closed_port, FIN | PSH | URG, 65535,
                          common[:2] + b"\x0f" + common[3:], df=False))
    probes.append(make_probe(source, target, "U1", udp_port, protocol=17,
                             df=False, ip_id=0x1042, sport=port(17), fingerprint=True))
    return probes


def parse_test_line(line):
    match = re.fullmatch(r"([A-Z0-9]+)\((.*)\)", line)
    if not match:
        raise ValueError("Invalid fingerprint test line: " + line[:100])
    fields = {}
    for item in match[2].split("%"):
        key, separator, value = item.partition("=")
        if not separator or not key:
            raise ValueError("Invalid fingerprint attribute: " + item)
        fields[key] = value
    return match[1], fields


def read_published_database(path):
    """Parse fingerprints, classifications, CPE identifiers and MatchPoints."""
    raw = Path(path).read_bytes()
    entries, points, current = [], {}, None
    for number, line in enumerate(raw.decode("utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("This nmap-os-db"):
            continue
        if line == "MatchPoints":
            current = points
        elif line.startswith("Fingerprint "):
            entry = {"label": line[12:], "tests": {}, "classes": [], "cpe": [], "line": number}
            entries.append(entry)
            current = entry["tests"]
        elif line.startswith("Class "):
            if not entries:
                raise ValueError("Classification before first fingerprint")
            values = [value.strip() for value in line[6:].split("|")]
            if len(values) != 4:
                raise ValueError("Invalid database classification")
            entries[-1]["classes"].append(dict(zip(("vendor", "family", "generation", "device_type"), values)))
        elif line.startswith("CPE "):
            if not entries:
                raise ValueError("CPE before first fingerprint")
            entries[-1]["cpe"].append(line[4:].split()[0])
        elif current is not None:
            category, fields = parse_test_line(line)
            current[category] = fields
        else:
            raise ValueError("Unrecognized database line %d" % number)
    if not entries or not points:
        raise ValueError("Database needs MatchPoints and at least one fingerprint")
    for fields in points.values():
        for key, value in fields.items():
            if not value.isdecimal():
                raise ValueError("MatchPoints must be nonnegative decimal integers")
            fields[key] = int(value)
    return {"kind": "published", "entries": entries, "points": points,
            "source": str(path), "sha256": hashlib.sha256(raw).hexdigest(),
            "count": len(entries)}


def expression_matches(observed, expression):
    """Reference alternatives, hexadecimal ranges and strict inequalities."""
    # Recent databases also put numeric subexpressions inside option strings.
    alternatives = re.split(r"\|(?![^\[]*\])", expression)
    for alternative in alternatives:
        if observed == alternative:
            return True
        if "[" in alternative:
            chunks = re.split(r"\[([^\]]+)\]", alternative)
            pattern = "".join(re.escape(chunk) if i % 2 == 0 else "([0-9A-F]+)"
                              for i, chunk in enumerate(chunks))
            match = re.fullmatch(pattern, observed)
            if match and all(expression_matches(value, expr) for value, expr in zip(match.groups(), chunks[1::2])):
                return True
            continue
        try:
            if alternative.startswith("<"):
                if int(observed, 16) < int(alternative[1:], 16):
                    return True
            elif alternative.startswith(">"):
                if int(observed, 16) > int(alternative[1:], 16):
                    return True
            elif re.fullmatch(r"[0-9A-F]+-[0-9A-F]+", alternative):
                first, last = (int(value, 16) for value in alternative.split("-"))
                if first <= int(observed, 16) <= last:
                    return True
        except ValueError:
            continue  # A categorical observation cannot satisfy a numeric range.
    return False


def encoded_options(options):
    """Encode option order AND values as M5B4ST11NW7, not just option names."""
    data, offset, result = bytes.fromhex(options), 0, ""
    while offset < len(data):
        kind = data[offset]
        if kind == 0:
            result += "L"
            offset += 1
            continue
        if kind == 1:
            result += "N"
            offset += 1
            continue
        if offset + 2 > len(data):
            return None
        length = data[offset + 1]
        if length < 2 or offset + length > len(data):
            return None
        value = data[offset + 2:offset + length]
        if kind == 2 and length == 4:
            result += "M%X" % struct.unpack("!H", value)[0]
        elif kind == 3 and length == 3:
            result += "W%X" % value[0]
        elif kind == 4 and length == 2:
            result += "S"
        elif kind == 8 and length == 10:
            first, second = struct.unpack("!II", value)
            result += "T%d%d" % (first != 0, second != 0)
        else:
            # Unknown options have no compatible database token: omit O entirely.
            return None
        offset += length
    return result


def id_classification(ids, minimum=2, icmp=False):
    if len(ids) < minimum:
        return None
    if not any(ids):
        return "Z"
    differences = [(b - a) % 65536 for a, b in zip(ids, ids[1:])]
    if not icmp and any(value >= 20000 for value in differences):
        return "RD"
    if not any(differences):
        return "%X" % ids[0]
    if any(value > 1000 and value % 256 != 0 for value in differences):
        return "RI"
    if all(value % 256 == 0 and value <= 5120 for value in differences):
        return "BI"
    if all(value < 10 for value in differences):
        return "I"
    return None


def standard_sequence(samples, echoes, closed):
    fields = {}
    # Retries can invert probe order. Do not classify that as a random ID
    # generator or use it to infer a shared TCP/ICMP counter.
    samples = [p for p in samples if p.attempts == 1]
    echoes = [p for p in echoes if p.attempts == 1]
    closed = [p for p in closed if p.attempts == 1]
    for key, replies, minimum, icmp in (("TI", samples, 3, False), ("CI", closed, 2, False),
                                         ("II", echoes, 2, True)):
        value = id_classification([p.response["id"] for p in replies], minimum, icmp)
        if value is not None:
            fields[key] = value
    timed = samples
    if len(timed) >= 4:
        deltas, rates = [], []
        for a, b in zip(timed, timed[1:]):
            elapsed = b.first_sent - a.first_sent
            difference = (b.response["seq"] - a.response["seq"]) % (2**32)
            difference = min(difference, 2**32 - difference)
            if elapsed <= 0:
                continue
            deltas.append(difference)
            rates.append(difference / elapsed)
        if len(rates) >= 3:
            gcd = math.gcd(*deltas)
            fields["GCD"] = "%X" % gcd
            average = statistics.mean(rates)
            fields["ISR"] = "%X" % (round(8 * math.log2(average)) if average >= 1 else 0)
            deviation = statistics.stdev([value / gcd if gcd > 9 else value for value in rates])
            fields["SP"] = "%X" % (round(8 * math.log2(deviation)) if deviation > 1 else 0)
    if len(samples) >= 2:
        if any("tsval" not in p.response for p in samples):
            fields["TS"] = "U"
        elif any(p.response["tsval"] == 0 for p in samples):
            fields["TS"] = "0"
        elif len(timed) >= 3:
            rates = []
            for a, b in zip(timed, timed[1:]):
                elapsed = b.first_sent - a.first_sent
                if elapsed > 0:
                    rates.append(((b.response["tsval"] - a.response["tsval"]) % (2**32)) / elapsed)
            # Random per-connection offsets must not be turned into a clock rate.
            if rates and all(value <= 10000 for value in rates):
                average = statistics.mean(rates)
                value = (1 if average <= 5.66 else 7 if 70 <= average <= 150
                         else 8 if 150 < average <= 350 else round(math.log2(average)) if average > 0 else 0)
                fields["TS"] = "%X" % value
    if len(samples) >= 3 and len(echoes) == 2 and fields.get("TI") == fields.get("II") and fields.get("TI") in ("RI", "BI", "I"):
        first, last = samples[0], samples[-1]
        count = int(last.name[1:]) - int(first.name[1:])
        average = ((last.response["id"] - first.response["id"]) % 65536) / max(count, 1)
        gap = (echoes[0].response["id"] - last.response["id"]) % 65536
        fields["SS"] = "S" if gap < 3 * average else "O"
    return fields


def standard_fingerprint(probes, target):
    by_name = {probe.name: probe for probe in probes}
    tests, warnings = {}, []
    def target_reply(probe, protocol):
        return probe and probe.response and probe.response["source"] == target and probe.response["protocol"] == protocol
    samples = [p for p in probes if re.fullmatch("S[1-6]", p.name) and target_reply(p, 6)
               and p.response["flags"] & (SYN | ACK | RST) == SYN | ACK]
    samples.sort(key=lambda p: int(p.name[1:]))
    echoes = [p for p in probes if p.name in ("IE1", "IE2") and target_reply(p, 1)
              and p.response.get("icmp_type") == 0]
    closed = [p for p in probes if p.name in ("T5", "T6", "T7") and target_reply(p, 6)]
    if samples:
        tests["SEQ"] = standard_sequence(samples, echoes, closed)
        tests["OPS"], tests["WIN"] = {}, {}
        for probe in samples:
            number = probe.name[1:]
            options = encoded_options(probe.response["options_hex"])
            if options is not None:
                tests["OPS"]["O" + number] = options
            tests["WIN"]["W" + number] = "%X" % probe.response["window"]
    # TG is a guess. If U1 supplies a forward hop estimate, report T separately.
    distance = None
    udp = by_name.get("U1")
    usable_udp = (target_reply(udp, 1)
                  and (udp.response.get("icmp_type"), udp.response.get("code")) == (3, 3)
                  and len(bytes.fromhex(udp.response.get("quote", {}).get("data_hex", ""))) >= 8)
    if usable_udp:
        sent_ttl = decode_ip(udp.packet)["ttl"]
        quote = udp.response["quote"]
        if 0 < quote["ttl"] <= sent_ttl:
            distance = sent_ttl - quote["ttl"]
    def ttl_fields(response):
        if distance is not None:
            return {"T": "%X" % (response["ttl"] + distance)}
        return {"TG": "%X" % ttl_guess(response["ttl"])}
    def tcp_fields(probe, ecn=False):
        response = probe.response
        fields = {"R": "Y", "DF": "Y" if response["df"] else "N", **ttl_fields(response),
                  "W": "%X" % response["window"],
                  "Q": ("R" if response["reserved"] or response["flags"] & 0x100 else "")
                        + ("U" if response["urgent"] and not response["flags"] & URG else "")}
        options = encoded_options(response["options_hex"])
        if options is not None:
            fields["O"] = options
        if ecn:
            fields["CC"] = {0: "N", ECE: "Y", ECE | CWR: "S", CWR: "O"}[response["flags"] & (ECE | CWR)]
        else:
            fields["S"] = ("Z" if response["seq"] == 0 else "A" if response["seq"] == probe.ack
                           else "A+" if response["seq"] == (probe.ack + 1) % (2**32) else "O")
            fields["A"] = ("Z" if response["ack"] == 0 else "S" if response["ack"] == probe.seq
                           else "S+" if response["ack"] == (probe.seq + 1) % (2**32) else "O")
            fields["F"] = "".join(letter for flag, letter in ((ECE, "E"), (URG, "U"), (ACK, "A"), (PSH, "P"), (RST, "R"), (SYN, "S"), (FIN, "F")) if response["flags"] & flag)
            data = bytes.fromhex(response["data_hex"])
            fields["RD"] = "%X" % (zlib.crc32(data) if response["flags"] & RST else 0)
        return fields
    for category, name in (("T1", "S1"), ("ECN", "ECN"), *[("T%d" % n, "T%d" % n) for n in range(2, 8)]):
        probe = by_name.get(name)
        if not probe:
            continue
        if target_reply(probe, 6):
            tests[category] = tcp_fields(probe, category == "ECN")
        elif probe.response is None and category != "T1":
            # Compatible R=N is explicitly weak negative evidence, not a reply.
            tests[category] = {"R": "N"}
    if len(echoes) == 2:
        a, b = (p.response for p in echoes)
        dfi = "Y" if a["df"] and b["df"] else "N" if not a["df"] and not b["df"] else "S" if a["df"] else "O"
        cd = ("Z" if a["code"] == b["code"] == 0 else "S" if a["code"] == 9 and b["code"] == 0
              else "%X" % a["code"] if a["code"] == b["code"] else "O")
        tests["IE"] = {"R": "Y", "DFI": dfi, "CD": cd, **ttl_fields(a)}
    if usable_udp:
        response, quote = udp.response, udp.response["quote"]
        quoted_header = bytes.fromhex(quote["header_hex"])
        quoted_body = bytes.fromhex(quote["data_hex"])
        sent_body = decode_ip(udp.packet)["payload"]
        tests["U1"] = {"R": "Y", "DF": "Y" if response["df"] else "N", **ttl_fields(response),
                       "IPL": "%X" % response["total_length"], "UN": "%X" % response["unused"],
                       "RIPL": "G" if quote["total_length"] == 328 else "%X" % quote["total_length"],
                       "RID": "G" if quote["id"] == 0x1042 else "%X" % quote["id"],
                       "RIPCK": "Z" if quoted_header[10:12] == b"\x00\x00" else "G" if checksum(quoted_header) == 0 else "I",
                       "RUCK": "G" if quoted_body[6:8] == sent_body[6:8] else "%X" % int.from_bytes(quoted_body[6:8], "big"),
                       "RUD": "G" if all(value == 0x43 for value in quoted_body[8:]) else "I"}
    if distance is not None:
        warnings.append("T uses U1's forward-hop estimate; asymmetric routes can affect it.")
    elif udp:
        warnings.append("No usable U1 hop estimate: using guessed initial TTL (TG), not an exact hop count.")
    if len(samples) < 6:
        warnings.append("Only %d/6 sequence SYN probes answered; version resolution is reduced." % len(samples))
    if "TS" not in tests.get("SEQ", {}) and samples:
        warnings.append("Timestamp clock rate unavailable or inconsistent; TS was omitted.")
    return tests, warnings


def fingerprint_text(tests):
    return "\n".join(name + "(" + "%".join(key + "=" + value for key, value in fields.items()) + ")"
                     for name, fields in tests.items() if fields)


def recover_timestamp_clock(network, battery, timeout):
    """Measure one tuple repeatedly when connection offsets hide the clock.

    Keep these samples out of ISN/IP-ID/options tests. ACK nonces distinguish
    late replies on the reused source port; no retries enter timing evidence.
    """
    first = next((p for p in battery if p.name == "S1" and p.response
                  and p.response["protocol"] == 6
                  and p.response["flags"] & (SYN | ACK | RST) == SYN | ACK
                  and "tsval" in p.response), None)
    if first is None:
        return [], None
    options = bytes.fromhex(decode_packet(first.packet)["options_hex"])
    clocks = [make_probe(network.source, network.target, "CLK%d" % n,
                         first.dport, flags=SYN, window=1, options=options,
                         sport=first.sport, fingerprint=True, df=False) for n in range(1, 4)]
    network.exchange(clocks, max(timeout, 1.0), 0, 3, 0.2)
    if any(not p.response or p.response["protocol"] != 6
           or p.response["flags"] & (SYN | ACK | RST) != SYN | ACK
           or "tsval" not in p.response or p.attempts != 1 for p in clocks):
        return clocks, None
    rates = []
    for a, b in zip(clocks, clocks[1:]):
        elapsed = b.first_sent - a.first_sent
        if elapsed <= 0:
            return clocks, None
        rates.append(((b.response["tsval"] - a.response["tsval"]) % (2**32)) / elapsed)
    average = statistics.mean(rates)
    # Reject changing offsets and frozen timestamps, rather than inventing TS.
    if not 0 < average <= 10000 or max(rates) - min(rates) > max(15, average * 0.35):
        return clocks, None
    return clocks, standard_sequence(clocks, [], []).get("TS")


def published_match(report, database):
    tests, points = report["standard_fingerprint"], database["points"]
    ranked = []
    for entry in database["entries"]:
        matched = possible = positive = negative = 0
        missing, differences = [], []
        total = 0
        for category, reference in entry["tests"].items():
            observed = tests.get(category, {})
            weights = points.get(category, {})
            for key, expression in reference.items():
                value = weights.get(key, 0)
                if key in ("T", "TG") and ((key == "T" and "TG" in observed) or (key == "TG" and "T" in observed)):
                    continue  # T and TG are alternative TTL tests, not missing twice.
                if key == "T" and "TG" in reference and not ({"T", "TG"} & observed.keys()):
                    continue  # With neither observed, count one unavailable TTL test.
                total += value
                if key not in observed:
                    missing.append(category + "." + key)
                    continue
                possible += value
                if observed.get("R") == "N":
                    negative += value
                else:
                    positive += value
                if expression_matches(observed[key], expression):
                    matched += value
                elif value:
                    differences.append(category + "." + key + ": " + observed[key] + " != " + expression)
        if not possible:
            continue
        classes = entry["classes"]
        ranked.append({"label": entry["label"], "family": "/".join(sorted({c["family"] for c in classes})),
                       "version": "/".join(sorted({c["generation"] for c in classes if c["generation"]})),
                       "score": round(100 * matched / possible, 2),
                       "confidence_percent": round(100 * matched / possible, 2),
                       "coverage": round(100 * possible / total, 1) if total else 0,
                       "positive_weight": positive, "negative_weight": negative,
                       "matched_weight": matched, "total_weight": possible,
                       "reference_weight": total, "classes": classes, "cpe": entry["cpe"],
                       "line": entry["line"], "differences": differences, "missing": missing})
    # Multiple captures of the same published label are alternatives, not ambiguity.
    best_by_label = {}
    for row in ranked:
        previous = best_by_label.get(row["label"])
        if previous is None or (row["score"], row["positive_weight"], row["coverage"]) > (previous["score"], previous["positive_weight"], previous["coverage"]):
            best_by_label[row["label"]] = row
    ranked = list(best_by_label.values())
    # Among equal scores, prefer more positive comparable evidence.
    ranked.sort(key=lambda r: (-r["score"], -r["positive_weight"], -r["coverage"], r["label"]))
    states = {p["state"] for p in report["ports"]}
    syn_count = len(tests.get("WIN", {}))
    responsive = [name for name, fields in tests.items() if fields.get("R") == "Y"]
    status, candidate, family = "unknown", None, None
    explanation = "Insufficient positive fingerprint evidence."
    plausible = []
    complete_timing = (syn_count == 6 and {"SP", "GCD", "ISR", "TS"} <= tests.get("SEQ", {}).keys()
                       and report.get("implementation_revision", IMPLEMENTATION_REVISION) >= IMPLEMENTATION_REVISION
                       and report.get("sequence_timing_complete", True)
                       and not report.get("unstable_fields")
                       and report.get("timestamp_source", "sequence") == "sequence")
    ambiguity_margin = 1.0
    if ranked:
        top = ranked[0]
        enough = ("open" in states and "closed" in states and syn_count >= 4
                  and top["positive_weight"] >= 450 and top["coverage"] >= 35
                  and any(name in responsive for name in ("T4", "T5", "T6", "ECN")))
        if enough and top["score"] >= 90:
            # Return near ties honestly; one hostname cannot certify an exact build.
            ambiguity_margin = 1.0 if complete_timing and top["coverage"] >= 75 else 5.0
            plausible = [r for r in ranked if r["score"] >= max(90, top["score"] - ambiguity_margin)
                         and r["positive_weight"] >= 0.8 * top["positive_weight"]
                         and r["coverage"] >= 35]
            family_sets = [{classification["family"] for classification in row["classes"]}
                           for row in plausible]
            common_families = set.intersection(*family_sets) if family_sets else set()
            family = "/".join(sorted(common_families)) or None
            if len(plausible) == 1 and complete_timing:
                status, candidate = "candidate", top["label"]
                explanation = "Closest published TCP/IP fingerprint; the label may already cover a version range."
            else:
                status = "ambiguous"
                explanation = ("%d published fingerprints remain plausible; legacy probes, incomplete sequence evidence, inconsistent rounds, or near matches prevent a unique version answer."
                               if not complete_timing else "%d published fingerprints fit too similarly for a unique version answer.") % len(plausible)
        elif not enough:
            explanation = "Need open/closed TCP ports, at least four SYN replies, and sufficient positive probe evidence."
        else:
            explanation = "No published fingerprint matched closely enough (best %.2f%%)." % top["score"]
    # Compact normal reports; retain ties and the top alternatives, not thousands of zeros.
    keep = max(20, len(plausible))
    ranked = ranked[:keep]
    hints = ["Consistent published OS family: " + family] if family else []
    return {"status": status, "candidate": candidate, "family": family,
            "explanation": explanation, "ranked": ranked, "family_hints": hints,
            "plausible_count": len(plausible), "database_count": database["count"],
            "database_sha256": database["sha256"], "syn_replies": syn_count,
            "responsive_tests": responsive,
            "sequence_evidence_complete": complete_timing, "ambiguity_margin_percent": ambiguity_margin,
            "confidence_method": "100 * matched_weight / total_weight (published IPv4 MatchPoints)",
            "coverage_meaning": "100 * comparable reference weight / relevant reference weight; measures evidence availability, not correctness.",
            "score_meaning": "Fingerprint similarity: weighted agreement on available comparison fields, not the probability that the OS label is correct."}


# Supplemental application evidence. Independent of nmap-os-db MatchPoints.

def banner_os_hints(platform_text, product):
    """Only explicit platform markers/product restrictions; never version lookup."""
    hints = []
    markers = (("Linux", r"Ubuntu|Debian|CentOS|Fedora|Red Hat|Alpine|Linux"),
               ("Windows", r"Windows(?: NT)?|Win32|Win64"),
               ("FreeBSD", r"FreeBSD"), ("OpenBSD", r"OpenBSD"),
               ("NetBSD", r"NetBSD"), ("Mac OS X", r"Mac OS X"))
    for family, pattern in markers:
        match = re.search(r"(?:^|[\s(;])(" + pattern + r")(?=$|[\s);/\-])",
                          platform_text, re.IGNORECASE)
        if match:
            hints.append({"family": family, "evidence": match[1], "basis": "explicit platform tag"})
    if product.lower() in ("microsoft-iis", "microsoft-httpapi", "openssh_for_windows"):
        if not any(hint["family"] == "Windows" for hint in hints):
            hints.append({"family": "Windows", "evidence": product,
                          "basis": "Windows-specific product banner"})
    return hints


def parse_service_banner(data):
    """Recognize a bounded banner; service versions are not OS release numbers."""
    text = data[:SERVICE_BYTE_LIMIT].decode("utf-8", errors="replace")
    # Do not publish a version cut off by a deadline, disconnect, or byte cap.
    text = text[:text.rfind("\n") + 1]
    service, product, version, evidence, platform = None, "", "", "", ""
    # SSH allows informational lines before the identification string.
    ssh = (re.search(r"(?m)^SSH-(?:2\.0|1\.99|1\.5)-([^\s]+)(?:[ \t]+([^\r\n]*))?\r?$", text)
           if not text.startswith("HTTP/") else None)
    if ssh:
        service, evidence = "ssh", ssh[0].rstrip("\r")
        software, platform = ssh[1], ssh[2] or ""
        split = re.fullmatch(r"(.+)[_-](\d[^\s]*)", software)
        product, version = (split[1], split[2]) if split else (software, "")
    elif re.match(r"^HTTP/1\.[01] [0-9]{3}(?: |\r?$)", text, re.MULTILINE):
        service = "http"
        # Ignore body text and unrelated headers: HTML mentioning an OS is not evidence.
        headers = re.split(r"\r?\n\r?\n", text, maxsplit=1)[0]
        server = re.search(r"(?im)^Server:[ \t]*([^\r\n]*)", headers)
        evidence = server[0] if server else text.splitlines()[0]
        platform = server[1].strip() if server else ""
        token = re.match(r"([^\s/();]+)(?:/([^\s();]+))?", platform)
        if token:
            product, version = token[1], token[2] or ""
    else:
        greeting = text.splitlines()[0] if text else ""
        if re.match(r"^220[ -]", greeting):
            if re.search(r"\b(?:ESMTP|SMTP)\b", greeting, re.IGNORECASE):
                service = "smtp"
            elif re.search(r"\b(?:FTP|vsFTPd|ProFTPD|Pure-FTPd|FileZilla)\b", greeting, re.IGNORECASE):
                service = "ftp"
        elif re.match(r"^\+OK\b.*\b(?:POP3|Dovecot|Courier)\b", greeting, re.IGNORECASE):
            service = "pop3"
        elif re.match(r"^\* OK\b.*\b(?:IMAP|Dovecot|Courier)\b", greeting, re.IGNORECASE):
            service = "imap"
        if service:
            evidence = greeting
            token = re.search(r"\b(vsFTPd|ProFTPD|Pure-FTPd|FileZilla|Postfix|Exim|Sendmail|Dovecot|Courier)"
                              r"(?:[ /](\d[\w.\-]*))?", greeting, re.IGNORECASE)
            if token:
                product, version = token[1], token[2] or ""
            # Platform hints in mail/FTP greetings must be parenthesized;
            # hostnames such as ubuntu.example.org must not become OS guesses.
            platform = " ".join(re.findall(r"\([^)]*\)", greeting))
    return {"service": service or "unknown", "product": product or None,
            "version": version or None, "evidence": evidence,
            "os_hints": banner_os_hints(platform, product) if service else []}


def read_service_bytes(connection, deadline, initial=b""):
    data = initial
    while len(data) < SERVICE_BYTE_LIMIT:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        connection.settimeout(remaining)
        try:
            chunk = connection.recv(min(2048, SERVICE_BYTE_LIMIT - len(data)))
        except (socket.timeout, ConnectionResetError):
            break
        if not chunk:
            break
        data += chunk
        if data.startswith(b"HTTP/"):
            if b"\r\n\r\n" in data or b"\n\n" in data:
                break
        elif b"\n" in data:
            # Keep waiting through SSH informational preamble lines.
            complete = data[:data.rfind(b"\n") + 1]
            if parse_service_banner(complete)["service"] != "unknown":
                break
    return data


def probe_service(target, port, timeout=3.0, hostname=None, http_ports=(), tls_ports=()):
    """One connection, absolute per-port deadline, bounded reads, no login."""
    row = {"port": port, "transport": "tcp", "service": "unknown", "product": None,
           "version": None, "os_hints": [], "evidence": "", "probes": [], "response_hex": ""}
    if port in SERVICE_EXCLUDED_PORTS:
        row.update(status="skipped", reason="printer port excluded from application probing")
        return row
    target = str(ipaddress.IPv4Address(target))  # Use the already-resolved scan endpoint.
    host = hostname or target
    if not re.fullmatch(r"[A-Za-z0-9.\-]+", host):
        raise ValueError("Invalid HTTP Host/TLS server name")
    deadline = time.monotonic() + timeout
    data = b""
    connection = None
    try:
        connection = socket.create_connection((target, port), timeout=timeout)
        if port in tls_ports:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout("service deadline reached")
            connection.settimeout(remaining)
            # Inspect self-signed services without claiming certificate authentication.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            connection = context.wrap_socket(connection, server_hostname=host)
            row.update(transport="tls", tls_version=connection.version(), tls_certificate_verified=False)
            row["probes"].append("TLS")
        row["probes"].append("NULL")
        greeting_deadline = (min(deadline, time.monotonic() + min(0.75, timeout / 3))
                             if port in http_ports else deadline)
        data = read_service_bytes(connection, greeting_deadline)
        if not data and port in http_ports:
            remaining = deadline - time.monotonic()
            if remaining > 0:
                connection.settimeout(remaining)
                request = ("GET / HTTP/1.0\r\nHost: %s:%d\r\nConnection: close\r\n\r\n" % (host, port)).encode("ascii")
                connection.sendall(request)
                row["probes"].append("HTTP GET")
                data = read_service_bytes(connection, deadline)
        row.update(parse_service_banner(data))
        row["status"] = "identified" if row["service"] != "unknown" else "unrecognized" if data else "no-banner"
    except OSError as error:
        row.update(status="error", reason=str(error))
        if data:
            row.update(parse_service_banner(data))
    finally:
        if connection is not None:
            connection.close()
    row["response_hex"] = data.hex()
    return row


def collect_services(target, ports, timeout=3.0, max_ports=16, hostname=None,
                     http_ports=(), tls_ports=()):
    # Give commonly informative services priority if the target has many ports.
    preferred = {21, 22, 25, 110, 143, *http_ports, *tls_ports}
    opened = sorted({p["port"] for p in ports if p["state"] == "open"},
                    key=lambda port: (port not in preferred, port))
    eligible = [p for p in opened if p not in SERVICE_EXCLUDED_PORTS]
    selected = eligible[:max_ports]
    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(lambda port: probe_service(target, port, timeout, hostname, http_ports, tls_ports), selected))
    return {"enabled": True, "ports": sorted(rows, key=lambda row: row["port"]),
            "excluded_ports": [p for p in opened if p in SERVICE_EXCLUDED_PORTS],
            "unprobed_ports": eligible[max_ports:], "byte_limit": SERVICE_BYTE_LIMIT,
            "timeout_per_port": timeout,
            "note": "Banners describe a service endpoint and may be customized or proxied; application versions do not prove OS releases."}


def application_os_assessment(report, stack_result):
    evidence = [{"port": row["port"], "service": row["service"], **hint}
                for row in report.get("services", {}).get("ports", [])
                for hint in row.get("os_hints", [])]
    families = {hint["family"] for hint in evidence}
    stack_family = stack_result.get("family")
    if not stack_family and stack_result.get("candidate") and stack_result.get("ranked"):
        stack_family = stack_result["ranked"][0].get("family")
    stack_families = set(stack_family.split("/")) if stack_family else set()
    status, family = "no-hint", None
    if len(families) > 1:
        status = "conflicting-banners"
    elif families:
        family = next(iter(families))
        status = ("corroborates-stack" if family in stack_families else "conflicts-with-stack"
                  if stack_families else "tentative")
    return {"status": status, "family": family, "evidence": evidence,
            "note": "Supplemental, self-reported OS-family evidence; does not change fingerprint scores or establish an OS version."}


# 4. Optional local calibration (the original report/probe format remains readable).

def weight(key):
    return {"options": 5, "window": 3, "ws": 2, "flags": 2}.get(key.split(".")[-1], 1)


def family_hints(features):
    """Broad heuristics are deliberately separate from learned version matches."""
    hints = []
    linux, windows = 0, 0
    for name in ("SP1", "SP2", "SP3"):
        ttl = features.get(name + ".ttl_guess")
        order = features.get(name + ".options", "")
        if ttl == 64 and order.startswith("MSS,SACK,TS,NOP,WS"):
            linux += 1
        if ttl == 128 and order.startswith("MSS,NOP,WS,NOP,NOP,SACK"):
            windows += 1
    if linux >= 2:
        hints.append("Linux-like TCP stack (TTL and TCP option order); release unknown")
    if windows >= 2:
        hints.append("Windows-like TCP stack (TTL and TCP option order); release unknown")
    return hints


def read_json(path):
    with Path(path).open(encoding="utf-8") as file:
        return json.load(file)


def write_json(path, data):
    """Write completely before replacing an existing report/database."""
    import os
    import tempfile
    path = Path(path)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                     prefix=path.name + ".", suffix=".tmp", delete=False) as file:
        temporary = Path(file.name)
        try:
            json.dump(data, file, indent=2, ensure_ascii=True, allow_nan=False)
            file.write("\n")
        except BaseException:
            file.close()
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def read_report(path):
    report = read_json(path)
    if not isinstance(report, dict) or report.get("format") != FORMAT or report.get("probe_set") not in (PROBE_SET, PUBLISHED_PROBES):
        raise ValueError("Not a compatible scanner report: " + str(path))
    if not isinstance(report.get("features"), dict) or not isinstance(report.get("ports"), list):
        raise ValueError("Report needs features and ports: " + str(path))
    validate_features(report["features"])
    if "services" in report:
        services = report["services"]
        if (not isinstance(services, dict) or type(services.get("enabled")) is not bool
                or not isinstance(services.get("ports"), list)):
            raise ValueError("Invalid application service evidence")
        for row in services["ports"]:
            if (not isinstance(row, dict) or type(row.get("port")) is not int
                    or not 1 <= row["port"] <= 65535
                    or any(not isinstance(row.get(key), str) for key in ("service", "transport", "status"))
                    or not isinstance(row.get("os_hints"), list)):
                raise ValueError("Invalid application service row")
            for hint in row["os_hints"]:
                if not isinstance(hint, dict) or any(not isinstance(hint.get(key), str)
                                                     for key in ("family", "evidence", "basis")):
                    raise ValueError("Invalid application OS hint")
    if report["probe_set"] == PUBLISHED_PROBES:
        tests = report.get("standard_fingerprint")
        if not isinstance(tests, dict) or any(not isinstance(fields, dict) or
            any(not isinstance(k, str) or not isinstance(v, str) for k, v in fields.items()) for fields in tests.values()):
            raise ValueError("Standard report needs its extracted standard_fingerprint")
        revision = report.setdefault("implementation_revision", 1)
        if type(revision) is not int or revision < 1:
            raise ValueError("Invalid scanner implementation_revision")
        if revision < IMPLEMENTATION_REVISION:
            note = "Legacy capture predates probe compatibility fixes; rescan for corrected Nmap-compatible packet fields."
            if note not in report.setdefault("warnings", []):
                report["warnings"].append(note)
    return report


def validate_features(features):
    if not isinstance(features, dict) or not features:
        if features == {}:
            return
        raise ValueError("Features must be a dictionary")
    allowed_probes = {"SP1", "SP2", "SP3", "NP", "XP", "AP", "ECN", "IE1", "IE2", "U1"}
    allowed_fields = {"ttl_guess", "df", "window", "options", "flags", "reserved", "urgent", "ws", "code"}
    for key, value in features.items():
        parts = key.split(".")
        if len(parts) != 2 or parts[0] not in allowed_probes or parts[1] not in allowed_fields:
            raise ValueError("Unrecognized feature: " + key)
        if type(value) not in (int, bool, str):
            raise ValueError("Invalid feature value: " + key)


def read_database(path):
    if not Path(path).exists():
        return {"format": FORMAT, "probe_set": PROBE_SET, "signatures": []}
    db = read_json(path)
    if not isinstance(db, dict) or db.get("format") != FORMAT or db.get("probe_set") != PROBE_SET:
        raise ValueError("Incompatible fingerprint database")
    if not isinstance(db.get("signatures"), list):
        raise ValueError("Database needs a signatures list")
    for entry in db["signatures"]:
        if not isinstance(entry, dict) or not all(isinstance(entry.get(k), str) and entry[k].strip()
                                                for k in ("label", "family", "version", "capture_id")):
            raise ValueError("Each signature needs label, family, version and capture_id")
        validate_features(entry.get("features"))
        if not entry["features"]:
            raise ValueError("Empty database signature")
    return db


def scan_conditions(report):
    states = {p["state"] for p in report["ports"]}
    responses = sum("SP%d.options" % n in report["features"] for n in (1, 2, 3))
    return "open" in states and "closed" in states and responses >= 2


def match_report(report, database):
    if database.get("kind") == "published":
        if report.get("probe_set") != PUBLISHED_PROBES:
            raise ValueError("The old probe set is incompatible with published signatures. Take a new scan using the default database.")
        result = published_match(report, database)
        if report.get("services", {}).get("enabled"):
            result["application_os"] = application_os_assessment(report, result)
        return result
    if report.get("probe_set") == PUBLISHED_PROBES:
        raise ValueError("Use nmap-os-db to match a standard fingerprint, not a local JSON calibration database")
    observed = report["features"]
    best_per_label = {}
    for entry in database["signatures"]:
        reference = entry["features"]
        total = sum(weight(key) for key in reference)
        available = sum(weight(key) for key in reference if key in observed)
        matched = sum(weight(key) for key, value in reference.items()
                      if key in observed and observed[key] == value)
        row = {"label": entry["label"], "family": entry["family"], "version": entry["version"],
               "score": round(100 * matched / total, 1),
               "coverage": round(100 * available / total, 1),
               "similarity": round(100 * matched / available, 1) if available else 0,
               "matched_weight": matched, "total_weight": total,
               "differences": [key for key in reference if key in observed and observed[key] != reference[key]],
               "missing": [key for key in reference if key not in observed]}
        previous = best_per_label.get(row["label"])
        if previous is None or (row["score"], row["coverage"]) > (previous["score"], previous["coverage"]):
            best_per_label[row["label"]] = row
    ranked = sorted(best_per_label.values(), key=lambda row: (-row["score"], -row["coverage"], row["label"]))
    status, candidate = "unknown", None
    explanation = "No calibrated signatures. Capture known lab machines and use learn."
    if ranked:
        best = ranked[0]
        if not scan_conditions(report):
            explanation = "Need a confirmed open and closed TCP port and at least two SYN fingerprints."
        elif best["score"] < 85 or best["coverage"] < 75 or best["matched_weight"] < 20:
            explanation = "Insufficient matching evidence for a version candidate."
        elif len(ranked) > 1 and best["score"] - ranked[1]["score"] < 5:
            status = "ambiguous"
            explanation = "Several labels match too similarly to distinguish their versions."
        else:
            status, candidate = "candidate", best["label"]
            explanation = "Closest locally calibrated fingerprint; an unrepresented OS may behave the same."
    result = {"status": status, "candidate": candidate, "explanation": explanation,
            "ranked": ranked, "family_hints": family_hints(observed),
            "score_meaning": "Weighted fingerprint agreement, not a probability or verified OS version."}
    if report.get("services", {}).get("enabled"):
        result["application_os"] = application_os_assessment(report, result)
    return result


def learn(args):
    report = read_report(args.report)
    if report["probe_set"] == PUBLISHED_PROBES:
        raise ValueError("Published fingerprints need no learning. For the optional local-calibration workflow, scan with --db fingerprints.json first.")
    if not scan_conditions(report) or not all("SP%d.options" % n in report["features"] for n in (1, 2, 3)):
        raise ValueError("Calibration requires open + closed TCP ports and all three SYN fingerprints. Rescan with suitable lab ports.")
    db = read_database(args.db)
    capture_id = report.get("capture_id")
    if not isinstance(capture_id, str) or not capture_id:
        raise ValueError("Report is missing its capture_id")
    if any(entry["capture_id"] == capture_id for entry in db["signatures"]):
        raise ValueError("This capture is already in the database; collect another scan for a new sample")
    for entry in db["signatures"]:
        if entry["label"] == args.label and (entry["family"], entry["version"]) != (args.family, args.version):
            raise ValueError("This label already has a different family/version")
    db["signatures"].append({"label": args.label, "family": args.family, "version": args.version,
                             "capture_id": capture_id, "captured_at": report.get("captured_at"),
                             "source_target": report.get("target"), "features": report["features"]})
    write_json(args.db, db)
    print("Learned %s (%d features). Database: %s" % (args.label, len(report["features"]), args.db))


def show_report(report, debug=False):
    print("Target: %s    Source: %s" % (report["target"], report.get("source", "unknown")))
    counts = Counter(port["state"] for port in report["ports"])
    print("TCP ports: " + ", ".join("%d %s" % (count, state) for state, count in sorted(counts.items())))
    print("PORT     STATE      REASON")
    for port in report["ports"]:
        if debug or port["state"] == "open" or len(report["ports"]) <= 20:
            print("%-8s %-10s %s" % (str(port["port"]) + "/tcp", port["state"], port["reason"]))
    result = report["result"]
    if result.get("database_count"):
        print("Database: %d published fingerprints; %d/6 SYN replies" % (result["database_count"], result["syn_replies"]))
    print("\nOS result: " + result["status"].upper())
    if result["candidate"]:
        print("Candidate: " + result["candidate"])
    print(result["explanation"])
    for hint in result["family_hints"]:
        print("Family hint: " + hint)
    if report.get("services", {}).get("enabled"):
        print("\nApplication service evidence:")
        for row in report["services"]["ports"]:
            description = " ".join(str(row.get(key) or "") for key in ("service", "product", "version")).strip()
            print("  %d/tcp %s %s [%s]" % (row["port"], row["transport"],
                  json.dumps(description, ensure_ascii=True), row["status"]))
        assessment = result["application_os"]
        print("Supplemental OS hint: %s (%s)" % (assessment["family"] or "unknown", assessment["status"]))
        for item in assessment["evidence"]:
            print("  %d/tcp: %s" % (item["port"], json.dumps(item["evidence"], ensure_ascii=True)))
        print(assessment["note"])
        for key in ("excluded_ports", "unprobed_ports"):
            if report["services"].get(key):
                print("  %s: %s" % (key.replace("_", " "), report["services"][key]))
    if result["ranked"]:
        published = "database_count" in result
        if published and result["status"] == "unknown":
            print("\nDiagnostic reference similarities only; no OS was identified.")
        print("\nRANK  %s  COVERAGE  OS LABEL" % ("SIMILARITY" if published else "MATCH     "))
        rows = result["ranked"] if debug else result["ranked"][:5]
        for i, row in enumerate(rows, 1):
            print("%-5d %9.2f%%  %5.1f%%    %s" % (i, row["score"], row["coverage"], row["label"]))
        score = result["ranked"][0]["score"]
        if result["status"] == "unknown":
            print("Highest diagnostic similarity: %.1f%% (OS identification unavailable)." % score)
        else:
            print("Highest fingerprint similarity: %.1f%%." % score)
        print(result["score_meaning"])
        print("Coverage: weighted reference evidence available for comparison; not the percentage of ports scanned.")
        if published:
            top = result["ranked"][0]
            print("Best reference: %d/%d comparable points matched; %d/%d reference points available."
                  % (top["matched_weight"], top["total_weight"], top["total_weight"], top["reference_weight"]))
            print("Missing reference evidence: %d weighted points; missing fields do not reduce similarity."
                  % (top["reference_weight"] - top["total_weight"]))
            if result["status"] == "unknown":
                print("These scores are fingerprint similarities only: detection evidence is insufficient.")
    for warning in report.get("warnings", []):
        print("Note: " + warning)
    if debug:
        print("\nFingerprint:\n" + json.dumps(report["features"], indent=2, sort_keys=True))
        print("Diagnostics:\n" + json.dumps(report.get("diagnostics", {}), indent=2))
        if report.get("standard_fingerprint"):
            print("\nStandard fingerprint:\n" + fingerprint_text(report["standard_fingerprint"]))
            for row in result["ranked"][:5]:
                print("\n" + row["label"] + " differences:")
                print("; ".join(row["differences"]) or "None on comparable fields")


def load_scan_database(path):
    if Path(path).suffix.lower() == ".json":
        return read_database(path)
    if not Path(path).exists():
        raise ValueError("Fingerprint database missing: %s. Keep nmap-os-db beside scanner.py or provide --db PATH." % path)
    return read_published_database(path)


def report_database(report, path=None):
    return load_scan_database(path or (PUBLISHED_DB if report["probe_set"] == PUBLISHED_PROBES else DEFAULT_DB))


def collect_standard_round(network, args, open_port, closed_port):
    battery = standard_probes(network.source, network.target, open_port, closed_port,
                              args.udp_port, network.reserve_port)
    sequence = [p for p in battery if re.fullmatch("S[1-6]", p.name) or p.name in ("IE1", "IE2")]
    rest = [p for p in battery if p not in sequence]
    # A late retry must not overlap the initial 500 ms sequence train.
    network.exchange(sequence, max(args.timeout, 1.0), args.retries, 8, 0.1)
    network.exchange(rest, args.timeout, args.retries, 8, 0.025)
    tests, notes = standard_fingerprint(battery, network.target)
    if "TS" not in tests.get("SEQ", {}):
        clocks, clock = recover_timestamp_clock(network, battery, args.timeout)
        battery.extend(clocks)
        if clock is not None:
            tests.setdefault("SEQ", {})["TS"] = clock
            notes = [note for note in notes if not note.startswith("Timestamp clock rate unavailable")]
            notes.append("Recovered TS=%s using three additional SYNs on one tuple; original sequence clock evidence remains incomplete." % clock)
    return battery, tests, notes


def sequence_timing_complete(battery):
    samples = sorted((p for p in battery if re.fullmatch("S[1-6]", p.name)),
                     key=lambda p: p.name)
    return (len(samples) == 6 and all(p.attempts == 1 for p in samples)
            and all(0.075 <= b.first_sent - a.first_sent <= 0.150
                    for a, b in zip(samples, samples[1:])))


def best_standard_round(network, args, db, ports, open_port, closed_port):
    rounds = []
    alternatives = [p["port"] for p in ports if p["state"] == "open" and p["port"] != open_port]
    for attempt in range(args.os_tries):
        selected_open = open_port if attempt == 0 or not alternatives else alternatives[(attempt - 1) % len(alternatives)]
        battery, tests, notes = collect_standard_round(network, args, selected_open, closed_port)
        timestamp_source = "same-tuple" if any("Recovered TS=" in note for note in notes) else "sequence"
        timing_complete = sequence_timing_complete(battery)
        if not timing_complete:
            notes.append("Sequence train had retries or spacing outside 75-150 ms; a unique version is withheld.")
        result = published_match({"ports": ports, "standard_fingerprint": tests,
                                  "timestamp_source": timestamp_source,
                                  "sequence_timing_complete": timing_complete}, db)
        rounds.append({"battery": battery, "tests": tests, "notes": notes, "result": result,
                       "open_port": selected_open, "closed_port": closed_port,
                       "timestamp_source": timestamp_source,
                       "sequence_timing_complete": timing_complete})
        best = next(iter(result["ranked"]), {})
        if (result["status"] == "candidate" and result["sequence_evidence_complete"]
                and best.get("score", 0) == 100 and best.get("coverage", 0) >= 75):
            break
        if open_port is None or closed_port is None:
            break  # Repeating cannot fix missing port discovery prerequisites.
    # Prefer completeness before agreement, rather than picking a lucky high score.
    def quality(item):
        top = next(iter(item["result"]["ranked"]), {})
        return (item["result"]["syn_replies"], top.get("positive_weight", 0), top.get("score", 0))
    selected = max(rounds, key=quality)
    selected = dict(selected)
    selected["tests"] = {category: dict(fields) for category, fields in selected["tests"].items()}
    selected["notes"] = list(selected["notes"])
    # Keep an actual captured fingerprint. Deleting conflicting R/DF/window
    # fields manufactures a partial match and can artificially improve scores.
    # Record instability separately and withhold a unique version instead.
    unstable = []
    for category, fields in list(selected["tests"].items()):
        for key in list(fields):
            if category == "SEQ" and key in ("SP", "GCD", "ISR"):
                continue  # Numeric ISN statistics naturally vary across rounds.
            observed = {item["tests"].get(category, {}).get(key) for item in rounds
                        if key in item["tests"].get(category, {})}
            if len(observed) > 1:
                unstable.append(category + "." + key)
    if unstable:
        selected["notes"].append("Inconsistent across fingerprint rounds; unique version withheld: " + ", ".join(unstable))
    selected["unstable_fields"] = unstable
    selected["result"] = published_match({"ports": ports,
        "standard_fingerprint": selected["tests"],
        "timestamp_source": selected["timestamp_source"],
        "sequence_timing_complete": selected["sequence_timing_complete"],
        "unstable_fields": unstable}, db)
    summaries = [{"open_port": item["open_port"], "closed_port": item["closed_port"],
                  "timestamp_source": item["timestamp_source"],
                  "sequence_timing_complete": item["sequence_timing_complete"],
                  "syn_replies": item["result"]["syn_replies"],
                  "best_match": item["result"]["ranked"][0]["label"] if item["result"]["ranked"] else None,
                  "standard_fingerprint": item["tests"],
                  "probes": [{"name": p.name, "response": p.response, "attempts": p.attempts,
                              "first_sent": p.first_sent,
                              "sent_packet_hex": p.packet.hex()} for p in item["battery"]]} for item in rounds]
    return selected, summaries


def scan(args):
    require_linux()
    target = resolve_target(args.target)
    db = load_scan_database(args.db)
    ports = set(args.ports)
    ports.update(p for p in (args.open_port, args.closed_port) if p is not None)
    ordered = sorted(ports)
    RNG.shuffle(ordered)
    network = RawNetwork(target)
    started = time.monotonic()
    try:
        print("Scanning %s from %s (%d TCP ports)..." % (target, network.source, len(ordered)), flush=True)
        probes = [make_probe(network.source, target, "scan", port) for port in ordered]
        network.exchange(probes, args.timeout, args.retries, args.parallel, args.delay, args.jitter)
        results = sorted((port_result(probe) for probe in probes), key=lambda port: port["port"])
        open_ports = [port["port"] for port in results if port["state"] == "open"]
        closed_ports = [port["port"] for port in results if port["state"] == "closed"]
        open_port = args.open_port if args.open_port in open_ports else next(iter(open_ports), None)
        closed_port = args.closed_port if args.closed_port in closed_ports else next(iter(closed_ports), None)
        print("Fingerprinting (open TCP=%s, closed TCP=%s)..." % (open_port, closed_port), flush=True)
        published = db.get("kind") == "published"
        if published:
            chosen, rounds = best_standard_round(network, args, db, results, open_port, closed_port)
            battery = chosen["battery"]
            open_port = chosen["open_port"]
            syns = [p for p in battery if re.fullmatch("S[1-6]", p.name)]
        else:
            battery = fingerprint_probes(network.source, target, open_port, closed_port, args.udp_port)
            syns = [p for p in battery if p.name.startswith("SP")]
            rest = [p for p in battery if not p.name.startswith("SP")]
            network.exchange(syns, args.timeout, args.retries, 3, 0.12)
            network.exchange(rest, args.timeout, args.retries, 10, 0.01)
        warnings = []
        if open_port is None or closed_port is None:
            warnings.append("An open AND a closed TCP port were not found. Broaden -p or configure the lab firewall.")
        if any(port["state"] == "filtered" for port in results):
            warnings.append("Filtered/no reply does not prove a firewall: loss and unreachable hosts can look the same.")
        for requested, available, state in ((args.open_port, open_ports, "open"), (args.closed_port, closed_ports, "closed")):
            if requested is not None and requested not in available:
                warnings.append("Requested %s port %d was not confirmed; used another if available." % (state, requested))
        udp = next(p for p in battery if p.name == "U1")
        confirmed_udp = bool(udp.response and udp.response["source"] == target
                             and udp.response.get("icmp_type") == 3 and udp.response.get("code") == 3)
        if not confirmed_udp:
            warnings.append("UDP port %d was not confirmed closed; its silence contributes no OS evidence." % args.udp_port)
        report = {"format": FORMAT, "probe_set": PUBLISHED_PROBES if published else PROBE_SET,
                  "implementation_revision": IMPLEMENTATION_REVISION,
                  "capture_id": RNG.getrandbits(128).to_bytes(16, "big").hex(),
                  "captured_at": datetime.now(timezone.utc).isoformat(),
                  "target": target, "source": network.source,
                  "elapsed_seconds": round(time.monotonic() - started, 3), "ports": results,
                  "open_port": open_port, "closed_port": closed_port,
                  "udp_port": args.udp_port, "udp_closed_confirmed": confirmed_udp,
                  "features": {} if published else extract_features(battery, target),
                  "probes": [{"name": p.name, "attempts": p.attempts,
                              "first_sent": p.first_sent,
                              "sent_packet_hex": p.packet.hex(), "response": p.response} for p in battery],
                  "diagnostics": sequence_observations(battery), "warnings": warnings}
        if published:
            tests, notes = chosen["tests"], chosen["notes"]
            report["standard_fingerprint"] = tests
            report["timestamp_source"] = chosen["timestamp_source"]
            report["sequence_timing_complete"] = chosen["sequence_timing_complete"]
            report["unstable_fields"] = chosen["unstable_fields"]
            report["fingerprint_rounds"] = rounds
            report["warnings"].extend(notes)
            report["diagnostics"] = {"sequence_samples": len(syns),
                                     "sequence_send_offsets_ms": [round((p.first_sent - syns[0].first_sent) * 1000, 3) for p in syns],
                                     "sequence_fields": tests.get("SEQ", {})}
        if args.service_version:
            print("Collecting application banners (up to %d open ports)..." % args.version_max_ports, flush=True)
            report["services"] = collect_services(target, results, args.version_timeout,
                args.version_max_ports, args.target, args.http_ports, args.tls_ports)
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        report["result"] = match_report(report, db)
        show_report(report, args.debug)
        if args.output:
            write_json(args.output, report)
            print("\nSaved: " + str(args.output))
        return report
    finally:
        network.close()


def evaluate(args):
    """Compare held-out reports against operator-supplied ground truth labels."""
    cases = read_json(args.cases)
    if not isinstance(cases, list) or not cases:
        raise ValueError("Evaluation file must contain a nonempty list of {report, label} cases")
    first_case = cases[0]
    if not isinstance(first_case, dict) or not isinstance(first_case.get("report"), str):
        raise ValueError("Each case needs a report path and ground-truth label")
    first_report = read_report(Path(args.cases).parent / first_case["report"])
    db = report_database(first_report, args.db)
    if db.get("kind") != "published" and not db["signatures"]:
        raise ValueError("Evaluation needs a calibrated database")
    trained = {entry["capture_id"] for entry in db.get("signatures", [])}
    rows = []
    seen = set()
    for case in cases:
        if not isinstance(case, dict) or not all(isinstance(case.get(k), str) and case[k] for k in ("report", "label")):
            raise ValueError("Each case needs a report path and ground-truth label")
        report = read_report(Path(args.cases).parent / case["report"])
        capture_id = report.get("capture_id")
        if not capture_id or capture_id in trained or capture_id in seen:
            raise ValueError("Evaluation needs unique held-out captures; this capture is reused: " + case["report"])
        seen.add(capture_id)
        result = match_report(report, db)
        actual_family = case.get("family")
        if actual_family is not None and (not isinstance(actual_family, str) or not actual_family):
            raise ValueError("Optional case family must be a nonempty string")
        predicted_family = result.get("family")
        if not predicted_family and result["candidate"]:
            predicted_family = result["ranked"][0]["family"]
        rows.append({"report": case["report"], "actual": case["label"],
                     "predicted": result["candidate"], "status": result["status"],
                     "correct": result["candidate"] == case["label"],
                     "actual_family": actual_family, "predicted_family": predicted_family,
                     "family_correct": actual_family == predicted_family if actual_family else None})
    correct = sum(row["correct"] for row in rows)
    answered = sum(row["status"] == "candidate" for row in rows)
    summary = {"cases": rows, "correct": correct, "total": len(rows), "answered": answered,
               "accuracy_percent": round(100 * correct / len(rows), 1),
               "answer_rate_percent": round(100 * answered / len(rows), 1),
               "note": "Exact operator labels compared. Unknown/ambiguous count as unanswered and not correct. This is not proof of exact remote version detection."}
    family_cases = [row for row in rows if row["actual_family"]]
    if family_cases:
        family_correct = sum(row["family_correct"] for row in family_cases)
        summary["family_accuracy_percent"] = round(100 * family_correct / len(family_cases), 1)
    for row in rows:
        print("%s: actual=%s; predicted=%s (%s)" % (row["report"], row["actual"], row["predicted"], row["status"]))
    print("Accuracy: %d/%d (%.1f%%). Answered: %d/%d." % (correct, len(rows), summary["accuracy_percent"], answered, len(rows)))
    if family_cases:
        print("OS family accuracy: %.1f%% on %d labeled cases." % (summary["family_accuracy_percent"], len(family_cases)))
    if args.output:
        write_json(args.output, summary)


# 5. Optional passive defense: flag port sweeps and unusual TCP flag combinations.

class ScanDetector:
    def __init__(self, window=10, threshold=20):
        self.window, self.threshold = window, threshold
        self.ports = defaultdict(dict)
        self.alerted = {}

    def observe(self, packet, now):
        for pair, ports in list(self.ports.items()):
            for port, seen in list(ports.items()):
                if now - seen >= self.window:
                    del ports[port]
            if not ports:
                del self.ports[pair]
        self.alerted = {key: seen for key, seen in self.alerted.items() if now - seen < self.window}
        if packet["protocol"] != 6:
            return []
        pair = packet["source"], packet["target"]
        flags = packet["flags"]
        reasons = []
        if flags == 0 or flags & (SYN | FIN) == SYN | FIN or flags & (FIN | PSH | URG) == FIN | PSH | URG:
            reasons.append("unusual TCP flags 0x%02x" % flags)
        if flags & SYN and not flags & ACK:
            self.ports[pair][packet["dport"]] = now
            if len(self.ports[pair]) >= self.threshold:
                reasons.append("distinct-port SYN sweep")
        alerts = []
        for reason in reasons:
            key = (*pair, reason)
            if key not in self.alerted:
                self.alerted[key] = now
                alerts.append({"source": pair[0], "target": pair[1], "reason": reason,
                               "distinct_ports": len(self.ports.get(pair, {}))})
        return alerts


def watch(args):
    require_linux()
    detector = ScanDetector(args.window, args.threshold)
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as receiver:
        receiver.bind((args.interface, 0))
        receiver.settimeout(1)
        print("Watching %s; alerts only. Ctrl+C stops." % args.interface, flush=True)
        start = time.monotonic()
        while not args.duration or time.monotonic() - start < args.duration:
            try:
                frame = receiver.recv(65535)
            except socket.timeout:
                continue
            if len(frame) < 14:
                continue
            protocol, offset = struct.unpack("!H", frame[12:14])[0], 14
            while protocol in (0x8100, 0x88a8) and len(frame) >= offset + 4:
                protocol = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
                offset += 4
            if protocol != 0x0800:
                continue
            try:
                packet = decode_packet(frame[offset:])
            except ValueError:
                continue
            for alert in detector.observe(packet, time.monotonic()):
                alert["time"] = datetime.now(timezone.utc).isoformat()
                print(json.dumps(alert), flush=True)


def parse_ports(text):
    ports = set()
    try:
        for item in text.split(","):
            bounds = item.split("-")
            if len(bounds) > 2:
                raise ValueError
            first, last = int(bounds[0]), int(bounds[-1])
            if not 1 <= first <= last <= 65535:
                raise ValueError
            ports.update(range(first, last + 1))
    except ValueError:
        raise argparse.ArgumentTypeError("Use ports/ranges between 1 and 65535, e.g. 22,80,1000-1100") from None
    return sorted(ports)


def bounded_number(low, high, integer=False):
    def parse(text):
        try:
            number = int(text) if integer else float(text)
        except ValueError:
            raise argparse.ArgumentTypeError("Expected a number") from None
        if not math.isfinite(number) or not low <= number <= high:
            raise argparse.ArgumentTypeError("Expected a number between %s and %s" % (low, high))
        return number
    return parse


def nonempty(text):
    if not text.strip():
        raise argparse.ArgumentTypeError("Value must not be empty")
    return text.strip()


def resolve_target(text):
    import re
    try:
        address = ipaddress.ip_address(text)
        if address.version != 4 or address.is_multicast or address.is_unspecified or text == "255.255.255.255":
            raise ValueError("Use a single unicast IPv4 target")
        return str(address)
    except ValueError:
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.\-]{0,252}", text) or re.fullmatch(r"[0-9.]+", text):
            raise ValueError("Use one IPv4 address or hostname, not a subnet/range/IPv6 address") from None
    addresses = socket.getaddrinfo(text, None, socket.AF_INET, socket.SOCK_STREAM)
    address = addresses[0][4][0]
    parsed = ipaddress.ip_address(address)
    if parsed.is_multicast or parsed.is_unspecified or address == "255.255.255.255":
        raise ValueError("Target resolved to a non-unicast IPv4 address")
    return address


def make_parser():
    parser = argparse.ArgumentParser(description=__doc__, epilog="Scan only machines you own or have permission to test.")
    commands = parser.add_subparsers(dest="command", required=True)
    live = commands.add_parser("scan", help="SYN scan and active fingerprinting (Linux, sudo)")
    live.add_argument("target", help="one IPv4 address or hostname")
    live.add_argument("-p", "--ports", type=parse_ports, default=parse_ports("1-1024,3389,5900,8000,8080,8443"))
    live.add_argument("--open-port", type=bounded_number(1, 65535, True), help="preferred open TCP port; verified first")
    live.add_argument("--closed-port", type=bounded_number(1, 65535, True), help="preferred closed TCP port; verified first")
    live.add_argument("--udp-port", type=bounded_number(1, 65535, True), default=33434, help="UDP port for U1; closed only if ICMP confirms it")
    live.add_argument("--timeout", type=bounded_number(0.05, 60), default=2.0, help="reply timeout per attempt in seconds (default 2)")
    live.add_argument("--retries", type=bounded_number(0, 5, True), default=2)
    live.add_argument("--os-tries", type=bounded_number(1, 3, True), default=2,
                      help="fresh fingerprint rounds if evidence is weak; stops early on a complete perfect match")
    live.add_argument("--parallel", type=bounded_number(1, 256, True), default=32)
    live.add_argument("--delay", type=bounded_number(0, 10), default=0.01, help="spacing between initial port probes in seconds")
    live.add_argument("--jitter", type=bounded_number(0, 10), default=0.01, help="additional random delay from 0 to this many seconds")
    live.add_argument("--db", type=Path, default=PUBLISHED_DB, help="default: bundled published data; use a .json path for legacy local calibration")
    live.add_argument("-o", "--output", type=Path, help="save full scan and packet evidence as JSON")
    live.add_argument("--debug", action="store_true")
    live.add_argument("-sV", "--service-version", action="store_true",
                      help="collect bounded application banners and supplemental OS-family hints")
    live.add_argument("--version-timeout", type=bounded_number(0.1, 30), default=3.0,
                      help="total application probing budget per port, seconds (default 3)")
    live.add_argument("--version-max-ports", type=bounded_number(1, 256, True), default=16,
                      help="maximum open ports to inspect for application banners (default 16)")
    live.add_argument("--http-ports", type=parse_ports,
                      default=parse_ports("80,81,443,8000,8008,8080,8081,8443,8888"),
                      help="ports eligible for an HTTP GET when no greeting arrives; replaces default list")
    live.add_argument("--tls-ports", type=parse_ports,
                      default=parse_ports("443,465,636,853,990,993,995,8443"),
                      help="ports to inspect through TLS; replaces default list")
    train = commands.add_parser("learn", help="add a known-OS capture to the local signature database")
    train.add_argument("report", type=Path)
    train.add_argument("--label", type=nonempty, required=True, help="ground-truth label, e.g. Ubuntu 24.04 / kernel 6.8")
    train.add_argument("--family", type=nonempty, required=True, help="ground truth, e.g. Linux or Windows")
    train.add_argument("--version", type=nonempty, required=True, help="ground-truth version string")
    train.add_argument("--db", type=Path, default=DEFAULT_DB)
    match = commands.add_parser("match", help="reclassify a saved scan without network traffic")
    match.add_argument("report", type=Path)
    match.add_argument("--db", type=Path, help="default chosen automatically for the report's probe set")
    match.add_argument("-o", "--output", type=Path)
    match.add_argument("--debug", action="store_true")
    evaluation = commands.add_parser("evaluate", help="measure label accuracy on held-out scan reports")
    evaluation.add_argument("cases", type=Path)
    evaluation.add_argument("--db", type=Path, help="default chosen automatically for the reports' probe set")
    evaluation.add_argument("-o", "--output", type=Path)
    defense = commands.add_parser("watch", help="passive scan alerts on an interface (Linux, sudo)")
    defense.add_argument("--interface", required=True)
    defense.add_argument("--window", type=bounded_number(1, 3600), default=10)
    defense.add_argument("--threshold", type=bounded_number(2, 65535, True), default=20)
    defense.add_argument("--duration", type=bounded_number(0, 86400), default=0, help="seconds; 0 means until Ctrl+C")
    return parser


def main(argv=None):
    args = make_parser().parse_args(argv)
    try:
        if args.command == "scan":
            scan(args)
        elif args.command == "learn":
            learn(args)
        elif args.command == "match":
            report = read_report(args.report)
            report["result"] = match_report(report, report_database(report, args.db))
            show_report(report, args.debug)
            if args.output:
                write_json(args.output, report)
        elif args.command == "evaluate":
            evaluate(args)
        else:
            watch(args)
    except PermissionError as error:
        print("Error: %s. Live raw sockets need sudo or CAP_NET_RAW; also check file permissions." % error, file=sys.stderr)
        return 1
    except (OSError, ValueError) as error:
        print("Error: " + str(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
