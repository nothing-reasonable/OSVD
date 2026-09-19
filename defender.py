#!/usr/bin/env python3
"""Victim-side IPv4 scan defense: nftables on Linux, WinDivert on Windows.

This reduces fingerprint evidence; it does not emulate another TCP/IP stack.
Bare run defaults to full supported defense; Linux monitors all local interfaces.
Use --profile normalize to select header normalization without automatic defense.
Run `python defender.py preview --help` before applying a policy.
"""

import argparse
import ctypes as c
from collections import OrderedDict, deque
from dataclasses import dataclass
import ipaddress
import json
import logging
import math
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time


TABLE = "portscan_defense"
LOG = logging.getLogger("defender")
STATE_LIMIT = 8192
FIN, SYN, RST, PSH, ACK, URG = 1, 2, 4, 8, 16, 32


def bounded_int(low, high):
    def parse(value):
        try:
            number = int(value)
            if low <= number <= high:
                return number
        except ValueError:
            pass
        raise argparse.ArgumentTypeError(f"expected an integer between {low} and {high}")
    return parse


def interface_value(value):
    if not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,15}", value) or value == "lo":
        raise argparse.ArgumentTypeError("select a non-loopback Linux interface (for example eth0)")
    return value


def in_networks(address, networks):
    return any(ipaddress.IPv4Address(address) in network for network in networks)


def ipv4_network(value):
    try:
        return ipaddress.IPv4Network(value, strict=False)
    except ValueError:
        raise argparse.ArgumentTypeError("--peer requires an IPv4 address or CIDR network") from None


def ttl_value(value):
    try:
        number = int(value)
        if 1 <= number <= 255:
            return number
    except ValueError:
        pass
    raise argparse.ArgumentTypeError("TTL must be an integer between 1 and 255")


def duration_value(value):
    try:
        number = float(value)
        if math.isfinite(number) and number >= 0:
            return number
    except ValueError:
        pass
    raise argparse.ArgumentTypeError("duration must be a finite, nonnegative number")


@dataclass(frozen=True)
class Policy:
    ttl: int = 64
    peers: tuple = (ipaddress.IPv4Network("0.0.0.0/0"),)
    mode: str = "normalize"
    quiet_probes: bool = False
    suppress_rst: bool = False
    interface: str = None
    trusted: tuple = ()
    block_sources: tuple = ()
    filter_flags: bool = False
    block_echo: bool = False
    block_legacy_icmp: bool = False
    udp_ports: tuple = ()
    syn_rate: int = 0
    syn_burst: int = 20
    connlimit: int = 0
    detect: bool = False
    auto_block: bool = False
    window: int = 10
    threshold: int = 20
    block_seconds: int = 60
    handshake_timeout: int = 10
    handshake_threshold: int = 20
    syn_cookies: bool = False
    decoy_ports: tuple = ()
    decoy_bind: str = "0.0.0.0"
    decoy_banner: str = "220 service ready"
    hardened: bool = False
    min_syn_window: int = 0

    @classmethod
    def from_args(cls, args):
        peers = tuple(ipaddress.collapse_addresses(args.peer or [ipv4_network("0.0.0.0/0")]))
        if len(peers) > 128:
            raise ValueError("at most 128 separate peer networks are supported")
        platform = getattr(args, "platform", "windows" if sys.platform == "win32" else "linux")
        profile = args.profile or "hardened"
        if profile == "active" and platform != "linux":
            raise ValueError("the active profile requires Linux")
        hardened = profile == "hardened"
        active = profile in ("active", "hardened") and platform == "linux"
        interface = args.interface
        if interface is None and platform == "linux" and (active or args.detect or args.auto_block):
            interface = "any"
        policy = cls(
            ttl=args.ttl, peers=peers, mode=args.mode, quiet_probes=args.quiet_probes or hardened,
            suppress_rst=args.suppress_rst or hardened, interface=interface,
            trusted=tuple(ipaddress.collapse_addresses(args.allow_peer or [])),
            block_sources=tuple(ipaddress.collapse_addresses(args.block_source or [])),
            filter_flags=args.filter_flags or active,
            block_echo=args.block_echo or active,
            block_legacy_icmp=args.block_legacy_icmp or active,
            udp_ports=tuple(sorted(set(args.block_udp_port or ([33434] if active else [])))),
            syn_rate=args.syn_rate if args.syn_rate is not None else (20 if active else 0),
            syn_burst=args.syn_burst, connlimit=args.connlimit,
            detect=args.detect or args.auto_block or active,
            auto_block=args.auto_block or active,
            window=args.window, threshold=args.threshold, block_seconds=args.block_seconds,
            handshake_timeout=args.handshake_timeout, handshake_threshold=args.handshake_threshold,
            syn_cookies=args.syn_cookies, decoy_ports=tuple(sorted(set(args.decoy_port or []))),
            decoy_bind=args.decoy_bind, decoy_banner=args.decoy_banner,
            hardened=hardened,
            min_syn_window=args.min_syn_window if args.min_syn_window is not None else (1024 if hardened else 0))
        if policy.detect and not policy.interface:
            raise ValueError("--detect, --auto-block, --active and --hardened require --interface (name or any)")
        if len(policy.decoy_ports) > 32:
            raise ValueError("at most 32 decoy listeners are supported")
        if len(policy.decoy_banner.encode("utf-8")) > 1024 or any(
                ord(char) < 32 for char in policy.decoy_banner):
            raise ValueError("--decoy-banner must be one printable line of at most 1024 bytes")
        return policy

    def protects(self, address):
        ip = ipaddress.IPv4Address(address)
        return (not ip.is_loopback and not ip.is_multicast and not ip.is_unspecified
                and str(ip) != "255.255.255.255"
                and in_networks(ip, self.peers) and not in_networks(ip, self.trusted))

    def linux_only(self):
        return any((self.interface, self.trusted, self.block_sources, self.filter_flags,
                    self.block_echo, self.block_legacy_icmp, self.udp_ports, self.syn_rate,
                    self.connlimit, self.detect, self.auto_block, self.syn_cookies, self.decoy_ports))


def nft_rules(policy):
    """An exclusive, atomic table creation; never flush the host's ruleset."""
    rows = [f"create table ip {TABLE}",
            f"add chain ip {TABLE} incoming {{ type filter hook input priority -10; policy accept; }}",
            f"add chain ip {TABLE} outgoing {{ type filter hook output priority -10; policy accept; }}",
            f'add rule ip {TABLE} incoming iifname "lo" return',
            f'add rule ip {TABLE} outgoing oifname "lo" return']
    # Discovery protocols can require TTL=255; do not normalize multicast or
    # limited broadcast traffic while protecting ordinary remote unicast hosts.
    for chain in ("incoming", "outgoing"):
        rows.append(f"add rule ip {TABLE} {chain} ip daddr 224.0.0.0/4 return")
        rows.append(f"add rule ip {TABLE} {chain} ip daddr 255.255.255.255 return")
    if policy.interface and policy.interface != "any":
        rows.extend((f'add rule ip {TABLE} incoming iifname != "{policy.interface}" return',
                     f'add rule ip {TABLE} outgoing oifname != "{policy.interface}" return'))
    for trusted in policy.trusted:
        rows.extend((f"add rule ip {TABLE} incoming ip saddr {trusted} return",
                     f"add rule ip {TABLE} outgoing ip daddr {trusted} return"))
    if policy.auto_block:
        rows.append(f"add set ip {TABLE} blocked {{ type ipv4_addr; flags dynamic,timeout; "
                    f"timeout {policy.block_seconds}s; size {STATE_LIMIT}; }}")
    if policy.syn_rate:
        rows.append(f"add set ip {TABLE} syn_rates {{ type ipv4_addr; flags dynamic,timeout; "
                    f"timeout 1m; size {STATE_LIMIT}; }}")
        if policy.auto_block:
            rows.append(f"add chain ip {TABLE} rate_block")
            rows.append(f"add rule ip {TABLE} rate_block add @blocked {{ ip saddr timeout {policy.block_seconds}s }} "
                        'counter drop comment "kernel-syn-rate-block"')
            rows.append(f'add rule ip {TABLE} rate_block counter drop comment "rate-drop-fallback"')
    if policy.connlimit:
        rows.append(f"add set ip {TABLE} connections {{ type ipv4_addr; flags dynamic; size {STATE_LIMIT}; }}")
    for peer in policy.peers:
        incoming = f"add rule ip {TABLE} incoming ip saddr {peer} "
        outgoing = f"add rule ip {TABLE} outgoing ip daddr {peer} "
        if policy.detect:
            rows.append(incoming + 'counter comment "scope-in"')
        if policy.auto_block:
            rows.append(incoming + "ip saddr @blocked counter drop")
            rows.append(outgoing + "ip daddr @blocked counter drop")
        for source in policy.block_sources:
            rows.append(incoming + f"ip saddr {source} counter drop")
            rows.append(outgoing + f"ip daddr {source} counter drop")
        def reject_probe(expression):
            if policy.auto_block:
                # Kernel enforcement runs before the host can send a reply;
                # Python detection alone loses this race on a low-latency LAN.
                rows.append(incoming + expression + f" add @blocked {{ ip saddr timeout {policy.block_seconds}s }}"
                            ' counter drop comment "kernel-scan-block"')
            # If a dynamic set is full, its update can abort that rule. This
            # separate fallback still drops the offending packet in that case.
            rows.append(incoming + expression + ' counter drop comment "probe-drop"')

        if policy.quiet_probes or policy.filter_flags or policy.auto_block:
            # Inspect before ordinary firewall rules; these are additional drops,
            # never permissions that override an existing firewall.
            for rule in (
                "tcp flags & (fin | syn) == (fin | syn)",
                "tcp flags & (syn | rst) == (syn | rst)",
                "tcp flags & (fin | syn | rst | psh | ack | urg) == 0",
                "tcp flags & (fin | psh | urg) == (fin | psh | urg)",
            ):
                reject_probe(rule)
        syn = "tcp flags & (fin | syn | rst | ack) == syn "
        if policy.min_syn_window:
            reject_probe(syn + f"tcp window < {policy.min_syn_window}")
        if policy.hardened:
            # No packet rewriting or TCP option removal: just reject packets
            # conntrack cannot associate with a valid flow. Do not source-ban
            # these alone, since delayed legitimate packets may be invalid.
            rows.append(incoming + 'ct state invalid counter drop comment "invalid-flow"')
        if policy.quiet_probes:
            rows.append(outgoing + "icmp type echo-reply counter drop")
            rows.append(outgoing + "icmp type destination-unreachable icmp code port-unreachable counter drop")
        if policy.block_echo:
            rows.append(incoming + "icmp type echo-request counter drop")
        if policy.block_legacy_icmp:
            rows.append(incoming + "icmp type { timestamp-request, address-mask-request } counter drop")
            rows.append(outgoing + "icmp type { timestamp-reply, address-mask-reply } counter drop")
        if policy.udp_ports:
            ports = ", ".join(map(str, policy.udp_ports))
            rows.append(incoming + f"udp dport {{ {ports} }} counter drop")
        if policy.syn_rate:
            verdict = "jump rate_block" if policy.auto_block else "drop"
            rows.append(incoming + syn + "update @syn_rates { ip saddr "
                        f"limit rate over {policy.syn_rate}/second burst {policy.syn_burst} packets }} counter {verdict}")
        if policy.connlimit:
            rows.append(incoming + "ct state new " + syn +
                        f"add @connections {{ ip saddr ct count over {policy.connlimit} }} counter drop")
        if policy.suppress_rst:
            rows.append(outgoing + "tcp flags & rst == rst counter drop")
        if policy.mode != "filter-only":
            rows.append(outgoing + f"ip ttl != {policy.ttl} counter ip ttl set {policy.ttl}")
        if policy.mode == "normalize":
            # RFC 6864 atomic datagrams: DF=1, MF=0, fragment offset=0.
            # IDs of packets that may need reassembly must remain untouched.
            rows.append(outgoing + "ip frag-off & 0x7fff == 0x4000 ip id != 0 counter ip id set 0")
    return "\n".join(rows) + "\n"


def divert_scope(peers, field):
    terms = []
    for peer in peers:
        if peer.prefixlen == 0:
            return "true"
        if peer.prefixlen == 32:
            terms.append(f"{field} == {peer.network_address}")
        else:
            terms.append(f"({field} >= {peer.network_address} and {field} <= {peer.broadcast_address})")
    return "(" + " or ".join(terms) + ")"


def divert_filters(policy):
    if policy.linux_only():
        raise ValueError("active detection and the extended defense options require Linux; use preview --platform linux")
    source = divert_scope(policy.peers, "ip.SrcAddr")
    target = divert_scope(policy.peers, "ip.DstAddr")
    changes = [f"ip.TTL != {policy.ttl}"] if policy.mode != "filter-only" else []
    if policy.mode == "normalize":
        changes.append("(ip.DF and !ip.MF and ip.FragOff == 0 and ip.Id != 0)")
    scope = ("ip and !loopback and (ip.DstAddr < 224.0.0.0 or ip.DstAddr > 239.255.255.255) "
             "and ip.DstAddr != 255.255.255.255")
    rewrite = f"{scope} and outbound and {target} and (" + (" or ".join(changes) or "false") + ")"
    rules = []
    replies = []
    if policy.suppress_rst:
        replies.append("(tcp and tcp.Rst)")
    if policy.quiet_probes:
        null = "(!tcp.Fin and !tcp.Syn and !tcp.Rst and !tcp.Psh and !tcp.Ack and !tcp.Urg)"
        rules.append(f"(inbound and {source} and tcp and ((tcp.Syn and tcp.Fin) or "
                     f"(tcp.Syn and tcp.Rst) or {null} or (tcp.Fin and tcp.Psh and tcp.Urg)))")
        replies.append("(icmp and icmp.Type == 0)")
        replies.append("(icmp and icmp.Type == 3 and icmp.Code == 3)")
    if policy.min_syn_window:
        rules.append(f"(inbound and {source} and tcp and tcp.Syn and !tcp.Ack and !tcp.Fin and !tcp.Rst "
                     f"and tcp.Window < {policy.min_syn_window})")
    if replies:
        rules.append(f"(outbound and {target} and (" + " or ".join(replies) + "))")
    drop = scope + " and (" + " or ".join(rules) + ")" if rules else None
    return drop, rewrite


def normalize_packet(packet, policy):
    """Modify only IPv4 TTL/atomic ID; caller repairs checksum before sending."""
    if len(packet) < 20 or packet[0] >> 4 != 4:
        raise ValueError("not an IPv4 packet")
    header_length = (packet[0] & 15) * 4
    if header_length < 20 or header_length > len(packet):
        raise ValueError("invalid IPv4 header length")
    result = bytearray(packet)
    if policy.mode != "filter-only":
        result[8] = policy.ttl
    fragment = int.from_bytes(result[6:8], "big")
    if policy.mode == "normalize" and fragment & 0x7fff == 0x4000:
        result[4:6] = b"\0\0"
    return bytes(result)


def checksum_flags(packet):
    # A fragment does not contain the complete transport message. Preserve its
    # transport checksum; TTL/ID only require an IPv4 header checksum update.
    # WinDivert NO_ICMP | NO_ICMPV6 | NO_TCP | NO_UDP_CHECKSUM = 30.
    return 30 if int.from_bytes(packet[6:8], "big") & 0x3fff else 0


def tcp_observation(raw):
    """Decode complete, unfragmented IPv4/TCP headers from a cooked packet socket."""
    if len(raw) < 20 or raw[0] >> 4 != 4 or raw[9] != 6:
        return None
    ihl = (raw[0] & 15) * 4
    total = int.from_bytes(raw[2:4], "big")
    if ihl < 20 or total > len(raw) or total < ihl + 20:
        return None
    if int.from_bytes(raw[6:8], "big") & 0x3fff:
        return None
    sport, dport, seq, ack, bits = struct.unpack_from("!HHIIH", raw, ihl)
    tcp_length = (bits >> 12) * 4
    if tcp_length < 20 or ihl + tcp_length > total:
        return None
    return dict(source=socket.inet_ntoa(raw[12:16]), target=socket.inet_ntoa(raw[16:20]),
                sport=sport, dport=dport, seq=seq, ack=ack, flags=bits & 0x1ff,
                window=int.from_bytes(raw[ihl + 14:ihl + 16], "big"))


def bounded_put(mapping, key, value):
    mapping[key] = value
    mapping.move_to_end(key)
    while len(mapping) > STATE_LIMIT:
        mapping.popitem(last=False)


class ActiveDetector:
    """Bounded rolling sweep and three-way-handshake state, using monotonic time."""
    def __init__(self, policy):
        self.policy = policy
        self.ports = OrderedDict()
        self.pending = OrderedDict()
        self.incomplete = OrderedDict()
        self.alerted = OrderedDict()

    def alert(self, pair, reason, count, now):
        key = (*pair, reason)
        if now - self.alerted.get(key, -float("inf")) < self.policy.window:
            return []
        bounded_put(self.alerted, key, now)
        return [dict(source=pair[0], target=pair[1], reason=reason, count=count)]

    def failed_handshake(self, key, now):
        pair = key[:2]
        events = self.incomplete.get(pair, deque(maxlen=self.policy.handshake_threshold))
        while events and now - events[0] >= self.policy.window:
            events.popleft()
        events.append(now)
        bounded_put(self.incomplete, pair, events)
        if len(events) >= self.policy.handshake_threshold:
            return self.alert(pair, "incomplete TCP handshakes", len(events), now)
        return []

    def expire(self, now):
        alerts = []
        for key, flow in list(self.pending.items()):
            if now - flow["started"] >= self.policy.handshake_timeout:
                del self.pending[key]
                # Count only a SYN that was answered by this host, never a
                # closed port or a SYN silently dropped by our own rate limit.
                if flow["server_seq"] is not None:
                    alerts.extend(self.failed_handshake(key, now))
        for pair, ports in list(self.ports.items()):
            fresh = {port: seen for port, seen in ports.items() if now - seen < self.policy.window}
            if fresh:
                self.ports[pair] = fresh
            else:
                del self.ports[pair]
        for mapping in (self.incomplete, self.alerted):
            for key, value in list(mapping.items()):
                seen = value[-1] if isinstance(value, deque) else value
                if now - seen >= self.policy.window:
                    del mapping[key]
        return alerts

    def forget(self, source):
        for mapping in (self.ports, self.pending, self.incomplete, self.alerted):
            for key in list(mapping):
                if key[0] == source:
                    del mapping[key]

    def observe(self, packet, now, outbound=False):
        flags = packet["flags"]
        if outbound:
            key = (packet["target"], packet["source"], packet["dport"], packet["sport"])
            flow = self.pending.get(key)
            if flow:
                if flags & RST:
                    del self.pending[key]
                elif flags & (SYN | ACK) == SYN | ACK and packet["ack"] == (flow["seq"] + 1) & 0xffffffff:
                    flow["server_seq"] = packet["seq"]
            return []
        key = (packet["source"], packet["target"], packet["sport"], packet["dport"])
        pair = key[:2]
        alerts = []
        if (flags & 0x3f == 0 or flags & (SYN | FIN) == SYN | FIN
                or flags & (SYN | RST) == SYN | RST or flags & (FIN | PSH | URG) == FIN | PSH | URG):
            alerts.extend(self.alert(pair, "unusual TCP flags", 1, now))
        if flags & SYN and not flags & (ACK | RST | FIN):
            if self.policy.min_syn_window and packet.get("window", 65535) < self.policy.min_syn_window:
                alerts.extend(self.alert(pair, "small-window SYN", 1, now))
            ports = {port: seen for port, seen in self.ports.get(pair, {}).items()
                     if now - seen < self.policy.window}
            ports[packet["dport"]] = now
            # Retain only enough recent ports to decide the threshold.
            if len(ports) > self.policy.threshold:
                del ports[min(ports, key=ports.get)]
            bounded_put(self.ports, pair, ports)
            if len(ports) >= self.policy.threshold:
                alerts.extend(self.alert(pair, "distinct-port SYN sweep", len(ports), now))
            flow = self.pending.get(key)
            if flow is None or flow["seq"] != packet["seq"]:
                bounded_put(self.pending, key, dict(started=now, seq=packet["seq"], server_seq=None))
        elif key in self.pending:
            flow = self.pending[key]
            expected = None if flow["server_seq"] is None else (flow["server_seq"] + 1) & 0xffffffff
            if flags & RST:
                del self.pending[key]
                if expected is not None:
                    alerts.extend(self.failed_handshake(key, now))
            elif flags & ACK and not flags & SYN and expected is not None:
                if packet["ack"] == expected and packet["seq"] == (flow["seq"] + 1) & 0xffffffff:
                    del self.pending[key]
        return alerts


class LinuxMonitor:
    def __init__(self, policy, backend):
        self.policy, self.backend = policy, backend
        self.detector = ActiveDetector(policy)
        self.blocked = OrderedDict()
        self.stopping = threading.Event()
        self.thread = None
        self.receiver = None
        self.error = None
        self.observed = 0
        self.last_report = time.monotonic()

    def start(self):
        # Explicit local addresses exclude forwarded traffic on a router/bridge.
        command = ["ip", "-j", "-4", "address", "show"]
        if self.policy.interface != "any":
            command += ["dev", self.policy.interface]
        result = subprocess.run(command,
                                capture_output=True, text=True, check=True, timeout=15)
        self.local = {item["local"] for link in json.loads(result.stdout)
                      for item in link.get("addr_info", []) if item.get("family") == "inet"
                      and link.get("ifname") != "lo"}
        if not self.local:
            raise ValueError("the selected interface has no local IPv4 address")
        LOG.warning("MONITOR interface=%s local-ipv4=%s", self.policy.interface, ",".join(sorted(self.local)))
        # A VM's NAT NIC and host-only NIC often have different names than a
        # copied example. Warn when an explicitly named attacker routes elsewhere.
        if self.policy.interface != "any":
            for peer in self.policy.peers:
                if peer.prefixlen != 32:
                    continue
                route = subprocess.run(["ip", "-j", "-4", "route", "get", str(peer.network_address)],
                                       capture_output=True, text=True, timeout=15, check=False)
                if route.returncode:
                    LOG.warning("Cannot verify return route to %s: %s", peer.network_address, route.stderr.strip())
                    continue
                for entry in json.loads(route.stdout):
                    if entry.get("dev") != self.policy.interface:
                        LOG.warning("INTERFACE MISMATCH: peer=%s routes via %s, selected=%s; "
                                    "check the VM adapter or use --interface any",
                                    peer.network_address, entry.get("dev"), self.policy.interface)
        self.receiver = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(3))
        if self.policy.interface != "any":
            self.receiver.bind((self.policy.interface, 0))
        self.receiver.settimeout(0.25)
        self.thread = threading.Thread(target=self.capture, name="defense-monitor", daemon=True)
        self.thread.start()

    def handle_alerts(self, alerts, now):
        for alert in alerts:
            source = alert["source"]
            if not self.policy.protects(source) or self.blocked.get(source, 0) > now:
                continue
            alert = dict(alert, action="alert")
            if self.policy.auto_block:
                # A fixed kernel timeout expires even if the monitor dies.
                # Ignore blocked traffic until expiry instead of extending it.
                started = time.monotonic()
                self.backend.block(source)
                bounded_put(self.blocked, source, now + self.policy.block_seconds + time.monotonic() - started)
                self.detector.forget(source)
                alert.update(action="block", seconds=self.policy.block_seconds)
            LOG.warning("ALERT %s", json.dumps(alert, sort_keys=True))

    def capture(self):
        next_expiry = 0
        try:
            while not self.stopping.is_set():
                now = time.monotonic()
                if now >= next_expiry:
                    self.handle_alerts(self.detector.expire(now), now)
                    for source, until in list(self.blocked.items()):
                        if until <= now:
                            del self.blocked[source]
                            LOG.info("UNBLOCK source=%s (kernel timeout elapsed)", source)
                    next_expiry = now + 0.25
                try:
                    raw, address = self.receiver.recvfrom(65535)
                except socket.timeout:
                    continue
                # PACKET_HOST=0, PACKET_OUTGOING=4. Exclude broadcasts,
                # multicast, and other-host packets visible to packet sockets.
                if address[0] == "lo" or address[1] != 0x0800 or address[2] not in (0, 4):
                    continue
                outbound = address[2] == 4
                packet = tcp_observation(raw)
                if packet is None:
                    continue
                remote, local = (packet["target"], packet["source"]) if outbound else (packet["source"], packet["target"])
                now = time.monotonic()
                if local not in self.local or not self.policy.protects(remote) or self.blocked.get(remote, 0) > now:
                    continue
                self.observed += 1
                self.handle_alerts(self.detector.observe(packet, now, outbound), now)
        except Exception as error:
            self.error = error

    def check(self):
        if self.error is not None:
            raise self.error
        if self.thread is not None and not self.thread.is_alive():
            raise OSError("scan monitor stopped unexpectedly")
        now = time.monotonic()
        if now - self.last_report >= 30:
            self.last_report = now
            LOG.info("MONITOR observed-tcp=%d userspace-blocks=%d interface=%s",
                     self.observed, len(self.blocked), self.policy.interface)
            if not self.observed:
                LOG.warning("No in-scope TCP observed; if a scan is running, check --interface, --peer, "
                            "and that defender runs inside the target VM")

    def close(self):
        self.stopping.set()
        if self.thread is not None and self.thread.ident is not None:
            self.thread.join(timeout=17)  # Includes a bounded in-flight nft call.
        if self.receiver is not None:
            self.receiver.close()
            self.receiver = None


class SynCookies:
    """Temporarily enable kernel SYN cookies, preserving existing forced mode."""
    def __init__(self):
        self.path = Path("/proc/sys/net/ipv4/tcp_syncookies")
        self.previous = None

    def start(self):
        old = self.path.read_text().strip()
        if old == "0":
            self.path.write_text("1\n")
            self.previous = old
        LOG.info("SYN cookies enabled (kernel mode %s)", "1" if old == "0" else old)

    def close(self):
        if self.previous is not None:
            if self.path.read_text().strip() == "1":
                self.path.write_text(self.previous + "\n")
            else:
                LOG.warning("SYN cookie setting changed externally; leaving it untouched")
            self.previous = None


class DecoyServices:
    """Small optional greeting listeners; never replace an occupied service."""
    def __init__(self, policy):
        self.policy = policy
        self.selector = selectors.DefaultSelector()
        self.stopping = threading.Event()
        self.thread = None
        self.error = None

    def start(self):
        for port in self.policy.decoy_ports:
            listener = socket.socket()
            try:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((self.policy.decoy_bind, port))
                listener.listen(16)
                listener.setblocking(False)
                self.selector.register(listener, selectors.EVENT_READ)
            except BaseException:
                listener.close()
                raise
        self.thread = threading.Thread(target=self.serve, name="defense-decoys", daemon=True)
        self.thread.start()

    def serve(self):
        try:
            while not self.stopping.is_set():
                for key, _ in self.selector.select(timeout=0.25):
                    try:
                        client, address = key.fileobj.accept()
                    except BlockingIOError:
                        continue
                    with client:
                        if self.policy.protects(address[0]):
                            client.settimeout(0.2)
                            try:
                                client.sendall((self.policy.decoy_banner + "\r\n").encode("utf-8"))
                            except OSError:
                                pass
        except Exception as error:
            self.error = error

    def check(self):
        if self.error is not None:
            raise self.error
        if self.thread is not None and not self.thread.is_alive():
            raise OSError("decoy worker stopped unexpectedly")

    def close(self):
        self.stopping.set()
        if self.thread is not None and self.thread.ident is not None:
            self.thread.join(timeout=8)
        for key in list((self.selector.get_map() or {}).values()):
            self.selector.unregister(key.fileobj)
            key.fileobj.close()
        self.selector.close()


class LinuxDefense:
    def __init__(self, policy):
        self.policy = policy
        self.active = False
        self.last_report = time.monotonic()
        self.nft = shutil.which("nft")
        if self.nft is None:
            raise OSError("nft not found; install nftables using your Linux package manager")

    def command(self, *arguments, script=None):
        result = subprocess.run([self.nft, *arguments], input=script, text=True,
                                capture_output=True, timeout=15, check=False)
        if result.returncode:
            raise OSError("nft failed: " + (result.stderr.strip() or result.stdout.strip()))
        return result.stdout

    def start(self):
        if os.geteuid() != 0:
            raise OSError("run the Linux defender as root (sudo)")
        script = nft_rules(self.policy)
        self.command("--check", "--file", "-", script=script)
        self.command("--file", "-", script=script)
        self.active = True

    def check(self):
        # Detect removal by a firewall reload, rather than silently claiming
        # protection after our table has disappeared.
        rules = self.command("list", "table", "ip", TABLE)
        now = time.monotonic()
        if now - self.last_report >= 30:
            self.last_report = now
            counts = {"scope-in": 0, "kernel-scan-block": 0, "drops": 0}
            for line in rules.splitlines():
                counter = re.search(r"counter packets (\d+)", line)
                if counter:
                    for name in ("scope-in", "kernel-scan-block"):
                        if f'comment "{name}"' in line:
                            counts[name] += int(counter.group(1))
                    if 'comment "kernel-syn-rate-block"' in line:
                        counts["kernel-scan-block"] += int(counter.group(1))
                    if " drop" in line:
                        counts["drops"] += int(counter.group(1))
            LOG.info("FIREWALL scoped-input=%d dropped-packets=%d kernel-source-blocks=%d",
                     counts["scope-in"], counts["drops"], counts["kernel-scan-block"])

    def block(self, source):
        source = str(ipaddress.IPv4Address(source))
        if not self.active or not self.policy.auto_block or not self.policy.protects(source):
            raise ValueError("refusing a block outside the active policy")
        self.command("--file", "-", script=f"add element ip {TABLE} blocked {{ {source} timeout {self.policy.block_seconds}s }}\n")

    def close(self):
        if self.active:
            self.command("delete", "table", "ip", TABLE)
            self.active = False


class WindowsDefense:
    def __init__(self, policy, directory=None):
        from windows_transport import DivertAddress, driver_error, load_library
        self.policy = policy
        self.address_type = DivertAddress
        self.driver_error = driver_error
        self.dll = load_library(directory)
        helper = self.dll.WinDivertHelperCalcChecksums
        helper.argtypes = [c.c_void_p, c.c_uint32, c.POINTER(DivertAddress), c.c_uint64]
        helper.restype = c.c_int32
        self.handles = []
        self.thread = None
        self.stopping = threading.Event()
        self.error = None
        self.rewritten = 0

    def open_handle(self, expression, priority, flags):
        handle = self.dll.WinDivertOpen(expression.encode("ascii"), 0, priority, flags)
        if handle in (None, c.c_void_p(-1).value):
            raise self.driver_error("WinDivertOpen")
        self.handles.append(handle)
        major = c.c_uint64()
        if not self.dll.WinDivertGetParam(handle, 3, c.byref(major)):
            raise self.driver_error("WinDivertGetParam")
        if major.value != 2:
            raise ValueError("defender requires WinDivert 2.x")
        return handle

    def start(self):
        drop, rewrite = divert_filters(self.policy)
        try:
            if drop:
                self.open_handle(drop, 100, 2)  # WINDIVERT_FLAG_DROP: kernel drops.
            handle = self.open_handle(rewrite, 90, 0)
            self.thread = threading.Thread(target=self.capture, args=(handle,),
                                           name="defense-ttl", daemon=True)
            self.thread.start()
        except BaseException:
            self.close()
            raise

    def capture(self, handle):
        buffer = c.create_string_buffer(65535)
        size, sent, address = c.c_uint32(), c.c_uint32(), self.address_type()
        try:
            while not self.stopping.is_set():
                if not self.dll.WinDivertRecv(handle, buffer, len(buffer), c.byref(size), c.byref(address)):
                    if not self.stopping.is_set():
                        raise self.driver_error("WinDivertRecv")
                    return
                packet = normalize_packet(buffer.raw[:size.value], self.policy)
                c.memmove(buffer, packet, len(packet))
                # Recalculate transport checksums too: outbound packets can be
                # captured before NIC checksum offloading has filled them in.
                if not self.dll.WinDivertHelperCalcChecksums(buffer, size.value, c.byref(address), checksum_flags(packet)):
                    raise OSError("WinDivertHelperCalcChecksums failed")
                if not self.dll.WinDivertSend(handle, buffer, size.value, c.byref(sent), c.byref(address)):
                    raise self.driver_error("WinDivertSend")
                if sent.value != size.value:
                    raise OSError("WinDivertSend injected an incomplete packet")
                self.rewritten += 1
        except Exception as error:
            self.error = error

    def check(self):
        if self.error is not None:
            raise self.error
        if self.thread is not None and not self.thread.is_alive():
            raise OSError("TTL worker stopped unexpectedly")

    def close(self):
        self.stopping.set()
        # Wake the receive first; do not close a handle while its worker sends.
        if self.thread is not None and self.thread.ident is not None and self.handles:
            self.dll.WinDivertShutdown(self.handles[-1], 1)  # RECV only.
            self.thread.join(timeout=3)
        failures = []
        for handle in reversed(self.handles):
            if not self.dll.WinDivertClose(handle):
                failures.append(str(self.driver_error("WinDivertClose")))
        self.handles.clear()
        if failures:
            raise OSError("; ".join(failures))


def make_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("preview", "run"):
        child = commands.add_parser(name, help="print policy without changes" if name == "preview" else "apply until stopped")
        child.add_argument("--mode", choices=("normalize", "ttl-only", "filter-only"), default="normalize",
                           help="header rewriting: TTL+ID (default), TTL, or none (filter-only)")
        child.add_argument("--ttl", type=ttl_value, default=64)
        child.add_argument("--peer", action="append", type=ipv4_network,
                           help="remote IPv4/CIDR to defend against; repeatable; default: all IPv4 peers")
        child.add_argument("--quiet-probes", action="store_true",
                           help="opt in to dropping unusual TCP probes, echo replies, and ICMP port-unreachable replies")
        child.add_argument("--suppress-rst", action="store_true",
                           help="opt in to dropping outbound TCP resets; may delay connection error handling")
        profiles = child.add_mutually_exclusive_group()
        profiles.add_argument("--profile", choices=("normalize", "active", "hardened"),
                              help="default: hardened; normalize disables automatic defenses; active is Linux only")
        profiles.add_argument("--active", action="store_const", dest="profile", const="active",
                           help="Linux: detect/block scans, filter flags/echo/legacy ICMP/UDP 33434, limit SYNs")
        profiles.add_argument("--hardened", action="store_const", dest="profile", const="hardened",
                           help="Linux: active defense plus small-window SYN filtering, invalid-flow drops and reply suppression")
        child.add_argument("--min-syn-window", type=bounded_int(0, 65535),
                           help="drop initial SYNs advertising a window below N; hardened default 1024, otherwise disabled")
        child.add_argument("--interface", type=interface_value, help="Linux: interface name, or any for all non-loopback interfaces")
        child.add_argument("--allow-peer", action="append", type=ipv4_network,
                           help="Linux: exempt a trusted IPv4 address/network from this defender")
        child.add_argument("--block-source", action="append", type=ipv4_network,
                           help="Linux: static source block within --peer scope, until stopped")
        child.add_argument("--filter-flags", action="store_true", help="Linux: drop abnormal TCP flags only")
        child.add_argument("--block-echo", action="store_true", help="Linux: drop ICMP echo requests")
        child.add_argument("--block-legacy-icmp", action="store_true",
                           help="Linux: suppress ICMP timestamp/address-mask requests and replies")
        child.add_argument("--block-udp-port", action="append", type=bounded_int(1, 65535),
                           help="Linux: drop inbound UDP to this port; repeatable")
        child.add_argument("--syn-rate", type=bounded_int(0, 1000000),
                           help="Linux: maximum SYN packets/second per source; 0 disables; --active default 20")
        child.add_argument("--syn-burst", type=bounded_int(1, 1000000), default=20,
                           help="Linux: SYN token bucket size (default 20)")
        child.add_argument("--connlimit", type=bounded_int(0, 1000000), default=0,
                           help="Linux: concurrent tracked TCP connections per source; default disabled")
        child.add_argument("--detect", action="store_true", help="Linux: log sweeps, unusual flags and incomplete handshakes")
        child.add_argument("--auto-block", action="store_true", help="Linux: detect and temporarily block scan sources")
        child.add_argument("--window", type=bounded_int(1, 3600), default=10, help="detection window/cooldown seconds (10)")
        child.add_argument("--threshold", type=bounded_int(2, 1024), default=20, help="distinct SYN destination ports (20)")
        child.add_argument("--block-seconds", type=bounded_int(1, 86400), default=60, help="automatic block lifetime (60)")
        child.add_argument("--handshake-timeout", type=bounded_int(1, 3600), default=10,
                           help="seconds to wait for final handshake ACK (10)")
        child.add_argument("--handshake-threshold", type=bounded_int(1, 1024), default=20,
                           help="incomplete answered handshakes per window before alert (20)")
        child.add_argument("--syn-cookies", action="store_true", help="Linux: enable kernel SYN cookies, restore on exit")
        child.add_argument("--decoy-port", action="append", type=bounded_int(1, 65535),
                           help="Linux: open a greeting-only decoy listener on an unused TCP port; repeatable")
        child.add_argument("--decoy-bind", type=lambda value: str(ipaddress.IPv4Address(value)), default="0.0.0.0",
                           help="decoy local IPv4 bind address (default all local addresses)")
        child.add_argument("--decoy-banner", default="220 service ready", help="one-line decoy greeting (CRLF appended)")
        if name == "preview":
            child.add_argument("--platform", choices=("linux", "windows"),
                               default="windows" if sys.platform == "win32" else "linux")
        else:
            child.add_argument("--windivert-dir", help="Windows: folder containing WinDivert.dll and its driver")
            child.add_argument("--duration", type=duration_value, default=0,
                               help="stop after this many seconds; default: run until interrupted")
            child.add_argument("--log-file", help="append operational logs to this file")
    return parser


def run(args, policy):
    log_handler = None
    if args.log_file:
        log_handler = logging.FileHandler(args.log_file, encoding="utf-8")
        log_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logging.getLogger().addHandler(log_handler)
    stop = threading.Event()
    previous = {}
    for sig in (signal.SIGINT, signal.SIGTERM):
        previous[sig] = signal.signal(sig, lambda *_: stop.set())
    backend = None
    resources = []
    workers = []
    try:
        if sys.platform == "win32":
            if policy.linux_only():
                raise ValueError("active detection and extended defense options require Linux")
            backend = WindowsDefense(policy, args.windivert_dir)
        elif sys.platform.startswith("linux"):
            backend = LinuxDefense(policy)
        else:
            raise OSError("live defense requires Linux or native Windows")
        resources.append(backend)
        backend.start()
        if not (policy.detect or policy.quiet_probes or policy.filter_flags or policy.block_sources
                or policy.suppress_rst or policy.syn_rate or policy.connlimit or policy.block_echo
                or policy.block_legacy_icmp or policy.udp_ports or policy.min_syn_window):
            LOG.warning("NORMALIZATION ONLY: scan detection/blocking is OFF. "
                        "For Linux active defense use run --hardened --interface any")
        if policy.syn_cookies:
            cookies = SynCookies()
            resources.append(cookies)
            cookies.start()
        if policy.decoy_ports:
            decoys = DecoyServices(policy)
            resources.append(decoys)
            workers.append(decoys)
            decoys.start()
        if policy.detect:
            monitor = LinuxMonitor(policy, backend)
            resources.append(monitor)
            workers.append(monitor)
            monitor.start()
        LOG.warning("ACTIVE: mode=%s TTL=%d peers=%s quiet-probes=%s suppress-rst=%s; IPv4 only, loopback excluded",
                    policy.mode, policy.ttl, ",".join(map(str, policy.peers)), policy.quiet_probes, policy.suppress_rst)
        LOG.info("interface=%s detection=%s auto-block=%s block-seconds=%s syn-rate=%s connlimit=%s decoys=%s",
                 policy.interface or "all", policy.detect, policy.auto_block, policy.block_seconds,
                 policy.syn_rate, policy.connlimit, policy.decoy_ports)
        if policy.hardened or policy.min_syn_window:
            LOG.warning("STRICT FILTER: min-syn-window=%s suppress-rst=%s; small-window clients may be blocked",
                        policy.min_syn_window, policy.suppress_rst)
        started = time.monotonic()
        next_check = started
        while not stop.wait(0.2):
            now = time.monotonic()
            for worker in workers:
                worker.check()
            if isinstance(backend, WindowsDefense) or now >= next_check:
                backend.check()
                next_check = now + 5
            if args.duration and now - started >= args.duration:
                break
        return 0
    finally:
        try:
            failures = []
            for resource in reversed(resources):
                try:
                    resource.close()
                except Exception as error:
                    failures.append(str(error))
            if failures:
                raise OSError("cleanup failed: " + "; ".join(failures))
            if resources:
                LOG.warning("STOPPED: defender resources removed; owned settings restored")
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
            if log_handler is not None:
                logging.getLogger().removeHandler(log_handler)
                log_handler.close()


def main(argv=None):
    parser = make_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        policy = Policy.from_args(args)
        if args.command == "preview":
            print("# IPv4 only; loopback excluded. Selected filters/limits/blocks may restrict connections.")
            if args.platform == "linux":
                print(nft_rules(policy), end="")
                if policy.detect:
                    print(f"# Monitor {policy.interface}: {policy.threshold} ports/{policy.window}s; "
                          f"incomplete handshakes {policy.handshake_threshold}/{policy.window}s; "
                          f"auto-block={policy.auto_block} for {policy.block_seconds}s")
                if policy.syn_cookies:
                    print("# Temporarily enable net.ipv4.tcp_syncookies; restore on graceful exit")
                if policy.decoy_ports:
                    print(f"# Decoy listeners: {policy.decoy_bind} ports={policy.decoy_ports} banner={policy.decoy_banner!r}")
            else:
                drop, rewrite = divert_filters(policy)
                print("# Kernel drop filter:\n" + (drop or "false"))
                print("# Outbound header rewrite filter:\n" + rewrite)
            return 0
        return run(args, policy)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        LOG.error("%s", error)
        return 1


if __name__ == "__main__":
    sys.exit(main())
