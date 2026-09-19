#!/usr/bin/env python3
"""Victim-side IPv4 scan defense: nftables on Linux, WinDivert on Windows.

This reduces fingerprint evidence; it does not emulate another TCP/IP stack.
Run `python defender.py preview --help` before applying a policy.
"""

import argparse
import ctypes as c
from dataclasses import dataclass
import ipaddress
import logging
import math
import os
import shutil
import signal
import subprocess
import sys
import threading
import time


TABLE = "portscan_defense"
LOG = logging.getLogger("defender")


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

    @classmethod
    def from_args(cls, args):
        peers = tuple(ipaddress.collapse_addresses(args.peer or [ipv4_network("0.0.0.0/0")]))
        if len(peers) > 128:
            raise ValueError("at most 128 separate peer networks are supported")
        return cls(args.ttl, peers, args.mode, args.quiet_probes, args.suppress_rst)


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
    for peer in policy.peers:
        incoming = f"add rule ip {TABLE} incoming ip saddr {peer} "
        outgoing = f"add rule ip {TABLE} outgoing ip daddr {peer} "
        if policy.quiet_probes:
            # Inspect before ordinary firewall rules; these are additional drops,
            # never permissions that override an existing firewall.
            rows.extend(incoming + rule + " counter drop" for rule in (
                "tcp flags & (fin | syn) == (fin | syn)",
                "tcp flags & (syn | rst) == (syn | rst)",
                "tcp flags & (fin | syn | rst | psh | ack | urg) == 0",
                "tcp flags & (fin | psh | urg) == (fin | psh | urg)",
            ))
            rows.append(outgoing + "icmp type echo-reply counter drop")
            rows.append(outgoing + "icmp type destination-unreachable icmp code port-unreachable counter drop")
        if policy.suppress_rst:
            rows.append(outgoing + "tcp flags & rst == rst counter drop")
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
    source = divert_scope(policy.peers, "ip.SrcAddr")
    target = divert_scope(policy.peers, "ip.DstAddr")
    changes = [f"ip.TTL != {policy.ttl}"]
    if policy.mode == "normalize":
        changes.append("(ip.DF and !ip.MF and ip.FragOff == 0 and ip.Id != 0)")
    scope = ("ip and !loopback and (ip.DstAddr < 224.0.0.0 or ip.DstAddr > 239.255.255.255) "
             "and ip.DstAddr != 255.255.255.255")
    rewrite = f"{scope} and outbound and {target} and (" + " or ".join(changes) + ")"
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


class LinuxDefense:
    def __init__(self, policy):
        self.policy = policy
        self.active = False
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
        self.command("list", "table", "ip", TABLE)

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
        child.add_argument("--mode", choices=("normalize", "ttl-only"), default="normalize")
        child.add_argument("--ttl", type=ttl_value, default=64)
        child.add_argument("--peer", action="append", type=ipv4_network,
                           help="remote IPv4/CIDR to defend against; repeatable; default: all IPv4 peers")
        child.add_argument("--quiet-probes", action="store_true",
                           help="opt in to dropping unusual TCP probes, echo replies, and ICMP port-unreachable replies")
        child.add_argument("--suppress-rst", action="store_true",
                           help="opt in to dropping outbound TCP resets; may delay connection error handling")
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
    if args.log_file:
        logging.getLogger().addHandler(logging.FileHandler(args.log_file, encoding="utf-8"))
    stop = threading.Event()
    previous = {}
    for sig in (signal.SIGINT, signal.SIGTERM):
        previous[sig] = signal.signal(sig, lambda *_: stop.set())
    backend = None
    try:
        if sys.platform == "win32":
            backend = WindowsDefense(policy, args.windivert_dir)
        elif sys.platform.startswith("linux"):
            backend = LinuxDefense(policy)
        else:
            raise OSError("live defense requires Linux or native Windows")
        backend.start()
        LOG.warning("ACTIVE: mode=%s TTL=%d peers=%s quiet-probes=%s suppress-rst=%s; IPv4 only, loopback excluded",
                    policy.mode, policy.ttl, ",".join(map(str, policy.peers)), policy.quiet_probes, policy.suppress_rst)
        started = time.monotonic()
        next_check = started
        while not stop.wait(0.2):
            now = time.monotonic()
            if isinstance(backend, WindowsDefense) or now >= next_check:
                backend.check()
                next_check = now + 5
            if args.duration and now - started >= args.duration:
                break
        return 0
    finally:
        try:
            if backend is not None:
                backend.close()
                LOG.warning("STOPPED: defender's rules/handles removed")
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)


def main(argv=None):
    parser = make_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        policy = Policy.from_args(args)
        if args.command == "preview":
            print("# IPv4 only; loopback excluded. Normal TCP connection requests are not blocked.")
            if args.platform == "linux":
                print(nft_rules(policy), end="")
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
