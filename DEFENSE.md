# Victim-side normalization and active scan defense

Run **`defender.py` on the PC being scanned**, using Python 3.10+. It runs on
Linux and native Windows and continuously changes selected outgoing IPv4 headers.
**`sudo python3 defender.py run` now starts the full Linux anti-scan profile.**
It defaults to `--profile hardened --interface any`: detection, temporary source
blocking, probe/reply filtering, per-source SYN rate control, and normalization.
It requires `nftables` and `iproute2`. Existing firewall rules still apply.

The older plain `run` command only normalized TTL and atomic IDs. That was not
active blocking and could make little difference on a Linux VM, whose TTL/ID
values might already match. Use `--profile normalize` explicitly to reproduce
that old behavior; `--active` selects the less restrictive active profile.

Run the defender **inside the VM being scanned**. `--interface any` covers its
non-loopback interfaces, avoiding confusion between NAT and lab adapters. In
the saved `TestsVM/Zorin18/Zorin18` output, `192.168.56.20` is on **enp0s3**;
**enp0s8** has `10.0.3.15`. Interface names in old examples are placeholders.
Running it on the hypervisor host does not protect guests' separate stacks.

The hardened profile adds these restrictions to active defense:

* Initial SYNs advertising receive windows below 1024 bytes are blocked. This
  catches all six standard sequence probes before SYN-ACKs expose the kernel's
  fingerprint. `--min-syn-window N` changes the cutoff; 0 disables it. Established
  connections may still advertise zero windows. Legitimate small-window clients
  may be rejected, and scanners using ordinary SYNs can bypass this heuristic.
* Outgoing RST, echo, and ICMP port-unreachable replies are suppressed. This
  reduces closed-port/ICMP evidence but delays some legitimate connection errors.
* Conntrack-invalid incoming traffic is dropped without source-banning it by
  itself, since delayed legitimate packets can also be invalid.

Abnormal flags, selected small-window SYNs, and excess per-source SYN rates now
insert timed blocks **directly in the kernel**. This prevents replies escaping
while Python notices a packet and launches a firewall command on a fast LAN.
The sensor still detects port sweeps and incomplete handshakes.

The default SYN allowance is **20 packets/second, burst 20, per source**. Exceeding
it blocks that source for 60 seconds, including existing connections. This is
more forgiving than the guide's deliberately strict 2/second demonstration:

```bash
# Full defense, overriding only the per-source rate and initial allowance:
sudo python3 -B defender.py run --syn-rate 2 --syn-burst 2
# Reproduce hashlimit-style excess-packet drops without timed source bans:
sudo python3 -B defender.py run --profile normalize --mode filter-only --syn-rate 2 --syn-burst 2
```

Rate limiting counts packets, including retransmissions, not distinct ports.
Repeated SYNs to one port can therefore trigger the rate defense. Other sources
have independent allowances. Timed blocks expire without being extended by
blocked packets. `--allow-peer` exemptions precede these rules.

Startup logs show interface and local IPv4 addresses. For explicit `/32` peers,
a route through another interface produces `INTERFACE MISMATCH`. Every 30 seconds
logs report observed TCP, kernel drops, and kernel source-block counters. No
observed traffic prompts an interface/scope diagnostic. Inspect the nftables set
for authoritative block state even when Python has not logged an alert.

Windows defaults to the strongest implemented **stateless** filters: small-window
SYN rejection, unusual TCP/ICMP filtering, RST suppression, and normalization.
Dynamic detection, per-source limits, and timed blocks still require Linux.

This is a fingerprint-reduction experiment, not an invisible-host guarantee or
a complete impersonation of another OS. Open ports remain discoverable.

## What it changes

The following table describes `--profile normalize`, not the new full-defense default.

| Behavior | Normalization profile | Why / limit |
| --- | --- | --- |
| Outbound IPv4 TTL | Set to 64 | Removes the usual Windows TTL=128 clue; routers can decrement it afterward |
| IPv4 identification field | Set to zero only when DF=1, MF=0, fragment offset=0 | Removes ID sequencing from these packets without changing IDs needed for fragmentation/reassembly |
| Incoming TCP connection requests | Pass through | No port allowlist or connection blocking |
| TCP windows, options, timestamps, sequence numbers, flags, payload | Unchanged | Changing these blindly can break connections; these fields can still identify an OS |
| Echo replies, TCP resets, ICMP errors | Pass through | Preserves ordinary response behavior in the normalization profile |
| IPv6, loopback, forwarded/router traffic | Unchanged | This version addresses the project's remote IPv4 scanner and locally generated replies |
| Multicast and limited broadcast (255.255.255.255) | Unchanged | Preserves TTL-sensitive local discovery traffic |

TTL and ID changes are applied to packets, not just OS defaults. Consequently,
applications choosing their own IPv4 TTL also have their outgoing packets
normalized within the selected scope. This applies to outgoing requests as well
as replies: the tool does not try to guess whether a remote peer is a scanner.
For TTL-dependent experiments such as traceroute, or protocols that validate a
particular unicast TTL, use `--peer` to limit normalization to your lab scanner.

Linux installs an isolated nftables table, `ip portscan_defense`; the kernel
performs rewriting and checksum updates. Windows uses WinDivert to divert matching
outbound packets, rewrite their headers, recalculate checksums, and reinject them.
It uses the existing `windows_transport.py` DLL loader. There are no Python package
dependencies. There are no registry or Windows Firewall policy changes. Linux
sysctl changes occur only with the explicit `--syn-cookies` option.

The IPv4 ID rule follows the definition of atomic datagrams in
[RFC 6864](https://www.rfc-editor.org/rfc/rfc6864.html#section-4).
Implementation references: [nftables manual](https://netfilter.org/projects/nftables/manpage.html),
[nftables header modification](https://wiki.nftables.org/wiki-nftables/index.php/Mangling_packet_headers),
and [WinDivert API](https://reqrypt.org/windivert-doc.html).

## Linux

Install Python and nftables if missing; for Ubuntu/Debian:

```bash
sudo apt install python3 nftables iproute2
```

From the project directory, preview without root or networking changes:

```bash
python3 -B defender.py preview --platform linux
```

Start full defense on the victim; it stays active until Ctrl+C:

```bash
sudo python3 -B defender.py run
```

To affect only traffic associated with your scanner's IPv4 address:

```bash
sudo python3 -B defender.py run --peer 192.168.56.10
```

Use the actual scanner address. Omit `--peer` to cover all remote IPv4 peers.
Specify multiple `--peer` arguments to select multiple addresses or CIDR networks.

For a background process on a Linux system with systemd, from the project directory:

```bash
sudo systemd-run --unit=portscan-defense --service-type=exec /usr/bin/python3 -B "$PWD/defender.py" run
sudo journalctl -u portscan-defense -n 20
```

Stop it and remove its rules:

```bash
sudo systemctl stop portscan-defense
```

The transient systemd service runs independently of the terminal; it does not
automatically start after a reboot. Do not launch a second instance while one is
active. To inspect counters and the exact applied policy:

```bash
sudo nft list table ip portscan_defense
```

Ctrl+C, SIGTERM, and a timed exit remove this tool's table. An abrupt kill, power
failure, or application crash can leave the table installed until the namespace
or machine restarts. Once you have stopped the defender, remove that stale table:

```bash
sudo nft delete table ip portscan_defense
```

The tool refuses to overwrite an existing table with this name. It never flushes
the host's firewall or deletes other tables. If another firewall manager removes
its table, the process reports failure within about five seconds; it does not
silently overwrite the manager's new policy. It checks table presence, not every
rule's contents. Firewall ordering or later header-rewrite rules can affect the
final packet, so confirm from another machine.

WSL applies this policy to WSL's Linux networking environment, **not the Windows
host's native TCP/IP stack**. Use the Windows command to protect Windows.

### Full Linux defender in the background

Install the detector's additional interface-discovery utility if needed:

```bash
sudo apt install iproute2
ip -br address
python3 -B defender.py preview --platform linux
sudo systemd-run --unit=portscan-defense --service-type=exec /usr/bin/python3 -u -B "$PWD/defender.py" run
sudo journalctl -u portscan-defense -f
```

This defaults to `--interface any`; pass an actual interface name to restrict
the scope. The service runs as root and keeps
running after the terminal closes. Add `--peer 192.168.56.10` to target only the
lab attacker, or `--allow-peer 192.168.56.1` to exempt a trusted administration
address. Exemptions take precedence over every defender rule, including static
blocks and normalization; they do not override the host's existing firewall.
Use a separate administration address if you intend to demonstrate blocking
your scanner's access.

The active profile (included in the hardened default) enables:

* TTL/atomic-ID normalization, as above.
* Incoming NULL, SYN+FIN, SYN+RST, and Xmas-style TCP filtering.
* Incoming ICMP echo and timestamp/address-mask filtering, outgoing legacy ICMP
  reply suppression, and incoming UDP destination port 33434 filtering. Other
  ICMP errors, including fragmentation-needed and time-exceeded, remain usable
  for sources that have not been blocked.
* A per-source SYN token bucket: 20 packets/second and a burst of 20. Exceeding
  it installs a timed source block in the kernel. This counts packets, including
  retransmissions, rather than distinct destination ports.
* Alerts for 20 distinct SYN destination ports in 10 seconds, unusual TCP flags,
  or 20 incomplete answered handshakes within 10 seconds.
* A fixed 60-second source block after any of those alerts, covering inbound and
  outbound traffic on the selected interface. The kernel expires the block;
  traffic during the block does not renew it. Scanning after expiry can trigger
  another block. Blocked clients also lose access to legitimate services.

The packet monitor sees traffic before firewall drops and is scoped to the
selected interface's local IPv4 addresses, obtained at startup. Restart after
changing those addresses. It does not inspect forwarded traffic or loopback.
Incomplete-handshake tracking requires an observed matching SYN/SYN-ACK; a
matching final ACK completes it, a client reset counts as incomplete, and an
unanswered SYN or closed-port reset does not count. Handshake timeouts are
processed even while the network is idle. Alerts aggregate repeated failures;
they do not log each individual handshake.

Tracking maps and firewall sets are bounded to 8,192 entries each. Old detector
entries expire or are evicted; very large/distributed scans can exceed those
limits. Retransmissions do not extend a pending handshake's lifetime. Source
addresses are not authenticated, and shared NAT clients share limits/blocks.
Use thresholds appropriate to your lab rather than treating every alert as
proof of malicious intent.

Inspect enforcement and stop cleanly:

```bash
sudo nft list table ip portscan_defense
sudo nft list set ip portscan_defense blocked
sudo systemctl stop portscan-defense
```

Stopping removes the table, timed blocks, sockets, and decoy listeners, and
restores a SYN-cookie setting this process changed, unless another administrator
has since changed it to a different value. This transient service does not
restart at boot. SIGKILL can leave the table and optional sysctl change behind;
the existing stale-table cleanup instructions still apply. A missing table or
failed sensor causes a reported failure and cleanup, rather than silent
continued operation.

### Controls for individual Linux experiments

Append these options to `run` or `preview --platform linux`. Use
`--profile normalize` to test mechanisms individually without the automatic
default profile. Linux-specific controls are rejected on Windows.

| Option | Behavior/default |
| --- | --- |
| `--profile hardened`, `--hardened` | Default: active defense plus small-window SYN/invalid-flow filtering and reply suppression |
| `--profile normalize` | Only TTL/ID normalization plus mechanisms explicitly selected |
| `--active` | Active Linux profile without hardened small-window/RST restrictions |
| `--interface IFACE` | Interface name or `any`; defaults to `any` for Linux detection |
| `--min-syn-window N` | Reject initial SYNs below N; hardened default 1024, otherwise disabled; Linux and Windows |
| `--mode filter-only` | Disable TTL/ID changes to test filtering or detection alone |
| `--allow-peer IPv4/CIDR` | Exempt trusted addresses; repeatable |
| `--block-source IPv4/CIDR` | Static bidirectional block within `--peer` scope until stopped; repeatable |
| `--filter-flags` | Abnormal TCP flags only, independently of ICMP |
| `--block-echo` | Drop incoming echo requests |
| `--block-legacy-icmp` | Drop ICMP timestamp/address-mask requests and replies |
| `--block-udp-port PORT` | Drop incoming UDP to selected ports; repeatable; active defaults to 33434 if none supplied |
| `--syn-rate N`, `--syn-burst N` | Per-source SYN packets/second and bucket capacity; rate 0 disables; active defaults to 20/20 |
| `--connlimit N` | Concurrent tracked TCP connections per source; 0 disables (default); independent of scan detection |
| `--detect` | Add detection; combine with `--profile normalize` for alerts without blocks |
| `--auto-block` | Enable detection and timed enforcement |
| `--window N`, `--threshold N` | Distinct-port window in seconds (10) and threshold (20) |
| `--block-seconds N` | Fixed automatic-block lifetime, default 60 seconds |
| `--handshake-timeout N` | Wait for the final handshake ACK, default 10 seconds |
| `--handshake-threshold N` | Incomplete answered handshakes within the window before alert, default 20 |
| `--syn-cookies` | Temporarily enable Linux SYN cookies if disabled; applies to the network namespace, preserves existing modes 1/2 |
| `--decoy-port PORT` | Open a greeting-only TCP decoy on an unused port; repeatable, maximum 32 listeners |
| `--decoy-bind IPv4` | Local address for decoys; default 0.0.0.0 (all interfaces), independent of rule scoping |
| `--decoy-banner TEXT` | Printable greeting line, default `220 service ready`; CRLF appended |

Example detection-only experiment with no header changes:

```bash
sudo python3 -B defender.py run --profile normalize --mode filter-only --detect --interface enp0s3 --peer 192.168.56.10
```

For the guide's SYN-rate experiment use `--profile normalize --mode filter-only --syn-rate 2
--syn-burst 2 --peer 192.168.56.10`. SYN cookies and connection limits are useful
stack protections, not reliable OS concealment. Linux already provides TCP ISN
generation; the defender does not substitute its own sequence numbers.

Decoys are explicitly optional and refuse occupied ports. A decoy listens on
the requested local address, sends its greeting to in-scope peers, then closes;
it does not implement SSH/FTP/HTTP or proxy real services. A listener can appear
open to any client that can reach its bind address, even if the greeting is
withheld by peer scoping. Use `--decoy-bind` to confine it to the lab address.
Neither decoy banners nor TTL changes replace the kernel's TCP/IP fingerprint.
TCP-option stripping/reordering remains deliberately omitted, following the
manual guide's recommendation; blind rewriting can break real connections.

The limits and timeout sets follow the [nftables manual](https://netfilter.org/projects/nftables/manpage.html).
SYN-cookie behavior follows the [Linux TCP settings](https://docs.kernel.org/networking/ip-sysctl.html#tcp-syncookies-integer).

## Windows

Use native Windows Python and WinDivert 2.x. Keep `defender.py` and
`windows_transport.py` together. Use a DLL matching Python's architecture, with
the signed driver next to it, as explained in the main README.

Preview in an ordinary terminal:

```powershell
python -B defender.py preview --platform windows
```

From this project's folder, in **PowerShell as Administrator**:

```powershell
python -B defender.py run --windivert-dir '.\WinDivert-2.2.2-A\x64'
```

The `x64` example assumes 64-bit Python. To scope the change to your lab scanner:

```powershell
python -B defender.py run --peer 192.168.56.10 --windivert-dir '.\WinDivert-2.2.2-A\x64'
```

Ctrl+C stops a foreground instance. For a hidden background process, run the
following from the project directory in the same elevated PowerShell session:

```powershell
$defenderScript = (Resolve-Path '.\defender.py').Path
$defenderDriver = (Resolve-Path '.\WinDivert-2.2.2-A\x64').Path
$defenderPython = (Get-Command python.exe).Source
$defenderProcess = Start-Process -FilePath $defenderPython -WindowStyle Hidden -PassThru -ArgumentList @('-B', ('"' + $defenderScript + '"'), 'run', '--windivert-dir', ('"' + $defenderDriver + '"')) -RedirectStandardOutput "$PWD\defender.stdout.log" -RedirectStandardError "$PWD\defender.stderr.log"
$defenderProcess.Id
Get-Content '.\defender.stderr.log'
```

Check for an `ACTIVE` log entry and that the process remains running. Stop this
instance from the same session:

```powershell
Stop-Process -Id $defenderProcess.Id
```

Windows releases the process's WinDivert handles when it exits, including forced
termination. Packet rewriting and this tool's optional drops then cease; packets
already queued may be lost. The shared WinDivert driver can remain loaded for
other applications. No persistent network setting needs restoration. Run only
one defender instance at a time. This background command does not register an
automatic startup task.

## Options and optional suppression

| Option | Meaning |
| --- | --- |
| `preview --platform linux/windows` | Show exact rules or filters without applying them |
| `run` | Apply the full supported defense profile and remain running; platform detected automatically |
| `--ttl 64` | Outgoing IPv4 TTL, integer 1–255; default 64 |
| `--mode normalize` | Default: normalize TTL plus atomic IPv4 IDs |
| `--mode ttl-only` | Change only TTL for comparison experiments |
| `--mode filter-only` | Skip header rewriting; use selected filters/detection only |
| `--peer ADDRESS_OR_CIDR` | Limit to remote IPv4 peers; repeatable; default all IPv4 |
| `--duration SECONDS` | `run` only: automatically stop and clean up; zero means unlimited |
| `--log-file PATH` | `run` only: append operational logs to a file |
| `--windivert-dir PATH` | `run` only: Windows DLL/driver directory; default `WinDivert` beside the scripts |
| `--quiet-probes` | Optional: drop incoming NULL/ECN-only, SYN+FIN, SYN+RST, and Xmas-style TCP probes, plus outgoing echo replies and ICMP port-unreachable replies |
| `--suppress-rst` | Optional: suppress outgoing TCP resets, including legitimate resets |

**Use `--profile normalize` for response modification without suppression.**
The default hardened profile enables both suppression controls automatically.
They also apply if selected with `--mode ttl-only` or `--mode filter-only`.

`--quiet-probes` permits ordinary TCP handshakes, including ECN negotiation, but
prevents ping replies and some ICMP diagnostics. It preserves ICMP fragmentation-
needed and time-exceeded messages. `--suppress-rst` removes closed-port/reset
fingerprints but also turns some immediate connection failures and aborts into
timeouts. Neither option hides the SYN-ACK from an accessible open port. UDP
services still receive traffic and can reveal application information.

## Before/after demonstration

Use two separate machines or VMs; loopback is deliberately excluded.

1. On the victim, start a demo service: `python -m http.server 8080 --bind 0.0.0.0`.
   Permit it in the existing firewall if needed for your lab.
2. From the scanner, capture a baseline:

   ```bash
   sudo python3 -B scanner.py scan 192.168.56.20 -p 8080-8082 -o before.json --debug
   ```

3. On the victim, start the appropriate Linux/Windows defender command above.
4. Repeat the same scan, saving `after.json`. Also open
   `http://192.168.56.20:8080/` from the other machine to verify ordinary TCP and
   application traffic still work.
5. Inspect replies in Wireshark on the scanner, or compare packet fields in the
   JSON reports. On the same subnet expect TTL 64 and ID 0 on atomic replies.
   Fragmentable packets keep their ID. Across routers, TTL can arrive below 64.
6. Stop the defender and repeat to verify restoration. For a TTL-only comparison,
   run it again with `--mode ttl-only`.

Replace the victim address with your own. Native Windows scanner commands use
the main README's WinDivert option instead of `sudo`.

Judge the experiment by changed packet evidence, successful connections, and
changes in matching coverage/candidates—not solely by the top OS label. Linux
may already send TTL 64 and atomic ID 0, so the default can make little or no
difference there. TCP option ordering, windows, timestamp clocks, ICMP behavior,
service banners, and IPv6 can still reveal the real OS. A scanner may still
identify Windows after normalization, or report a different/ambiguous match.
No measured guarantee of reduced OS-identification accuracy is claimed.

The tool does not rewrite application banners, randomize packets per response,
or pretend to implement a complete Linux/Windows TCP stack. Windows packet
diversion adds userspace overhead; heavy traffic can exceed its processing
capacity. Existing TCP/IP security, firewall, and update practices remain useful.

## Verification

Offline regressions (no admin/root needed):

```bash
python -B -m unittest test_defender test_defender_active -v
```

Native WinDivert filter evaluation against constructed packets, without opening
driver handles or changing the network:

```powershell
$env:DEFENDER_WINDIVERT_DIR = (Resolve-Path '.\WinDivert-2.2.2-A\x64').Path
python -B -m unittest test_defender -v
Remove-Item Env:\DEFENDER_WINDIVERT_DIR
```

Live Linux checks use disposable network namespaces, an isolated veth pair,
real packets, and a real TCP echo connection:

```bash
sudo unshare --net -- env DEFENDER_LINUX_TEST=1 python3 -B -m unittest test_defender_linux -v
```

Requires `nft`, `ip`, `nsenter`, and `unshare`. The tests reject the host network
namespace. These checks cover packet rewriting/checksums, fragmentable ID
preservation, peer scoping, TCP connectivity with optional filtering, table
ownership, timed source-block expiry, trusted exemptions, real incomplete
handshake detection, SYN/connection limits, ICMP/UDP/flag drops, decoy greetings,
kernel-only blocking, independent source rate limits, same-link scanner
fingerprint suppression, all-interface detection, incorrect-interface warnings,
and default-profile background SIGTERM/sysctl cleanup. Windows tests cover native filter compilation/evaluation
and a simulated driver lifecycle; a real Windows-to-remote-host packet test is
still needed for validation on your particular Windows network setup.
