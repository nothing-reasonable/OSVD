# Victim-side response normalization

Run **`defender.py` on the PC being scanned**, using Python 3.10+. It runs on
Linux and native Windows and continuously changes selected outgoing IPv4 headers.
The default policy **does not block new TCP connections, close ports, or suppress
replies**. Existing firewall rules still apply.

This is a fingerprint-reduction experiment, not an invisible-host guarantee or
a complete impersonation of another OS. Open ports remain discoverable.

## What it changes

| Behavior | Default | Why / limit |
| --- | --- | --- |
| Outbound IPv4 TTL | Set to 64 | Removes the usual Windows TTL=128 clue; routers can decrement it afterward |
| IPv4 identification field | Set to zero only when DF=1, MF=0, fragment offset=0 | Removes ID sequencing from these packets without changing IDs needed for fragmentation/reassembly |
| Incoming TCP connection requests | Pass through | No port allowlist or connection blocking |
| TCP windows, options, timestamps, sequence numbers, flags, payload | Unchanged | Changing these blindly can break connections; these fields can still identify an OS |
| Echo replies, TCP resets, ICMP errors | Pass through | Preserves ordinary response behavior by default |
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
dependencies and no registry, sysctl, or Windows Firewall policy changes.

The IPv4 ID rule follows the definition of atomic datagrams in
[RFC 6864](https://www.rfc-editor.org/rfc/rfc6864.html#section-4).
Implementation references: [nftables manual](https://netfilter.org/projects/nftables/manpage.html),
[nftables header modification](https://wiki.nftables.org/wiki-nftables/index.php/Mangling_packet_headers),
and [WinDivert API](https://reqrypt.org/windivert-doc.html).

## Linux

Install Python and nftables if missing; for Ubuntu/Debian:

```bash
sudo apt install python3 nftables
```

From the project directory, preview without root or networking changes:

```bash
python3 -B defender.py preview --platform linux
```

Start on the victim; it stays active until Ctrl+C:

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
| `run` | Apply policy and remain running; platform detected automatically |
| `--ttl 64` | Outgoing IPv4 TTL, integer 1–255; default 64 |
| `--mode normalize` | Default: normalize TTL plus atomic IPv4 IDs |
| `--mode ttl-only` | Change only TTL for comparison experiments |
| `--peer ADDRESS_OR_CIDR` | Limit to remote IPv4 peers; repeatable; default all IPv4 |
| `--duration SECONDS` | `run` only: automatically stop and clean up; zero means unlimited |
| `--log-file PATH` | `run` only: append operational logs to a file |
| `--windivert-dir PATH` | `run` only: Windows DLL/driver directory; default `WinDivert` beside the scripts |
| `--quiet-probes` | Optional: drop incoming NULL/ECN-only, SYN+FIN, SYN+RST, and Xmas-style TCP probes, plus outgoing echo replies and ICMP port-unreachable replies |
| `--suppress-rst` | Optional: suppress outgoing TCP resets, including legitimate resets |

**Leave the last two flags off for response modification without suppression.**
They are separate experimental choices, not needed for the default behavior you
requested. They also apply if selected with `--mode ttl-only`.

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
python -B -m unittest test_defender -v
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
ownership, and cleanup. Windows tests cover native filter compilation/evaluation
and a simulated driver lifecycle; a real Windows-to-remote-host packet test is
still needed for validation on your particular Windows network setup.
