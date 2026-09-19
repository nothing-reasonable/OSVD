# Manual testing and defense demonstration

Prepared for the current `scanner.py`, the Ubuntu, Zorin, and Windows 7 VMs,
and the defense proposals in `Project_8.pdf`, pages 8–9.

These are instructions for you to execute manually. No VM, LAN, or remote scan
was performed while preparing this guide. Example IP addresses must be replaced
if your network uses a different subnet. Test devices you own or have permission
to test; use the isolated VMs for repeated and full-port experiments.

Quick navigation:

| Task | Sections |
| --- | --- |
| Set up your VirtualBox VMs | [Network](#2-network-setup-using-your-existing-three-vms), [ground truth](#3-record-ground-truth-before-scanning), [Zorin target](#4-prepare-the-zorin-target-open-closed-filtered), [Windows 7 target](#5-prepare-windows-7-without-installing-python) |
| Run and judge tests | [Baseline and captures](#6-baseline-scans-and-packet-evidence), [manual checklist](#7-thorough-manual-test-checklist) |
| Demonstrate defenses | [Defense experiments](#8-defenses-assessment-and-practical-experiments) |
| Test other networks | [Physical LAN](#9-scan-devices-on-the-same-physical-lan), [remote target](#10-remote-demonstration) |
| Finish the project | [Results](#11-evidence-and-final-results), [presentation](#12-a-practical-live-presentation-order), [cleanup](#13-local-cleanup-and-troubleshooting) |

## 1. What you can demonstrate

Do the work in this order:

1. Set up a predictable isolated network and record each target's actual OS.
2. Verify open, closed, and filtered ports on Zorin and Windows 7 from Ubuntu.
3. Swap Linux roles and test Ubuntu from Zorin.
4. Repeat scans, compare with Nmap, and inspect packet captures.
5. Enable one defense at a time and repeat the same measurements.
6. Scan a few explicitly selected devices on your physical LAN.
7. Optionally demonstrate a remote Linux target, first through a VPN and then
   directly through its public address if you need an Internet-facing comparison.

Important facts about the implementation:

| Item | What the current code actually does |
| --- | --- |
| Live scanner | Python 3.10+; Linux raw sockets with `sudo`, or native Windows with Administrator and WinDivert 2.x |
| Targets | IPv4 devices, including Windows 7 |
| Input | One IPv4 address or hostname; no CIDR, IPv6, or address-range input |
| Default database | Bundled `nmap-os-db`; no installed Nmap needed to scan |
| Fingerprint | Default full battery is 16 probes when open/closed ports are available; retries and supplemental probes can add packets |
| `watch` | Linux-only passive detection; prints alerts; does **not** install firewall rules |
| `-sV` | Optional application connections/banner collection; these complete TCP handshakes |
| Score | Fingerprint similarity, not a calibrated probability that an OS version is correct |
| Version | Can be a range or an ambiguous result; exact distribution/build identification is not guaranteed |

The PDF describes an earlier nine-probe, self-built-database design and mentions
Windows/Npcap and optional decoys. Native Windows scanning now uses WinDivert,
not Npcap; decoys remain unimplemented. See the [native Windows setup](README.md#native-windows).
Test the implementation that is present. Do not present proposed
features as implemented features.

Ubuntu and Zorin both use Linux kernels. Two distributions with similar kernels
may have indistinguishable fingerprints. A correct Linux family/range is useful;
failure to print the word “Zorin” is not by itself a defect. Record distribution
and kernel separately.

## 2. Network setup using your existing three VMs

### 2.1 Roles and addresses

Use this example isolated subnet:

| VM | Lab IPv4 | Initial role | Later role |
| --- | --- | --- | --- |
| Ubuntu | `192.168.56.10/24` | Scanner | Linux target |
| Zorin | `192.168.56.20/24` | Target and local detector | Scanner for Ubuntu |
| Windows 7 | `192.168.56.30/24` | Target | Target |

Use a host-only network shared by all three VMs. Choose a subnet that does not
overlap your physical LAN or VPN. Reserve the example addresses or place them
outside the host-only DHCP pool to prevent duplicates. The host adapter often
uses `.1`; do not assign that address to a VM.

No fourth VM is necessary. Zorin can monitor packets addressed to itself while
Ubuntu scans it. A third VM attached to an ordinary switch does not automatically
see traffic between other machines; a separate sensor needs a mirror/TAP or a
properly configured virtual switch capture path.

### 2.2 Configure the hypervisor

For **VirtualBox**:

1. Power off the VMs.
2. In VirtualBox's Network tool/Host Network Manager, create or select a host-only
   network with subnet `192.168.56.0/24`. Menu names vary by version.
3. For each VM, open **Settings → Network**. Enable an adapter, choose
   **Host-only Adapter**, and select the **same host-only network**.
4. Ensure **Cable Connected** is enabled.
5. Ubuntu/Zorin may have a second NAT adapter for installing packages. Use their
   host-only addresses for scans. Disconnect the NAT adapters during the clean
   demonstration if you want fewer moving parts.
6. Keep Windows 7 on the isolated adapter; do not expose it to the Internet for
   this exercise.

Host-only networking connects the guests and host without attaching the guests
to the physical LAN; bridged networking serves a different purpose later.
See [Oracle's networking documentation](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/networkingdetails.html).

### 2.3 Set addresses inside the guests

On Ubuntu and Zorin, open the network connection's settings, select the
host-only adapter, and set IPv4 to **Manual**. Enter the corresponding address
and subnet mask `255.255.255.0` (prefix `24`). Leave gateway and DNS empty for
this adapter. If available, select “use this connection only for resources on
its network.” Keep any Internet default route on the separate NAT adapter.

On Windows 7: **Control Panel → Network and Sharing Center → Change adapter
settings → Local Area Connection → Properties → Internet Protocol Version 4 →
Properties**. Set `.30`, mask `255.255.255.0`, and no gateway/DNS on this isolated
adapter.

Check Ubuntu/Zorin:

```bash
ip -br address
ip route
```

On Ubuntu:

```bash
ip route get 192.168.56.20
ip route get 192.168.56.30
ping -c 3 192.168.56.20
```

The route should show the lab interface and `src 192.168.56.10`. Record the
interface name; it might be `enp0s3`, `enp0s8`, or `ens33`. Do not assume `eth0`.

On Windows 7:

```cmd
ipconfig /all
route print
```

Ping failure alone is inconclusive: a target firewall may block ICMP while
allowing TCP. If all TCP probes also fail, check addresses, adapter attachment,
and route before changing scanner settings.

### 2.4 Prepare files and tools

Copy `scanner.py`, `nmap-os-db`, and `NMAP-DATABASE-LICENSE.txt` into the same
folder on **both Linux VMs**, using a shared folder or your usual file-transfer
method. Include the test files only if you want the optional regression checks.
For these examples, put them in `~/osfp-project`.

On both Linux VMs while package access is available:

```bash
sudo apt update
sudo apt install python3 iptables tcpdump nmap curl
cd ~/osfp-project
python3 --version
python3 -B scanner.py scan --help
python3 -B scanner.py watch --help
mkdir -p results lab-web
sha256sum scanner.py nmap-os-db > results/software-hashes.txt
```

Use Python 3.10 or newer. Nmap is an independent comparison tool, not a dependency
of your scanner. Run all scanner commands from this project folder unless shown
otherwise. Output directories must exist. Use a new output name for each run;
an existing JSON file is overwritten.

Take a VM snapshot before configuring the test firewall. Make firewall changes
from the VM console so you can recover without depending on the scanned network.

## 3. Record ground truth before scanning

On **each Linux target**:

```bash
date -Is
cat /etc/os-release
uname -r
uname -m
ip -br address
ss -ltn
ss -lun
sudo ufw status verbose
sudo iptables -S
sudo nft list ruleset
```

If `ufw` or `nft` is not installed, record that and continue with the available
firewall tools. Save the distribution, kernel, IP, active listeners, and initial
firewall state in a text file or screenshots. Do not change unrelated rules.

On **Windows 7**, use an elevated Command Prompt:

```cmd
ver
wmic os get Caption,Version,BuildNumber,OSArchitecture,ServicePackMajorVersion
ipconfig
netstat -ano -p tcp
netsh advfirewall show allprofiles
```

Also capture `winver`. These work on typical Windows 7 installations. The README's
`Get-CimInstance`, `Get-NetTCPConnection`, `New-NetFirewallRule`, and `::new()`
examples require newer components and should not be assumed available there.

Keep the actual OS labels fixed throughout testing. Do not relabel a machine
to match a prediction.

## 4. Prepare the Zorin target: open, closed, filtered

### 4.1 Start a harmless service

On **Zorin**, from the project folder, in a terminal left open:

```bash
python3 -m http.server 8080 --bind 192.168.56.20 --directory lab-web
```

The directory should be empty or contain only a test page. Binding to the lab
address keeps this service on the intended interface.

In another Zorin terminal:

```bash
ss -ltn
ss -lun
```

Verify TCP 8080 is listening, TCP 8081/8082/8083 are not, and UDP 33434 has no
listener. Choose another unused port and update the commands if necessary.

### 4.2 Create a scoped lab firewall

These temporary rules apply only to Ubuntu's source IP on Zorin's lab interface.
They create a baseline plus an initially empty defense chain. Use them on the
disposable lab VM; avoid firewall-manager reloads while the experiment is active.
An independent nftables base chain or security agent can still drop traffic, so
verify the result on the wire instead of assuming these rules override everything.

On **Zorin**, substitute the actual interface:

```bash
LAB_IF=enp0s8
SCANNER_IP=192.168.56.10
sudo iptables-save > results/firewall-before.rules
sudo iptables -N OSFP_LAB
sudo iptables -N OSFP_DEF
sudo iptables -A OSFP_LAB -j OSFP_DEF
sudo iptables -A OSFP_LAB -p tcp --dport 8082 -j DROP
sudo iptables -A OSFP_LAB -p tcp -m multiport --dports 8080,8081,8083 -j ACCEPT
sudo iptables -A OSFP_LAB -p udp --dport 33434 -j ACCEPT
sudo iptables -A OSFP_LAB -p icmp -j ACCEPT
sudo iptables -I INPUT 1 -i "$LAB_IF" -s "$SCANNER_IP" -j OSFP_LAB
sudo iptables -L OSFP_LAB -n -v --line-numbers
```

Create the chains once. If a chain already exists, inspect it rather than rerun
the setup and accidentally add duplicate rules. Variables belong to the terminal
where you set them; set them again if you open a new terminal.

Expected baseline:

| Port/protocol | Actual target condition | Scanner should observe |
| --- | --- | --- |
| TCP 8080 | Listening; allowed | `open` from SYN-ACK |
| TCP 8081 | No listener; allowed | `closed` from RST |
| TCP 8082 | No listener; deliberately dropped | `filtered`/no response |
| TCP 8083 | No listener; allowed; used later | `closed` if scanned |
| UDP 33434 | No listener; allowed | ICMP port-unreachable if the stack/policy permits |

Allowing an unused TCP port does **not** open it. It lets the kernel receive a
probe and return a reset. This distinction is central to the experiment.

On **Ubuntu**, verify the service with one intentional application request:

```bash
curl --max-time 3 http://192.168.56.20:8080/
```

The server should log this request. Finish this check before capturing the
scanner's half-open behavior.

## 5. Prepare Windows 7 without installing Python

### 5.1 Create a TCP listener

On **Windows 7**, open PowerShell and paste:

```powershell
$labAddress = [System.Net.IPAddress]::Parse('192.168.56.30')
$labListener = New-Object System.Net.Sockets.TcpListener -ArgumentList @($labAddress, 8080)
$labListener.Start()
Write-Host 'Listening on TCP 8080; Ctrl+C to stop.'
try {
    while ($true) {
        if ($labListener.Pending()) {
            $labClient = $labListener.AcceptTcpClient()
            Write-Host ('Completed connection from ' + $labClient.Client.RemoteEndPoint)
            $labClient.Close()
        } else {
            Start-Sleep -Milliseconds 100
        }
    }
} finally {
    $labListener.Stop()
}
```

Leave it running. This is a plain TCP listener, not HTTP: a successful `curl`
page is not expected. It prints only after an accepted connection. Half-open
SYN probing should not produce those completed-connection messages.

In another Windows Command Prompt:

```cmd
netstat -ano -p tcp | findstr ":808"
netstat -ano -p udp | findstr ":33434"
```

Check 8080 is LISTENING, 8081 and 8082 are not, and UDP 33434 is unused.

### 5.2 Allow only the scanner's lab probes

In an **Administrator Command Prompt on Windows 7**:

```cmd
netsh advfirewall export "%USERPROFILE%\Desktop\osfp-before.wfw"
netsh advfirewall firewall add rule name="OSFP Lab TCP" dir=in action=allow protocol=TCP localport=8080,8081 remoteip=192.168.56.10 profile=any
netsh advfirewall firewall add rule name="OSFP Lab UDP" dir=in action=allow protocol=UDP localport=33434 remoteip=192.168.56.10 profile=any
netsh advfirewall firewall add rule name="OSFP Lab ICMP" dir=in action=allow protocol=icmpv4 remoteip=192.168.56.10 profile=any
netsh advfirewall firewall add rule name="OSFP Lab Filtered" dir=in action=block protocol=TCP localport=8082 remoteip=192.168.56.10 profile=any
```

Keep Windows Firewall enabled. Explicit block rules and other security products
can still suppress responses. Check the active profile and existing rules if
8081 remains filtered. A stateful Windows filter may reject unusual probes even
after a port allow rule; record the resulting evidence gaps.

The source-restricted `netsh advfirewall` approach is documented by
[Microsoft](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/netsh-advfirewall-firewall-control-firewall-behavior).

### 5.3 Windows unused ports may remain filtered: stealth mode

A port allow rule does not guarantee a closed-port reset on Windows. Windows
Filtering Platform's stealth mode can suppress TCP RST and ICMP port-unreachable
messages when no application is listening. Thus 8080 open with 8081 filtered can
be a valid firewall-on result rather than a scanner bug. See
[Microsoft's stealth-mode explanation](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/disable-stealth-mode).

If both the scanner and Nmap report 8081 filtered, record that as the protected
baseline. For a short unprotected comparison, first verify Windows 7 has only
its host-only adapter connected, with no bridged/NAT Internet path. Keep the
8080 listener running and use the VM console. In Administrator Command Prompt:

```cmd
netsh advfirewall show currentprofile
netsh advfirewall set currentprofile state off
```

Immediately scan from Ubuntu with Nmap and the scanner, saving new reports:

```bash
sudo nmap -n -Pn -sS -p 8080-8082 --reason 192.168.56.30
sudo python3 -B scanner.py scan 192.168.56.30 -p 8080-8082 --open-port 8080 --closed-port 8081 --debug -o results/win7-firewall-off.json
```

With no listeners on 8081/8082, both should now be closed if Windows Firewall
was suppressing responses. The 8082 block rule is inactive while its firewall
profile is off, so do not expect the original three-state baseline in this test.
Other filtering software can still affect the result. Restore immediately:

```cmd
netsh advfirewall set currentprofile state on
netsh advfirewall show currentprofile
```

Repeat the protected scan and retain both conditions as a defense comparison.
Do not stop the firewall service. This is an isolated VM experiment, not a
recommendation to disable an endpoint firewall in normal use. Keep Zorin as the
controlled simultaneous open/closed/filtered demonstration; Windows can provide
the unprotected-versus-protected fingerprint comparison.

## 6. Baseline scans and packet evidence

### 6.1 Capture traffic separately from other checks

On **Ubuntu**, in a second terminal, set the actual lab interface and start:

```bash
LAB_IF=enp0s8
sudo tcpdump -i "$LAB_IF" -nn -s 0 -U -w results/zorin-baseline-01.pcap 'host 192.168.56.20 and (tcp or udp or icmp)'
```

Leave it running, execute exactly one scan below in another terminal, then stop
tcpdump with Ctrl+C. Capture Windows with `.30` and a new filename. Use separate
captures for your scanner, Nmap, and each defense condition.

### 6.2 Run the actual scanner

On **Ubuntu**:

```bash
sudo python3 -B scanner.py scan 192.168.56.20 -p 8080-8082 --open-port 8080 --closed-port 8081 --udp-port 33434 --timeout 2 --retries 1 --os-tries 3 --debug -o results/zorin-baseline-01.json 2>&1 | tee results/zorin-baseline-01.txt
```

Then Windows:

```bash
sudo python3 -B scanner.py scan 192.168.56.30 -p 8080-8082 --open-port 8080 --closed-port 8081 --udp-port 33434 --timeout 2 --retries 1 --os-tries 3 --debug -o results/win7-baseline-01.json 2>&1 | tee results/win7-baseline-01.txt
```

Verify the expected three port states before judging OS accuracy. If they are
wrong, fix the service, route, or firewall and save a new capture. A completed
scan with `UNKNOWN` is different from an execution error.

`--os-tries 3` allows up to three rounds and may stop early. It is not three
independent test runs. For repeatability, run each baseline command five times,
changing `01` to `02` through `05`. Allow about 10 seconds between runs and keep
the VM load, rules, and port list fixed. A full three-target baseline is 15 runs.

Inspect a saved report without more network traffic:

```bash
python3 -B scanner.py match results/zorin-baseline-01.json --debug
python3 -m json.tool results/zorin-baseline-01.json
```

Look at `result.status`, `result.family`, `result.candidate`, the top ranked
labels, similarity and coverage, `syn_replies`, `sequence_timing_complete`,
`unstable_fields`, `udp_closed_confirmed`, warnings, and `elapsed_seconds`.
JSON statuses are lowercase; the terminal prints them uppercase.

| Result | Interpretation |
| --- | --- |
| CANDIDATE | One acceptable label remains; that label may itself be a version range |
| AMBIGUOUS | Several labels or incomplete sequence evidence prevent a unique version; a family can still be usable |
| UNKNOWN | Insufficient evidence or match quality; a displayed diagnostic ranking is not an identification |

Do not select the first diagnostic row and call it a successful detection when
the decision is UNKNOWN. Missing evidence can leave similarity high while
coverage falls; a defense need not reduce the printed similarity score.

### 6.3 Test Ubuntu by swapping Linux roles

1. On Ubuntu, start the same HTTP server, binding to `192.168.56.10`.
2. Configure the section 4 lab chains on Ubuntu with **Ubuntu's** lab interface
   and `SCANNER_IP=192.168.56.20`.
3. On Zorin, verify `ip route get 192.168.56.10` uses source `.20`.
4. Run the baseline scan from Zorin with target `.10` and filenames
   `results/ubuntu-baseline-01.json`/`.txt`.
5. Repeat five times. Preserve Zorin's results separately or copy them to your
   final evidence folder.

Do not use Ubuntu's loopback address to stand in for this test. A cross-VM scan
provides a more representative network path.

### 6.4 Compare with Nmap

On the same scanner, against the same target, under the same firewall condition:

```bash
sudo nmap -n -Pn -sS -O --osscan-guess --max-os-tries 3 -p 8080-8082 --reason -oA results/zorin-nmap-01 192.168.56.20
```

Repeat for Windows and Ubuntu with the appropriate scanner and filenames.
`-Pn` prevents failed ping discovery from excluding the target. `-oA` saves
normal, XML, and grepable output. Nmap may choose different UDP tests or timing,
so identical port lists do not mean identical packet batteries.

The target's locally recorded OS is ground truth. Nmap is a reference comparison,
and both tools use the Nmap fingerprint data family, possibly different database
versions. Agreement is not independent proof. Record `nmap --version`; keep the
bundled database hash. Open and closed TCP ports improve OS detection, as Nmap's
[OS detection documentation](https://nmap.org/book/man-os-detection.html) explains.

### 6.5 Check the half-open claim

Open the PCAP in Wireshark on your host computer. Filter:

```text
ip.addr == 192.168.56.20 && tcp.port == 8080
```

Inspect an ordinary discovery exchange:

```text
scanner -> target : SYN
target -> scanner : SYN, ACK
scanner -> target : RST (possibly RST, ACK)
```

There should be no normal handshake-completing ACK followed by an application
request for this exchange. The fingerprint battery intentionally contains other
flag combinations, including ACK probes; distinguish those by their connection
tuple and sequence numbers instead of treating every ACK as a completed session.

For closed 8081, expect RST in response to discovery SYN. For dropped 8082,
expect outgoing attempts without corresponding target replies. The capture plus
the target rule counter establishes intentional filtering; silence alone could
also be packet loss or a disconnected machine.

Useful Wireshark display filters:

```text
tcp.flags.syn == 1 && tcp.flags.ack == 0
tcp.flags.reset == 1
tcp.flags == 0x000
tcp.flags.syn == 1 && tcp.flags.fin == 1
icmp.type == 3 && icmp.code == 3
```

The Windows listener should show no completed connection for the basic scan.
For a Linux accept-log check, stop the HTTP server, then run this on Zorin:

```bash
python3 -u - <<'PY'
import socket
with socket.socket() as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('192.168.56.20', 8080))
    server.listen()
    print('Accept-log listener ready')
    while True:
        connection, peer = server.accept()
        print('ACCEPT', peer, flush=True)
        connection.close()
PY
```

First verify the log works with an intentional connection from Ubuntu:

```bash
python3 -c "import socket; socket.create_connection(('192.168.56.20',8080),3).close()"
```

It should print ACCEPT. Then run the scanner **without `-sV`** and check for no
additional ACCEPT entries. Stop this listener and restore the HTTP server after
the test. “No HTTP request log” alone does not prove no connection completed;
the accept log and packet trace are the better evidence. Half-open is detectable
by packet monitoring even when the application sees no accepted connection.

### 6.6 Check optional service detection separately

With Zorin's HTTP server restored:

```bash
sudo python3 -B scanner.py scan 192.168.56.20 -p 8080-8082 -sV --version-max-ports 1 --debug -o results/zorin-banners.json
```

Expect an HTTP connection/request and Python HTTP-server information, not proof
of the Zorin release. The plain Windows listener may yield no banner; that is
correct. A product version such as Python or IIS is not an OS version. Banners
are supplemental evidence and may disagree with the network fingerprint.

## 7. Thorough manual test checklist

Use the baseline command with a new output filename unless a row gives a changed
command. Restore the baseline before the next row. Perform state-changing tests
on Zorin first; repeat the relevant cases on the other VMs if time permits.

| ID | Action | Expected result / what to record |
| --- | --- | --- |
| T01 | Five baseline scans per target | Correct controlled port states; record family, range, variation, warnings, runtime |
| T02 | Nmap comparison per target | Agreement/disagreement against locally recorded ground truth |
| T03 | Stop the 8080 service; scan 8080–8082 | 8080 becomes closed; no discovered open port; conservative OS outcome |
| T04 | Restore service; scan only `-p 8080`, without preferred-port flags | No discovered closed port; warn/abstain instead of inventing evidence |
| T05 | Keep service; scan only `-p 8081`, without preferred-port flags | No discovered open port; conservative OS outcome |
| T06 | Scan only `-p 8082`, without preferred-port flags | Filtered/no reply; no confident OS identification |
| T07 | Scan 8080–8082 with `--open-port 8081 --closed-port 8080` | Warn about invalid preferences; use independently verified alternatives |
| T08 | Start the HTTP service on 8083 instead; scan `-p 8080-8083` with no preferred ports | 8083 open, 8080/8081 closed, 8082 filtered; automatic selection works |
| T09 | Disconnect target's virtual cable and scan its known IP | Error or no replies; no confident identification; reconnect afterward |
| T10 | `-p 8080,8080-8082` | Three unique discovery ports, no duplicated port records |
| T11 | Invalid `-p 0`, `-p 65536`, `-p 8082-8080`, or `--timeout 0` | Clear input error before live probing |
| T12 | Target `192.168.56.0/24` or `::1` | Clear unsupported-input error; tool is single-target IPv4 |
| T13 | Basic scan without `sudo` on a normal unprivileged account | Permission failure explaining raw-socket requirement; capabilities can change this |
| T14 | Save then `match` the same JSON with the same database | Same underlying decision/ranking without network traffic |
| T15 | Interrupt a scan using Ctrl+C | Clean stop; do not mistake an old file for a newly completed report |
| T16 | Basic scan vs `-sV` | Basic half-open evidence vs intentional application connections |
| T17 | Defenses in section 8 | Before/after evidence, counters/alerts, availability and restoration |
| T18 | LAN and remote paths | Record path restrictions and confidence/coverage changes |

Preferred ports are added to the discovery set, so omitting those flags in
T04–T06 matters. During T08 stop the old server, start port 8083, test, then
restore 8080. Do not change more than one condition at once.

Optional wider discovery, only on your isolated VM:

```bash
sudo python3 -B scanner.py scan 192.168.56.20 -p 1-1024,8080-8083 --parallel 8 --delay 0.05 --jitter 0.02 --debug -o results/zorin-wide.json
```

For a full-range parser/discovery exercise, substitute `-p 1-65535`, use one
round and bounded retries, and allow a long run. At 50 ms initial spacing alone,
65,535 ports take at least about 55 minutes, before jitter, timeouts, and OS
probes. This is optional and unnecessary for the short presentation.

`--delay`, `--jitter`, and `--parallel` govern discovery. They do not uniformly
slow the fixed-timing fingerprint battery or all retransmissions.

Optional network-quality test on the **Zorin target's lab interface**:

```bash
sudo tc qdisc show dev "$LAB_IF"
sudo tc qdisc add dev "$LAB_IF" root netem delay 100ms
```

Run three baseline scans under this fixed egress delay, save separately, then:

```bash
sudo tc qdisc del dev "$LAB_IF" root
sudo tc qdisc add dev "$LAB_IF" root netem loss 2%
```

Run three more, then remove the test qdisc:

```bash
sudo tc qdisc del dev "$LAB_IF" root
```

This changes target egress traffic, not both directions. Do this only where no
custom root qdisc is configured; if `add` reports an existing qdisc, skip rather
than replace someone else's configuration. Verify the original qdisc state
afterward. Loss can reduce sequence completeness; a conservative result is
preferable to a confidently wrong version. Use the VM console for recovery.

## 8. Defenses: assessment and practical experiments

### 8.1 Which report proposals are viable?

| PDF proposal | Assessment for this project |
| --- | --- |
| Unusual TCP flag detection | Good demonstration; already present in `watch` |
| Distinct destination-port detection | Good demonstration; already present in `watch` |
| Log incomplete handshakes | Useful with stateful flow tracking; current `watch` does not implement this correlation; use packet/accept-log evidence here |
| TTL normalization | Viable partial modification; other identifying fields remain; setting Linux's usual 64 to 64 may change nothing |
| Strip/reorder TCP options | Technically possible but requires a carefully engineered middlebox; can break timestamps, scaling, checksums, and connectivity; omit from this coursework demo |
| Limit echo/UDP-derived evidence | Viable partial defense; test the actual probes the code sends |
| Disable timestamp/address-mask ICMP replies | Does not directly target this scanner: it sends echo and a UDP probe, not ICMP timestamp/address-mask requests |
| SYN cookies and ISN randomization | Useful normal stack protections, not reliable OS concealment; do not generate a SYN flood to activate them |
| Decoy services/banners | Can mislead service evidence or remove obvious closed ports, but application banners alone do not replace the kernel's TCP/IP behavior |
| `hashlimit` | Viable SYN packet-rate control; count is not distinct destination ports |
| `connlimit` | Counts concurrent tracked connections, not distinct probed ports; poor primary fit for rapidly reset half-open scans |
| Temporary source blocking after detection | Effective lab demonstration; requires connecting detection to a firewall action; not built into `watch` |

SYN cookies normally engage under SYN-backlog pressure rather than hiding the
stack during a small scan; TCP timestamps are also distinct from ICMP timestamp
requests. See the [Linux kernel's TCP settings](https://docs.kernel.org/networking/ip-sysctl.html).

Use **Zorin as the defense target**, Ubuntu as scanner. Restore the HTTP service
on 8080 and the section 4 baseline rules first. Each experiment below starts
from that baseline. Re-run the same baseline scan with a distinct JSON/TXT/PCAP
filename, then test HTTP availability. Do not combine defenses until you have
measured them separately.

### 8.2 D1: Detect scans using your own tool

On **Zorin**, in its project folder:

```bash
LAB_IF=enp0s8
sudo python3 -u -B scanner.py watch --interface "$LAB_IF" --window 10 --threshold 20 --duration 180 2>&1 | tee results/d1-watch.txt
```

From **Ubuntu**, within those three minutes:

```bash
sudo python3 -B scanner.py scan 192.168.56.20 -p 8000-8030,8080-8082 --parallel 8 --delay 0.05 --jitter 0.01 --os-tries 1 --retries 0 --debug -o results/d1-sweep.json
```

Expected: a `distinct-port SYN sweep` alert with source `.10` and target `.20`.
The 34 distinct discovery ports are enough to cross the threshold within ten
seconds. The other destination ports need not be open for the sensor to see SYNs.
Also look for `unusual TCP flags` alerts from the fingerprint phase. Alert lines
contain time, source, target, reason, and distinct-port count.

Repeat a normal three-port baseline. At threshold 20 it may produce unusual-flag
alerts without a sweep alert. Repeated probes to one port do not count as many
distinct ports. Threshold 3 is useful to illustrate the rule during a tiny demo,
but is easier to trigger with legitimate traffic; label it as a demonstration
setting.

For a benign control, restart `watch` for a clean detector state, make a few
ordinary `curl` requests to 8080 only, and verify no sweep/unusual-flag alert for
that traffic. No alert from the built-in rules does not prove traffic is benign.

Success evidence: an alert and matching packet trace. Scanning should still
work because detection alone installs no block. The sensor must be on the
target's Ethernet lab interface; this implementation expects Ethernet frames.

### 8.3 D2: Detect, then manually block the source

After recording a D1 alert, on **Zorin**:

```bash
sudo iptables -I OSFP_DEF 1 -j DROP
sudo iptables -L OSFP_DEF -n -v
```

`OSFP_DEF` is reached only through the interface/source-scoped lab chain. This
blocks the lab scanner's traffic without making a machine-wide DROP rule.

From **Ubuntu**, repeat the baseline scan as `results/d2-blocked.json`. Expect
filtered/no-reply ports and insufficient OS evidence. Run:

```bash
curl --max-time 3 http://192.168.56.20:8080/
```

It should fail from Ubuntu while the listener still exists on Zorin. Check that
the DROP counter increases. Then, on Zorin:

```bash
sudo iptables -D OSFP_DEF -j DROP
```

Repeat the baseline and curl; both should recover. Report this honestly as
**manual response after detection**, not automatic blocking. It is a strong,
simple live demonstration.

For the equivalent **Windows 7** source block, use Administrator Command Prompt:

```cmd
netsh advfirewall firewall add rule name="OSFP Lab Block Source" dir=in action=block remoteip=192.168.56.10 profile=any
```

Scan `.30`, save the blocked result, then restore with:

```cmd
netsh advfirewall firewall delete rule name="OSFP Lab Block Source"
```

### 8.4 D3: Filter abnormal TCP flags while keeping ordinary HTTP

On **Zorin**, confirm `OSFP_DEF` has no leftover D2 rule, then:

```bash
sudo iptables -A OSFP_DEF -p tcp --tcp-flags ALL NONE -j DROP
sudo iptables -A OSFP_DEF -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
sudo iptables -A OSFP_DEF -p tcp --tcp-flags FIN,PSH,URG FIN,PSH,URG -j DROP
```

Repeat baseline as `d3-flags.json`, check counters, and make a normal curl
request. TCP 8080 should remain reachable; some fingerprint replies may disappear.
Some kernels already ignore these probes, so **no change** is a legitimate result.
Normal SYN/ACK behavior can still identify a family. Do not promise that filtering
a few flag patterns hides the OS.

Restore only the custom defense chain:

```bash
sudo iptables -F OSFP_DEF
```

This command empties your lab defense chain, not INPUT or the machine's firewall.
Do not use an unqualified `iptables -F`.

### 8.5 D4: Reduce ICMP/UDP fingerprint evidence

On **Zorin**:

```bash
sudo iptables -A OSFP_DEF -p icmp --icmp-type echo-request -j DROP
sudo iptables -A OSFP_DEF -p udp --dport 33434 -j DROP
```

Repeat baseline as `d4-icmp-udp.json`; verify HTTP still works. The echo replies
and U1 port-unreachable should now be absent. Inspect `udp_closed_confirmed`,
fingerprint fields, coverage, and warnings. TCP evidence can still support an
OS family. Silence must not be treated as proof that UDP 33434 is closed.

This targets only the lab source and tested probe types. Do not globally block
all ICMP as a general recommendation; other ICMP errors support normal networking.

Restore:

```bash
sudo iptables -F OSFP_DEF
```

### 8.6 D5: Demonstrate TTL modification, with limited claims

On Zorin a baseline TTL may already be 64. To make the modification observable,
temporarily set replies **to the scanner only** to 128:

```bash
SCANNER_IP=192.168.56.10
LAB_IF=enp0s8
sudo iptables -t mangle -I POSTROUTING 1 -o "$LAB_IF" -d "$SCANNER_IP" -j TTL --ttl-set 128
```

Capture `d5-ttl.pcap`, repeat baseline as `d5-ttl.json`, and expand the IPv4 header
of target replies in Wireshark. Check the rule counter:

```bash
sudo iptables -t mangle -L POSTROUTING -n -v
```

This is a controlled host-egress rewrite, not a complete gateway normalization
deployment. It changes one family of evidence, not TCP option order, windows,
ISNs, or every ICMP quote. The output may remain Linux, become ambiguous, or
change incorrectly; measure it. Do not describe TTL alone as proof of an OS.

Restore the exact rule:

```bash
sudo iptables -t mangle -D POSTROUTING -o "$LAB_IF" -d "$SCANNER_IP" -j TTL --ttl-set 128
```

If your kernel/backend lacks the TTL target, record the experiment as unavailable
and continue. Netfilter describes TTL rewriting in its
[TTL target documentation](https://www.netfilter.org/documentation/HOWTO/netfilter-extensions-HOWTO-4.html).

### 8.7 D6: SYN packet-rate limiting

On **Zorin**, with `OSFP_DEF` empty:

```bash
sudo iptables -A OSFP_DEF -p tcp --syn -m hashlimit --hashlimit-above 2/second --hashlimit-burst 2 --hashlimit-mode srcip --hashlimit-name osfp_syn -j DROP
```

Run the same D1 sweep command, saving `d6-rate.json`. Look at dropped-packet
counters and compare with the unthrottled D1 run. Also test curl after a quiet
interval, and during a scan if you want to demonstrate the availability tradeoff.

The deliberately small lab limit can suppress fingerprint SYNs and legitimate
new connections. The result depends on timing and retries; some ports can appear
filtered because a probe was rate-dropped. A drop counter is stronger evidence
than expecting a particular final score. This is a SYN packet-rate experiment,
not a unique-port detector and not a SYN-flood test.

Restore:

```bash
sudo iptables -F OSFP_DEF
```

The distinction between rate matching (`hashlimit`) and concurrent connection
matching (`connlimit`) is described in the
[iptables extension manual](https://man7.org/linux/man-pages/man8/iptables-extensions.8.html).

### 8.8 Optional D7: A temporary automatic block for the bonus demo

The scanner does not contain automatic firewall integration. This optional
**separate lab adapter** connects its existing JSON alerts to a timed IP set.
It reacts only to the exact Ubuntu→Zorin pair, preventing accidental blocking
of other addresses. Skip it if D1 plus D2 is enough for your presentation.

On **Zorin**, install the extra tool and attach a set to the existing defense
chain, with other defense experiments cleared:

```bash
sudo apt install ipset
sudo ipset create osfp_block hash:ip timeout 60
sudo iptables -A OSFP_DEF -m set --match-set osfp_block src -j DROP
```

Create `lab_autoblock.py` in the Zorin project folder with this content:

```python
import json
import subprocess
import sys

for line in sys.stdin:
    try:
        alert = json.loads(line)
    except ValueError:
        continue  # The watcher also prints a startup line.
    if not isinstance(alert, dict):
        continue
    if (alert.get('source') == '192.168.56.10'
            and alert.get('target') == '192.168.56.20'
            and alert.get('reason') == 'distinct-port SYN sweep'):
        subprocess.run(
            ['ipset', 'add', 'osfp_block', '192.168.56.10',
             'timeout', '60', '-exist'], check=True)
        print('Blocked lab scanner for 60 seconds from this alert', flush=True)
```

Change both fixed addresses if your lab differs. Run from the project directory:

```bash
sudo -v
sudo python3 -u -B scanner.py watch --interface "$LAB_IF" --window 10 --threshold 20 --duration 180 | tee results/d7-alerts.txt | sudo python3 -u lab_autoblock.py
```

From Ubuntu, run the D1 sweep. On Zorin, verify:

```bash
sudo ipset list osfp_block
sudo iptables -L OSFP_DEF -n -v
```

Expect a set entry with a decreasing timeout and DROP counter increases. Then
run a short baseline scan/curl during the block. Some early ports in the triggering
scan may already have answered; use a separate follow-up scan to demonstrate
the block. Stop scanning for more than 60 seconds after the last triggering
alert, then verify a single curl works again. Further sweep alerts renew the
timeout. A host packet sensor can still see packets that INPUT drops.

For cleanup, stop the pipeline with Ctrl+C, then:

```bash
sudo iptables -D OSFP_DEF -m set --match-set osfp_block src -j DROP
sudo ipset destroy osfp_block
```

This is a small lab demonstration, not a production IPS: spoofed sources,
multiple clients behind NAT, false positives, and threshold tuning need separate
engineering. IP set timeouts provide automatic expiry even if the adapter exits;
the [ipset manual](https://ipset.netfilter.org/ipset.man.html) documents them.

### 8.9 Compare defense effectiveness correctly

Use a table with one row per defense and at least three repeated measurements
for conclusions about fingerprint changes:

| Condition | 8080 accessible? | Port states | OS decision/family | Coverage | Replies missing | Alert/counter evidence | Recovery verified? |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Baseline | | | | | | | |
| Detection only | | | | | | | |
| Source block | | | | | | | |
| Abnormal flags | | | | | | | |
| Echo/U1 filtered | | | | | | | |
| TTL rewrite | | | | | | | |
| SYN rate limit | | | | | | | |

Detection success, fingerprint suppression, and preserving legitimate service
are three different outcomes. Record all three. A source block can be effective
while also denying legitimate access from the blocked source. A firewall-induced
wrong OS guess is a scanner robustness failure as well as a distortion effect;
it should not be celebrated as accurate detection.

## 9. Scan devices on the same physical LAN

### 9.1 Put the Linux scanner on the LAN

In VirtualBox, power off **Ubuntu**. Keep its host-only adapter for lab access.
Change/add a second adapter to **Bridged Adapter**, selecting the host's actual
Ethernet or Wi-Fi adapter. Start Ubuntu and obtain an address through the LAN's
DHCP server. Do not bridge Windows 7 for this test.

Inside Ubuntu:

```bash
ip -br address
ip route
```

For example, Ubuntu might now have lab `.56.10` and physical LAN `192.168.1.50`.
The LAN devices might be `192.168.1.60` and `192.168.1.70`. These are examples,
not devices already discovered in your network.

If bridging over Wi-Fi does not work, try Ethernet or a Linux machine directly
on that LAN. Guest Wi-Fi/client isolation can intentionally prevent peer access.
You can test routed access through a NAT adapter, but record that as a NAT path
and check the source address seen by the target; it is not the same experiment.

### 9.2 Select a small, known inventory

Find addresses using the device's own network settings or your router's client/
DHCP page. Record permission, IP, device type, and ground-truth OS where available.
`ip neigh` shows recently learned neighbors; it is not a complete host inventory.
Use a laptop/desktop you control for the first comparison. Phones and embedded
devices frequently expose no suitable open/closed port pair.

On an owned Linux LAN target, you can repeat the service and lab rules from
section 4, substituting its actual interface/address and Ubuntu's **LAN** source
IP. Do not use `192.168.56.10` in its firewall if packets arrive from `.1.50`.
For a device you cannot configure, leave its services and firewall as they are
and treat missing prerequisites as a result.

### 9.3 Scan one selected device

From Ubuntu:

```bash
ip route get 192.168.1.60
sudo python3 -B scanner.py scan 192.168.1.60 -p 22,80,443,445,3389,8080,8081 --parallel 2 --delay 0.2 --jitter 0.05 --timeout 3 --retries 1 --os-tries 1 --debug -o results/lan-device1.json
```

Use ports appropriate to the selected device and scope. Start with a few known
service ports and an unused port; do not force `--closed-port 8081` unless its
state is actually confirmed. The tool will still send its OS fingerprint probes,
including ICMP/UDP; it has no discovery-only option. Small discovery settings do
not rate-limit every part of fingerprinting.

Repeat manually for the next authorized IP with a new output filename. Do not
pass `192.168.1.0/24`; the scanner does not accept it. Do not run the VM sweep/
full-port experiments against every phone, printer, router, or IoT device.

For an unknown physical device:

* All filtered: could be firewalling, isolation, loss, sleep, or wrong address.
* Closed ports but no open port: reachable stack, insufficient fingerprint input.
* Open services but no closed response: a firewall may hide unused ports.
* Router/gateway result: may describe that device's stack, not devices behind it.
* No independently recorded OS: report “unverified candidate,” not an accuracy win.

To demonstrate a LAN defense, repeat D2 on a configurable owned Linux endpoint,
with the correct LAN source/interface restrictions. For a router-managed policy,
traffic between peers may not cross the router firewall; same-LAN isolation needs
endpoint rules, switch/AP isolation, or a routed VLAN boundary. Check the path.

## 10. Remote demonstration

### 10.1 Choose what “remote” means in your presentation

Two distinct demonstrations are possible:

| Path | What it establishes |
| --- | --- |
| Internet transport carrying a WireGuard tunnel to your own remote Linux host | Remote routed fingerprinting of the host through a controlled tunnel |
| Direct scan of your server's public IPv4 | Fingerprinting through the real Internet/cloud firewall/NAT path |

Start with the tunnel: it gives you a known target, a known closed port, and
fewer cloud-filtering surprises. Label it accurately as a VPN test. A normal
SSH `-L` port forward or HTTP tunnel does not forward arbitrary raw TCP/ICMP/UDP
probes and is not a substitute.

Use a current Linux server you control, such as an existing VPS, with sudo access
and a reachable public IPv4. Keep provider console access available. Do not
port-forward the Windows 7 VM onto the Internet. Check your provider's conditions
before scanning the hosted machine.

### 10.2 Build a two-host WireGuard path

Example addresses, chosen not to overlap existing routes:

| Role | Tunnel address |
| --- | --- |
| Remote Linux server/target | `10.77.0.1/24` |
| Ubuntu scanner | `10.77.0.2/24` |

Ubuntu needs ordinary Internet access through NAT or bridging. You do not need
to configure forwarding or masquerading between other machines: the target is
the remote WireGuard endpoint itself.

On **both Ubuntu and the remote server**:

```bash
sudo apt update
sudo apt install wireguard python3 iptables tcpdump
mkdir -p ~/osfp-wireguard
cd ~/osfp-wireguard
umask 077
wg genkey > privatekey
wg pubkey < privatekey > publickey
cat publickey
```

Generate once per machine. Exchange the **public** keys through your existing
administration channel. Keep private keys local and out of screenshots/reports.
The [WireGuard quick start](https://www.wireguard.com/quickstart/) documents key
generation and keepalives for peers behind NAT.

On the **remote server**, use `sudoedit /etc/wireguard/wg0.conf` to create:

```ini
[Interface]
Address = 10.77.0.1/24
ListenPort = 51820
PrivateKey = REPLACE_WITH_REMOTE_PRIVATE_KEY

[Peer]
PublicKey = REPLACE_WITH_UBUNTU_PUBLIC_KEY
AllowedIPs = 10.77.0.2/32
```

On **Ubuntu**, create `/etc/wireguard/wg0.conf`:

```ini
[Interface]
Address = 10.77.0.2/24
PrivateKey = REPLACE_WITH_UBUNTU_PRIVATE_KEY

[Peer]
PublicKey = REPLACE_WITH_REMOTE_PUBLIC_KEY
Endpoint = REPLACE_WITH_SERVER_PUBLIC_IPV4:51820
AllowedIPs = 10.77.0.1/32
PersistentKeepalive = 25
```

Replace the literal placeholder values; do not leave them in the files. The
private-key field is the key's contents, not its filename. On each machine:

```bash
sudo chmod 600 /etc/wireguard/wg0.conf
```

In the remote provider's cloud firewall/security group, allow inbound **UDP
51820** from the scanner's current public egress IPv4 `/32`. Also allow that UDP
traffic in the remote host firewall. Preserve the existing SSH/management rules.
If you administer the server by SSH **from this Ubuntu scanner over the same
Internet path**, the first address in `echo "$SSH_CONNECTION"` on the server
shows that connection's public source. Otherwise obtain the egress IP from the
router/provider or a trusted IP-check service and confirm it in a server capture.
It may change after an ISP reconnect or VPN change.

If the remote host uses UFW, a source-limited example is:

```bash
PUBLIC_SCANNER_IP=REPLACE_WITH_ACTUAL_PUBLIC_IPV4
sudo ufw allow from "$PUBLIC_SCANNER_IP" to any port 51820 proto udp
```

Do not newly enable UFW just for this command on an SSH-managed server. If it
uses another firewall, add the equivalent rule there. UFW and cloud rules are
separate layers; opening one does not open the other.

Start on the server first, then Ubuntu:

```bash
sudo wg-quick up wg0
sudo wg show wg0
ip -br address show wg0
```

On Ubuntu:

```bash
ip route get 10.77.0.1
ping -c 3 10.77.0.1
```

The route should use `wg0` and source `.0.2`. Ping can be blocked until the next
step; `wg show` should show a recent handshake after traffic is attempted. If
there is no handshake, fix UDP reachability, endpoint, and keys before scanning.
`wg-quick` installs addresses/routes from these settings; see its
[official manual](https://git.zx2c4.com/wireguard-tools/about/src/man/wg-quick.8).

### 10.3 Prepare and scan the tunnel target

On the **remote server**:

```bash
cat /etc/os-release
uname -r
mkdir -p ~/osfp-remote-web
ss -ltn
ss -lun
```

Verify 8080/8081/8082 and UDP 33434 are unused. Then configure a separate lab
chain, restricted to the tunnel and peer:

```bash
sudo iptables -N OSFP_REMOTE
sudo iptables -A OSFP_REMOTE -p tcp --dport 8082 -j DROP
sudo iptables -A OSFP_REMOTE -p tcp -m multiport --dports 8080,8081 -j ACCEPT
sudo iptables -A OSFP_REMOTE -p udp --dport 33434 -j ACCEPT
sudo iptables -A OSFP_REMOTE -p icmp -j ACCEPT
sudo iptables -I INPUT 1 -i wg0 -s 10.77.0.2 -j OSFP_REMOTE
python3 -m http.server 8080 --bind 10.77.0.1 --directory ~/osfp-remote-web
```

Keep the service terminal open. As with the VM rules, check for other independent
firewall policies if packets still disappear.

On **Ubuntu**, back in the scanner project folder:

```bash
cd ~/osfp-project
curl --max-time 5 http://10.77.0.1:8080/
sudo python3 -B scanner.py scan 10.77.0.1 -p 8080-8082 --open-port 8080 --closed-port 8081 --timeout 3 --retries 1 --os-tries 3 --debug -o results/remote-vpn-baseline.json
```

Capture inner traffic separately with:

```bash
sudo tcpdump -i wg0 -nn -s 0 -w results/remote-vpn.pcap 'host 10.77.0.1'
```

Run tcpdump before the scan and stop afterward. The project's `watch` assumes
Ethernet framing, so do **not** use it on `wg0` and expect working detection.
The scanner's raw IPv4 transport and tcpdump can operate on this tunnel, whereas
the Ethernet parser in `watch` has a different interface requirement.

For a remote blocking demonstration, on the **remote server**:

```bash
sudo iptables -I OSFP_REMOTE 1 -j DROP
```

Repeat scan/curl from Ubuntu and inspect the chain counters. SSH over the normal
public management path is outside this tunnel-scoped rule. Restore:

```bash
sudo iptables -D OSFP_REMOTE -j DROP
```

Record delay, missing probes, timing completeness, and ground-truth agreement.
Tunnel MTU/routing and Internet loss can affect the observed fingerprint. A VPN
result is not evidence that a direct public-address scan would behave identically.

### 10.4 Optional direct public-address scan

Use the same owned Linux server if you want an Internet-facing demonstration:

1. Stop the tunnel-bound HTTP server. Start it bound to the server's actual
   external-facing local address, or `0.0.0.0` with source-restricted firewall
   rules. A provider's public IP can be NAT-mapped and absent from `ip address`;
   in that case do not try binding directly to the unmapped public IP.
2. In the cloud firewall/security group allow inbound TCP **8080 and 8081**,
   UDP **33434**, and ICMPv4 from your scanner's current public source `/32`.
   Keep 8082 denied. Allowing only 8080 usually leaves no accessible closed port.
3. Add corresponding host rules. If section 10.3's `OSFP_REMOTE` chain still
   exists, with its DROP defense removed, reuse its protocol rules using the
   source/interface jump below. Do not recreate an existing chain.
4. Keep the normal cloud return-traffic policy. With stateless network ACLs,
   allow return packets to the scanner's ephemeral ports and ICMP errors too.
5. Verify 8080 is listening and 8081 is unused. Capture on the server to see
   whether probes arrive and whether reset/ICMP responses leave.

On the **server**, set the actual external interface and source:

```bash
WAN_IF=ens3
PUBLIC_SCANNER_IP=REPLACE_WITH_ACTUAL_PUBLIC_IPV4
sudo iptables -I INPUT 1 -i "$WAN_IF" -s "$PUBLIC_SCANNER_IP" -j OSFP_REMOTE
python3 -m http.server 8080 --bind 0.0.0.0 --directory ~/osfp-remote-web
```

On **Ubuntu**:

```bash
REMOTE_PUBLIC_IP=REPLACE_WITH_SERVER_PUBLIC_IPV4
sudo python3 -B scanner.py scan "$REMOTE_PUBLIC_IP" -p 8080-8082 --timeout 3 --retries 1 --os-tries 2 --parallel 2 --delay 0.2 --debug -o results/remote-public.json
```

A provider firewall can accept ordinary SYN traffic yet suppress unusual flags
or ICMP. An UNKNOWN/AMBIGUOUS answer through that path is a valid demonstration
of the limitation. The public address must lead to the target itself; a CDN,
load balancer, or TCP proxy may expose its own stack instead of the origin OS.

For a remote device behind someone else's home router, simple port forwarding
is less suitable: CGNAT/double NAT may prevent inbound access, and forwarding
only one service does not reproduce closed TCP, ICMP, and UDP fingerprint tests.
Prefer a VPN endpoint on the actual Linux device you control. Scanning a router's
WAN address does not establish the OS of an internal laptop.

### 10.5 Remote cleanup

Stop the HTTP server. On the remote server, remove the public-path jump **if you
added it**, using the same actual interface/source values, then the VPN jump:

```bash
sudo iptables -D INPUT -i "$WAN_IF" -s "$PUBLIC_SCANNER_IP" -j OSFP_REMOTE
sudo iptables -D INPUT -i wg0 -s 10.77.0.2 -j OSFP_REMOTE
sudo iptables -F OSFP_REMOTE
sudo iptables -X OSFP_REMOTE
```

Run only the matching removal commands for rules actually added. Remove the
extra cloud firewall entries and, if used, the exact UFW WireGuard allow rule:

```bash
sudo ufw delete allow from "$PUBLIC_SCANNER_IP" to any port 51820 proto udp
```

On each WireGuard endpoint:

```bash
sudo wg-quick down wg0
```

The guide uses manual `up`, not boot-time service enablement. Retain configs only
if you want to reuse the lab; protect their private keys. Verify your ordinary
management connection and firewall policy still work. Remove a paid test server
through its provider console when finished if you created it only for this demo.

## 11. Evidence and final results

For each condition, keep:

* Ground truth: actual distribution, kernel/build, architecture, target IP.
* Setup: VirtualBox adapter mode, route/interface, service listeners, rule state.
* Scanner evidence: JSON, terminal transcript, PCAP, scanner/database hashes.
* Comparison evidence: Nmap output, command/version, independent OS truth.
* Defense evidence: alerts, counters, availability check, restoration check.

Suggested result sheet columns:

```text
run_id,target,actual_distribution,actual_kernel_or_build,path,defense,
expected_ports,observed_ports,status,predicted_family,predicted_label,
similarity,coverage,syn_replies,udp_closed,sequence_timing_complete,
elapsed_seconds,family_correct,range_contains_truth,false_unique,notes
```

Record false unique claims explicitly. If a returned label covers Windows
7/8/Server versions, it may include Windows 7 without uniquely identifying it.
For a Linux range, manually check whether the actual kernel falls inside it.
“Cannot judge” is preferable to forcing unclear labels into correct/incorrect.

Report these metrics separately:

| Metric | Calculation |
| --- | --- |
| Controlled port-state accuracy | Correct controlled port classifications / tested controlled ports |
| Family accuracy across all runs | Correct supported family conclusions / all labeled runs; unknown family counts as no correct answer |
| Family accuracy when answered | Correct family conclusions / runs with a supported family conclusion |
| Unique-label answer rate | CANDIDATE runs / all runs |
| Version-range correctness | Correct truth-containing ranges / runs with an assessable version/range claim; report the denominator |
| False unique rate | Wrong CANDIDATE claims / CANDIDATE claims; also give the absolute count |
| Repeatability | Number of repeated runs agreeing on family/status/range, with variations listed |
| Performance | Median and min/max elapsed time, and packet count under the same capture filter |

An optional built-in evaluation file in `results/cases.json` looks like:

```json
[
  {"report": "zorin-baseline-01.json", "label": "REPLACE WITH ACTUAL ZORIN AND KERNEL", "family": "Linux"},
  {"report": "win7-baseline-01.json", "label": "REPLACE WITH ACTUAL WINDOWS BUILD", "family": "Windows"}
]
```

After replacing the labels with real ground truth:

```bash
python3 -B scanner.py evaluate results/cases.json -o results/evaluation.json
```

Paths are relative to `cases.json`. This evaluator uses **exact label equality**,
so it does not calculate whether a kernel is inside a returned range. Its label
accuracy can penalize differences in wording; use the manual range metric above.
Do not change ground truth to match a database label. Do not train and evaluate
on the same capture if you separately experiment with the legacy `learn` mode.

Fifteen baseline runs across your VMs are useful repeatability evidence, not a
broad claim of performance across all operating systems. Two of the three
targets belong to the same OS family. Distinguish clean-baseline accuracy from
performance under deliberately modified/blocked traffic.

## 12. A practical live presentation order

Prepare snapshots, addresses, listeners, evidence folders, and commands before
the presentation. Keep a saved run/PCAP for each stage as fallback evidence,
clearly labeled as a previous capture if used.

| Approximate time | Demonstration |
| --- | --- |
| 1 minute | Show topology and target ground truth |
| 2–3 minutes | Zorin baseline: open/closed/filtered and OS interpretation |
| 2–3 minutes | Windows 7 baseline and comparison with its actual build |
| 1–2 minutes | Show a packet exchange and no accept-log event for a basic scan |
| 2 minutes | Start `watch`; run a bounded sweep and show alerts |
| 2 minutes | Apply source block; rescan; show counters and service failure |
| 1 minute | Remove block and verify recovery |
| Optional | TTL or ICMP experiment, one LAN device, or VPN remote target |

Do not promise a precise version or invent a successful result during the demo.
If the tool abstains, explain the missing evidence and show that it still
classified the controlled ports correctly. If it guesses incorrectly, show the
ground truth and record the failure. That is a valid testing outcome.

For a concise defense story, use **detection → source block → verification →
unblock → recovery**. Keep the more variable TTL/rate experiments in the report
or a backup demonstration.

## 13. Local cleanup and troubleshooting

### 13.1 Restore the local VMs

On each Linux target, stop the test service and watcher. Remove any TTL/netem/
ipset experiment using its section's cleanup first. Then set the correct values
for that target and remove only the lab chain jump:

```bash
LAB_IF=enp0s8
SCANNER_IP=192.168.56.10
sudo iptables -D INPUT -i "$LAB_IF" -s "$SCANNER_IP" -j OSFP_LAB
sudo iptables -F OSFP_LAB
sudo iptables -F OSFP_DEF
sudo iptables -X OSFP_LAB
sudo iptables -X OSFP_DEF
```

For Ubuntu when it was the target, use Zorin's `.20` source and Ubuntu's interface.
Check `sudo iptables -S` afterward. These temporary rules were not made persistent.
Avoid restoring a whole firewall snapshot if unrelated rules have changed since
the experiment; removing the named additions is more precise.

On **Windows 7**, stop the listener, then in Administrator Command Prompt:

```cmd
netsh advfirewall firewall delete rule name="OSFP Lab TCP"
netsh advfirewall firewall delete rule name="OSFP Lab UDP"
netsh advfirewall firewall delete rule name="OSFP Lab ICMP"
netsh advfirewall firewall delete rule name="OSFP Lab Filtered"
netsh advfirewall firewall delete rule name="OSFP Lab Block Source"
```

“No rules match” is harmless if that particular rule was not created or was
already removed. Confirm the listener has stopped with `netstat`. Keep Windows
7 isolated. Revert network adapter changes if they were only for the lab.

### 13.2 Common problems

| Symptom | Check next |
| --- | --- |
| Native Windows scan fails | Live scanning must run inside Linux; Windows 7 is a target |
| All ports filtered | Correct target IP, cable/network attachment, route/source, listener, and rule counters |
| 8080 closed | Service not running, bound to another address, or crashed |
| 8081 filtered | No listener is insufficient; target/path must permit a returning RST |
| Linux lab allow rules seem ineffective | Another nftables base chain, security agent, different backend/interface, or wrong source address |
| No UDP closed confirmation | UDP listener, dropped probe, blocked/rate-limited ICMP, or path filtering |
| `watch` shows no alerts | Wrong interface, no visibility, threshold not met, expired duration, or use on a non-Ethernet tunnel |
| Windows listener creation fails | Run the supplied `New-Object` version; check IP binding and port use; do not use `::new()` on stock PS2 |
| Correct family but wrong distro | Kernel fingerprint does not uniquely identify the distribution |
| Very high similarity but UNKNOWN | Check evidence gates/coverage; diagnostic similarity is not an OS decision |
| Repeated runs vary | VM CPU contention, packet loss, timing, rate limiting, unstable fields, or differing selected ports |
| LAN device unreachable | Guest/AP isolation, Wi-Fi bridge restrictions, sleep, or target firewall |
| WireGuard has no handshake | Wrong endpoint/key, UDP 51820 blocked, stale source allowlist, or missing Internet route |
| VPN works but `watch wg0` does not | Ethernet parsing limitation; use tcpdump for tunnel capture |
| Public port open but OS unknown | Missing closed port or unusual probes suppressed by provider/NAT/proxy |

The network-emulation commands are documented in the
[netem manual](https://man7.org/linux/man-pages/man8/tc-netem.8.html). Use the
current code and local captures to settle implementation-specific behavior.
