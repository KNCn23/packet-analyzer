# packet-analyzer

A two-part network packet analyzer:

- **`pktscan`** — a fast C parser that reads libpcap-format capture files and emits structured records for Ethernet / IPv4 / IPv6 / TCP / UDP / ICMP / ARP.
- **`dashboard.py`** — a terminal dashboard that consumes the parser's JSON output and renders protocol distribution, top talkers, top ports, and top flows.

No external dependencies (C: libc only; Python: stdlib only). Works on any pcap captured with `tcpdump`, `Wireshark`, or `tshark`.

## Build

```bash
make
```

## Capture some traffic

```bash
# macOS
sudo tcpdump -i en0 -w capture.pcap -c 500

# Linux
sudo tcpdump -i any -w capture.pcap -c 500
```

(Or download any sample pcap, e.g. https://wiki.wireshark.org/SampleCaptures.)

## Run

```bash
# Human-readable text dump
./pktscan capture.pcap

# Pipe straight into the dashboard
./pktscan --json capture.pcap | python python/dashboard.py
```

Sample dashboard output:

```
╔══════════════════════════════════════════════════════════════════╗
║                    Packet Analyzer Dashboard                     ║
╚══════════════════════════════════════════════════════════════════╝

Total packets :        500
Total bytes   :   312.4 KB
Duration      :     12.480 s
Avg. rate     :       40.1 pps   ( 25.0 KB/s)

── Protocol distribution ──
  TCP    ████████████████████░░░░░░░░  342    231.2 KB  (68.4%)
  UDP    ████████░░░░░░░░░░░░░░░░░░░░   98     61.3 KB  (19.6%)
  ICMP   █░░░░░░░░░░░░░░░░░░░░░░░░░░░   34      4.8 KB  ( 6.8%)
  ARP    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░   26     15.1 KB  ( 5.2%)

── Top 5 talkers (by bytes sent) ──
  192.168.1.42            105.4 KB
  ...

── Top 5 destination ports ──
    443    218 packets  https
     53     74 packets  dns
   8080     31 packets  http-alt
```

## File layout

```
├── include/parser.h    # PcapGlobalHeader, ParsedPacket, parse_pcap()
├── src/
│   ├── parser.c        # libpcap reader: Ethernet → IPv4/IPv6 → TCP/UDP
│   └── cli.c           # Text + JSON output formatter
├── python/
│   └── dashboard.py    # Counter-based stats, ASCII bar charts
└── Makefile
```

## Why split into two languages?

- **C for the hot path**: parsing tens of thousands of packets per second is a tight loop over `fread`-ed byte buffers. No GC, no overhead.
- **Python for presentation**: aggregation, sorting, and pretty-printing are I/O-bound and trivial to extend (add new statistics in 3–4 lines).

## License

MIT
