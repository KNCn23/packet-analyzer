"""
Terminal dashboard for packet captures.
Reads JSON output from the C parser and renders live-updating statistics.

Usage:
    ./pktscan --json capture.pcap | python python/dashboard.py
    python python/dashboard.py capture.json
"""

import sys
import json
from collections import Counter, defaultdict


def load_packets(stream):
    data = stream.read()
    return json.loads(data) if data.strip() else []


def fmt_bytes(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:6.1f} {unit}"
        n /= 1024
    return f"{n:6.1f} TB"


def bar(width, fraction):
    fill = int(width * fraction)
    return "█" * fill + "░" * (width - fill)


def render(packets):
    if not packets:
        print("No packets to analyze."); return

    total_bytes = sum(p["len"] for p in packets)
    duration = packets[-1]["ts"] - packets[0]["ts"]
    proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

    proto_count = Counter()
    proto_bytes = Counter()
    flows       = Counter()
    ports       = Counter()
    talkers     = Counter()

    for p in packets:
        proto = proto_map.get(p["proto"], f"proto-{p['proto']}")
        if p["eth"] == 0x0806: proto = "ARP"
        if p["eth"] == 0x86DD: proto = "IPv6"
        proto_count[proto] += 1
        proto_bytes[proto] += p["len"]

        if p["sport"] >= 0:
            flow = (p["src"], p["sport"], p["dst"], p["dport"], proto)
            flows[flow] += p["len"]
            ports[p["dport"]] += 1
        talkers[p["src"]] += p["len"]

    print("\n╔══════════════════════════════════════════════════════════════════╗")
    print("║                    Packet Analyzer Dashboard                     ║")
    print("╚══════════════════════════════════════════════════════════════════╝")

    print(f"\nTotal packets : {len(packets):>10}")
    print(f"Total bytes   : {fmt_bytes(total_bytes):>10}")
    print(f"Duration      : {duration:>10.3f} s")
    if duration > 0:
        print(f"Avg. rate     : {len(packets)/duration:>10.1f} pps   "
              f"({fmt_bytes(total_bytes/duration)}/s)")

    print("\n── Protocol distribution ──")
    for proto, count in proto_count.most_common():
        frac = count / len(packets)
        print(f"  {proto:<6} {bar(28, frac)} {count:5}  "
              f"{fmt_bytes(proto_bytes[proto]):>9}  ({frac*100:4.1f}%)")

    print("\n── Top 5 talkers (by bytes sent) ──")
    for ip, b in talkers.most_common(5):
        print(f"  {ip:<22}  {fmt_bytes(b)}")

    print("\n── Top 5 destination ports ──")
    for port, count in ports.most_common(5):
        guess = WELL_KNOWN.get(port, "")
        print(f"  {port:>5}  {count:>6} packets  {guess}")

    print("\n── Top 5 flows (by bytes) ──")
    for (src, sp, dst, dp, proto), b in flows.most_common(5):
        print(f"  {src}:{sp} → {dst}:{dp} ({proto})  {fmt_bytes(b)}")
    print()


WELL_KNOWN = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 80: "http", 110: "pop3", 123: "ntp",
    143: "imap", 443: "https", 465: "smtps", 587: "smtp-tls",
    993: "imaps", 995: "pop3s", 3306: "mysql", 3389: "rdp",
    5432: "postgres", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
}


def main():
    if len(sys.argv) > 1:
        with open(sys.argv[1]) as f:
            packets = load_packets(f)
    else:
        packets = load_packets(sys.stdin)
    render(packets)


if __name__ == "__main__":
    main()
