#!/usr/bin/env python3
"""End-to-end test for synfin.

Writes a synthetic capture with known sessions in several file formats (pcap,
pcapng) and link layers, runs the analyzer on each and checks every reported
session. Uses only the Python standard library.

Usage: python3 tests/test_sessions.py [path/to/synfin]
"""

import json
import os
import struct
import subprocess
import sys
import tempfile

SYN, FIN, RST, PSH, ACK = 0x02, 0x01, 0x04, 0x08, 0x10
TIMEOUT = 60
# Two years before the test runs, so wall-clock based timeouts would fire on everything.
BASE = 1_700_000_000


class Capture:
    def __init__(self):
        self.packets = []

    def add(self, t, src, dst, flags):
        (sip, sport), (dip, dport) = src, dst
        tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 65535, 0, 0)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, 6, 0,
                         bytes(map(int, sip.split("."))), bytes(map(int, dip.split("."))))
        self.packets.append((BASE + t, ip + tcp))

    def handshake(self, t, client, server):
        self.add(t, client, server, SYN)
        self.add(t + 0.01, server, client, SYN | ACK)
        self.add(t + 0.02, client, server, ACK)

    def write(self, path, fmt="pcap", link="ethernet"):
        link_type, header = LINKS[link]
        packets = [(split_ts(ts), header + data) for ts, data in sorted(self.packets, key=lambda p: p[0])]
        with open(path, "wb") as f:
            if fmt.startswith("pcapng"):
                write_pcapng(f, fmt, link_type, packets)
            else:
                write_pcap(f, fmt, link_type, packets)


ETHERNET = b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02"
# link name -> (link-layer header type, header put in front of every IP packet)
LINKS = {
    "ethernet": (1, ETHERNET + b"\x08\x00"),
    "vlan": (1, ETHERNET + b"\x81\x00\x00\x64\x08\x00"),
    "linux-sll": (113, struct.pack("!HHH8sH", 0, 1, 6, b"\x02\x00\x00\x00\x00\x01", 0x0800)),
    "linux-sll2": (276, struct.pack("!HHIHBB8s", 0x0800, 0, 1, 1, 0, 6, b"\x02\x00\x00\x00\x00\x01")),
    "raw": (101, b""),
    "loopback": (0, struct.pack("<I", 2)),
}


def split_ts(ts):
    """Float seconds -> (seconds, nanoseconds)."""
    sec = int(ts)
    return sec, int(round((ts - sec) * 1e9))


def write_pcap(f, fmt, link_type, packets):
    order = ">" if fmt == "pcap-be" else "<"
    nanos = fmt == "pcap-ns"
    f.write(struct.pack(order + "IHHiIII", 0xA1B23C4D if nanos else 0xA1B2C3D4, 2, 4, 0, 0, 65535, link_type))
    for (sec, ns), data in packets:
        frac = ns if nanos else ns // 1000
        f.write(struct.pack(order + "IIII", sec, frac, len(data), len(data)) + data)


def pcapng_block(order, block_type, body):
    body += b"\x00" * (-len(body) % 4)
    total = len(body) + 12
    return struct.pack(order + "II", block_type, total) + body + struct.pack(order + "I", total)


def write_pcapng_section(f, order, link_type, packets, nanos):
    f.write(pcapng_block(order, 0x0A0D0D0A, struct.pack(order + "IHHq", 0x1A2B3C4D, 1, 0, -1)))
    options = b""
    if nanos:
        options = struct.pack(order + "HH", 9, 1) + b"\x09\x00\x00\x00" + struct.pack(order + "HH", 0, 0)
    f.write(pcapng_block(order, 1, struct.pack(order + "HHI", link_type, 0, 65535) + options))
    f.write(pcapng_block(order, 4, struct.pack(order + "HH", 0, 0)))  # name resolution: skipped
    for (sec, ns), data in packets:
        ticks = sec * 10**9 + ns if nanos else sec * 10**6 + ns // 1000
        body = struct.pack(order + "IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(data), len(data)) + data
        f.write(pcapng_block(order, 6, body))


def write_pcapng(f, fmt, link_type, packets):
    if fmt == "pcapng":
        write_pcapng_section(f, "<", link_type, packets, nanos=False)
    elif fmt == "pcapng-ns-be":
        write_pcapng_section(f, ">", link_type, packets, nanos=True)
    elif fmt == "pcapng-sections":
        # Two sections with different byte orders; interface ids restart in each.
        half = len(packets) // 2
        write_pcapng_section(f, "<", link_type, packets[:half], nanos=False)
        write_pcapng_section(f, ">", link_type, packets[half:], nanos=True)
    else:
        raise ValueError(fmt)


# (file format, link layer, worker threads)
VARIANTS = [
    ("pcap", "ethernet", 1),
    ("pcap", "ethernet", 4),
    ("pcap-ns", "ethernet", 4),
    ("pcap-be", "ethernet", 4),
    ("pcapng", "ethernet", 4),
    ("pcapng-ns-be", "ethernet", 4),
    ("pcapng-sections", "ethernet", 4),
    ("pcap", "vlan", 4),
    ("pcap", "linux-sll", 4),
    ("pcapng", "linux-sll2", 4),
    ("pcap", "raw", 4),
    ("pcapng", "loopback", 4),
]


def build_capture():
    cap = Capture()
    server = "10.0.0.2"
    expected = {}  # (source, destination, start) -> (closed_by, end)

    # Client opens, client sends FIN first, server's FIN closes the session.
    c, s = ("10.0.0.1", 40000), (server, 80)
    cap.handshake(10, c, s)
    cap.add(11, c, s, PSH | ACK)
    cap.add(12, c, s, FIN | ACK)
    cap.add(12.5, s, c, FIN | ACK)
    cap.add(12.51, c, s, ACK)  # final ACK after both FINs: not a new session
    expected[(c, s, 10)] = ("fin", 12.5)

    # The same ports are reused later: a new SYN starts a new session.
    cap.handshake(40, c, s)
    cap.add(41, s, c, RST)
    expected[(c, s, 40)] = ("rst", 41)

    # Server resets the connection.
    c, s = ("10.0.0.3", 40001), (server, 443)
    cap.handshake(20, c, s)
    cap.add(21, s, c, RST)
    cap.add(21.2, s, c, RST)  # retransmitted RST
    cap.add(21.3, c, s, PSH | ACK)  # data still in flight
    expected[(c, s, 20)] = ("rst", 21)

    # Capture starts after the SYN: the first packet seen is the server's SYN-ACK.
    c, s = ("10.0.0.4", 40002), (server, 22)
    cap.add(30, s, c, SYN | ACK)
    cap.add(30.01, c, s, ACK)
    cap.add(31, s, c, FIN | ACK)
    cap.add(32, c, s, FIN | ACK)
    expected[(c, s, 30)] = ("fin", 32)

    # Goes silent after 1 s while the capture continues for minutes: a real timeout.
    c, s = ("10.0.0.5", 40003), (server, 80)
    cap.handshake(0, c, s)
    cap.add(1, c, s, PSH | ACK)
    expected[(c, s, 0)] = ("timeout", 1)

    # Still open when the capture ends.
    c, s = ("10.0.0.6", 40004), (server, 8080)
    cap.handshake(195, c, s)
    cap.add(199, s, c, PSH | ACK)
    expected[(c, s, 195)] = ("end_of_capture", 199)

    # Background traffic: short sessions closed normally, enough packets for periodic timeout checks.
    for i in range(300):
        t = 2 + i * 0.65
        c = (f"192.168.{i // 200}.{i % 200 + 1}", 50000 + i)
        s = ("93.184.216.34", 443)
        cap.handshake(t, c, s)
        cap.add(t + 0.1, c, s, PSH | ACK)
        cap.add(t + 0.2, s, c, PSH | ACK)
        cap.add(t + 0.3, s, c, FIN | ACK)
        cap.add(t + 0.4, c, s, FIN | ACK)
        cap.add(t + 0.41, s, c, ACK)
        expected[(c, s, round(t, 3))] = ("fin", t + 0.4)

    return cap, expected


def endpoint(obj):
    return (obj["ip"], obj["port"])


def timestamp(obj):
    return obj["seconds"] + obj["microseconds"] / 1e6 - BASE


def run(binary, pcap, threads):
    out = subprocess.run([binary, "-i", pcap, "-t", str(TIMEOUT), "-j", str(threads)],
                         check=True, capture_output=True, text=True).stdout
    return [json.loads(line) for line in out.splitlines() if line.startswith("{")]


def check(sessions, expected):
    errors = []
    seen = set()
    for s in sessions:
        key = (endpoint(s["source"]), endpoint(s["destination"]), round(timestamp(s["start_time"]), 3))
        if key not in expected:
            errors.append(f"unexpected session {key}")
            continue
        if key in seen:
            errors.append(f"session reported twice {key}")
        seen.add(key)
        closed_by, end = expected[key]
        start = key[2]
        if s.get("closed_by") != closed_by:
            errors.append(f"{key}: closed_by {s.get('closed_by')!r}, expected {closed_by!r}")
        if s["timeout"] != (closed_by == "timeout"):
            errors.append(f"{key}: timeout {s['timeout']}, expected {closed_by == 'timeout'}")
        if abs(timestamp(s["start_time"]) - start) > 1e-3 or abs(timestamp(s["end_time"]) - end) > 1e-3:
            errors.append(f"{key}: times {timestamp(s['start_time']):.3f}-{timestamp(s['end_time']):.3f}, "
                          f"expected {start:.3f}-{end:.3f}")
    for key in expected.keys() - seen:
        errors.append(f"missing session {key}")
    return errors


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join(root, "build", "synfin")
    cap, expected = build_capture()
    failed = False
    with tempfile.TemporaryDirectory() as tmp:
        for fmt, link, threads in VARIANTS:
            path = os.path.join(tmp, f"test-{fmt}-{link}.{'pcapng' if fmt.startswith('pcapng') else 'pcap'}")
            cap.write(path, fmt, link)
            errors = check(run(binary, path, threads), expected)
            status = "FAIL" if errors else "ok"
            print(f"[{status}] {len(expected)} sessions, {fmt}, {link}, {threads} thread(s)")
            for e in errors[:20]:
                print("   ", e)
            failed |= bool(errors)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
