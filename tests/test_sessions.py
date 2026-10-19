#!/usr/bin/env python3
"""End-to-end test for TCP_Analysis.

Writes a synthetic capture with known sessions, runs the analyzer on it and
checks every reported session. Uses only the Python standard library.

Usage: python3 tests/test_sessions.py [path/to/TCP_Analysis]
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
        eth = b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00"
        self.packets.append((BASE + t, eth + ip + tcp))

    def handshake(self, t, client, server):
        self.add(t, client, server, SYN)
        self.add(t + 0.01, server, client, SYN | ACK)
        self.add(t + 0.02, client, server, ACK)

    def write(self, path):
        self.packets.sort(key=lambda p: p[0])
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for ts, data in self.packets:
                sec = int(ts)
                usec = int(round((ts - sec) * 1e6))
                f.write(struct.pack("<IIII", sec, usec, len(data), len(data)) + data)


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
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join(root, "build", "TCP_Analysis")
    cap, expected = build_capture()
    failed = False
    with tempfile.TemporaryDirectory() as tmp:
        pcap = os.path.join(tmp, "test.pcap")
        cap.write(pcap)
        for threads in (1, 4):
            errors = check(run(binary, pcap, threads), expected)
            status = "FAIL" if errors else "ok"
            print(f"[{status}] {len(expected)} sessions, {threads} thread(s)")
            for e in errors[:20]:
                print("   ", e)
            failed |= bool(errors)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
