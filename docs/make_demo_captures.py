#!/usr/bin/env python3
"""Writes the synthetic captures used for the README screenshots.

Usage: python3 docs/make_demo_captures.py OUTPUT_FILE.pcap

The capture covers the last 30 minutes: normal sessions closed by FIN or RST,
14 sessions that went idle long ago (reported as timed out with the default
600 s timeout) and 3 that are still open when it ends.
"""
import random, struct, sys, time
out = sys.argv[1]
random.seed(out.rsplit("/", 1)[-1])
now = int(time.time()); base = now - 30 * 60
packets = []
def ip2b(s): return bytes(int(x) for x in s.split("."))
def pkt(ts, src, sport, dst, dport, flags):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, random.getrandbits(32), 0, 5 << 4, flags, 64240, 0, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0x4000, 64, 6, 0, ip2b(src), ip2b(dst))
    packets.append((ts, b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00" + ip + tcp))
SYN, ACK, FIN, RST, PSH = 0x02, 0x10, 0x01, 0x04, 0x08
servers = [("93.184.216.34", 443), ("140.82.112.3", 443), ("151.101.1.69", 80), ("8.8.8.8", 53),
           ("10.0.0.1", 22), ("192.168.1.1", 8080), ("172.217.16.142", 443)]
clients = ["192.168.1.10", "192.168.1.23", "192.168.1.42", "10.0.0.5"]
def session(start, kind):
    c, (s, sp) = random.choice(clients), random.choice(servers); cp = random.randint(32768, 60999); t = start
    pkt(t, c, cp, s, sp, SYN); t += 0.02; pkt(t, s, sp, c, cp, SYN | ACK); t += 0.02; pkt(t, c, cp, s, sp, ACK)
    for _ in range(random.randint(3, 25)):
        t += random.uniform(0.01, 4)
        pkt(t, *((c, cp, s, sp) if random.random() < .5 else (s, sp, c, cp)), PSH | ACK)
    t += 0.05
    if kind == "fin":
        pkt(t, c, cp, s, sp, FIN | ACK); pkt(t + 0.02, s, sp, c, cp, FIN | ACK); pkt(t + 0.04, c, cp, s, sp, ACK)
    elif kind == "rst":
        pkt(t, s, sp, c, cp, RST)
for i in range(14): session(base + i * 15, "idle")
t = now - 9 * 60
while t < now - 20:
    session(t, "rst" if random.random() < .2 else "fin"); t += random.uniform(2, 12)
for i in range(3): session(now - 40 + i * 8, "idle")
packets.sort(key=lambda p: p[0])
with open(out, "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for ts, data in packets:
        f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(data), len(data)) + data)
