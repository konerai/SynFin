#!/usr/bin/env python3
"""Checks that the Windows GUI exports the same sessions as the command-line analyzer.

Runs synfin.exe and synfin-gui.exe --export on the same synthetic captures (under
non-ASCII file names) and compares the JSON Lines export line by line with the
command-line output, then checks the shape of the CSV export. Windows only.

Usage: python tests/test_gui_export.py path/to/synfin.exe path/to/synfin-gui.exe
"""

import csv
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_sessions  # noqa: E402

CSV_HEADER = ["#", "Source", "Destination", "Start", "End", "Duration, s", "Closed by"]
LABELS = {"FIN", "RST", "Timeout", "Still open"}


def main():
    cli, gui = sys.argv[1], sys.argv[2]
    cap, _ = test_sessions.build_capture()
    errors = []
    with tempfile.TemporaryDirectory() as tmp:
        inputs = []
        for fmt, link in [("pcap", "ethernet"), ("pcapng", "linux-sll2")]:
            path = os.path.join(tmp, f"захват {fmt}.{fmt}")
            cap.write(path, fmt, link)
            inputs.append(path)
        options = ["--timeout", "60", "--threads", "4"]

        out = subprocess.run([cli, "-t", "60", "-j", "4", *inputs], capture_output=True, text=True, check=True).stdout
        expected = sorted(line for line in out.splitlines() if line.startswith("{"))

        jsonl = os.path.join(tmp, "export.jsonl")
        subprocess.run([gui, "--export", jsonl, *options, *inputs], check=True, timeout=300)
        with open(jsonl, encoding="utf-8") as f:
            exported = sorted(line.rstrip("\n") for line in f)
        if exported != expected:
            errors.append(f"JSON Lines export differs from the CLI ({len(exported)} vs {len(expected)} sessions)")

        csv_path = os.path.join(tmp, "export.csv")
        subprocess.run([gui, "--export", csv_path, *options, *inputs], check=True, timeout=300)
        with open(csv_path, encoding="utf-8", newline="") as f:
            rows = list(csv.reader(f))
        if rows[0] != CSV_HEADER:
            errors.append(f"CSV header {rows[0]}")
        if len(rows) - 1 != len(expected):
            errors.append(f"CSV has {len(rows) - 1} sessions, expected {len(expected)}")
        if any(len(r) != 7 or r[6] not in LABELS for r in rows[1:]):
            errors.append("CSV rows have the wrong shape")

    print(f"[{'FAIL' if errors else 'ok'}] GUI export of {len(expected)} sessions matches the CLI")
    for e in errors:
        print("   ", e)
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
