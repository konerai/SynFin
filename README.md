# SynFin

**TCP sessions from SYN to FIN.** SynFin is a multithreaded C++ tool that reads `.pcap` capture files, reconstructs TCP sessions from the raw packets, and reports each session — who opened it and to whom (IP and port), start/end timestamps, and how it ended: FIN, RST, idle timeout, or still open when the capture ended. It comes with two front ends:

- **`synfin`** — the command-line analyzer; prints one JSON object per session to `stdout`, ready to pipe into `jq`, a log shipper or a script.
- **SynFin GUI** — a dark-themed desktop window (Python + Tkinter) that runs the analyzer for you and shows the sessions in a sortable, filterable table.

![SynFin GUI with analysis results](docs/screenshots/02-results.png)

> SynFin was called *TCP-IP_Analyzed* before v0.3.0, and its binary was `TCP_Analysis`.

It's built for offline analysis of large packet captures: instead of loading a whole capture into memory, it streams packets from libpcap, shards them across worker threads by session, and emits results as soon as each session ends.

## Contents

- [Where it runs](#where-it-runs)
- [Download](#download)
- [Requirements](#requirements)
- [Building](#building)
- [Graphical interface](#graphical-interface)
- [Command-line usage](#command-line-usage)
- [Output format](#output-format)
- [How it works](#how-it-works)
- [Project layout](#project-layout)
- [Tests](#tests)
- [Known limitations](#known-limitations)

## Where it runs

**Linux only.** The analyzer relies on POSIX/Linux headers (`<endian.h>`, `<unistd.h>`), so it does not build as-is on Windows or macOS. The GUI is plain Python + Tkinter and runs on any Linux desktop (X11 or Wayland via XWayland).

Tested builds:

| Distribution | Compiler | CMake | Boost | libpcap | jsoncpp | Python / Tk | Result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Ubuntu 24.04 LTS | GCC 13.3 | 3.28 | 1.83 | 1.10.4 | 1.9.5 | 3.12 / 8.6 | builds cleanly, CLI and GUI work |
| Ubuntu 22.04 LTS | GCC 11.4 | 3.22 | 1.74 | 1.10.1 | 1.9.5 | — | builds cleanly |

Other distributions with the same or newer library versions (Debian 12+, Linux Mint 21+, Fedora, Arch) should work as well — install the equivalent packages listed below.

**Input:** offline capture files with an Ethernet link layer (`DLT_EN10MB`) — what `tcpdump -w` and Wireshark produce on a normal Ethernet or Wi-Fi interface. Only IPv4/TCP packets are analyzed; everything else (IPv6, UDP, ARP, …) is skipped. Live capture from a network interface is not supported.

## Download

Ready-to-run builds for Linux x86_64 and ARM64 are attached to every [release](https://github.com/konerai/SynFin/releases/latest). Boost, jsoncpp and libpcap are built into the binary; it only needs glibc 2.34+ (Ubuntu 22.04+, Debian 12+, Fedora 35+, RHEL 9+) and `libdbus`, which every mainstream distribution ships.

```bash
tar -xzf synfin-<version>-linux-x86_64.tar.gz
cd synfin-<version>-linux-x86_64
./synfin --version
python3 gui/synfin_gui.py   # needs Tkinter, see below
```

To build from source instead, read on.

## Requirements

Analyzer:

- CMake 3.10+
- A C++17 compiler (GCC 9+ or Clang 9+)
- [libpcap](https://www.tcpdump.org/) (development headers)
- Boost 1.74+ (`program_options`, `lockfree`)
- [jsoncpp](https://github.com/open-source-parsers/jsoncpp)

GUI (optional):

- Python 3.8+
- Tkinter (`python3-tk`); no other Python packages are needed

On Debian/Ubuntu:

```bash
sudo apt-get install build-essential cmake libpcap-dev libboost-program-options-dev libjsoncpp-dev python3-tk
```

On Fedora:

```bash
sudo dnf install gcc-c++ cmake libpcap-devel boost-devel jsoncpp-devel python3-tkinter
```

On Arch:

```bash
sudo pacman -S base-devel cmake libpcap boost jsoncpp tk
```

## Building

```bash
git clone https://github.com/konerai/SynFin.git
cd SynFin
mkdir build && cd build
cmake ..
make
```

This produces the `synfin` binary in `build/`.

## Graphical interface

`gui/synfin_gui.py` is a dark-themed desktop front end for the analyzer. Build the analyzer first (see above), then from the project root:

```bash
python3 gui/synfin_gui.py
```

The GUI looks for the binary at `build/synfin` (then `./synfin`, then `synfin` on `PATH`); another one can be chosen under **Settings → Analyzer binary**. The badge in the top-right corner shows the analyzer's version, or *Analyzer not found* in red.

![Main window before an analysis](docs/screenshots/01-start.png)

### Workflow

1. **Captures** — **Add files…** picks one or more `.pcap` files, **Add folder…** adds every `.pcap` file in a directory. **Remove** (or the <kbd>Delete</kbd> key) deletes the selected entries, **Clear** empties the list.
2. **Settings** — **Timeout, s** is the idle time after which an unfinished session is reported as timed out (`--timeout`); **Threads** is the number of worker threads (`--threads`, defaults to the number of CPU cores).
3. **Analyze** — runs `synfin` on all listed files. A progress bar runs while it works and sessions appear in the table as they are reported; **Stop** terminates it early.
4. **Explore and export** the results (see below).

### Summary tiles

The row of tiles above the table counts the sessions by how they ended: **FIN** (both sides sent FIN), **RST** (reset), **Timeout** (idle longer than the timeout) and **Still open** (no FIN/RST, not idle long enough when the capture ended). Click a tile to show only those sessions, click it again (or **Sessions**) to show all.

### Results table

Each row is one TCP session reported by the analyzer:

| Column | Meaning |
| --- | --- |
| Closed by | How the session ended, with the tile's color: FIN, RST, Timeout or Still open |
| `#` | Order in which the analyzer reported the session |
| Source / Destination | `IP:port` of the endpoint that opened the connection, and of the one it connected to |
| Start / End | Timestamps of the first and last packet of the session, taken from the capture (local time; the table shows milliseconds, exports keep microseconds) |
| Duration, s | End − Start |

The status bar at the bottom shows whether the analyzer is running (with the elapsed time) or how long the last run took. Everything the analyzer writes besides session JSON (its header lines, errors on `stderr`, the exit code) goes to the **Log** pane.

### Filtering

Click a summary tile to filter by status, and/or type into the search box to show only rows where any column contains the text — an IP address, a port (`:443`), a date, or a status:

![Filtering for timed-out sessions](docs/screenshots/03-filter.png)

### Sorting

Click a column header to sort by it, click again to reverse the order; an arrow marks the sorted column. Numeric columns (`#`, Duration) sort by value — for example, the longest sessions first:

![Sessions sorted by duration](docs/screenshots/04-sorted.png)

### Export

**Export…** saves all sessions from the last run (regardless of the filter):

- **CSV** (`.csv`) — the table's columns, with microsecond timestamps, ready for a spreadsheet;
- **JSON Lines** (`.jsonl`) — the analyzer's original JSON objects, one per line.

## Command-line usage

Analyze one or more capture files directly:

```bash
./synfin -i capture1.pcap capture2.pcap
```

Or point it at a directory and it will pick up every `.pcap` file in it:

```bash
./synfin -d /path/to/captures/
```

### Options

| Option | Description | Default |
| --- | --- | --- |
| `-i`, `--input <files...>` | One or more input `.pcap` files | — |
| `-d`, `--dir <path>` | Directory to scan for `.pcap` files | — |
| `-t`, `--timeout <seconds>` | Idle time (in capture time) after which an open session is force-closed and reported | `600` |
| `-j`, `--threads <n>` | Number of worker threads used to process sessions in parallel | number of CPU cores |
| `-q`, `--queue-size <n>` | Size of the internal packet queues (currently not used, see below) | `2048` |
| `-v`, `--version` | Show the version | — |
| `-h`, `--help` | Show usage information | — |

`--input`/`-i` and `--dir`/`-d` can be combined; at least one input file must be found or the tool exits with an error.

Before the sessions, the analyzer prints a few plain-text header lines (`Analyzing files: …`, `Timeout: …`, `Threads: …`) to `stdout`. Keep only the JSON lines when piping into other tools:

```bash
./synfin -i capture.pcap | grep '^{' | jq -r '"\(.source.ip):\(.source.port) -> \(.destination.ip):\(.destination.port)"'
```

## Output format

Each session is printed to `stdout` as a single-line JSON object:

```json
{"source":{"ip":"192.168.1.10","port":54321},"destination":{"ip":"93.184.216.34","port":443},"start_time":{"seconds":1717000000,"microseconds":123456},"end_time":{"seconds":1717000042,"microseconds":654321}, "timeout":false,"closed_by":"fin"}
```

- `source` — the endpoint that opened the connection: the sender of the session's first packet, or its receiver if that first packet is a SYN-ACK (the capture started mid-handshake). `destination` is the other endpoint.
- `start_time` / `end_time` — Unix timestamps of the first and last packet seen for the session, from the capture itself (not wall-clock time)
- `closed_by` — how the session ended:
  - `fin` — FIN seen from both sides;
  - `rst` — a RST was seen;
  - `timeout` — no packets for longer than `--timeout` seconds of capture time;
  - `end_of_capture` — the input ended while the session was still open and not yet idle for `--timeout`.
- `timeout` — `true` exactly when `closed_by` is `timeout` (kept for compatibility with 0.1.0)

## How it works

1. **Packet capture** – each input file is opened with `libpcap` (`pcap_open_offline`) and read packet by packet.
2. **Parsing** – only Ethernet-framed IPv4/TCP packets are analyzed (`DLT_EN10MB` link layer); everything else is skipped. The Ethernet, IPv4, and TCP headers are parsed manually to pull out source/destination IP and port and the TCP flags.
3. **Session sharding** – each packet is reduced to a canonical `SessionKey` (the IP:port pair of both endpoints, direction-independent) and hashed to one of *N* worker threads. Because a given session always hashes to the same worker, its packets are processed in order with no locking needed between sessions.
4. **Session tracking** – each worker keeps a hash map of open sessions and updates the start/end time on every packet. A session is closed and handed off for output when:
   - a **RST** is seen, or
   - **FIN** has been seen in both directions, or
   - it has been idle longer than `--timeout` seconds. Idle time is measured in capture time — against the timestamp of the packet being read, not the computer's clock — so old captures are handled correctly. The check runs every 1000 packets and once more at the end of the input.

   Sessions left open when the input ends are reported too, with `closed_by: "end_of_capture"`.
5. **Output** – a dedicated output thread drains completed sessions from a lock-free queue and prints one JSON object per line to `stdout`, so results can be consumed while analysis is still running.

The GUI is a thin wrapper: it starts `synfin -t <timeout> -j <threads> -i <files…>` as a subprocess (through `stdbuf -oL` when available, so rows arrive line by line), parses each JSON line from `stdout` into a table row and shows everything else in the log.

## Project layout

| Path | Contents |
| --- | --- |
| `synfin.cpp` | Command-line entry point: option parsing, input file discovery |
| `session_analyzer.h` | `SessionAnalyzer` — packet parsing, worker threads, session tracking, JSON output |
| `tcp_ip_headers.h` | Packed Ethernet / IPv4 / TCP header structs and flag constants |
| `CMakeLists.txt` | Build configuration |
| `gui/synfin_gui.py` | Tkinter GUI |
| `tests/test_sessions.py` | End-to-end test with a synthetic capture |
| `docs/screenshots/` | Screenshots used in this README |

## Tests

`tests/test_sessions.py` writes a synthetic capture with known sessions (normal close with the final ACK, reset with trailing packets, port reuse, capture starting mid-handshake, a real timeout, a session still open at the end, and 300 background sessions, all dated years in the past) and checks every session the analyzer reports, with 1 and 4 worker threads:

```bash
python3 tests/test_sessions.py build/synfin
```

## Known limitations

- Only Ethernet-framed IPv4/TCP is analyzed; IPv6, VLAN-tagged frames and other link layers are skipped. `--dir` and the GUI's **Add folder…** pick up only `.pcap` files (not `.pcapng`).
- The `-q`/`--queue-size` option is parsed but not yet wired into `SessionAnalyzer`'s internal queue sizes.
