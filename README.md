# TCP-IP_Analyzed

A multithreaded C++ tool that reads `.pcap` capture files, reconstructs TCP sessions from the raw packets, and reports each finished session — its endpoints (IP and port), start/end timestamps, and whether it closed normally (FIN/RST) or timed out. It comes with two front ends:

- **`TCP_Analysis`** — the command-line analyzer; prints one JSON object per session to `stdout`, ready to pipe into `jq`, a log shipper or a script.
- **TCP Session Analyzer GUI** — a small desktop window (Python + Tkinter) that runs the analyzer for you and shows the sessions in a sortable, filterable table.

![TCP Session Analyzer GUI with analysis results](docs/screenshots/02-results.png)

It's built for offline analysis of large packet captures: instead of loading a whole capture into memory, it streams packets from libpcap, shards them across worker threads by session, and emits results as soon as each session ends.

## Contents

- [Where it runs](#where-it-runs)
- [Requirements](#requirements)
- [Building](#building)
- [Graphical interface](#graphical-interface)
- [Command-line usage](#command-line-usage)
- [Output format](#output-format)
- [How it works](#how-it-works)
- [Project layout](#project-layout)
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
git clone https://github.com/konerai/TCP-IP_Analyzed.git
cd TCP-IP_Analyzed
mkdir build && cd build
cmake ..
make
```

This produces the `TCP_Analysis` binary in `build/`.

## Graphical interface

`gui/tcp_analyzer_gui.py` is a desktop front end for the analyzer. Build the analyzer first (see above), then from the project root:

```bash
python3 gui/tcp_analyzer_gui.py
```

The GUI looks for the binary at `build/TCP_Analysis` (then `./TCP_Analysis`, then `TCP_Analysis` on `PATH`); another location can be chosen with **Browse…**.

![Main window before an analysis](docs/screenshots/01-start.png)

### Workflow

1. **Add captures** — **Add files…** picks one or more `.pcap` files, **Add folder…** adds every `.pcap` file in a directory. **Remove** deletes the selected entries, **Clear** empties the list.
2. **Set options** — **Timeout, s** is the idle time after which an unfinished session is reported as timed out (`--timeout`); **Threads** is the number of worker threads (`--threads`, defaults to the number of CPU cores).
3. **Analyze** — runs `TCP_Analysis` on all listed files. Sessions appear in the table while the analyzer is still running; **Stop** terminates it early.
4. **Explore and export** the results (see below).

### Results table

Each row is one TCP session reported by the analyzer:

| Column | Meaning |
| --- | --- |
| `#` | Order in which the analyzer reported the session |
| Source / Destination | `IP:port` of the two endpoints |
| Start / End | Timestamps of the first and last packet of the session, taken from the capture (local time, microsecond precision) |
| Duration, s | End − Start |
| Closed by | `FIN/RST` — closed normally; `timeout` — idle longer than the timeout. Timed-out rows are highlighted in orange |

The status bar shows the run state and the number of sessions, timed-out sessions and rows currently shown. Everything the analyzer writes besides session JSON (its header lines, errors on `stderr`, the exit code) goes to the **Log** pane.

### Filtering

Type into **Filter** to show only rows where any column contains the text — an IP address, a port (`:443`), a date, or `timeout` to see just the sessions that timed out:

![Filtering for timed-out sessions](docs/screenshots/03-filter.png)

### Sorting

Click a column header to sort by it, click again to reverse the order. Numeric columns (`#`, Duration) sort by value — for example, the longest sessions first:

![Sessions sorted by duration](docs/screenshots/04-sorted.png)

### Export

**Export…** saves all sessions from the last run (regardless of the filter):

- **CSV** (`.csv`) — the same columns as the table, ready for a spreadsheet;
- **JSON Lines** (`.jsonl`) — the analyzer's original JSON objects, one per line.

## Command-line usage

Analyze one or more capture files directly:

```bash
./TCP_Analysis -i capture1.pcap capture2.pcap
```

Or point it at a directory and it will pick up every `.pcap` file in it:

```bash
./TCP_Analysis -d /path/to/captures/
```

### Options

| Option | Description | Default |
| --- | --- | --- |
| `-i`, `--input <files...>` | One or more input `.pcap` files | — |
| `-d`, `--dir <path>` | Directory to scan for `.pcap` files | — |
| `-t`, `--timeout <seconds>` | Idle time after which an open session is force-closed and reported | `600` |
| `-j`, `--threads <n>` | Number of worker threads used to process sessions in parallel | number of CPU cores |
| `-q`, `--queue-size <n>` | Size of the internal packet queues (currently not used, see below) | `2048` |
| `-h`, `--help` | Show usage information | — |

`--input`/`-i` and `--dir`/`-d` can be combined; at least one input file must be found or the tool exits with an error.

Before the sessions, the analyzer prints a few plain-text header lines (`Analyzing files: …`, `Timeout: …`, `Threads: …`) to `stdout`. Keep only the JSON lines when piping into other tools:

```bash
./TCP_Analysis -i capture.pcap | grep '^{' | jq -r '"\(.source.ip):\(.source.port) -> \(.destination.ip):\(.destination.port)"'
```

## Output format

Each completed session is printed to `stdout` as a single-line JSON object:

```json
{"source":{"ip":"192.168.1.10","port":54321},"destination":{"ip":"93.184.216.34","port":443},"start_time":{"seconds":1717000000,"microseconds":123456},"end_time":{"seconds":1717000042,"microseconds":654321},"timeout":false}
```

- `source` / `destination` — the two endpoints of the session (see [Known limitations](#known-limitations) for which one ends up as `source`)
- `start_time` / `end_time` — Unix timestamps of the first and last packet seen for the session, from the capture itself (not wall-clock time)
- `timeout` — `true` if the session was closed because it exceeded `--timeout` with no FIN/RST seen, `false` if it closed normally (RST, or FIN from both sides)

## How it works

1. **Packet capture** – each input file is opened with `libpcap` (`pcap_open_offline`) and read packet by packet.
2. **Parsing** – only Ethernet-framed IPv4/TCP packets are analyzed (`DLT_EN10MB` link layer); everything else is skipped. The Ethernet, IPv4, and TCP headers are parsed manually to pull out source/destination IP and port and the TCP flags.
3. **Session sharding** – each packet is reduced to a canonical `SessionKey` (the IP:port pair of both endpoints, direction-independent) and hashed to one of *N* worker threads. Because a given session always hashes to the same worker, its packets are processed in order with no locking needed between sessions.
4. **Session tracking** – each worker keeps a hash map of open sessions and updates the start/end time on every packet. A session is closed and handed off for output when:
   - a **RST** is seen, or
   - **FIN** has been seen in both directions, or
   - it has been idle longer than `--timeout` seconds (checked every 1000 packets).
5. **Output** – a dedicated output thread drains completed sessions from a lock-free queue and prints one JSON object per line to `stdout`, so results can be consumed while analysis is still running.

The GUI is a thin wrapper: it starts `TCP_Analysis -t <timeout> -j <threads> -i <files…>` as a subprocess (through `stdbuf -oL` when available, so rows arrive line by line), parses each JSON line from `stdout` into a table row and shows everything else in the log.

## Project layout

| Path | Contents |
| --- | --- |
| `TCP_Analysis.cpp` | Command-line entry point: option parsing, input file discovery |
| `Session_Analyzed.h` | `SessionAnalyzer` — packet parsing, worker threads, session tracking, JSON output |
| `TCP_IP_Header.h` | Packed Ethernet / IPv4 / TCP header structs and flag constants |
| `CMakeLists.txt` | Build configuration |
| `gui/tcp_analyzer_gui.py` | Tkinter GUI |
| `docs/screenshots/` | Screenshots used in this README |

## Known limitations

- **Timeouts are measured against the current time, not the capture's time.** The idle check compares each session's last packet with the computer's clock. On a capture recorded more than `--timeout` seconds ago, every session that is still open when a check runs is reported as timed out (and its remaining packets start a new session). Until this is fixed, analyze old captures with a `--timeout` larger than their age.
- **`source` is not always the initiator.** A session closed by FIN/RST is reported with the direction of the packet that closed it, so `source` is often the server (e.g. `93.184.216.34:443 → 192.168.1.10:54321`). Timed-out sessions keep the direction of their first packet.
- **Sessions still open at the end of the input are not reported.** Only sessions closed by FIN/RST or the timeout check appear in the output.
- Only Ethernet-framed IPv4/TCP is analyzed; IPv6, VLAN-tagged frames and other link layers are skipped. `--dir` and the GUI's **Add folder…** pick up only `.pcap` files (not `.pcapng`).
- The `-q`/`--queue-size` option is parsed but not yet wired into `SessionAnalyzer`'s internal queue sizes.

## License

No license has been specified for this project. All rights reserved by the author unless stated otherwise.
