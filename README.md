# TCP-IP_Analyzed

A multithreaded C++ tool that reads `.pcap` capture files, reconstructs TCP sessions from the raw packets, and streams each finished session out as a JSON line — its client/server addresses, ports, start/end timestamps, and whether it closed normally or timed out.

It's built for offline analysis of large packet captures: instead of loading a whole capture into memory, it streams packets from libpcap, shards them across worker threads by session, and emits results as soon as each session ends.

## How it works

1. **Packet capture** – each input file is opened with `libpcap` (`pcap_open_offline`) and read packet by packet.
2. **Parsing** – only Ethernet-framed IPv4/TCP packets are analyzed (`DLT_EN10MB` link layer); everything else is skipped. The Ethernet, IPv4, and TCP headers are parsed manually to pull out source/destination IP and port and the TCP flags.
3. **Session sharding** – each packet is reduced to a canonical `SessionKey` (the IP:port pair of both endpoints, direction-independent) and hashed to one of *N* worker threads. Because a given session always hashes to the same worker, its packets are processed in order with no locking needed between sessions.
4. **Session tracking** – each worker keeps a hash map of open sessions and updates the start/end time on every packet. A session is closed and handed off for output when:
   - a **RST** is seen, or
   - **FIN** has been seen in both directions, or
   - it has been idle longer than `--timeout` seconds (checked periodically as packets are read).
5. **Output** – a dedicated output thread drains completed sessions from a lock-free queue and prints one JSON object per line to `stdout`, so results can be piped straight into another tool (`jq`, a log shipper, etc.) while analysis is still running.

## Supported platforms

Linux only. The code relies on `libpcap`'s `DLT_EN10MB` Ethernet capture format and on POSIX/Linux headers (`<endian.h>`, `<unistd.h>`), so it will not build as-is on Windows or macOS.

## Requirements

- CMake 3.10+
- A C++17 compiler (GCC or Clang)
- [libpcap](https://www.tcpdump.org/) (development headers)
- Boost 1.74+ (`program_options`, `lockfree`)
- [jsoncpp](https://github.com/open-source-parsers/jsoncpp)

On Debian/Ubuntu:

```bash
sudo apt-get install build-essential cmake libpcap-dev libboost-program-options-dev libjsoncpp-dev
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

## Usage

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
| `-q`, `--queue-size <n>` | Size of the internal packet queues | `2048` |
| `-h`, `--help` | Show usage information | — |

`--input`/`-i` and `--dir`/`-d` can be combined; at least one input file must be found or the tool exits with an error.

## Graphical interface

`gui/tcp_analyzer_gui.py` is a small Tkinter front end for Linux: pick `.pcap` files (or a whole folder), set the timeout and thread count, press **Analyze**, and every session shows up in a sortable table (timed-out sessions are highlighted). The table can be filtered by IP/port and exported to CSV or JSON Lines.

It only needs Python 3 with Tkinter:

```bash
sudo apt-get install python3-tk
```

Build the analyzer first (see above), then from the project root:

```bash
python3 gui/tcp_analyzer_gui.py
```

The GUI looks for the binary at `build/TCP_Analysis`; another location can be chosen with **Browse…**.

## Output format

Each completed session is printed to `stdout` as a single-line JSON object:

```json
{"source":{"ip":"192.168.1.10","port":54321},"destination":{"ip":"93.184.216.34","port":443},"start_time":{"seconds":1717000000,"microseconds":123456},"end_time":{"seconds":1717000042,"microseconds":654321},"timeout":false}
```

- `source` / `destination` — the endpoint that sent the first packet of the session and the endpoint it talked to
- `start_time` / `end_time` — timestamps of the first and last packet seen for the session, from the capture itself (not wall-clock time)
- `timeout` — `true` if the session was closed because it exceeded `--timeout` with no FIN/RST seen, `false` if it closed normally (RST, or FIN from both sides)

## Known limitations

- The `-q`/`--queue-size` option is parsed but not yet wired into `SessionAnalyzer`'s internal queue sizes.

## License

No license has been specified for this project. All rights reserved by the author unless stated otherwise.
