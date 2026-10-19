#!/usr/bin/env python3
"""Simple Tkinter GUI for the TCP_Analysis command-line tool.

Runs the TCP_Analysis binary on the chosen .pcap files and shows every
reported TCP session in a table. Needs only Python 3 with Tkinter
(Debian/Ubuntu: sudo apt-get install python3-tk).
"""

import csv
import json
import os
import queue
import shutil
import subprocess
import threading
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BINARY_CANDIDATES = [
    os.path.join(PROJECT_DIR, "build", "TCP_Analysis"),
    os.path.join(PROJECT_DIR, "TCP_Analysis"),
]
PCAP_EXTENSIONS = (".pcap",)
ROWS_PER_TICK = 2000  # keep the UI responsive on huge captures

COLUMNS = [
    ("num", "#", 60),
    ("src", "Source", 170),
    ("dst", "Destination", 170),
    ("start", "Start", 200),
    ("end", "End", 200),
    ("duration", "Duration, s", 100),
    ("status", "Closed by", 90),
]


def find_default_binary():
    for path in BINARY_CANDIDATES:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return shutil.which("TCP_Analysis") or BINARY_CANDIDATES[0]


def format_ts(ts):
    seconds = ts["seconds"] + ts["microseconds"] / 1_000_000
    return datetime.fromtimestamp(seconds).strftime("%Y-%m-%d %H:%M:%S.%f")


def to_seconds(ts):
    return ts["seconds"] + ts["microseconds"] / 1_000_000


class AnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("TCP Session Analyzer")
        self.root.geometry("1100x700")
        self.root.minsize(800, 500)

        self.process = None
        self.events = queue.Queue()
        self.sessions = []  # raw JSON objects, in the order they arrived
        self.timeouts = 0
        self.finished = False

        self.binary_var = tk.StringVar(value=find_default_binary())
        self.timeout_var = tk.IntVar(value=600)
        self.threads_var = tk.IntVar(value=os.cpu_count() or 1)
        self.filter_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")

        self._build_ui()
        self.filter_var.trace_add("write", lambda *_: self._apply_filter())
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(100, self._drain_events)

    # ---------- layout ----------

    def _build_ui(self):
        top = ttk.Frame(self.root, padding=8)
        top.pack(fill=tk.X)

        # Binary
        ttk.Label(top, text="TCP_Analysis binary:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(top, textvariable=self.binary_var).grid(row=0, column=1, sticky=tk.EW, padx=4)
        ttk.Button(top, text="Browse…", command=self._choose_binary).grid(row=0, column=2)
        top.columnconfigure(1, weight=1)

        # Input files
        files_frame = ttk.LabelFrame(self.root, text="Input .pcap files", padding=8)
        files_frame.pack(fill=tk.X, padx=8)

        self.files_list = tk.Listbox(files_frame, height=4, selectmode=tk.EXTENDED)
        self.files_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        file_buttons = ttk.Frame(files_frame)
        file_buttons.pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(file_buttons, text="Add files…", command=self._add_files).pack(fill=tk.X)
        ttk.Button(file_buttons, text="Add folder…", command=self._add_folder).pack(fill=tk.X, pady=2)
        ttk.Button(file_buttons, text="Remove", command=self._remove_files).pack(fill=tk.X)
        ttk.Button(file_buttons, text="Clear", command=lambda: self.files_list.delete(0, tk.END)).pack(fill=tk.X, pady=2)

        # Options + run controls
        options = ttk.Frame(self.root, padding=8)
        options.pack(fill=tk.X)
        ttk.Label(options, text="Timeout, s:").pack(side=tk.LEFT)
        ttk.Spinbox(options, from_=1, to=86400, width=8, textvariable=self.timeout_var).pack(side=tk.LEFT, padx=(4, 12))
        ttk.Label(options, text="Threads:").pack(side=tk.LEFT)
        ttk.Spinbox(options, from_=1, to=256, width=5, textvariable=self.threads_var).pack(side=tk.LEFT, padx=(4, 12))

        self.run_button = ttk.Button(options, text="▶ Analyze", command=self._start)
        self.run_button.pack(side=tk.LEFT)
        self.stop_button = ttk.Button(options, text="■ Stop", command=self._stop, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=4)

        ttk.Button(options, text="Export…", command=self._export).pack(side=tk.RIGHT)
        ttk.Entry(options, textvariable=self.filter_var, width=24).pack(side=tk.RIGHT, padx=4)
        ttk.Label(options, text="Filter:").pack(side=tk.RIGHT)

        # Results table and log
        panes = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        panes.pack(fill=tk.BOTH, expand=True, padx=8)

        table_frame = ttk.Frame(panes)
        self.table = ttk.Treeview(table_frame, columns=[c[0] for c in COLUMNS], show="headings")
        for key, title, width in COLUMNS:
            self.table.heading(key, text=title, command=lambda k=key: self._sort_by(k, False))
            self.table.column(key, width=width, anchor=tk.W, stretch=key in ("src", "dst"))
        self.table.tag_configure("timeout", foreground="#b35c00")
        yscroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.table.yview)
        self.table.configure(yscrollcommand=yscroll.set)
        self.table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)
        panes.add(table_frame, weight=4)

        log_frame = ttk.LabelFrame(panes, text="Log", padding=4)
        self.log = tk.Text(log_frame, height=6, state=tk.DISABLED, wrap=tk.WORD)
        self.log.pack(fill=tk.BOTH, expand=True)
        panes.add(log_frame, weight=1)

        ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=(8, 2)).pack(fill=tk.X, side=tk.BOTTOM)

    # ---------- file selection ----------

    def _choose_binary(self):
        path = filedialog.askopenfilename(title="Select TCP_Analysis binary", initialdir=PROJECT_DIR)
        if path:
            self.binary_var.set(path)

    def _current_files(self):
        return list(self.files_list.get(0, tk.END))

    def _add_paths(self, paths):
        existing = set(self._current_files())
        for path in paths:
            if path not in existing:
                self.files_list.insert(tk.END, path)
                existing.add(path)

    def _add_files(self):
        paths = filedialog.askopenfilenames(
            title="Select capture files",
            filetypes=[("pcap captures", "*.pcap"), ("All files", "*")],
        )
        self._add_paths(paths)

    def _add_folder(self):
        folder = filedialog.askdirectory(title="Select folder with .pcap files")
        if not folder:
            return
        found = sorted(
            os.path.join(folder, name)
            for name in os.listdir(folder)
            if name.lower().endswith(PCAP_EXTENSIONS)
        )
        if not found:
            messagebox.showinfo("No captures", f"No .pcap files in {folder}")
        self._add_paths(found)

    def _remove_files(self):
        for index in reversed(self.files_list.curselection()):
            self.files_list.delete(index)

    # ---------- running the analyzer ----------

    def _start(self):
        binary = self.binary_var.get().strip()
        files = self._current_files()
        if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
            messagebox.showerror("Binary not found", f"Cannot run {binary!r}.\nBuild the project first (see README).")
            return
        if not files:
            messagebox.showerror("No input", "Add at least one .pcap file.")
            return
        try:
            timeout = int(self.timeout_var.get())
            threads = int(self.threads_var.get())
        except (tk.TclError, ValueError):
            messagebox.showerror("Bad options", "Timeout and threads must be whole numbers.")
            return

        cmd = [binary, "-t", str(timeout), "-j", str(threads), "-i", *files]
        # The analyzer writes "\n" without flushing, so line-buffer it when we can
        # to get rows while it is still running rather than all at the end.
        if shutil.which("stdbuf"):
            cmd = ["stdbuf", "-oL", *cmd]

        self._clear_results()
        self._log("$ " + " ".join(cmd))
        try:
            self.process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
            )
        except OSError as exc:
            messagebox.showerror("Failed to start", str(exc))
            self.process = None
            return

        self.run_button.configure(state=tk.DISABLED)
        self.stop_button.configure(state=tk.NORMAL)
        self.status_var.set("Analyzing…")
        threading.Thread(target=self._read_stream, args=(self.process.stdout, "out"), daemon=True).start()
        threading.Thread(target=self._read_stream, args=(self.process.stderr, "err"), daemon=True).start()
        threading.Thread(target=self._wait_process, args=(self.process,), daemon=True).start()

    def _read_stream(self, stream, kind):
        for line in stream:
            self.events.put((kind, line.rstrip("\n")))

    def _wait_process(self, process):
        code = process.wait()
        self.events.put(("exit", code))

    def _stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self._log("Stopped by user.")

    def _drain_events(self):
        handled = 0
        try:
            while handled < ROWS_PER_TICK:
                kind, payload = self.events.get_nowait()
                handled += 1
                if kind == "out":
                    self._handle_output_line(payload)
                elif kind == "err":
                    self._log(payload)
                elif kind == "exit":
                    self._finish(payload)
        except queue.Empty:
            pass
        if handled:
            self._update_status()
        self.root.after(50 if handled else 100, self._drain_events)

    def _handle_output_line(self, line):
        if not line.startswith("{"):
            if line:
                self._log(line)  # "Analyzing files: ...", "Timeout: ..." etc.
            return
        try:
            session = json.loads(line)
        except json.JSONDecodeError:
            self._log("Unparsed: " + line)
            return
        self.sessions.append(session)
        if session.get("timeout"):
            self.timeouts += 1
        if self._matches_filter(session):
            self._insert_row(len(self.sessions), session)

    def _finish(self, code):
        self.process = None
        self.run_button.configure(state=tk.NORMAL)
        self.stop_button.configure(state=tk.DISABLED)
        self.finished = True
        self._log(f"Analyzer exited with code {code}.")

    # ---------- table ----------

    @staticmethod
    def _row_values(num, s):
        start, end = s["start_time"], s["end_time"]
        return (
            num,
            f'{s["source"]["ip"]}:{s["source"]["port"]}',
            f'{s["destination"]["ip"]}:{s["destination"]["port"]}',
            format_ts(start),
            format_ts(end),
            f"{to_seconds(end) - to_seconds(start):.6f}",
            "timeout" if s.get("timeout") else "FIN/RST",
        )

    def _insert_row(self, num, session):
        tags = ("timeout",) if session.get("timeout") else ()
        self.table.insert("", tk.END, values=self._row_values(num, session), tags=tags)

    def _matches_filter(self, session):
        needle = self.filter_var.get().strip().lower()
        if not needle:
            return True
        return any(needle in str(v).lower() for v in self._row_values(0, session)[1:])

    def _apply_filter(self):
        self.table.delete(*self.table.get_children())
        for num, session in enumerate(self.sessions, start=1):
            if self._matches_filter(session):
                self._insert_row(num, session)
        self._update_status()

    def _sort_by(self, column, descending):
        rows = [(self.table.set(item, column), item) for item in self.table.get_children("")]

        def key(row):
            value = row[0]
            try:
                return (0, float(value))
            except ValueError:
                return (1, value)

        rows.sort(key=key, reverse=descending)
        for index, (_, item) in enumerate(rows):
            self.table.move(item, "", index)
        self.table.heading(column, command=lambda: self._sort_by(column, not descending))

    def _clear_results(self):
        self.sessions.clear()
        self.timeouts = 0
        self.finished = False
        self.table.delete(*self.table.get_children())
        self.log.configure(state=tk.NORMAL)
        self.log.delete("1.0", tk.END)
        self.log.configure(state=tk.DISABLED)

    def _update_status(self):
        shown = len(self.table.get_children())
        total = len(self.sessions)
        state = "Analyzing…" if self.process else ("Done" if self.finished else "Ready")
        self.status_var.set(
            f"{state}   Sessions: {total}   Timed out: {self.timeouts}   Shown: {shown}"
        )

    def _log(self, text):
        self.log.configure(state=tk.NORMAL)
        self.log.insert(tk.END, text + "\n")
        self.log.see(tk.END)
        self.log.configure(state=tk.DISABLED)

    # ---------- export ----------

    def _export(self):
        if not self.sessions:
            messagebox.showinfo("Nothing to export", "Run an analysis first.")
            return
        path = filedialog.asksaveasfilename(
            title="Export sessions",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("JSON Lines", "*.jsonl")],
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                if path.endswith(".jsonl"):
                    for session in self.sessions:
                        f.write(json.dumps(session) + "\n")
                else:
                    writer = csv.writer(f)
                    writer.writerow([title for _, title, _ in COLUMNS])
                    for num, session in enumerate(self.sessions, start=1):
                        writer.writerow(self._row_values(num, session))
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        self._log(f"Exported {len(self.sessions)} sessions to {path}")

    def _on_close(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
        self.root.destroy()


def main():
    root = tk.Tk()
    AnalyzerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
