#!/usr/bin/env python3
"""SynFin: a desktop GUI for the synfin TCP session analyzer.

Runs the synfin binary on the chosen .pcap / .pcapng files and shows every
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
import time
import tkinter as tk
import tkinter.font as tkfont
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BINARY_CANDIDATES = [
    os.path.join(PROJECT_DIR, "build", "synfin"),
    os.path.join(PROJECT_DIR, "synfin"),
]
ICON_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icons")
ICON_SIZES = (16, 24, 32, 48, 64, 128, 256)
PCAP_EXTENSIONS = (".pcap", ".pcapng")
ROWS_PER_TICK = 2000  # keep the UI responsive on huge captures

# Dark palette
BG = "#0d1117"
SURFACE = "#161b22"
RAISED = "#1f2630"
HOVER = "#262d38"
BORDER = "#30363d"
BORDER_HI = "#484f58"
TEXT = "#e6edf3"
MUTED = "#8b949e"
FAINT = "#6e7681"
ACCENT = "#2f81f7"
ACCENT_HI = "#4493f8"
ACCENT_LO = "#1f6feb"
ROW_ALT = "#1a2029"
SELECT = "#1c3a63"

# How a session ended: key from the analyzer's "closed_by" -> (label, color)
STATUSES = {
    "fin": ("FIN", "#3fb950"),
    "rst": ("RST", "#f85149"),
    "timeout": ("Timeout", "#d29922"),
    "end_of_capture": ("Still open", "#a371f7"),
}
LEGACY_CLOSED = ("FIN/RST", TEXT)  # analyzers older than 0.2.0 don't tell FIN and RST apart

# The status is shown in the tree column (#0) so it can carry a colored dot.
STATUS_COLUMN = ("#0", "Closed by", 110)
COLUMNS = [
    # key, title, width, stretch
    ("num", "#", 46, False),
    ("src", "Source", 140, True),
    ("dst", "Destination", 140, True),
    ("start", "Start", 194, False),
    ("end", "End", 194, False),
    ("duration", "Duration, s", 104, False),
]
EXPORT_HEADER = [title for _, title, _, _ in COLUMNS] + [STATUS_COLUMN[1]]


def find_default_binary():
    for path in BINARY_CANDIDATES:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return shutil.which("synfin") or BINARY_CANDIDATES[0]


def status_key(session):
    reason = session.get("closed_by")
    if reason is None:
        return "timeout" if session.get("timeout") else "closed"
    return reason


def status_label(key):
    return STATUSES.get(key, LEGACY_CLOSED)[0]


def to_seconds(ts):
    return ts["seconds"] + ts["microseconds"] / 1_000_000


def format_ts(ts, precise):
    text = datetime.fromtimestamp(to_seconds(ts)).strftime("%Y-%m-%d %H:%M:%S.%f")
    return text if precise else text[:-3]


def make_dot(color, diameter=9, width=20):
    """A colored circle on a transparent image, padded on the right to space it from the text."""
    image = tk.PhotoImage(width=width, height=diameter)
    r = diameter / 2
    for y in range(diameter):
        for x in range(diameter):
            if (x + 0.5 - r) ** 2 + (y + 0.5 - r) ** 2 <= r * r:
                image.put(color, (x, y))
    return image


def pick_family(root, candidates, fallback_font):
    available = set(tkfont.families(root))
    for name in candidates:
        if name in available:
            return name
    return tkfont.nametofont(fallback_font).actual("family")


def shorten_home(path):
    home = os.path.expanduser("~")
    return "~" + path[len(home):] if path.startswith(home + os.sep) else path


class AnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SynFin — TCP Session Analyzer")
        self.root.geometry("1360x840")
        self.root.minsize(1100, 680)
        self.root.configure(bg=BG)
        self._set_window_icon()

        self.process = None
        self.events = queue.Queue()
        self.files = []
        self.sessions = []  # raw JSON objects, in the order they arrived
        self.counts = {}
        self.finished = False
        self.exit_code = None
        self.started_at = None
        self.elapsed = 0.0
        self.status_filter = None
        self.sort_state = None  # (column, descending)

        self.binary_var = tk.StringVar(value=find_default_binary())
        self.timeout_var = tk.IntVar(value=600)
        self.threads_var = tk.IntVar(value=os.cpu_count() or 1)
        self.filter_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")

        self._init_fonts()
        self._init_styles()
        self._build_ui()
        self._reset_counts()
        self._refresh_files()
        self._check_binary()

        self.filter_var.trace_add("write", lambda *_: self._apply_filter())
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(100, self._drain_events)

    # ---------- look ----------

    def _icon(self, size):
        path = os.path.join(ICON_DIR, f"synfin-{size}.png")
        try:
            return tk.PhotoImage(file=path)
        except tk.TclError:  # icons missing, e.g. the script was copied on its own
            return None

    def _set_window_icon(self):
        self.icons = [icon for icon in map(self._icon, ICON_SIZES) if icon]
        if self.icons:
            self.root.iconphoto(True, *self.icons)

    def _init_fonts(self):
        ui = pick_family(self.root, ["Inter", "Ubuntu", "Cantarell", "Noto Sans", "DejaVu Sans"], "TkDefaultFont")
        mono = pick_family(self.root, ["JetBrains Mono", "Ubuntu Mono", "Noto Sans Mono", "DejaVu Sans Mono"],
                           "TkFixedFont")
        self.f_base = (ui, 10)
        self.f_small = (ui, 9)
        self.f_label = (ui, 8, "bold")
        self.f_bold = (ui, 10, "bold")
        self.f_h2 = (ui, 11, "bold")
        self.f_title = (ui, 17, "bold")
        self.f_stat = (ui, 22, "bold")
        self.f_mono = (mono, 9)

    def _init_styles(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure(".", background=SURFACE, foreground=TEXT, font=self.f_base,
                        bordercolor=BORDER, lightcolor=SURFACE, darkcolor=SURFACE,
                        troughcolor=SURFACE, fieldbackground=RAISED,
                        selectbackground=SELECT, selectforeground=TEXT, insertcolor=TEXT)

        # Buttons
        style.configure("TButton", background=RAISED, foreground=TEXT, bordercolor=BORDER,
                        lightcolor=RAISED, darkcolor=RAISED, focuscolor=RAISED,
                        padding=(12, 6), relief="flat")
        style.map("TButton",
                  background=[("disabled", SURFACE), ("pressed", BORDER), ("active", HOVER)],
                  lightcolor=[("disabled", SURFACE), ("pressed", BORDER), ("active", HOVER)],
                  darkcolor=[("disabled", SURFACE), ("pressed", BORDER), ("active", HOVER)],
                  focuscolor=[("active", HOVER)],
                  bordercolor=[("active", BORDER_HI)],
                  foreground=[("disabled", FAINT)])
        style.configure("Accent.TButton", background=ACCENT, foreground="#ffffff", bordercolor=ACCENT,
                        lightcolor=ACCENT, darkcolor=ACCENT, focuscolor=ACCENT,
                        font=self.f_bold, padding=(16, 9))
        style.map("Accent.TButton",
                  background=[("disabled", RAISED), ("pressed", ACCENT_LO), ("active", ACCENT_HI)],
                  lightcolor=[("disabled", RAISED), ("pressed", ACCENT_LO), ("active", ACCENT_HI)],
                  darkcolor=[("disabled", RAISED), ("pressed", ACCENT_LO), ("active", ACCENT_HI)],
                  focuscolor=[("disabled", RAISED), ("active", ACCENT_HI)],
                  bordercolor=[("disabled", BORDER), ("active", ACCENT_HI)],
                  foreground=[("disabled", FAINT)])
        rst = STATUSES["rst"][1]
        style.configure("Stop.TButton", foreground=rst, font=self.f_bold, padding=(16, 9))
        style.map("Stop.TButton", foreground=[("disabled", FAINT)],
                  bordercolor=[("disabled", BORDER), ("active", rst)])

        # Inputs
        for name in ("TEntry", "TSpinbox"):
            style.configure(name, fieldbackground=RAISED, foreground=TEXT, bordercolor=BORDER,
                            lightcolor=RAISED, darkcolor=RAISED, background=RAISED,
                            arrowcolor=MUTED, padding=(8, 6), insertwidth=1)
            style.map(name, bordercolor=[("focus", ACCENT)], lightcolor=[("focus", RAISED)],
                      arrowcolor=[("active", TEXT)], background=[("active", HOVER)])

        # Table
        style.configure("Treeview", background=SURFACE, fieldbackground=SURFACE, foreground=TEXT,
                        bordercolor=SURFACE, lightcolor=SURFACE, darkcolor=SURFACE,
                        rowheight=28, font=self.f_base)
        style.map("Treeview", background=[("selected", SELECT)], foreground=[("selected", TEXT)])
        style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        style.layout("Treeview.Item", [("Treeitem.padding", {"sticky": "nswe", "children": [
            ("Treeitem.image", {"side": "left", "sticky": ""}),
            ("Treeitem.text", {"side": "left", "sticky": ""}),
        ]})])
        style.configure("Treeview", indent=0)
        style.configure("Treeview.Heading", background=RAISED, foreground=MUTED, font=self.f_label,
                        bordercolor=BORDER, lightcolor=RAISED, darkcolor=RAISED,
                        relief="flat", padding=(8, 7))
        style.map("Treeview.Heading", background=[("active", HOVER)], foreground=[("active", TEXT)])

        # Thin scrollbars without arrows
        for orient in ("Vertical", "Horizontal"):
            name = f"{orient}.TScrollbar"
            style.layout(name, [(f"{orient}.Scrollbar.trough", {
                "sticky": "ns" if orient == "Vertical" else "ew",
                "children": [(f"{orient}.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})],
            })])
            style.configure(name, background=BORDER, troughcolor=SURFACE, bordercolor=SURFACE,
                            lightcolor=BORDER, darkcolor=BORDER, gripcount=0, arrowsize=10)
            style.map(name, background=[("active", BORDER_HI)],
                      lightcolor=[("active", BORDER_HI)], darkcolor=[("active", BORDER_HI)])

        style.configure("Accent.Horizontal.TProgressbar", background=ACCENT, troughcolor=RAISED,
                        bordercolor=RAISED, lightcolor=ACCENT, darkcolor=ACCENT, thickness=4)
        style.configure("TPanedwindow", background=BG)
        style.configure("Sash", background=BG, lightcolor=BG, darkcolor=BG, bordercolor=BG,
                        sashthickness=12, gripcount=0)

    def _card(self, parent, title=None):
        outer = tk.Frame(parent, bg=SURFACE, highlightthickness=1,
                         highlightbackground=BORDER, highlightcolor=BORDER)
        header = None
        if title:
            header = tk.Frame(outer, bg=SURFACE)
            header.pack(fill=tk.X, padx=16, pady=(14, 10))
            tk.Label(header, text=title, font=self.f_h2, bg=SURFACE, fg=TEXT).pack(side=tk.LEFT)
        body = tk.Frame(outer, bg=SURFACE)
        body.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0 if title else 14, 16))
        return outer, header, body

    def _field_label(self, parent, text):
        return tk.Label(parent, text=text.upper(), font=self.f_label, bg=SURFACE, fg=MUTED, anchor="w")

    # ---------- layout ----------

    def _build_ui(self):
        # Header
        header = tk.Frame(self.root, bg=BG)
        header.pack(fill=tk.X, padx=24, pady=(18, 14))
        self.logo = self._icon(48)
        if self.logo:
            tk.Label(header, image=self.logo, bg=BG).pack(side=tk.LEFT, padx=(0, 12))
        titles = tk.Frame(header, bg=BG)
        titles.pack(side=tk.LEFT)
        tk.Label(titles, text="SynFin", font=self.f_title, bg=BG, fg=TEXT).pack(anchor="w")
        tk.Label(titles, text="TCP sessions from SYN to FIN, reconstructed from .pcap captures", font=self.f_base,
                 bg=BG, fg=MUTED).pack(anchor="w")
        self.version_pill = tk.Label(header, font=self.f_small, bg=RAISED, fg=MUTED, padx=12, pady=5,
                                     highlightthickness=1, highlightbackground=BORDER)
        self.version_pill.pack(side=tk.RIGHT, anchor="center")

        # Status bar (packed before the body so it keeps its place when the window shrinks)
        footer = tk.Frame(self.root, bg=SURFACE, highlightthickness=1, highlightbackground=BORDER)
        footer.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_dot = tk.Label(footer, text="●", font=self.f_small, bg=SURFACE, fg=FAINT)
        self.status_dot.pack(side=tk.LEFT, padx=(16, 6), pady=6)
        tk.Label(footer, textvariable=self.status_var, font=self.f_small, bg=SURFACE, fg=MUTED).pack(side=tk.LEFT)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill=tk.BOTH, expand=True, padx=24, pady=(0, 18))
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        sidebar = tk.Frame(body, bg=BG, width=310)
        sidebar.grid(row=0, column=0, sticky="ns", padx=(0, 18))
        sidebar.grid_propagate(False)
        sidebar.pack_propagate(False)
        self._build_sidebar(sidebar)

        main = tk.Frame(body, bg=BG)
        main.grid(row=0, column=1, sticky="nsew")
        self._build_main(main)

    def _build_sidebar(self, sidebar):
        # Captures
        card, header, files = self._card(sidebar, "Captures")
        card.pack(fill=tk.BOTH, expand=True)
        self.files_badge = tk.Label(header, font=self.f_label, bg=RAISED, fg=MUTED, padx=8, pady=2)
        self.files_badge.pack(side=tk.RIGHT)

        list_frame = tk.Frame(files, bg=RAISED, highlightthickness=1, highlightbackground=BORDER)
        list_frame.pack(fill=tk.BOTH, expand=True)
        self.files_list = tk.Listbox(
            list_frame, selectmode=tk.EXTENDED, activestyle="none", font=self.f_small,
            bg=RAISED, fg=TEXT, selectbackground=SELECT, selectforeground=TEXT,
            highlightthickness=0, borderwidth=0, relief=tk.FLAT,
        )
        self.files_list.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        self.files_list.bind("<Delete>", lambda _: self._remove_files())
        self.files_empty = tk.Label(list_frame, text="No captures yet\nAdd .pcap / .pcapng files or a folder",
                                    font=self.f_small, bg=RAISED, fg=FAINT, justify=tk.CENTER)

        buttons = tk.Frame(files, bg=SURFACE)
        buttons.pack(fill=tk.X, pady=(10, 0))
        buttons.columnconfigure((0, 1), weight=1, uniform="files")
        ttk.Button(buttons, text="Add files…", command=self._add_files).grid(row=0, column=0, sticky="ew", padx=(0, 4))
        ttk.Button(buttons, text="Add folder…", command=self._add_folder).grid(row=0, column=1, sticky="ew", padx=(4, 0))
        ttk.Button(buttons, text="Remove", command=self._remove_files).grid(row=1, column=0, sticky="ew", padx=(0, 4), pady=(8, 0))
        ttk.Button(buttons, text="Clear", command=self._clear_files).grid(row=1, column=1, sticky="ew", padx=(4, 0), pady=(8, 0))

        # Settings
        card, _, settings = self._card(sidebar, "Settings")
        card.pack(fill=tk.X, pady=(16, 0))
        settings.columnconfigure((0, 1), weight=1, uniform="settings")
        self._field_label(settings, "Timeout, s").grid(row=0, column=0, sticky="w")
        self._field_label(settings, "Threads").grid(row=0, column=1, sticky="w", padx=(8, 0))
        ttk.Spinbox(settings, from_=1, to=86400, increment=60, textvariable=self.timeout_var,
                    width=8).grid(row=1, column=0, sticky="ew", pady=(4, 12))
        ttk.Spinbox(settings, from_=1, to=256, textvariable=self.threads_var,
                    width=5).grid(row=1, column=1, sticky="ew", padx=(8, 0), pady=(4, 12))
        self._field_label(settings, "Analyzer binary").grid(row=2, column=0, columnspan=2, sticky="w")
        binary_row = tk.Frame(settings, bg=SURFACE)
        binary_row.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(4, 0))
        entry = ttk.Entry(binary_row, textvariable=self.binary_var)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        entry.bind("<FocusOut>", lambda _: self._check_binary())
        entry.bind("<Return>", lambda _: self._check_binary())
        ttk.Button(binary_row, text="…", width=3, command=self._choose_binary).pack(side=tk.LEFT, padx=(8, 0))

        # Run controls
        actions = tk.Frame(sidebar, bg=BG)
        actions.pack(fill=tk.X, pady=(16, 0))
        actions.columnconfigure((0, 1), weight=1, uniform="actions")  # same width for both buttons
        self.run_button = ttk.Button(actions, text="▶  Analyze", style="Accent.TButton", command=self._start)
        self.run_button.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        self.stop_button = ttk.Button(actions, text="■  Stop", style="Stop.TButton", command=self._stop,
                                      state=tk.DISABLED)
        self.stop_button.grid(row=0, column=1, sticky="nsew", padx=(4, 0))
        self.progress = ttk.Progressbar(actions, mode="indeterminate", style="Accent.Horizontal.TProgressbar")
        self.progress.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        self.progress.grid_remove()

    def _build_main(self, main):
        # Stat tiles; clicking one filters the table by that status
        tiles = tk.Frame(main, bg=BG)
        tiles.pack(fill=tk.X)
        self.tiles = {}
        tile_specs = [(None, "Sessions", TEXT)] + [(key, label, color) for key, (label, color) in STATUSES.items()]
        for index, (key, label, color) in enumerate(tile_specs):
            tiles.columnconfigure(index, weight=1, uniform="tiles")
            tile = tk.Frame(tiles, bg=SURFACE, highlightthickness=1, highlightbackground=BORDER, cursor="hand2")
            tile.grid(row=0, column=index, sticky="ew", padx=(0 if index == 0 else 12, 0))
            caption = tk.Frame(tile, bg=SURFACE)
            caption.pack(fill=tk.X, padx=16, pady=(14, 0))
            if key:
                tk.Label(caption, text="●", font=self.f_small, bg=SURFACE, fg=color).pack(side=tk.LEFT, padx=(0, 6))
            tk.Label(caption, text=label.upper(), font=self.f_label, bg=SURFACE, fg=MUTED).pack(side=tk.LEFT)
            value = tk.Label(tile, text="0", font=self.f_stat, bg=SURFACE, fg=color, anchor="w")
            value.pack(fill=tk.X, padx=16, pady=(2, 12))
            for widget in (tile, caption, value, *caption.winfo_children()):
                widget.bind("<Button-1>", lambda _, k=key: self._toggle_status_filter(k))
                widget.bind("<Enter>", lambda _, t=tile, k=key: self._hover_tile(t, k, True))
                widget.bind("<Leave>", lambda _, t=tile, k=key: self._hover_tile(t, k, False))
            self.tiles[key] = (tile, value, color)

        panes = ttk.PanedWindow(main, orient=tk.VERTICAL)
        panes.pack(fill=tk.BOTH, expand=True, pady=(16, 0))

        # Results
        card, header, results = self._card(panes, "Sessions")
        self.shown_label = tk.Label(header, font=self.f_small, bg=SURFACE, fg=MUTED)
        self.shown_label.pack(side=tk.LEFT, padx=(10, 0))
        ttk.Button(header, text="Export…", command=self._export).pack(side=tk.RIGHT)
        search = ttk.Entry(header, textvariable=self.filter_var, width=34)
        search.pack(side=tk.RIGHT, padx=(0, 8))
        hint = tk.Label(search, text="Filter by IP, port, date or status", font=self.f_small,
                        bg=RAISED, fg=FAINT, cursor="xterm")
        hint.bind("<Button-1>", lambda _: search.focus_set())

        def update_hint(*_):
            if self.filter_var.get() or self.root.focus_get() is search:
                hint.place_forget()
            else:
                hint.place(x=9, rely=0.5, anchor="w")

        search.bind("<FocusIn>", update_hint, add="+")
        search.bind("<FocusOut>", update_hint, add="+")
        self.filter_var.trace_add("write", update_hint)
        update_hint()

        table_frame = tk.Frame(results, bg=SURFACE, highlightthickness=1, highlightbackground=BORDER)
        table_frame.pack(fill=tk.BOTH, expand=True)
        self.table = ttk.Treeview(table_frame, columns=[c[0] for c in COLUMNS], show=("tree", "headings"))
        key, title, width = STATUS_COLUMN
        self.table.heading(key, text=title.upper(), anchor=tk.W, command=lambda: self._sort_by("#0"))
        self.table.column(key, width=width, minwidth=width, anchor=tk.W, stretch=False)
        for key, title, width, stretch in COLUMNS:
            self.table.heading(key, text=title.upper(), anchor=tk.W, command=lambda k=key: self._sort_by(k))
            self.table.column(key, width=width, minwidth=48, anchor=tk.W, stretch=stretch)
        self.dots = {key: make_dot(color) for key, (_, color) in STATUSES.items()}
        self.dots["closed"] = make_dot(MUTED)
        self.table.tag_configure("odd", background=ROW_ALT)
        yscroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.table.yview)
        self.table.configure(yscrollcommand=yscroll.set)
        self.table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)
        panes.add(card, weight=5)

        # Log
        card, _, log_body = self._card(panes, "Log")
        self.log = tk.Text(log_body, height=5, wrap=tk.WORD, font=self.f_mono, bg=SURFACE, fg=MUTED,
                           insertbackground=TEXT, relief=tk.FLAT, highlightthickness=0, borderwidth=0,
                           state=tk.DISABLED)
        self.log.tag_configure("cmd", foreground=ACCENT_HI)
        self.log.tag_configure("err", foreground=STATUSES["rst"][1])
        self.log.tag_configure("ok", foreground=STATUSES["fin"][1])
        self.log.pack(fill=tk.BOTH, expand=True)
        panes.add(card, weight=1)

    # ---------- files ----------

    def _refresh_files(self):
        self.files_list.delete(0, tk.END)
        for path in self.files:
            self.files_list.insert(tk.END, f"{os.path.basename(path)}   ·   {shorten_home(os.path.dirname(path))}")
        count = len(self.files)
        self.files_badge.configure(text=f"{count} FILE{'' if count == 1 else 'S'}")
        if self.files:
            self.files_empty.place_forget()
        else:
            self.files_empty.place(relx=0.5, rely=0.5, anchor="center")

    def _add_paths(self, paths):
        for path in paths:
            if path not in self.files:
                self.files.append(path)
        self._refresh_files()

    def _add_files(self):
        paths = filedialog.askopenfilenames(
            title="Select capture files",
            filetypes=[("Captures", "*.pcap *.pcapng"), ("All files", "*")],
        )
        self._add_paths(paths)

    def _add_folder(self):
        folder = filedialog.askdirectory(title="Select folder with captures")
        if not folder:
            return
        found = sorted(
            os.path.join(folder, name)
            for name in os.listdir(folder)
            if name.lower().endswith(PCAP_EXTENSIONS)
        )
        if not found:
            messagebox.showinfo("No captures", f"No .pcap or .pcapng files in {folder}")
        self._add_paths(found)

    def _remove_files(self):
        for index in reversed(self.files_list.curselection()):
            del self.files[index]
        self._refresh_files()

    def _clear_files(self):
        self.files.clear()
        self._refresh_files()

    # ---------- analyzer binary ----------

    def _choose_binary(self):
        path = filedialog.askopenfilename(title="Select the synfin binary", initialdir=PROJECT_DIR)
        if path:
            self.binary_var.set(path)
            self._check_binary()

    def _check_binary(self):
        binary = self.binary_var.get().strip()
        if not (os.path.isfile(binary) and os.access(binary, os.X_OK)):
            self.version_pill.configure(text="●  Analyzer not found", fg=STATUSES["rst"][1])
            return
        text = "Analyzer ready"
        try:
            out = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=3)
            if out.returncode == 0 and out.stdout.startswith(("synfin", "TCP_Analysis")):
                text = "synfin " + out.stdout.split()[-1]
        except (OSError, subprocess.SubprocessError):
            pass
        self.version_pill.configure(text=f"●  {text}", fg=STATUSES["fin"][1])

    # ---------- running the analyzer ----------

    def _start(self):
        binary = self.binary_var.get().strip()
        if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
            messagebox.showerror("Analyzer not found", f"Cannot run {binary!r}.\nBuild the project first (see README).")
            return
        if not self.files:
            messagebox.showerror("No captures", "Add at least one capture file.")
            return
        try:
            timeout = int(self.timeout_var.get())
            threads = int(self.threads_var.get())
        except (tk.TclError, ValueError):
            messagebox.showerror("Bad settings", "Timeout and threads must be whole numbers.")
            return

        cmd = [binary, "-t", str(timeout), "-j", str(threads), "-i", *self.files]
        # The analyzer writes "\n" without flushing, so line-buffer it when we can
        # to get rows while it is still running rather than all at the end.
        if shutil.which("stdbuf"):
            cmd = ["stdbuf", "-oL", *cmd]

        self._clear_results()
        self._log("$ " + " ".join(cmd), "cmd")
        try:
            self.process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
            )
        except OSError as exc:
            messagebox.showerror("Failed to start", str(exc))
            self.process = None
            return

        self.started_at = time.monotonic()
        self.run_button.configure(state=tk.DISABLED)
        self.stop_button.configure(state=tk.NORMAL)
        self.progress.grid()
        self.progress.start(12)
        self._update_status()
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
            self._log("Stopped by user.", "err")

    def _drain_events(self):
        handled = 0
        try:
            while handled < ROWS_PER_TICK:
                kind, payload = self.events.get_nowait()
                handled += 1
                if kind == "out":
                    self._handle_output_line(payload)
                elif kind == "err":
                    self._log(payload, "err")
                elif kind == "exit":
                    self._finish(payload)
        except queue.Empty:
            pass
        if handled or self.process:
            self._update_counts()
            self._update_status()
        self.root.after(50 if handled else 150, self._drain_events)

    def _handle_output_line(self, line):
        if not line.startswith("{"):
            if line:
                self._log(line)  # "Analyzing files: ...", "Timeout: ..." etc.
            return
        try:
            session = json.loads(line)
        except json.JSONDecodeError:
            self._log("Unparsed: " + line, "err")
            return
        self.sessions.append(session)
        key = status_key(session)
        self.counts[key] = self.counts.get(key, 0) + 1
        if self._matches_filter(session):
            self._insert_row(len(self.sessions), session)

    def _finish(self, code):
        self.process = None
        self.finished = True
        self.elapsed = time.monotonic() - self.started_at
        self.progress.stop()
        self.progress.grid_remove()
        self.run_button.configure(state=tk.NORMAL)
        self.stop_button.configure(state=tk.DISABLED)
        self._log(f"Analyzer exited with code {code}.", "ok" if code == 0 else "err")
        self.exit_code = code

    # ---------- table ----------

    @staticmethod
    def _row_values(num, s, precise=False):
        start, end = s["start_time"], s["end_time"]
        return (
            num,
            f'{s["source"]["ip"]}:{s["source"]["port"]}',
            f'{s["destination"]["ip"]}:{s["destination"]["port"]}',
            format_ts(start, precise),
            format_ts(end, precise),
            f"{to_seconds(end) - to_seconds(start):.6f}",
            status_label(status_key(s)),
        )

    def _insert_row(self, num, session):
        key = status_key(session)
        values = self._row_values(num, session)
        tags = ("odd",) if len(self.table.get_children()) % 2 else ()
        self.table.insert("", tk.END, text=values[-1], image=self.dots[key], values=values[:-1], tags=tags)

    def _restripe(self):
        for index, item in enumerate(self.table.get_children()):
            self.table.item(item, tags=("odd",) if index % 2 else ())

    def _matches_filter(self, session):
        if self.status_filter and status_key(session) != self.status_filter:
            return False
        needle = self.filter_var.get().strip().lower()
        if not needle:
            return True
        return any(needle in str(v).lower() for v in self._row_values(0, session)[1:])

    def _apply_filter(self):
        self.table.delete(*self.table.get_children())
        for num, session in enumerate(self.sessions, start=1):
            if self._matches_filter(session):
                self._insert_row(num, session)
        if self.sort_state:
            column, descending = self.sort_state
            self._sort_by(column, descending)
        self._update_status()

    def _toggle_status_filter(self, key):
        self.status_filter = None if key is None or key == self.status_filter else key
        for tile_key, (tile, _, color) in self.tiles.items():
            selected = tile_key == self.status_filter and tile_key is not None
            tile.configure(highlightbackground=color if selected else BORDER)
        self._apply_filter()

    def _hover_tile(self, tile, key, inside):
        if key is not None and key == self.status_filter:
            return
        tile.configure(highlightbackground=BORDER_HI if inside else BORDER)

    def _sort_by(self, column, descending=None):
        if descending is None:
            same = self.sort_state and self.sort_state[0] == column
            descending = not self.sort_state[1] if same else False
        if column == "#0":
            rows = [(self.table.item(item, "text"), item) for item in self.table.get_children("")]
        else:
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
        self.sort_state = (column, descending)
        for key_, title in [STATUS_COLUMN[:2]] + [(c[0], c[1]) for c in COLUMNS]:
            arrow = (" ▼" if descending else " ▲") if key_ == column else ""
            self.table.heading(key_, text=title.upper() + arrow)
        self._restripe()

    def _reset_counts(self):
        self.counts = {}
        self._update_counts()

    def _clear_results(self):
        self.sessions.clear()
        self.finished = False
        self.exit_code = None
        self._reset_counts()
        self.table.delete(*self.table.get_children())
        self.log.configure(state=tk.NORMAL)
        self.log.delete("1.0", tk.END)
        self.log.configure(state=tk.DISABLED)

    def _update_counts(self):
        for key, (_, value, _) in self.tiles.items():
            count = len(self.sessions) if key is None else self.counts.get(key, 0)
            value.configure(text=f"{count:,}".replace(",", " "))

    def _update_status(self):
        shown = len(self.table.get_children())
        total = len(self.sessions)
        self.shown_label.configure(text=f"showing {shown:,} of {total:,}".replace(",", " "))
        if self.process:
            elapsed = time.monotonic() - self.started_at
            dot, text = ACCENT, f"Analyzing {len(self.files)} capture(s)…   {elapsed:.1f} s"
        elif self.finished:
            ok = self.exit_code == 0
            dot = STATUSES["fin"][1] if ok else STATUSES["rst"][1]
            text = f"{'Done' if ok else 'Analyzer failed'} in {self.elapsed:.1f} s   ·   {total:,} sessions".replace(",", " ")
        else:
            dot, text = FAINT, "Ready"
        self.status_dot.configure(fg=dot)
        self.status_var.set(text)

    def _log(self, text, tag=None):
        self.log.configure(state=tk.NORMAL)
        self.log.insert(tk.END, text + "\n", tag or ())
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
                    writer.writerow(EXPORT_HEADER)
                    for num, session in enumerate(self.sessions, start=1):
                        writer.writerow(self._row_values(num, session, precise=True))
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        self._log(f"Exported {len(self.sessions)} sessions to {path}", "ok")

    def _on_close(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
        self.root.destroy()


def main():
    # Tk turns the class name into the window's WM_CLASS "Synfin", which the desktop
    # entry's StartupWMClass matches so docks show SynFin's icon for this window.
    root = tk.Tk(className="synfin")
    AnalyzerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
