# req_ui_bootstrap.py - ttkbootstrap UI for the requester dashboard.
# Theme: darkly.  Run via migration/REQ2.py.

import threading
import tkinter as tk

import ttkbootstrap as tb

from . import req_actions as A
from . import req_log as L
from . import req_state as S
from . import req_tray as T

_THEME = "darkly"


# ── set_status override ───────────────────────────────────────────────────────

def _set_status_bootstrap(text: str, mode: str = "ready") -> None:
    if S.status_label is None:
        return
    if threading.current_thread() is not threading.main_thread():
        if S.root is not None:
            S.root.after(0, lambda: _set_status_bootstrap(text, mode))
        return
    S.status_var.set(f"  {text}  ")
    S.status_label.configure(bootstyle="primary-inverse")


# ── tooltip ───────────────────────────────────────────────────────────────────

def _add_tooltip(widget, text: str) -> None:
    tip = {"w": None}

    def show(_e=None):
        if tip["w"]:
            return
        x = widget.winfo_rootx() + widget.winfo_width() + 8
        y = widget.winfo_rooty() + widget.winfo_height() // 2
        win = tk.Toplevel(widget)
        win.wm_overrideredirect(True)
        win.wm_geometry(f"+{x}+{y}")
        tk.Label(win, text=text, bg="#1e293b", fg="white",
                 padx=8, pady=4, font=("Segoe UI", 9)).pack()
        tip["w"] = win

    def hide(_e=None):
        if tip["w"]:
            tip["w"].destroy()
            tip["w"] = None

    widget.bind("<Enter>", show, add="+")
    widget.bind("<Leave>", hide, add="+")
    widget.bind("<ButtonPress>", hide, add="+")


# ── helpers ───────────────────────────────────────────────────────────────────

def _card(parent, title: str, row: int, sticky: str = "ew",
          pady: tuple = (0, 10)) -> tb.Frame:
    """A titled card: LabelFrame without padding kwarg."""
    lf = tb.Labelframe(parent, text=f"  {title}  ", bootstyle="primary")
    lf.grid(row=row, column=0, sticky=sticky, pady=pady)
    lf.grid_columnconfigure(0, weight=1)
    return lf


def _icon_btn(parent, text, command, tooltip="", style="secondary-outline",
              width=12):
    btn = tb.Button(parent, text=text, command=command,
                    bootstyle=style, width=width)
    if tooltip:
        _add_tooltip(btn, tooltip)
    return btn


# ── build ─────────────────────────────────────────────────────────────────────

def build_ui() -> None:
    L._init_file_logger()
    L.set_status = _set_status_bootstrap

    S.root = tb.Window(themename=_THEME)
    S.root.title("Requester Dashboard")
    S.root.geometry("1180x720")
    S.root.minsize(1100, 650)

    # colours from the active theme
    colors = tb.Style().colors
    input_bg = colors.inputbg
    input_fg = colors.inputfg
    sel_bg   = colors.primary

    main = tb.Frame(S.root)
    main.pack(fill="both", expand=True, padx=16, pady=16)
    main.grid_rowconfigure(2, weight=1)
    main.grid_columnconfigure(0, weight=1)

    # ── header ────────────────────────────────────────────────────────────────
    hdr = tb.Frame(main)
    hdr.grid(row=0, column=0, sticky="ew", pady=(0, 10))
    hdr.grid_columnconfigure(0, weight=1)

    tb.Label(hdr, text="Requester Dashboard",
             font=("Segoe UI Semibold", 18),
             bootstyle="primary").grid(row=0, column=0, sticky="w")
    tb.Label(hdr, text="FileTrust · Decentralised File Access",
             font=("Segoe UI", 9),
             bootstyle="secondary").grid(row=1, column=0, sticky="w")

    # ── policies card ─────────────────────────────────────────────────────────
    pol_card = _card(main, "Accessible Policies", row=1)

    # header row inside card
    ph = tb.Frame(pol_card)
    ph.grid(row=0, column=0, sticky="ew", padx=10, pady=(8, 4))
    ph.grid_columnconfigure(0, weight=1)

    _icon_btn(ph, "✕  Clear", A.clear_selected_policy,
              "Clear selection").pack(side="right")
    _icon_btn(
        ph,
        "⟳  Refresh",
        lambda: A.load_available_policies_for_requester(preserve_selection=True),
        "Refresh policies from blockchain",
        style="primary-outline",
    ).pack(side="right", padx=(0, 6))

    # treeview
    tf = tb.Frame(pol_card)
    tf.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
    tf.grid_rowconfigure(0, weight=1)
    tf.grid_columnconfigure(0, weight=1)

    S.policies_table = tb.Treeview(
        tf,
        columns=[key for key, *_ in S.POLICY_TABLE_COLUMNS],
        show="tree headings",
        height=9,
        selectmode="browse",
        bootstyle="primary",
    )
    S.policies_table.heading("#0", text="", anchor="center")
    S.policies_table.column("#0", width=24, minwidth=24, stretch=False)
    S.policies_table.tag_configure(
        "policy_group", font=("Segoe UI Semibold", 9))
    for key, title, width, anchor in S.POLICY_TABLE_COLUMNS:
        S.policies_table.heading(
            key, text=title, anchor="center",
            command=lambda col=key: A.sort_policy_table(col))
        S.policies_table.column(
            key, width=width, minwidth=max(48, width - 24),
            anchor=anchor,
            stretch=key in {"owner", "fileId", "latestDataId"})
    S.policies_table.grid(row=0, column=0, sticky="ew")
    S.policies_table.bind("<<TreeviewSelect>>", A.select_policy_from_table)

    ys = tb.Scrollbar(tf, orient="vertical", command=S.policies_table.yview,
                      bootstyle="primary-round")
    ys.grid(row=0, column=1, sticky="ns")
    xs = tb.Scrollbar(tf, orient="horizontal", command=S.policies_table.xview,
                      bootstyle="primary-round")
    xs.grid(row=1, column=0, sticky="ew")
    S.policies_table.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)

    # ── log + files split ─────────────────────────────────────────────────────
    split = tb.Frame(main)
    split.grid(row=2, column=0, sticky="nsew", pady=(0, 10))
    split.grid_rowconfigure(0, weight=1)
    split.grid_columnconfigure(0, weight=4)
    split.grid_columnconfigure(1, weight=1)

    # log panel
    log_lf = tb.Labelframe(split, text="  Network Results  ", bootstyle="primary")
    log_lf.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
    log_lf.grid_rowconfigure(1, weight=1)
    log_lf.grid_columnconfigure(0, weight=1)

    _icon_btn(log_lf, "🗑  Clear", L.clear_output,
              "Clear results").grid(row=0, column=0, sticky="e",
                                    padx=10, pady=(6, 4))

    S.result_text = tk.Text(
        log_lf,
        font=("Consolas", 9),
        relief="flat", borderwidth=0,
        wrap="word",
        bg=input_bg, fg=input_fg,
        insertbackground=input_fg,
    )
    S.result_text.grid(row=1, column=0, sticky="nsew", padx=(10, 0), pady=(0, 10))

    log_ys = tb.Scrollbar(log_lf, orient="vertical",
                           command=S.result_text.yview,
                           bootstyle="primary-round")
    log_ys.grid(row=1, column=1, sticky="ns", pady=(0, 10), padx=(0, 6))
    S.result_text.configure(yscrollcommand=log_ys.set)

    # files panel
    files_lf = tb.Labelframe(split, text="  Files  ", bootstyle="primary")
    files_lf.grid(row=0, column=1, sticky="nsew")
    files_lf.grid_rowconfigure(1, weight=1)
    files_lf.grid_columnconfigure(0, weight=1)

    _icon_btn(files_lf, "⟳  Refresh", A.refresh_files_list,
              "Refresh downloaded files",
              style="secondary-outline", width=10).grid(
        row=0, column=0, sticky="e", padx=10, pady=(6, 4))

    S.files_listbox = tk.Listbox(
        files_lf,
        borderwidth=0, highlightthickness=0,
        font=("Segoe UI", 9),
        bg=input_bg, fg=input_fg,
        selectbackground=sel_bg, selectforeground="white",
        activestyle="none",
    )
    S.files_listbox.grid(row=1, column=0, sticky="nsew", padx=(10, 0), pady=(0, 10))

    fls = tb.Scrollbar(files_lf, orient="vertical",
                        command=S.files_listbox.yview,
                        bootstyle="primary-round")
    fls.grid(row=1, column=1, sticky="ns", pady=(0, 10), padx=(0, 6))
    S.files_listbox.configure(yscrollcommand=fls.set)

    # ── action bar ────────────────────────────────────────────────────────────
    act = tb.Frame(main)
    act.grid(row=3, column=0, sticky="ew", pady=(0, 6))

    btn_dl = tb.Button(
        act, text="↓  Download File", width=18,
        bootstyle="primary",
        command=lambda: threading.Thread(target=A.run_all, daemon=True).start())
    btn_dl.pack(side="left", padx=(0, 10))
    _add_tooltip(btn_dl, "Use existing key or create one, then request PRE partials and download")
    btn_pause = tb.Button(
        act, text="Pause", width=10, bootstyle="secondary-outline",
        command=A.pause_vaultmesh_downloads)
    btn_pause.pack(side="left", padx=(0, 8))
    _add_tooltip(btn_pause, "Pause active piece downloads and keep partial bytes")
    btn_resume = tb.Button(
        act, text="Resume", width=10, bootstyle="secondary-outline",
        command=A.resume_vaultmesh_downloads)
    btn_resume.pack(side="left", padx=(0, 10))
    _add_tooltip(btn_resume, "Resume saved piece downloads")

    btn_keygen = tb.Button(
        act, text="⚿  Generate Key", width=18,
        bootstyle="primary-outline",
        command=A.run_keygen_request)
    btn_keygen.pack(side="left")
    _add_tooltip(btn_keygen, "Force-generate a fresh requester key for the selected policy")

    # ── status bar ────────────────────────────────────────────────────────────
    sb = tb.Frame(main)
    sb.grid(row=4, column=0, sticky="ew")
    sb.grid_columnconfigure(0, weight=1)

    tb.Label(sb, text="Status", font=("Segoe UI", 9),
             bootstyle="secondary").grid(row=0, column=0, sticky="w")

    S.status_var = tk.StringVar(value="  Ready  ")
    S.status_label = tb.Label(
        sb,
        textvariable=S.status_var,
        font=("Segoe UI Semibold", 9),
        bootstyle="primary-inverse",
    )
    S.status_label.grid(row=0, column=1, sticky="e")

    # ── initial load ──────────────────────────────────────────────────────────
    A.refresh_files_list()
    A.load_requester_keys_if_exist()
    A.load_available_policies_for_requester(auto_select_first=True, quiet=True)
    A.start_policy_auto_refresh()
    L.set_status("Ready", "ready")
    tray_started = T.start_tray_icon()
    if tray_started:
        S.root.protocol("WM_DELETE_WINDOW", T.hide_window_to_tray)
    else:
        S.root.protocol("WM_DELETE_WINDOW", S.root.destroy)
    S.root.mainloop()
