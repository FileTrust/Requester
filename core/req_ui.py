# req_ui.py - CustomTkinter UI for the requester migration dashboard.

import threading
import time
from pathlib import Path
import tkinter as tk
from tkinter import ttk

import customtkinter as ctk

try:
    from PIL import Image, ImageDraw, ImageTk as _ITk
    _PIL = True
except ImportError:
    _PIL = False

_indicator_images: list = []   # keeps PhotoImage refs alive (GC guard)

from . import req_actions as A
from . import req_config as C
from . import req_log as L
from . import req_state as S
from . import req_tray as T

# ── design tokens — FileTrust palette ────────────────────────────────────────
# Dark navy shell + gold accent, matching https://filetrust.io
_BG       = "#1F2641"   # window shell        — deep navy
_SURFACE  = "#2A3355"   # card surface        — medium navy
_BASE     = "#232840"   # textbox / table bg  — darkest navy
_ACCENT   = "#FFD700"   # gold                — FileTrust primary accent
_ACCENT_H = "#e6c200"   # gold darker         — hover
_ACCENT_S = "#2f3a5e"   # soft navy           — secondary button bg
_ACCENT_SH= "#374468"   # soft navy hover
_TXT1     = "#FFFFFF"   # white               — primary text
_TXT2     = "#8899cc"   # muted blue-gray     — secondary / labels
_MUTED    = "#3E497A"   # medium navy-purple  — borders / icon-btn bg
_MUTED_H  = "#4a578e"   # slightly lighter    — icon-btn hover
_FONT     = "Catamaran" # FileTrust brand font (falls back to system sans)


def _add_tooltip(widget, text: str) -> None:
    tip = {"window": None}

    def show(_event=None):
        if tip["window"] is not None:
            return
        x = widget.winfo_rootx() + widget.winfo_width() + 8
        y = widget.winfo_rooty() + widget.winfo_height() // 2
        window = tk.Toplevel(widget)
        window.wm_overrideredirect(True)
        window.wm_geometry(f"+{x}+{y}")
        tk.Label(
            window,
            text=text,
            bg="#1e293b",
            fg="white",
            padx=8,
            pady=4,
            font=(_FONT, 9),
        ).pack()
        tip["window"] = window

    def hide(_event=None):
        w = tip.get("window")
        if w:
            w.destroy()
            tip["window"] = None

    widget.bind("<Enter>", show, add="+")
    widget.bind("<Leave>", hide, add="+")
    widget.bind("<ButtonPress>", hide, add="+")


def _autoscroll(scrollbar):
    """Return an xscrollcommand/yscrollcommand that auto-hides the scrollbar."""
    def _set(first, last):
        if float(first) <= 0.0 and float(last) >= 1.0:
            scrollbar.grid_remove()
        else:
            scrollbar.grid()
        scrollbar.set(first, last)
    return _set


def _icon_btn(parent, text, command, tooltip="", width=30, height=26, soft=False):
    """Small square icon button.  soft=True uses the accent-tinted palette."""
    bg  = _ACCENT_S  if soft else _MUTED
    hov = _ACCENT_SH if soft else _MUTED_H
    fg  = _ACCENT    if soft else _TXT1
    btn = ctk.CTkButton(
        parent, text=text, command=command,
        width=width, height=height,
        fg_color=bg, hover_color=hov, text_color=fg,
        font=(_FONT, 12), corner_radius=8,
    )
    if tooltip:
        _add_tooltip(btn, tooltip)
    return btn


def _make_tree_indicator(size: int, plus: bool | None):
    """Square +/- tree indicator drawn with PIL using the accent palette.
    plus=None → fully transparent (used as the default/leaf placeholder)."""
    if not _PIL:
        return None
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    if plus is not None:
        def _rgba(h: str):
            h = h.lstrip("#")
            return tuple(int(h[i:i+2], 16) for i in (0, 2, 4)) + (255,)
        d = ImageDraw.Draw(img)
        d.rectangle([0, 0, size-1, size-1], fill=_rgba(_ACCENT_S), outline=_rgba(_ACCENT), width=1)
        m, p = size // 2, 3
        d.line([(p, m), (size-p-1, m)], fill=_rgba(_ACCENT), width=1)
        if plus:
            d.line([(m, p), (m, size-p-1)], fill=_rgba(_ACCENT), width=1)
    ph = _ITk.PhotoImage(img)
    _indicator_images.append(ph)
    return ph


def _section_label(parent, text):
    return ctk.CTkLabel(
        parent, text=text,
        font=(_FONT, 11),
        text_color=_ACCENT,
    )


# ── Your account ──────────────────────────────────────────────────────────────
# This matters more here than in the Data Owner app: a requester cannot be
# given access to anything until somebody else knows this address.


def _account_balance_text() -> str:
    try:
        wei = int(C.w3.eth.get_balance(C.REQ_ADDRESS))
    except Exception:
        return "balance unavailable"
    if wei == 0:
        return "0 FTU — needs funds before downloading"
    return f"{wei / 10 ** 18:,.4f} FTU"


_balance_text = "checking balance…"
_balance_fetching = False


def _poll_balance() -> None:
    """Copy whatever the worker has written onto the label. Window thread only.

    Polling stops as soon as the answer is in, so an idle window schedules
    nothing: handing the value back with `after` from the worker is not safe --
    `after` is itself a Tcl call, and a scheduled update was observed never
    arriving.
    """
    root = S.root
    if root is None:
        return
    if S.account_balance_var is not None:
        S.account_balance_var.set(_balance_text)
    if _balance_fetching:
        root.after(400, _poll_balance)


def refresh_account_balance() -> None:
    """Read the balance once, on a worker. Called at start-up and by the button.

    Not on a timer: a balance only changes when this account spends or is paid,
    and a window left open all day would otherwise keep asking a node that has
    nothing new to say.
    """
    global _balance_fetching
    if _balance_fetching:
        return
    _balance_fetching = True
    if S.account_balance_var is not None:
        S.account_balance_var.set("checking…")

    def work() -> None:
        global _balance_text, _balance_fetching
        try:
            _balance_text = _account_balance_text()
        finally:
            _balance_fetching = False

    threading.Thread(target=work, daemon=True, name="balance").start()
    _poll_balance()


def _build_account_row(parent, row: int) -> None:
    """Show this app's own address, with a copy button, and its balance.

    A user who let install.sh create the account sees the address once, in
    terminal output that scrolls away, and the app never showed it again. The
    address is derived from the key here, so what is on screen is always the
    identity actually signing. A Data Owner needs this address before they can
    share a file with you.
    """
    box = ctk.CTkFrame(parent, fg_color="transparent")
    box.grid(row=row, column=0, sticky="w", pady=(8, 0))

    ctk.CTkLabel(
        box, text="Give this address to the file owner", font=(_FONT, 10), text_color=_TXT2,
    ).pack(side="left")
    ctk.CTkLabel(
        box, text=C.REQ_ADDRESS, font=(_FONT, 11), text_color=_TXT1,
    ).pack(side="left", padx=(8, 8))

    copy_button = ctk.CTkButton(
        box, text="Copy", width=60, height=24,
        fg_color=_ACCENT_S, hover_color=_ACCENT_SH, text_color=_ACCENT,
        font=(_FONT, 10), corner_radius=8,
    )

    def _copy() -> None:
        root = S.root
        if root is None:
            return
        root.clipboard_clear()
        root.clipboard_append(C.REQ_ADDRESS)
        # Confirm it happened: a clipboard write is otherwise invisible, and a
        # user who is not sure clicks again and again.
        copy_button.configure(text="Copied")
        root.after(1500, lambda: copy_button.configure(text="Copy"))

    copy_button.configure(command=_copy)
    copy_button.pack(side="left")

    S.account_balance_var = tk.StringVar(value="checking balance…")
    ctk.CTkLabel(
        box, textvariable=S.account_balance_var,
        font=(_FONT, 10), text_color=_TXT2,
    ).pack(side="left", padx=(14, 4))
    _icon_btn(
        box, "\u21bb", refresh_account_balance,
        tooltip="Check the balance again", width=26, height=22, soft=True,
    ).pack(side="left")
    refresh_account_balance()


def _build_trusted_owners_tab(parent, style) -> None:
    """Whose files this app may fetch without being asked, one owner at a time.

    A download deposits escrow on chain before anything can be checked, and
    any address can create a policy and add this one to it. So automatic
    fetching is granted per owner, by hand, and off until it is.
    """
    card = ctk.CTkFrame(parent, corner_radius=16, fg_color=_SURFACE)
    card.grid(row=0, column=0, sticky="nsew")
    card.grid_columnconfigure(0, weight=1)
    card.grid_rowconfigure(2, weight=1)

    head = ctk.CTkFrame(card, fg_color="transparent")
    head.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 2))
    head.grid_columnconfigure(0, weight=1)
    _section_label(head, "Trusted Data Owners").grid(row=0, column=0, sticky="w")
    ctk.CTkLabel(
        head,
        text=("Auto-sync downloads new files from that owner on its own. Each "
              "download spends your balance, so it is off until you turn it on. "
              "Click the Auto-sync cell to switch a row."),
        font=(_FONT, 9), text_color=_TXT2, justify="left",
    ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(2, 0))

    form = ctk.CTkFrame(card, fg_color="transparent")
    form.grid(row=1, column=0, sticky="ew", padx=16, pady=(8, 4))
    form.grid_columnconfigure(3, weight=1)

    ctk.CTkLabel(form, text="Name", font=(_FONT, 10), text_color=_TXT2).grid(
        row=0, column=0, padx=(0, 6), sticky="w"
    )
    S.trusted_name_entry = ctk.CTkEntry(
        form, width=150, fg_color=_BASE, text_color=_TXT1, border_color=_MUTED,
    )
    S.trusted_name_entry.grid(row=0, column=1, padx=(0, 12))
    ctk.CTkLabel(form, text="Address", font=(_FONT, 10), text_color=_TXT2).grid(
        row=0, column=2, padx=(0, 6), sticky="w"
    )
    S.trusted_address_entry = ctk.CTkEntry(
        form, fg_color=_BASE, text_color=_TXT1, border_color=_MUTED,
    )
    S.trusted_address_entry.grid(row=0, column=3, sticky="ew", padx=(0, 12))

    ctk.CTkButton(
        form, text="Add", width=70, height=28,
        fg_color=_ACCENT, hover_color=_ACCENT_H, text_color="#1F2641",
        font=(_FONT, 10), corner_radius=8, command=A.add_trusted_owner_from_form,
    ).grid(row=0, column=4, padx=(0, 6))
    ctk.CTkButton(
        form, text="Add owner of selected policy", width=200, height=28,
        fg_color=_ACCENT_S, hover_color=_ACCENT_SH, text_color=_ACCENT,
        font=(_FONT, 10), corner_radius=8,
        command=A.add_trusted_owner_from_selected_policy,
    ).grid(row=0, column=5, padx=(0, 6))
    ctk.CTkButton(
        form, text="Remove", width=90, height=28,
        fg_color="#4a0e0e", hover_color="#6b1414", text_color="#f87171",
        font=(_FONT, 10), corner_radius=8, command=A.remove_selected_trusted_owner,
    ).grid(row=0, column=6)

    table_frame = ctk.CTkFrame(card, fg_color="transparent")
    table_frame.grid(row=2, column=0, sticky="nsew", padx=16, pady=(4, 16))
    table_frame.grid_columnconfigure(0, weight=1)
    table_frame.grid_rowconfigure(0, weight=1)

    style.configure(
        "Trusted.Treeview",
        background=_BASE, fieldbackground=_BASE, foreground=_TXT1,
        borderwidth=0, rowheight=26, font=(_FONT, 9),
    )
    style.configure(
        "Trusted.Treeview.Heading",
        background=_MUTED, foreground=_TXT2, font=(_FONT, 9),
        relief="flat", padding=(4, 4),
    )
    style.map(
        "Trusted.Treeview",
        background=[("selected", _ACCENT)],
        foreground=[("selected", "#1F2641")],
    )
    style.layout("Trusted.Treeview", [("Treeview.treearea", {"sticky": "nswe"})])

    S.trusted_table = ttk.Treeview(
        table_frame, columns=("name", "address", "autosync"),
        show="headings", selectmode="browse", style="Trusted.Treeview",
    )
    S.trusted_table.heading("name", text="Name", anchor="w")
    S.trusted_table.heading("address", text="Address", anchor="w")
    S.trusted_table.heading("autosync", text="Auto-sync", anchor="center")
    S.trusted_table.column("name", width=180, minwidth=120, anchor="w")
    S.trusted_table.column("address", width=420, minwidth=300, anchor="w", stretch=True)
    S.trusted_table.column("autosync", width=100, minwidth=90, anchor="center", stretch=False)
    S.trusted_table.grid(row=0, column=0, sticky="nsew")

    ys = ctk.CTkScrollbar(
        table_frame, orientation="vertical", command=S.trusted_table.yview,
        fg_color=_BASE, button_color=_MUTED, button_hover_color=_ACCENT,
    )
    ys.grid(row=0, column=1, sticky="ns")
    S.trusted_table.configure(yscrollcommand=ys.set)

    # A table row cannot hold a real switch, so the cell is the switch.
    S.trusted_table.bind("<Button-1>", A.trusted_table_clicked)
    A.refresh_trusted_owners_table()


def build_ui() -> None:
    L._init_file_logger()
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    S.root = ctk.CTk()
    S.root.title("Requester Dashboard")
    S.root.geometry("1280x860")
    S.root.minsize(1100, 700)
    S.root.configure(fg_color=_BG)

    # The window's own icon, so the task bar and the title bar carry the mark.
    try:
        from PIL import ImageTk, Image
        _logo = Path(__file__).resolve().parent / "assets" / "logo.png"
        if _logo.is_file():
            S.root._window_icon = ImageTk.PhotoImage(Image.open(_logo))
            S.root.iconphoto(True, S.root._window_icon)
    except Exception:
        pass

    main = ctk.CTkFrame(S.root, corner_radius=20, fg_color=_BASE)
    main.pack(fill="both", expand=True, padx=20, pady=20)
    main.grid_rowconfigure(1, weight=1)   # the policy table takes the room
    main.grid_columnconfigure(0, weight=1)

    # ── header ────────────────────────────────────────────────────────────────
    header = ctk.CTkFrame(main, fg_color="transparent")
    header.grid(row=0, column=0, sticky="ew", padx=20, pady=(16, 10))
    header.grid_columnconfigure(0, weight=1)

    ctk.CTkLabel(
        header,
        text="Requester Dashboard",
        font=(_FONT, 20),
        text_color=_TXT1,
    ).grid(row=0, column=0, sticky="w")

    ctk.CTkLabel(
        header,
        text="FileTrust · Decentralised File Access",
        font=(_FONT, 10),
        text_color=_TXT2,
    ).grid(row=1, column=0, sticky="w")
    _build_account_row(header, 2)

    # The two things this window does, in the corner, on every row of policies.
    # They sat under a log panel that has moved out to a window of its own.
    actions = ctk.CTkFrame(header, fg_color="transparent")
    actions.grid(row=0, column=1, rowspan=2, sticky="e", padx=(16, 0))

    btn_keygen = ctk.CTkButton(
        actions, text="⚿  Generate Key", width=140, height=40,
        fg_color=_ACCENT_S, hover_color=_ACCENT_SH, text_color=_ACCENT,
        font=(_FONT, 11), corner_radius=10,
        command=A.run_keygen_request,
    )
    btn_keygen.pack(side="right")
    _add_tooltip(btn_keygen, "Force-generate a fresh requester key for the selected policy")

    btn_download = ctk.CTkButton(
        actions, text="↓  Download File", width=150, height=40,
        fg_color=_ACCENT, hover_color=_ACCENT_H, text_color="#1F2641",
        font=(_FONT, 12), corner_radius=10,
        command=lambda: threading.Thread(target=A.run_all, daemon=True).start(),
    )
    btn_download.pack(side="right", padx=(0, 8))
    _add_tooltip(btn_download, "Use the existing key or create one, then request the pieces and download")

    # No Pause or Resume. An interrupted download continues by itself when the
    # app comes back, from the bytes already on disk, so the only thing those
    # buttons offered was a way to stop work the app would have finished.

    # ── tabs ──────────────────────────────────────────────────────────────────
    tabview = ctk.CTkTabview(
        main, fg_color=_SURFACE, corner_radius=12,
        segmented_button_fg_color=_BASE,
        segmented_button_selected_color=_ACCENT,
        segmented_button_selected_hover_color=_ACCENT_H,
        segmented_button_unselected_color=_MUTED,
        segmented_button_unselected_hover_color=_MUTED_H,
        text_color="#1F2641", anchor="w",
    )
    tabview.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 10))
    dash_tab = tabview.add("Dashboard")
    trusted_tab = tabview.add("Trusted Data Owners")
    dash_tab.grid_columnconfigure(0, weight=1)
    dash_tab.grid_rowconfigure(0, weight=1)
    trusted_tab.grid_columnconfigure(0, weight=1)
    trusted_tab.grid_rowconfigure(0, weight=1)

    # ── policies card ─────────────────────────────────────────────────────────
    policies_card = ctk.CTkFrame(dash_tab, corner_radius=16, fg_color=_SURFACE)
    policies_card.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)
    policies_card.grid_columnconfigure(0, weight=1)
    policies_card.grid_rowconfigure(1, weight=1)

    ph = ctk.CTkFrame(policies_card, fg_color="transparent")
    ph.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 6))
    ph.grid_columnconfigure(0, weight=1)

    _section_label(ph, "Accessible Policies").grid(row=0, column=0, sticky="w")

    btn_load = _icon_btn(
        ph,
        "⟳",
        lambda: A.load_available_policies_for_requester(preserve_selection=True),
        "Refresh policies",
    )
    btn_load.grid(row=0, column=1, padx=(8, 4))

    btn_clear_policy = _icon_btn(ph, "✕", A.clear_selected_policy, "Clear selection", soft=True)
    btn_clear_policy.grid(row=0, column=2)

    # treeview container
    tf = ctk.CTkFrame(policies_card, fg_color="transparent")
    tf.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 12))
    tf.grid_columnconfigure(0, weight=1)
    tf.grid_rowconfigure(0, weight=1)

    style = ttk.Style(S.root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    style.configure(
        "Policy.Treeview",
        background=_BASE,
        fieldbackground=_BASE,
        foreground=_TXT1,
        borderwidth=0,
        rowheight=26,
        font=(_FONT, 9),
    )
    style.configure(
        "Policy.Treeview.Heading",
        background=_MUTED,
        foreground=_TXT2,
        font=(_FONT, 9),
        relief="flat",
        padding=(4, 4),
    )
    style.map(
        "Policy.Treeview",
        background=[("selected", _ACCENT)],
        foreground=[("selected", "#1F2641")],   # dark navy text on gold selection
    )
    style.layout("Policy.Treeview", [
        ("Treeview.treearea", {"sticky": "nswe"}),
    ])

    # The Files window uses this style and is built later, from the tray, so
    # it is defined here where the one Style object lives.
    style.configure(
        "Files.Treeview",
        background=_BASE,
        fieldbackground=_BASE,
        foreground=_TXT1,
        borderwidth=0,
        rowheight=22,
        font=(_FONT, 9),
    )
    style.configure(
        "Files.Treeview.Heading",
        background=_MUTED,
        foreground=_TXT2,
        font=(_FONT, 8),
        relief="flat",
    )
    style.map(
        "Files.Treeview",
        background=[("selected", _ACCENT)],
        foreground=[("selected", "#1F2641")],
    )
    style.layout("Files.Treeview", [
        ("Treeview.treearea", {"sticky": "nswe"}),
    ])

    # Suppress default triangle; set +/- image per-row via item(image=) instead
    _ind_empty = _make_tree_indicator(13, None)      # transparent — hides default triangle
    S.tree_ind_plus  = _make_tree_indicator(13, True)
    S.tree_ind_minus = _make_tree_indicator(13, False)
    if _ind_empty:
        try:
            style.element_create(
                "Policy.Treeitem.indicator", "image",
                _ind_empty,                  # single transparent image — no state logic
                sticky="w", padding=(2, 0),
            )
            style.layout("Policy.Treeview.Item", [
                ("Treeitem.padding", {"sticky": "nswe", "children": [
                    ("Policy.Treeitem.indicator", {"side": "left", "sticky": ""}),
                    ("Treeitem.image",             {"side": "left", "sticky": ""}),
                    ("Treeitem.focus",             {"side": "left", "sticky": "", "children": [
                        ("Treeitem.text",          {"side": "left", "sticky": ""}),
                    ]}),
                ]})
            ])
        except tk.TclError:
            pass

    S.policies_table = ttk.Treeview(
        tf,
        columns=[key for key, *_ in S.POLICY_TABLE_COLUMNS],
        show="tree headings",
        height=9,
        selectmode="browse",
        style="Policy.Treeview",
    )
    S.policies_table.heading("#0", text="", anchor="center")
    S.policies_table.column("#0", width=24, minwidth=24, stretch=False)
    S.policies_table.tag_configure(
        "policy_group",
        background=_ACCENT_S,
        foreground=_ACCENT,       # gold text on dark navy row
        font=(_FONT, 9),
    )
    for key, title, width, anchor in S.POLICY_TABLE_COLUMNS:
        S.policies_table.heading(
            key, text=title, anchor="center",
            command=lambda col=key: A.sort_policy_table(col),
        )
        S.policies_table.column(
            key, width=width, minwidth=max(48, width - 24),
            anchor=anchor,
            stretch=key in {"owner", "fileId", "latestDataId"},
        )
    S.policies_table.grid(row=0, column=0, sticky="nsew")
    S.policies_table.bind("<<TreeviewSelect>>", A.select_policy_from_table)

    def _on_group_open(event):
        iid = S.policies_table.focus()
        if iid and S.tree_ind_minus:
            S.policies_table.item(iid, image=S.tree_ind_minus)

    def _on_group_close(event):
        iid = S.policies_table.focus()
        if iid and S.tree_ind_plus:
            S.policies_table.item(iid, image=S.tree_ind_plus)

    S.policies_table.bind("<<TreeviewOpen>>",  _on_group_open)
    S.policies_table.bind("<<TreeviewClose>>", _on_group_close)

    ys = ctk.CTkScrollbar(
        tf, orientation="vertical", command=S.policies_table.yview,
        fg_color=_BASE, button_color=_MUTED, button_hover_color=_ACCENT,
    )
    ys.grid(row=0, column=1, sticky="ns")
    xs = ctk.CTkScrollbar(
        tf, orientation="horizontal", command=S.policies_table.xview,
        fg_color=_BASE, button_color=_MUTED, button_hover_color=_ACCENT,
    )
    xs.grid(row=1, column=0, sticky="ew")
    S.policies_table.configure(
        yscrollcommand=_autoscroll(ys),
        xscrollcommand=_autoscroll(xs),
    )

    _build_trusted_owners_tab(trusted_tab, style)

    # ── status bar ────────────────────────────────────────────────────────────
    sb = ctk.CTkFrame(main, fg_color="transparent")
    sb.grid(row=4, column=0, sticky="ew", padx=20, pady=(6, 16))
    # The side columns share the spare width equally, so the bar sits in the
    # middle of the window and does not slide as the status wording changes.
    sb.grid_columnconfigure(0, weight=1, uniform="statusbar")
    sb.grid_columnconfigure(2, weight=1, uniform="statusbar", minsize=170)

    ctk.CTkLabel(
        sb, text="Status",
        font=(_FONT, 9),
        text_color=_TXT2,
    ).grid(row=0, column=0, sticky="w")

    S.status_var = tk.StringVar(value="Ready")
    S.status_label = ctk.CTkLabel(
        sb,
        textvariable=S.status_var,
        font=(_FONT, 9),
        text_color="#1F2641",
        fg_color="#FFD700",
        corner_radius=999,
        padx=10, pady=3,
    )
    S.status_label.grid(row=0, column=2, sticky="e")

    # One bar for whatever was asked for -- a download, a key. Hidden until
    # something is running, because a bar at zero with nothing happening reads
    # as a task that has stalled.
    S.progress_var = tk.StringVar(value="")
    S.progress_box = ctk.CTkFrame(sb, fg_color="transparent")
    S.progress_box.grid(row=0, column=1, padx=10)
    S.progress_bar = ctk.CTkProgressBar(
        S.progress_box, width=220, height=10, corner_radius=999,
        fg_color=_MUTED, progress_color=_ACCENT,
    )
    S.progress_bar.set(0)
    S.progress_bar.pack(side="right")
    ctk.CTkLabel(
        S.progress_box, textvariable=S.progress_var,
        font=(_FONT, 9), text_color=_TXT2,
    ).pack(side="right", padx=(0, 8))
    S.progress_box.grid_remove()   # shown by req_progress once work starts

    # ── initial load ──────────────────────────────────────────────────────────
    A.refresh_files_list()
    A.load_requester_keys_if_exist()
    # Cached rows now, chain rows when the worker has them: this call used to
    # block the window for the length of a full chain walk before it opened.
    A.load_available_policies_for_requester(
        auto_select_first=True, quiet=True, background_sync=True,
    )
    A.start_policy_auto_refresh()
    # An interrupted download continues from the bytes already on disk, with
    # no button to press: the app was going to finish it anyway.
    S.root.after(1200, A.continue_unfinished_downloads)
    L.set_status("Ready", "ready")
    tray_started = False if __import__('os').environ.get('FILETRUST_CONTAINER') == '1' else T.start_tray_icon()
    if tray_started:
        S.root.protocol("WM_DELETE_WINDOW", T.hide_window_to_tray)
    else:
        S.root.protocol("WM_DELETE_WINDOW", S.root.destroy)
    from .ft_update_ui import attach
    from . import req_progress
    attach(S.root, Path(__file__).resolve().parents[1], busy=req_progress.is_running)
    from .ft_update_bootstrap import ready
    ready(Path(__file__).resolve().parents[1])
    if __import__('os').environ.get('FILETRUST_CONTAINER') == '1':
        from .ft_desktop_lifecycle import install
        install(S.root, req_progress.is_running, lambda: (T.stop_tray_icon(), S.root.destroy()))
    S.root.mainloop()
