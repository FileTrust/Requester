# req_log.py - file/UI logging, status, and dialog helpers.

import atexit
import datetime
import threading
import time
import tkinter as tk

import customtkinter as ctk

from . import req_config as C
from . import req_state as S

# ── palette (kept in sync with req_ui tokens) ─────────────────────────────────
_BG  = "#1F2641"; _SRF = "#2A3355"; _ACC = "#FFD700"; _ACH = "#e6c200"
_T1  = "#FFFFFF"; _T2  = "#8899cc"; _MUT = "#3E497A"; _FNT = "Catamaran"
_RED = "#f87171"; _AMB = "#fde68a"; _SKY = "#7dd3fc"

_LOG_LOCK = threading.Lock()
_LOG_FILE = None
_LOG_STATE: dict = {}


def _init_file_logger() -> None:
    global _LOG_FILE
    try:
        C.LOG_DIR.mkdir(parents=True, exist_ok=True)
        date_str = datetime.datetime.now().strftime("%Y-%m-%d")
        _LOG_FILE = open(C.LOG_DIR / f"req_{date_str}.log", "a", encoding="utf-8", buffering=1)
        _write_raw("")
        _write_raw("=" * 72)
        _write_raw(f"  SESSION START  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        _write_raw("=" * 72)
        _start_log_archiver()
    except Exception:
        _LOG_FILE = None


def _start_log_archiver() -> None:
    """Zip yesterday's logs and drop ones past their retention, then daily."""
    try:
        from . import log_archive

        options = log_archive.options_from_config(C.config)
        log_archive.start_daily(
            C.LOG_DIR,
            keep_days_by_name={"transactions": 90, "calls": 3},
            on_done=lambda s: s.get("rotated") and _write_raw(
                f"[log-archive] zipped {s['rotated']}, removed "
                f"{s['deleted_old'] + s['deleted_for_size']} old archive(s)"
            ),
            **options,
        )
    except Exception:
        pass  # tidying logs must never stop the app starting


def _close_file_logger() -> None:
    global _LOG_FILE
    if _LOG_FILE is None:
        return
    try:
        _write_raw("-" * 72)
        _write_raw(f"  SESSION END    {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        _write_raw("-" * 72)
        _LOG_FILE.close()
    except Exception:
        pass
    _LOG_FILE = None


atexit.register(_close_file_logger)


def _write_raw(line: str) -> None:
    if _LOG_FILE is None:
        return
    with _LOG_LOCK:
        try:
            _LOG_FILE.write(line + "\n")
        except Exception:
            pass


def _write_log(level: str, text: str, tag: str = "") -> None:
    if _LOG_FILE is None:
        return
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    tag_part = f"[{tag:<12}]  " if tag else "               "
    _write_raw(f"{ts}  {level:<8}  {tag_part}{text}")


def set_status(text: str, mode: str = "ready") -> None:
    if S.status_label is None:
        return
    if threading.current_thread() is not threading.main_thread():
        if S.root is not None:
            S.root.after(0, lambda t=text, m=mode: set_status(t, m))
        return

    colors = {
        "ready":   ("#FFD700", "#1F2641"),
        "running": ("#1e3a5f", "#93c5fd"),
        "waiting": ("#78350f", "#fde68a"),
        "done":    ("#0c4a6e", "#7dd3fc"),
        "error":   ("#7f1d1d", "#fca5a5"),
    }
    bg, fg = colors.get(mode, colors["ready"])
    S.status_var.set(text)
    S.status_label.configure(fg_color=bg, text_color=fg)


def log(text: str, tag: str = "") -> None:
    _write_log("INFO", text, tag)
    if S.result_text is None:
        return
    if threading.current_thread() is not threading.main_thread():
        if S.root is not None:
            S.root.after(0, lambda t=text, tg=tag: log(t, tg))
        return
    S.result_text.insert(tk.END, text + "\n")
    S.result_text.see(tk.END)
    try:
        S.result_text.update_idletasks()
        S.result_text.update()
    except Exception:
        pass


def log_state(key, state, message: str) -> None:
    if _LOG_STATE.get(key) != state:
        log(message)
        _LOG_STATE[key] = state


def log_every(key: str, message: str, seconds: int = 30) -> None:
    now = time.time()
    last = S._LOG_LAST_TIME.get(key, 0.0)
    if now - last >= seconds:
        log(message)
        S._LOG_LAST_TIME[key] = now


def clear_output() -> None:
    if S.result_text is not None:
        S.result_text.delete("1.0", tk.END)
    if S.files_listbox is not None:
        S.files_listbox.delete(0, tk.END)
    if S.files_table is not None:
        children = S.files_table.get_children()
        if children:
            S.files_table.delete(*children)
    set_status("Network results cleared", "ready")


def _themed_dialog(title: str, message: str, kind: str = "info") -> None:
    accent = {"error": _RED, "warning": _AMB, "info": _ACC}.get(kind, _ACC)
    icon   = {"error": "✕", "warning": "⚠", "info": "ℹ"}.get(kind, "ℹ")

    root = S.root
    if root is None:
        return

    dlg = tk.Toplevel(root)
    dlg.title(title)
    dlg.resizable(False, False)
    dlg.configure(bg=_BG)
    dlg.after(40, dlg.grab_set)

    card = ctk.CTkFrame(dlg, fg_color=_SRF, corner_radius=16)
    card.pack(padx=20, pady=20, fill="both", expand=True)

    hdr = ctk.CTkFrame(card, fg_color="transparent")
    hdr.pack(fill="x", padx=18, pady=(16, 6))
    ctk.CTkLabel(hdr, text=icon, font=(_FNT, 20), text_color=accent).pack(side="left", padx=(0, 10))
    ctk.CTkLabel(hdr, text=title, font=(_FNT, 13), text_color=_T1).pack(side="left")

    ctk.CTkFrame(card, fg_color=_MUT, height=1, corner_radius=0).pack(fill="x", padx=18, pady=(0, 10))

    ctk.CTkLabel(
        card, text=message,
        font=(_FNT, 11), text_color=_T2,
        wraplength=340, justify="left", anchor="w",
    ).pack(fill="x", padx=18, pady=(0, 16))

    ctk.CTkButton(
        card, text="OK", width=120, height=32,
        fg_color=_MUT, hover_color="#4a578e", text_color=_T1,
        font=(_FNT, 11), corner_radius=8,
        command=dlg.destroy,
    ).pack(pady=(0, 16))

    def _centre():
        dlg.update_idletasks()
        px = root.winfo_rootx() + (root.winfo_width()  - dlg.winfo_width())  // 2
        py = root.winfo_rooty() + (root.winfo_height() - dlg.winfo_height()) // 2
        dlg.wm_geometry(f"+{px}+{py}")

    dlg.after(10, _centre)


def _is_headless() -> bool:
    root = S.root
    return root is None or type(root).__name__ == "HeadlessRoot"


def _dispatch_dialog(level: str, title: str, message: str, kind: str) -> None:
    _write_log(level, f"{title}: {message}")
    if _LOG_FILE is None:
        try:
            print(f"[REQ {level}] {title}: {message}", flush=True)
        except Exception:
            pass
    if S.root is None or _is_headless():
        return
    if threading.current_thread() is threading.main_thread():
        _themed_dialog(title, message, kind)
    else:
        S.root.after(0, lambda t=title, m=message, k=kind: _themed_dialog(t, m, k))


def show_error(title: str, message: str) -> None:
    _dispatch_dialog("ERROR", title, message, "error")


def show_warning(title: str, message: str) -> None:
    _dispatch_dialog("WARNING", title, message, "warning")


def show_info(title: str, message: str) -> None:
    _dispatch_dialog("INFO", title, message, "info")
