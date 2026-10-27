# req_actions.py - requester migration UI callbacks and orchestration.

import json
import concurrent.futures
import os
import platform
import shutil
import subprocess
import time
import threading
import tkinter as tk
from tkinter import messagebox
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from web3 import Web3
from eth_utils import event_abi_to_log_topic
from hexbytes import HexBytes

from . import req_chain as CH
from . import req_config as C
from . import req_crypto as CRY
from . import req_log as L
from . import req_progress as PROG
from . import req_records as R
from . import req_state as S
from . import req_trusted as TRUST
from . import req_txlog as TX
from . import req_vaultmesh as VM


# Receipt logs may include events emitted by several contracts during one
# transaction. Decode only the exact contract address and event topic instead
# of asking Web3 to warn while discarding unrelated logs.
def _matching_receipt_events(contract_event, receipt) -> list:
    event_abi = contract_event._get_event_abi()
    expected_topic = HexBytes(event_abi_to_log_topic(event_abi))
    expected_address = str(contract_event.address or "").lower()
    decoded = []
    for log_entry in receipt.get("logs", []):
        address = str(log_entry.get("address", "") or "").lower()
        topics = log_entry.get("topics") or []
        if address != expected_address or not topics:
            continue
        if HexBytes(topics[0]) != expected_topic:
            continue
        decoded.append(contract_event.process_log(log_entry))
    return decoded


# ── files list ────────────────────────────────────────────────────────────────

def _fmt_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _path_display_size(path: Path) -> str:
    if path.is_dir():
        return "folder"
    try:
        return _fmt_size(path.stat().st_size)
    except OSError:
        return ""


def _insert_file_tree_node(parent: str, path: Path, base: Path) -> None:
    if S.files_table is None:
        return
    rel = path.relative_to(base).as_posix()
    iid = f"{base.name}:{rel}"
    if S.files_table.exists(iid):
        return
    S.files_table.insert(parent, tk.END, iid=iid, text=path.name, values=(_path_display_size(path),))
    S.files_table_paths[iid] = path
    if path.is_dir():
        for child in sorted(path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
            _insert_file_tree_node(iid, child, base)


# What the requester is willing to unpack without being asked. A stored file is
# whatever its owner chose to put there, and this runs automatically after
# decryption -- no click, no prompt -- so the ceiling has to exist before the
# content is known.
MAX_EXTRACT_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_EXTRACT_MEMBERS = 50_000
_EXTRACT_CHUNK = 1024 * 1024


def _safe_extract_zip(
    zip_path: Path,
    extract_dir: Path,
    max_total_bytes: int = MAX_EXTRACT_TOTAL_BYTES,
    max_members: int = MAX_EXTRACT_MEMBERS,
) -> None:
    """Unpack an archive the requester did not write.

    Two separate questions, and the path check only ever answered the first.

    Where each member lands: unchanged, and still refused if it escapes.

    How much lands: highly compressible content means a few hundred kilobytes
    can become hundreds of gigabytes, and every member of such an archive is
    perfectly well-behaved about its path. The budget is counted against bytes
    actually written rather than the sizes declared in the header, because the
    header is written by whoever built the archive -- trusting it is asking the
    attacker how large the attack is.
    """
    extract_dir.mkdir(parents=True, exist_ok=True)
    extract_root = extract_dir.resolve()
    with zipfile.ZipFile(zip_path, "r") as zf:
        members = zf.infolist()
        if len(members) > max_members:
            raise ValueError(
                f"archive has too many entries ({len(members)} > {max_members})"
            )
        for member in members:
            target = (extract_dir / member.filename).resolve()
            if target != extract_root and extract_root not in target.parents:
                raise ValueError(f"Unsafe ZIP path: {member.filename}")

        written = 0
        for member in members:
            target = extract_dir / member.filename
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member, "r") as src, open(target, "wb") as dst:
                while True:
                    chunk = src.read(_EXTRACT_CHUNK)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > max_total_bytes:
                        dst.close()
                        target.unlink(missing_ok=True)
                        raise ValueError(
                            f"archive exceeds the {max_total_bytes} byte extraction "
                            f"limit; it is too large to unpack automatically"
                        )
                    dst.write(chunk)


def extract_zip_if_needed(file_path: str | os.PathLike) -> Path | None:
    path = Path(file_path)
    if not path.is_file() or path.suffix.lower() != ".zip":
        return None

    extract_dir = C.UNZIPPED_DATA_DIR / path.stem
    try:
        if extract_dir.exists():
            shutil.rmtree(extract_dir)
        _safe_extract_zip(path, extract_dir)
        L.log(f"[ZIP] Extracted {path} -> {extract_dir}")
        return extract_dir
    except Exception as exc:
        L.log(f"[ZIP] Extraction error for {path}: {exc}")
        L.show_error("ZIP Extraction Error", str(exc))
        return None


def refresh_files_list() -> None:
    C.DATA_DIR.mkdir(parents=True, exist_ok=True)
    C.UNZIPPED_DATA_DIR.mkdir(parents=True, exist_ok=True)

    for zip_path in sorted(C.DATA_DIR.glob("*.zip"), key=lambda p: p.name.lower()):
        if not (C.UNZIPPED_DATA_DIR / zip_path.stem).exists():
            extract_zip_if_needed(zip_path)

    raw_files = sorted(C.DATA_DIR.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
    extracted_items = sorted(C.UNZIPPED_DATA_DIR.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))

    # ctk UI — Treeview with name + size columns
    if S.files_table is not None:
        children = S.files_table.get_children()
        if children:
            S.files_table.delete(*children)
        S.files_table_paths.clear()

        if not raw_files and not extracted_items:
            S.files_table.insert("", tk.END, text="(no downloaded files)", values=("",))
        else:
            raw_root = S.files_table.insert("", tk.END, iid="group:raw", text="data", values=("raw",))
            S.files_table_paths[raw_root] = C.DATA_DIR
            for path in raw_files:
                _insert_file_tree_node(raw_root, path, C.DATA_DIR)

            extracted_root = S.files_table.insert("", tk.END, iid="group:unzipped", text="data_unzipped", values=("folder",))
            S.files_table_paths[extracted_root] = C.UNZIPPED_DATA_DIR
            for path in extracted_items:
                _insert_file_tree_node(extracted_root, path, C.UNZIPPED_DATA_DIR)

            S.files_table.item(raw_root, open=True)
            S.files_table.item(extracted_root, open=True)

    # bootstrap UI — plain Listbox
    if S.files_listbox is not None:
        S.files_listbox.delete(0, tk.END)
        if not raw_files and not extracted_items:
            S.files_listbox.insert(tk.END, "(no downloaded files)")
        else:
            for path in raw_files:
                S.files_listbox.insert(tk.END, f"data/{path.name}  ({_path_display_size(path)})")
            for path in extracted_items:
                S.files_listbox.insert(tk.END, f"data_unzipped/{path.name}  ({_path_display_size(path)})")


# ── policy table sort / group / select ───────────────────────────────────────

def _open_system_directory(directory: Path) -> None:
    directory = directory.resolve()
    try:
        system = platform.system()
        if system == "Windows":
            os.startfile(str(directory))
        elif system == "Darwin":
            subprocess.Popen(["open", str(directory)])
        else:
            subprocess.Popen(["xdg-open", str(directory)])
    except Exception as exc:
        L.log(f"[Files] Could not open directory: {exc}")


def browse_selected_file_tree(_event=None) -> None:
    """On single click, expand directories so their contents are visible in the list."""
    if S.files_table is None:
        return
    selection = S.files_table.selection()
    if not selection:
        return
    iid = selection[0]
    path = S.files_table_paths.get(iid)
    if path and path.is_dir():
        S.files_table.item(iid, open=True)


def open_file_directory(_event=None) -> None:
    """Double-click opens a selected directory, or a file's containing directory."""
    if S.files_table is None:
        return
    selection = S.files_table.selection()
    if not selection:
        return
    iid = selection[0]
    label = S.files_table.item(iid, "text")
    if not label or str(label).startswith("("):
        return   # placeholder row

    path = S.files_table_paths.get(iid)
    if path is None:
        return
    _open_system_directory(path if path.is_dir() else path.parent)


def _policy_sort_value(row: dict, column: str):
    numeric_columns = {
        "index", "mode", "threshold", "guardianCount",
        "latestBatchId", "latestDate", "keyEpoch", "pieceCount",
    }
    if column == "rowNumber":
        return 0
    if column == "owner":
        return str(row.get("owner", "")).lower()
    if column == "fileId":
        return str(row.get("fileId", "")).lower()
    if column == "access":
        return (int(row.get("threshold", 0)), int(row.get("guardianCount", 0)))
    if column == "ida":
        return (int(row.get("t", 0)), int(row.get("n", 0)))
    if column == "latestDate":
        return int(row.get("latestTimestamp", 0) or 0)
    if column == "sharedDateTime":
        return int(row.get("sharedTimestamp", 0) or 0)
    if column == "fileExt":
        return str(row.get("fileExt", "") or "").lower()
    if column in numeric_columns:
        return int(row.get(column, 0) or 0)
    return str(row.get(column, "") or "").lower()


def _policy_table_values(row: dict, row_number: int) -> tuple:
    return (
        row_number,
        row.get("owner", ""),
        "",
        row.get("access", ""),
        row.get("ida", ""),
        row.get("latestDataId", ""),
        row.get("latestDate", ""),
        row.get("sharedDateTime", ""),
        row.get("fileExt", ""),
        row.get("latestBatchId", "") or "",
        row.get("keyEpoch", "") or "",
    )


def _policy_group_values(row: dict, file_count: int) -> tuple:
    label = f"{file_count} file" if file_count == 1 else f"{file_count} files"
    return (
        "",
        row.get("owner", ""),
        row.get("fileId", ""),
        row.get("access", ""),
        row.get("ida", ""),
        label,
        "", "", "", "", "",
    )


def _group_policy_rows(rows: list[dict]) -> list[tuple[str, list[dict]]]:
    grouped: list[tuple[str, list[dict]]] = []
    by_file_id: dict[str, list[dict]] = {}
    for row in rows:
        file_id = row.get("fileId", "")
        if file_id not in by_file_id:
            by_file_id[file_id] = []
            grouped.append((file_id, by_file_id[file_id]))
        by_file_id[file_id].append(row)
    return grouped


def render_policy_table() -> None:
    if S.policies_table is None:
        return

    S.policy_table_rendering = True
    try:
        selected = S.policies_table.selection()
        selected_iid = selected[0] if selected else ""
        children = S.policies_table.get_children()
        if children:
            S.policies_table.delete(*children)

        for key, title, _width, _anchor in S.POLICY_TABLE_COLUMNS:
            heading = title
            if key == S.policy_sort_column:
                heading = f"{title} {'v' if S.policy_sort_reverse else '^'}"
            S.policies_table.heading(key, text=heading, anchor="center", command=lambda col=key: sort_policy_table(col))

        row_number = 1
        for file_id, rows in _group_policy_rows(S.policy_rows):
            if not rows:
                continue
            group_iid = f"policy:{file_id}"
            S.policies_table.insert(
                "",
                tk.END,
                iid=group_iid,
                text="",
                image=S.tree_ind_minus or "",   # groups start expanded → show −
                values=_policy_group_values(rows[0], len(rows)),
                open=True,
                tags=("policy_group",),
            )
            for row in rows:
                S.policies_table.insert(
                    group_iid,
                    tk.END,
                    iid=row["rowId"],
                    text="",
                    values=_policy_table_values(row, row_number),
                )
                row_number += 1

        if selected_iid and S.policies_table.exists(selected_iid):
            S.policies_table.selection_set(selected_iid)
            S.policies_table.focus(selected_iid)
    finally:
        S.policy_table_rendering = False


def sort_policy_table(column: str) -> None:
    if S.policy_sort_column == column:
        S.policy_sort_reverse = not S.policy_sort_reverse
    else:
        S.policy_sort_column = column
        S.policy_sort_reverse = False

    S.policy_rows = sorted(
        S.policy_rows,
        key=lambda row: _policy_sort_value(row, column),
        reverse=S.policy_sort_reverse,
    )
    render_policy_table()


def _select_policy_row(row_id_or_file_id: str | None):
    if not row_id_or_file_id:
        return None
    row_id_or_file_id = str(row_id_or_file_id)
    for row in S.policy_rows:
        if str(row.get("rowId", "")) == row_id_or_file_id:
            return row
    try:
        target = R.normalize_file_id_hex(row_id_or_file_id)
    except Exception:
        return None
    for row in S.policy_rows:
        if R.normalize_file_id_hex(row.get("fileId", "")) == target:
            return row
    return None


def _clear_policy_selection_state() -> None:
    S.selected_policy_row_id = None
    S.selected_policy_file_id = None
    S.selected_policy_owner = None
    S.selected_data_tag = ""
    S.selected_date_str = ""
    S.requester_keys = None
    S.requester_key_file_id = None


def _restore_policy_selection(
    previous_row_id: str | None,
    previous_file_id: str | None,
    quiet: bool = False,
) -> bool:
    row = _select_policy_row(previous_row_id) or _select_policy_row(previous_file_id)
    if row is None:
        _clear_policy_selection_state()
        if S.policies_table is not None:
            selection = S.policies_table.selection()
            if selection:
                S.policies_table.selection_remove(*selection)
        if previous_file_id and not quiet:
            L.log("[Policy] Previously selected policy is no longer accessible.")
        return False

    S.selected_policy_row_id = row["rowId"]
    S.selected_policy_file_id = row["fileId"]
    S.selected_policy_owner = row["owner"]
    _apply_cached_policy_defaults(row, quiet=quiet)

    if S.policies_table is not None and S.policies_table.exists(row["rowId"]):
        S.policies_table.selection_set(row["rowId"])
        S.policies_table.focus(row["rowId"])
        S.policies_table.see(row["rowId"])

    try:
        selected_key_file_id = R.normalize_file_id_hex(row["fileId"])
    except Exception:
        selected_key_file_id = str(row["fileId"]).lower()
    if S.requester_key_file_id != selected_key_file_id:
        load_policy_key(row["fileId"], quiet=quiet)
    return True


def select_policy_from_table(_event=None) -> None:
    if S.policies_table is None or S.policy_table_rendering:
        return
    selection = S.policies_table.selection()
    if not selection:
        return

    row = _select_policy_row(selection[0])
    if row is None:
        children = S.policies_table.get_children(selection[0])
        if children:
            S.policies_table.item(selection[0], open=True)
            S.policies_table.selection_set(children[0])
            S.policies_table.focus(children[0])
            row = _select_policy_row(children[0])
        if row is None:
            return

    row_id = str(row.get("rowId", ""))
    if S.selected_policy_row_id == row_id:
        return

    S.selected_policy_row_id = row_id
    S.selected_policy_file_id = row["fileId"]
    S.selected_policy_owner = row["owner"]

    L.log("[Policy] Selected file for request flow:")
    L.log(f"  owner : {row['owner']}")
    L.log(f"  fileId: {row['fileId']}")
    L.log(f"  access: {row['threshold']}/{row['guardianCount']}")
    L.log(f"  data  : {row.get('latestDataId', '') or '(none)'}")
    L.log(f"  batch : {row.get('latestBatchId', '') or '(none)'}")

    load_policy_key(row["fileId"])
    _apply_cached_policy_defaults(row)


def _apply_cached_policy_defaults(row: dict, quiet: bool = False) -> None:
    data_id = row.get("latestDataId", "")
    date_str = row.get("latestDate", "")
    S.selected_data_tag = str(data_id or "")
    S.selected_date_str = str(date_str or "")

    if not quiet and (data_id or date_str):
        L.log(
            f"[Policy] Selected batch: batchId={row.get('latestBatchId', '')}, "
            f"Data ID={data_id or '(none)'}, Date={date_str or '(none)'}, "
            f"IDA={row.get('ida', '') or '(unknown)'}, keyEpoch={row.get('keyEpoch', '') or '(unknown)'}"
        )


def clear_selected_policy() -> None:
    _clear_policy_selection_state()
    if S.policies_table is not None:
        selection = S.policies_table.selection()
        if selection:
            S.policies_table.selection_remove(*selection)
    L.set_status("Policy selection cleared", "ready")


def _select_first_policy_row() -> None:
    if not S.policy_rows:
        return
    first_row = S.policy_rows[0]
    first_iid = first_row["rowId"]
    if S.policies_table is None:
        S.selected_policy_row_id = first_iid
        S.selected_policy_file_id = first_row["fileId"]
        S.selected_policy_owner = first_row["owner"]
        _apply_cached_policy_defaults(first_row, quiet=True)
        load_policy_key(first_row["fileId"], quiet=True)
        return

    S.policies_table.selection_set(first_iid)
    S.policies_table.focus(first_iid)
    S.policies_table.see(first_iid)
    select_policy_from_table()


def load_available_policies_for_requester(
    auto_select_first: bool = False,
    quiet: bool = False,
    preserve_selection: bool = False,
    background_sync: bool = False,
):
    """Show this requester's accessible files, from cache and then from chain.

    `background_sync` hands the chain walk to a worker and returns as soon as
    the cached rows are on screen. The window uses it; the load-test harness and
    the other callers here want the rows before they continue, so they do not.
    """
    requester = CH.get_requester_checksum()
    previous_row_id = S.selected_policy_row_id if preserve_selection else None
    previous_file_id = S.selected_policy_file_id if preserve_selection else None
    S.policy_rows = []
    if not preserve_selection:
        _clear_policy_selection_state()

    cached_rows = R.load_policy_cache(requester_checksum=requester, quiet=quiet)
    cache_existed = C.POLICY_CACHE_FILE.exists()
    if cached_rows:
        S.policy_rows = cached_rows
        render_policy_table()
        if not quiet:
            L.log(f"[Policy] Loaded {len(cached_rows)} cached accessible file(s) from {C.POLICY_CACHE_FILE.name}.")
    else:
        render_policy_table()
        if not cache_existed and not quiet:
            L.log(f"[Policy] Local {C.POLICY_CACHE_FILE.name} not found. Creating it from blockchain policies.")

    previous_ids = {row["rowId"] for row in cached_rows}
    if background_sync:
        start_policy_sync(force=True)
        if preserve_selection:
            _restore_policy_selection(previous_row_id, previous_file_id, quiet=quiet)
        elif auto_select_first and S.policy_rows:
            _select_first_policy_row()
        return S.policy_rows

    try:
        if not quiet:
            L.set_status("Syncing policies", "running")
        chain_rows = CH.fetch_accessible_file_rows()
        new_ids = {row["rowId"] for row in chain_rows} - previous_ids
        S.policy_rows = chain_rows
        render_policy_table()
        R.save_policy_cache(S.policy_rows, requester)

        if not quiet:
            L.log(f"[Policy] Synced {len(S.policy_rows)} accessible file(s) where requester {requester} is allowed.")
            if new_ids:
                L.log(f"[Policy] Added {len(new_ids)} new accessible file(s) to {C.POLICY_CACHE_FILE.name}.")
            if not S.policy_rows:
                L.log("[Policy] No accessible file found. DO must upload data under a policy that allows this requester.")
        if not quiet:
            L.set_status("Policies synced", "done")
    except Exception as exc:
        if cached_rows:
            if not quiet:
                L.log(f"[Policy] Blockchain sync failed; using local cache. Error: {exc}")
                L.set_status("Using cached policies", "waiting")
        else:
            if not quiet:
                L.log(f"[Policy] Load error: {exc}")
                L.show_error("Policy Load Error", str(exc))
            if not cache_existed:
                try:
                    R.save_policy_cache([], requester)
                except Exception as write_error:
                    if not quiet:
                        L.log(f"[Policy] Could not create {C.POLICY_CACHE_FILE.name}: {write_error}")
            if not quiet:
                L.set_status("Policy sync failed", "error")

    restored = False
    if preserve_selection:
        restored = _restore_policy_selection(previous_row_id, previous_file_id, quiet=quiet)

    if auto_select_first and not restored and S.policy_rows:
        _select_first_policy_row()
    return S.policy_rows


# ── Policy sync, off the thread that draws the window ────────────────────────
# fetch_accessible_file_rows() walks every policy on the chain and makes several
# blocking calls for each one. That is tens of seconds against a busy node, and
# it used to run on the window's own thread -- once at start-up and then again
# every ten seconds, which is far less than one pass takes. The app therefore
# spent nearly all of its life unresponsive: measured at 35-45 seconds per pass,
# with 86% of the window's first 45 seconds blocked inside a socket read.
#
# The fetch now happens on a worker, which touches nothing but these three
# variables. The window collects the result on its own timer; no thread but the
# window's ever calls into Tk.
_policy_sync_lock = threading.Lock()
_policy_sync_running = False
_policy_sync_finished_at = 0.0
_policy_sync_result: tuple[list | None, Exception | None] | None = None

# One pass was measured at 39 seconds against the live node, and the window asks
# every ten, so without a gap the app would walk the chain back to back for as
# long as it is open. Waiting here costs freshness the user cannot perceive and
# saves the node a permanent reader.
POLICY_SYNC_MIN_GAP_SECONDS = 30.0


def start_policy_sync(force: bool = False) -> bool:
    """Begin a chain sync unless one is running or one just finished."""
    global _policy_sync_running
    with _policy_sync_lock:
        if _policy_sync_running:
            return False
        if not force and time.time() - _policy_sync_finished_at < POLICY_SYNC_MIN_GAP_SECONDS:
            return False
        _policy_sync_running = True

    def work() -> None:
        global _policy_sync_running, _policy_sync_result, _policy_sync_finished_at
        try:
            outcome: tuple[list | None, Exception | None] = (CH.fetch_accessible_file_rows(), None)
        except Exception as exc:  # reported on the window's thread, not here
            outcome = (None, exc)
        with _policy_sync_lock:
            _policy_sync_result = outcome
            _policy_sync_finished_at = time.time()
            _policy_sync_running = False

    threading.Thread(target=work, daemon=True, name="policy-sync").start()
    return True


def apply_finished_policy_sync(quiet: bool = True) -> bool:
    """Put a finished sync on screen. Call only from the window's thread."""
    global _policy_sync_result
    with _policy_sync_lock:
        outcome, _policy_sync_result = _policy_sync_result, None
    if outcome is None:
        return False

    rows, error = outcome
    requester = CH.get_requester_checksum()
    if error is not None:
        if not quiet:
            if S.policy_rows:
                L.log(f"[Policy] Blockchain sync failed; using local cache. Error: {error}")
                L.set_status("Using cached policies", "waiting")
            else:
                L.log(f"[Policy] Load error: {error}")
                L.set_status("Policy sync failed", "error")
        return True

    previous_ids = {str(row.get("rowId", "")) for row in S.policy_rows}
    selected_row_id = S.selected_policy_row_id
    selected_file_id = S.selected_policy_file_id
    S.policy_rows = rows
    render_policy_table()
    try:
        R.save_policy_cache(rows, requester)
    except Exception as exc:
        if not quiet:
            L.log(f"[Policy] Could not write {C.POLICY_CACHE_FILE.name}: {exc}")

    restored = _restore_policy_selection(selected_row_id, selected_file_id, quiet=True)
    if not restored and not selected_row_id and rows:
        _select_first_policy_row()

    if not quiet:
        new_count = len({str(r.get("rowId", "")) for r in rows} - previous_ids)
        L.log(f"[Policy] Synced {len(rows)} accessible file(s) for requester {requester}.")
        if new_count:
            L.log(f"[Policy] Added {new_count} new accessible file(s).")
        L.set_status("Policies synced", "done")
    return True


def auto_refresh_available_policies() -> None:
    """One turn of the periodic refresh: collect a finished sync, start the next.

    Returns immediately. Previously this ran the whole chain walk inline, so
    every tick froze the window for longer than the interval between ticks.
    """
    previous_ids = {str(row.get("rowId", "")) for row in S.policy_rows}
    if apply_finished_policy_sync(quiet=True):
        new_count = len({str(r.get("rowId", "")) for r in S.policy_rows} - previous_ids)
        if new_count:
            label = "policy" if new_count == 1 else "policies"
            L.log(f"[Policy] Auto-refresh found {new_count} new/updated accessible {label}. Select it from the list to download.")
            L.set_status("New policy available", "done")
    start_trusted_auto_sync()
    start_policy_sync()


# ── the trusted owners table ─────────────────────────────────────────────────

def refresh_trusted_owners_table() -> None:
    if S.trusted_table is None:
        return
    for iid in S.trusted_table.get_children():
        S.trusted_table.delete(iid)
    for owner in TRUST.load_owners():
        S.trusted_table.insert(
            "", tk.END, iid=owner["address"].lower(),
            values=(
                owner.get("name", "") or "(no name)",
                owner["address"],
                "On" if owner.get("autoSync") else "Off",
            ),
        )


def add_trusted_owner_from_form() -> None:
    address = S.trusted_address_entry.get().strip() if S.trusted_address_entry else ""
    name = S.trusted_name_entry.get().strip() if S.trusted_name_entry else ""
    ok, message = TRUST.add_owner(address, name)
    if not ok:
        L.show_error("Trusted owner", message)
        return
    if S.trusted_address_entry is not None:
        S.trusted_address_entry.delete(0, tk.END)
    if S.trusted_name_entry is not None:
        S.trusted_name_entry.delete(0, tk.END)
    refresh_trusted_owners_table()
    L.log(f"[trusted] added {address} ({name or 'no name'}), auto-sync off")


def add_trusted_owner_from_selected_policy() -> None:
    owner = str(S.selected_policy_owner or "").strip()
    if not owner:
        L.show_error(
            "Trusted owner",
            "Select a policy in the Dashboard first; its owner is added here.",
        )
        return
    name = S.trusted_name_entry.get().strip() if S.trusted_name_entry else ""
    ok, message = TRUST.add_owner(owner, name)
    if not ok:
        L.show_error("Trusted owner", message)
        return
    refresh_trusted_owners_table()
    L.log(f"[trusted] added {owner} from the selected policy, auto-sync off")


def remove_selected_trusted_owner() -> None:
    if S.trusted_table is None:
        return
    selection = S.trusted_table.selection()
    if not selection:
        L.show_error("Trusted owner", "Select an owner in the table first.")
        return
    address = str(selection[0])
    if TRUST.remove_owner(address):
        refresh_trusted_owners_table()
        L.log(f"[trusted] removed {address}")


def trusted_table_clicked(event=None) -> None:
    """Clicking the Auto-sync cell switches that owner on or off.

    A table row cannot hold a real switch, so the cell is the switch. Turning
    one on says plainly what it will spend, because that is the whole point of
    the setting.
    """
    if S.trusted_table is None or event is None:
        return
    if S.trusted_table.identify_region(event.x, event.y) != "cell":
        return
    if S.trusted_table.identify_column(event.x) != "#3":
        return
    row_id = S.trusted_table.identify_row(event.y)
    if not row_id:
        return

    owners = {o["address"].lower(): o for o in TRUST.load_owners()}
    owner = owners.get(str(row_id).lower())
    if owner is None:
        return
    turning_on = not owner.get("autoSync")

    if turning_on and not messagebox.askyesno(
        "Turn on auto-sync",
        f"Automatically download every new file from\n{owner['address']}?\n\n"
        "Each download pays an escrow deposit and gas on chain before the "
        "contents can be checked, and that money is not refunded if the file "
        "turns out to be wrong.\n\n"
        "Only turn this on for an owner you trust.",
        icon="warning",
    ):
        return

    TRUST.set_auto_sync(owner["address"], turning_on)
    refresh_trusted_owners_table()
    L.log(f"[trusted] auto-sync {'on' if turning_on else 'off'} for {owner['address']}")
    if turning_on:
        start_trusted_auto_sync()


# ── automatic download from trusted owners ───────────────────────────────────
#
# Only from an owner this requester put in the list and switched on. Any
# address can create a policy and add this one to it, and a request deposits
# escrow on chain before the contents can be checked, so "download whatever is
# shared with me" would let a stranger spend this balance on rubbish.

_auto_sync_running = False
_auto_sync_lock = threading.Lock()


def _auto_sync_candidates() -> list[dict]:
    """Rows worth fetching now: trusted owner, a batch to fetch, not had yet."""
    trusted = TRUST.auto_sync_addresses()
    if not trusted:
        return []
    candidates = []
    for row in S.policy_rows:
        if str(row.get("owner", "")).lower() not in trusted:
            continue
        batch_id = row.get("latestBatchId", "")
        if not str(batch_id or "").strip():
            continue   # a policy with nothing uploaded to it yet
        if not row.get("latestDataId") or not row.get("latestDate"):
            continue
        if not TRUST.should_try(row.get("fileId", ""), batch_id):
            continue
        candidates.append(row)
    return candidates


def start_trusted_auto_sync() -> None:
    """Fetch anything new from trusted owners, one file at a time.

    Started after each policy refresh and does nothing when there is nothing
    new: every file already fetched is recorded, and one that failed is left
    alone for hours rather than retried on the next pass, because each attempt
    can cost gas.
    """
    global _auto_sync_running
    with _auto_sync_lock:
        if _auto_sync_running:
            return
        candidates = _auto_sync_candidates()
        if not candidates:
            return
        _auto_sync_running = True

    # Taken on the window's thread: the worker must not read the table.
    jobs = [
        {
            "rowId": str(row.get("rowId", "")),
            "fileId": str(row.get("fileId", "")),
            "owner": str(row.get("owner", "")),
            "batchId": row.get("latestBatchId", ""),
            "dataId": str(row.get("latestDataId", "")),
            "date": str(row.get("latestDate", "")),
        }
        for row in candidates
    ]
    word = "file" if len(jobs) == 1 else "files"
    L.log(f"[sync] {len(jobs)} new {word} from trusted owners")

    def work() -> None:
        global _auto_sync_running
        try:
            for job in jobs:
                _auto_sync_one(job)
        finally:
            _auto_sync_running = False

    threading.Thread(target=work, daemon=True, name="trusted-sync").start()


def _auto_sync_one(job: dict) -> None:
    """Download one file from a trusted owner, and remember the outcome."""
    label = f"{job['dataId'] or job['fileId'][:12]} from {job['owner'][:10]}"
    L.log(f"[sync] {label}: starting")
    try:
        # The selection the request flow reads. An existing request for this
        # exact file, batch and key is found and reused by the flow itself, so
        # a second run never pays a second time.
        S.selected_policy_row_id = job["rowId"]
        S.selected_policy_file_id = job["fileId"]
        S.selected_policy_owner = job["owner"]
        S.selected_data_tag = job["dataId"]
        S.selected_date_str = job["date"]
        S.current_request_id = None
        load_policy_key(job["fileId"], quiet=True)

        ok = run_all(sync_label=label)
    except Exception as exc:
        TRUST.mark_failed(job["fileId"], job["batchId"], str(exc))
        L.log(f"[sync] {label}: failed ({exc})")
        return

    if ok:
        TRUST.mark_done(job["fileId"], job["batchId"])
        L.log(f"[sync] {label}: downloaded")
    else:
        TRUST.mark_failed(job["fileId"], job["batchId"], "download did not finish")
        L.log(f"[sync] {label}: did not finish; will not retry for hours")


def start_policy_auto_refresh() -> None:
    if S.root is None or S.policy_auto_refresh_after_id is not None:
        return

    def _schedule_next() -> None:
        if S.root is None:
            return
        try:
            if not S.root.winfo_exists():
                return
            S.policy_auto_refresh_after_id = S.root.after(
                S.policy_auto_refresh_interval_ms,
                _tick,
            )
        except tk.TclError:
            S.policy_auto_refresh_after_id = None

    def _tick() -> None:
        S.policy_auto_refresh_after_id = None
        try:
            auto_refresh_available_policies()
        finally:
            _schedule_next()

    _schedule_next()


# ── requester key management ──────────────────────────────────────────────────

def _policy_key_id(file_id: str) -> str:
    try:
        return R.normalize_file_id_hex(file_id)
    except Exception:
        return str(file_id or "").lower()


def load_policy_key(file_id: str = None, quiet: bool = False) -> None:
    """Load the requester key bound to the given fileId (or the currently selected policy)."""
    fid = file_id or S.selected_policy_file_id
    if not fid:
        S.requester_keys = None
        S.requester_key_file_id = None
        if not quiet:
            L.log("[Key] No policy selected — key not loaded.")
        return
    key_path = C.key_path_for_policy(fid)
    if not key_path.exists():
        S.requester_keys = None
        S.requester_key_file_id = None
        if not quiet:
            L.log("[Key] No key found for this policy. Download will create one automatically, or use Generate Key to force a new one.")
        return
    try:
        S.requester_keys = json.loads(key_path.read_text(encoding="utf-8"))
        S.requester_key_file_id = _policy_key_id(fid)
        if not quiet:
            L.log(f"[Key] Loaded key for policy {fid[:18]}...")
            L.log(f"[Key] PK_req.x: {S.requester_keys.get('PK_req_x')}")
            L.log(f"[Key] PK_req.y: {S.requester_keys.get('PK_req_y')}")
    except Exception as exc:
        S.requester_keys = None
        S.requester_key_file_id = None
        if not quiet:
            L.log(f"[Key] Error loading key: {exc}")


def load_requester_keys_if_exist() -> None:
    """Called on startup — loads key for the selected policy if one is already selected."""
    load_policy_key()


def _generate_policy_key(fid: str, show_dialog: bool, context: str) -> bool:
    if not fid:
        return False

    C.KEYS_DIR.mkdir(parents=True, exist_ok=True)
    key_path = C.key_path_for_policy(fid)
    existed = key_path.exists()
    try:
        S.requester_keys = CRY.generate_requester_ec_keys(str(key_path))
        S.requester_key_file_id = _policy_key_id(fid)
    except Exception as exc:
        S.requester_keys = None
        S.requester_key_file_id = None
        L.show_error("Key Generation Error", str(exc))
        L.log(f"[{context}] Error: {exc}")
        return False

    action = "updated" if existed else "created"
    L.log(f"[{context}] Key {action} for policy {fid[:18]}...")
    L.log(f"[{context}] Curve: {S.requester_keys['curve']}")
    L.log(f"[{context}] PK_req.x: {S.requester_keys['PK_req_x']}")
    L.log(f"[{context}] PK_req.y: {S.requester_keys['PK_req_y']}")
    L.log(f"[{context}] Saved to: keys/{key_path.name}")
    if show_dialog:
        L.show_info("Key Generated", f"Requester key {action} for policy:\n{fid[:22]}...\n\nFile: keys/{key_path.name}")
    return True


def ensure_selected_policy_key() -> bool:
    fid = S.selected_policy_file_id
    if not fid:
        return False

    key_id = _policy_key_id(fid)
    if S.requester_keys is None or S.requester_key_file_id != key_id:
        load_policy_key(fid)
    if S.requester_keys is not None and S.requester_key_file_id == key_id:
        return True

    L.log("[Key] Creating requester key automatically for selected policy.")
    return _generate_policy_key(fid, show_dialog=False, context="Auto Key")


def run_keygen_request() -> None:
    fid = S.selected_policy_file_id
    if not fid:
        L.show_warning("No Policy Selected", "Select a policy from the list before generating a key.")
        L.log("[Generate Key] No policy selected.")
        return

    _generate_policy_key(fid, show_dialog=True, context="Generate Key")


# ── pieces dir ────────────────────────────────────────────────────────────────

def clean_pieces_dir(log_cleanup: bool = False) -> None:
    C.PIECES_DIR.mkdir(parents=True, exist_ok=True)
    removed = 0
    for item in C.PIECES_DIR.iterdir():
        if item.is_dir():
            shutil.rmtree(item)
        else:
            item.unlink()
        removed += 1
    if log_cleanup:
        L.log(f"[Pieces] Cleaned temporary pieces directory ({removed} item(s) removed).")


def delete_all_pieces() -> None:
    clean_pieces_dir(log_cleanup=True)
    refresh_files_list()


# ── file context resolution ───────────────────────────────────────────────────

def get_current_request_file_context():
    """Return (file_id_bytes, file_id_hex, owner, source) from the selected policy row."""
    if S.selected_policy_file_id:
        file_id_hex = R.normalize_file_id_hex(S.selected_policy_file_id)
        file_id = Web3.to_bytes(hexstr=file_id_hex)
        owner = Web3.to_checksum_address(S.selected_policy_owner) if S.selected_policy_owner else None
        return file_id, file_id_hex, owner, "selected_policy"

    rows = load_available_policies_for_requester(auto_select_first=False, quiet=True)
    if len(rows) == 1:
        row = rows[0]
        S.selected_policy_row_id = row["rowId"]
        S.selected_policy_file_id = row["fileId"]
        S.selected_policy_owner = row["owner"]
        if S.policies_table is not None:
            S.policies_table.selection_set(row["rowId"])
            S.policies_table.focus(row["rowId"])
        file_id_hex = R.normalize_file_id_hex(row["fileId"])
        file_id = Web3.to_bytes(hexstr=file_id_hex)
        owner = Web3.to_checksum_address(row["owner"])
        return file_id, file_id_hex, owner, "auto_selected_allowed_policy"

    if not rows:
        raise ValueError(
            "No accessible uploaded file found for this requester. "
            "The Data Owner must upload data under a policy that allows this REQ address."
        )
    raise ValueError(
        "Multiple files are accessible to this requester. "
        "Select the intended file from the list before downloading."
    )


# ── reuse check ───────────────────────────────────────────────────────────────

def _find_prior_request_id(
    w3, dv, req_checksum: str, file_id: bytes, batch_id: int, pkreq_x: int, pkreq_y: int
) -> int | None:
    """
    Scan DataAccessRequestedV2 events (newest first) for a prior request from
    the same requester with the same fileId, batchId, and public key.

    reusableRequestPlusOneByKey is only set by Legacy TElG (storeReencryptedCids),
    never by V2, so events are the correct source for V2 request discovery.
    """
    file_id_hex = file_id.hex() if isinstance(file_id, bytes) else str(file_id)
    try:
        # Paged, because a chain that caps log ranges refuses one request for
        # all of history (Cosmos: 10,000 blocks, about three hours of chain).
        from core.req_chain import collect_logs_windowed
        events = collect_logs_windowed(w3, dv.events.DataAccessRequestedV2)
    except Exception as exc:
        L.log(f"[Flow] Could not read DataAccessRequestedV2 events: {exc}")
        return None

    for event in reversed(events):
        try:
            args = event["args"]
            if (
                str(args["requester"]).lower() == req_checksum.lower()
                and bytes(args["fileId"]).hex() == file_id_hex
                and int(args["batchId"]) == int(batch_id)
                and int(args["pkReqX"]) == int(pkreq_x)
                and int(args["pkReqY"]) == int(pkreq_y)
            ):
                return int(args["requestId"])
        except Exception:
            continue
    return None


def _check_reusable_request(
    w3, dv, req_checksum: str, file_id: bytes, batch_id: int, pkreq_x: int, pkreq_y: int
) -> tuple[int, str] | None:
    """
    Return (requestId, flow) for matching completed access or a funded request
    still awaiting partials. Pending work must be resumed rather than duplicated.
    """
    try:
        prior_id = _find_prior_request_id(w3, dv, req_checksum, file_id, batch_id, pkreq_x, pkreq_y)
        if prior_id is None:
            return None

        L.log(f"[Flow] Found prior request #{prior_id} for same fileId+batch+pubkey.")

        # Fast path: local decrypted keys file already exists from a previous run
        local_file = R.reenc_cids_path(prior_id)
        if local_file.exists():
            L.log(f"[Flow] Reusing request #{prior_id}: local decrypted keys file exists.")
            return prior_id, "reuse"

        # Slow path: V2 PRE partials may still be on-chain from the previous request
        L.log(f"[Flow] Attempting to aggregate on-chain V2 partials for request #{prior_id}...")
        if CH.build_reenc_cids_from_pre_partials(prior_id):
            L.log(f"[Flow] Reusing request #{prior_id}: V2 PRE partials available on-chain.")
            return prior_id, "reuse"

        reward_addr = getattr(C.config, "REWARD_MANAGER_ADDRESS", "")
        reward_json = getattr(C.config, "REWARD_MANAGER_JSON", "")
        if reward_addr and reward_json:
            rewards = C.load_contract_from_config(w3, reward_addr, reward_json)
            if rewards.functions.hasV2AccessEscrow(prior_id).call():
                L.log(f"[Flow] Resuming funded request #{prior_id}; waiting for Guardian partials.")
                return prior_id, "pending"

        L.log(f"[Flow] Prior request #{prior_id} has no reusable partials or remaining access escrow.")
        return None

    except Exception as exc:
        L.log(f"[Flow] Reuse check skipped: {exc}. Proceeding with new request.")
        return None


# ── on-chain request flow ─────────────────────────────────────────────────────

def run_request_data_flow():
    """Send requestReencForFile + requestDataAccess, or reuse existing permission."""
    if not S.selected_policy_file_id:
        load_available_policies_for_requester(auto_select_first=True, quiet=True)
        if not S.selected_policy_file_id:
            L.log("[Flow] No file selected.")
            L.show_warning("Missing File", "Select one accessible file from the list.")
            return None

    if not ensure_selected_policy_key():
        L.log("[Flow] Could not prepare requester key for this policy.")
        return None

    selected_row = _select_policy_row(S.selected_policy_row_id or S.selected_policy_file_id)
    truck_id = str(S.selected_data_tag or (selected_row or {}).get("latestDataId", "")).strip()
    date_str = str(S.selected_date_str or (selected_row or {}).get("latestDate", "")).strip()

    if not truck_id or not date_str:
        L.log("[Flow] Selected file row has no batch data to request.")
        L.show_warning("No Batch", "Selected file row has no batch data to download. Refresh policies and try again.")
        return None

    try:
        file_id, file_id_hex, policy_owner, file_id_source = get_current_request_file_context()
    except Exception as exc:
        L.log(f"[Flow] Invalid policy/DO context: {exc}")
        L.show_error("Policy Error", str(exc))
        return None

    date_str = date_str.split()[0]
    try:
        day = datetime.strptime(date_str, "%Y-%m-%d").date()
    except ValueError:
        L.log(f"[Flow] Invalid date format for selected policy: {date_str}")
        L.show_error("Invalid Date", "Date must be in format YYYY-MM-DD.")
        return None

    pkreq_x = int(S.requester_keys["PK_req_x"])
    pkreq_y = int(S.requester_keys["PK_req_y"])

    L.log("=== Starting on-chain request flow ===")

    w3 = C.new_web3(C.config)
    if not w3.is_connected():
        L.log("[Flow] Web3 not connected.")
        L.show_error("Web3 Error", "Cannot connect to RPC endpoint.")
        return None

    try:
        req_account = w3.eth.account.from_key(C.config.REQ_PRIVATE_KEY)
        req_address = req_account.address
        L.log(f"[ACL] Using REQ account: {req_address}")

        acl = C.load_contract_from_config(w3, C.config.ACL_ADDRESS, C.config.ACL_JSON)
        dv  = C.load_contract_from_config(w3, C.config.DV_ADDRESS, C.config.DV_JSON)

        req_checksum = Web3.to_checksum_address(req_account.address)
        ts = int(datetime(day.year, day.month, day.day, tzinfo=timezone.utc).timestamp())

        L.log(f"[DV] fileId source: {file_id_source}")
        L.log(f"[DV] fileId: {file_id_hex}")
        L.log(f"[DV] Looking for batch: dataId='{truck_id}', ts={ts}")

        batch_exists, batch_id, batch_data = CH.find_batch_by_policy_data_date(dv, file_id, truck_id, ts)

        if not batch_exists or int(batch_id) == 0 or batch_data is None:
            L.log("[DV] No batch found for this selected policy + Data ID + Date.")
            L.show_error("DataVault Error", "No batch found for this selected policy + Data ID + Date.")
            return None

        (
            file_id, data_owner, dataId_on, ts_on,
            n_on, t_on, keyEpoch_on, cid_indices,
        ) = batch_data

        file_id_hex = file_id.hex()
        L.log(f"[DV] BatchId: {batch_id}")
        L.log(f"[DV] fileId : {file_id_hex}")
        L.log(f"[DV] DataOwner: {data_owner}")

        # Check if the same (requester, fileId, batchId, pubkey) was already processed
        reuse = _check_reusable_request(w3, dv, req_checksum, file_id, batch_id, pkreq_x, pkreq_y)
        if reuse is not None:
            reuse_id, reuse_flow = reuse
            S.current_request_id = reuse_id
            S.current_n = int(n_on)
            S.current_t = int(t_on)
            S.current_file_ext = ""
            return reuse_flow

        is_req           = acl.functions.isRequester(req_checksum).call()
        is_req_for_file  = acl.functions.isRequesterForFile(file_id, req_checksum).call()
        has_reenc_before = acl.functions.hasRequestedReenc(req_checksum).call()

        L.log(f"[ACL] isRequester              : {is_req}")
        L.log(f"[ACL] isRequesterForFile       : {is_req_for_file}")
        L.log(f"[ACL] hasRequestedReenc(before): {has_reenc_before}")

        # The global Requester role is not what the V2 path checks -- DataVault
        # and TElGv2 both ask only isRequesterForFile. Refusing here on the
        # role alone turned away an address the contracts would have served,
        # which is what a Data Owner recovering its own file looks like: it
        # holds the DataOwner role and is on its own file's list.
        if not is_req:
            L.log("[ACL] No global Requester role; the V2 path does not need one.")

        if not is_req_for_file:
            L.log("[ACL] Requester is not allowed for this fileId.")
            L.show_error("ACL Error", "Requester is not allowed for this fileId. DO must add this REQ first.")
            return None

        if not has_reenc_before:
            # Per file, not global: requestReenc() requires the Requester
            # role, requestReencForFile() requires only being on that file's
            # list -- and it sets the same flag DataVault then checks.
            fn_req = acl.functions.requestReencForFile(file_id)
            gas_est = fn_req.estimate_gas({"from": req_address})
            TX.log_eth_call(
                C,
                contract_name="eth",
                function_name="estimateGas",
                contract_address=acl.address,
                actor_address=req_address,
                status="success",
                gas_estimate=gas_est,
                target_function="requestReencForFile",
            )
            L.log(f"[ACL] requestReencForFile gas estimate: {gas_est}")
            nonce = w3.eth.get_transaction_count(req_address)
            TX.log_eth_call(
                C,
                contract_name="eth",
                function_name="getTransactionCount",
                actor_address=req_address,
                status="success",
                nonce=nonce,
                target_function="requestReencForFile",
            )
            gas_price_req = C.gas_price_wei()
            TX.log_eth_call(
                C,
                contract_name="eth",
                function_name="gasPrice",
                actor_address=req_address,
                status="success",
                result=gas_price_req,
                target_function="requestReencForFile",
            )
            tx_req = fn_req.build_transaction({
                "from": req_address,
                "nonce": nonce,
                "gas": gas_est + 50_000,
                "gasPrice": gas_price_req,
            })
            signed_req = req_account.sign_transaction(tx_req)
            tx_hash_req = w3.eth.send_raw_transaction(signed_req.raw_transaction)
            L.log(f"[ACL] requestReencForFile tx: {tx_hash_req.hex()}")
            receipt_req = w3.eth.wait_for_transaction_receipt(tx_hash_req)
            TX.log_contract_transaction(
                C,
                w3,
                actor_address=req_address,
                contract_name="AccessControlFT",
                function_name="requestReencForFile",
                contract_address=acl.address,
                tx=tx_req,
                tx_hash=tx_hash_req,
                receipt=receipt_req,
            )
            L.log(f"[ACL] Tx status: {receipt_req.status}")
            has_reenc_after = acl.functions.hasRequestedReenc(req_checksum).call()
            L.log(f"[ACL] hasRequestedReenc(after): {has_reenc_after}")
        else:
            L.log("[ACL] Re-encryption already requested; skipping requestReencForFile().")

    except Exception as exc:
        L.log(f"[ACL/DV] Error before requestDataAccess: {exc}")
        L.show_error("ACL/DataVault Error", str(exc))
        return None

    try:
        try:
            policy_mode = int(acl.functions.getFilePolicyMode(file_id).call())
        except Exception:
            policy_mode = 0

        access_escrow = 0
        if policy_mode == 1:
            reward_addr = getattr(C.config, "REWARD_MANAGER_ADDRESS", "")
            reward_json = getattr(C.config, "REWARD_MANAGER_JSON", "")
            if not reward_addr or not reward_json:
                raise RuntimeError("ZKDKG_V2 access requires RewardManager config for requester-funded PRE escrow.")
            reward_manager = C.load_contract_from_config(w3, reward_addr, reward_json)
            access_escrow = int(reward_manager.functions.estimateV2PreEscrow(file_id, int(batch_id)).call())
            CH.log_v2_pre_price_estimate(w3, acl, reward_manager, file_id)
            L.log(f"[REQ-V2] Required PRE/access escrow: {access_escrow} wei")
            fn_dv = dv.functions.requestDataAccessForFileDataWithEscrow(
                file_id, truck_id, ts, pkreq_x, pkreq_y
            )
        else:
            fn_dv = dv.functions.requestDataAccessForFileData(
                file_id, truck_id, ts, pkreq_x, pkreq_y
            )

        fn_dv_name = TX.function_name(fn_dv, "requestDataAccessForFileData")
        gas_est_dv = fn_dv.estimate_gas({"from": req_account.address, "value": access_escrow})
        TX.log_eth_call(
            C,
            contract_name="eth",
            function_name="estimateGas",
            contract_address=dv.address,
            actor_address=req_account.address,
            status="success",
            gas_estimate=gas_est_dv,
            target_function=fn_dv_name,
            access_escrow_wei=access_escrow,
        )
        L.log(f"[DV] requestDataAccessForFileData gas estimate: {gas_est_dv}")
        nonce2 = w3.eth.get_transaction_count(req_account.address)
        TX.log_eth_call(
            C,
            contract_name="eth",
            function_name="getTransactionCount",
            actor_address=req_account.address,
            status="success",
            nonce=nonce2,
            target_function=fn_dv_name,
        )
        gas_price_dv = C.gas_price_wei()
        TX.log_eth_call(
            C,
            contract_name="eth",
            function_name="gasPrice",
            actor_address=req_account.address,
            status="success",
            result=gas_price_dv,
            target_function=fn_dv_name,
        )
        tx_dv = fn_dv.build_transaction({
            "from": req_account.address,
            "nonce": nonce2,
            "gas": gas_est_dv + 50_000,
            "gasPrice": gas_price_dv,
            "value": access_escrow,
        })
        signed_dv = req_account.sign_transaction(tx_dv)
        tx_hash_dv = w3.eth.send_raw_transaction(signed_dv.raw_transaction)
        L.log(f"[DV] requestDataAccessForFileData tx: {tx_hash_dv.hex()}")
        receipt_dv = w3.eth.wait_for_transaction_receipt(tx_hash_dv)
        TX.log_contract_transaction(
            C,
            w3,
            actor_address=req_account.address,
            contract_name="DataVault",
            function_name=fn_dv_name,
            contract_address=dv.address,
            tx=tx_dv,
            tx_hash=tx_hash_dv,
            receipt=receipt_dv,
            file_id=file_id_hex,
            batch_id=int(batch_id),
            data_id=truck_id,
            timestamp=ts,
            access_escrow_wei=access_escrow,
        )
        L.log(f"[DV] Tx status: {receipt_dv.status}")

        # Resolve the exact requestId from the tx receipt event to avoid races
        # when multiple requesters submit near-simultaneously.
        resolved_request_id = None
        try:
            events = _matching_receipt_events(
                dv.events.DataAccessRequestedV2(), receipt_dv
            )
            for ev in reversed(events):
                args = ev.get("args", {})
                try:
                    ev_requester = str(args.get("requester", "")).lower()
                    ev_file_id = bytes(args.get("fileId", b"")).hex()
                    ev_batch_id = int(args.get("batchId"))
                    ev_pkreq_x = int(args.get("pkReqX"))
                    ev_pkreq_y = int(args.get("pkReqY"))
                    if (
                        ev_requester == req_checksum.lower()
                        and ev_file_id == file_id_hex
                        and ev_batch_id == int(batch_id)
                        and ev_pkreq_x == int(pkreq_x)
                        and ev_pkreq_y == int(pkreq_y)
                    ):
                        resolved_request_id = int(args.get("requestId"))
                        break
                except Exception:
                    continue
        except Exception as exc:
            L.log(f"[DV] Could not decode DataAccessRequestedV2 from receipt: {exc}")

        if resolved_request_id is None:
            # Backward-safe fallback if receipt decode is unavailable.
            next_id = dv.functions.nextAccessRequestId().call()
            resolved_request_id = int(next_id) - 1
            L.log(f"[DV] requestId event decode failed; fallback to nextAccessRequestId-1 => {resolved_request_id}")
        else:
            L.log(f"[DV] requestId resolved from receipt event => {resolved_request_id}")

        S.current_request_id = int(resolved_request_id)
        L.log(f"[DV] Created access requestId: {S.current_request_id}")

        if policy_mode == 1:
            balance = int(reward_manager.functions.accessEscrowBalance(int(S.current_request_id)).call())
            L.log(f"[REQ-V2] Access escrow deposited for requestId {S.current_request_id}: {balance} wei")

    except Exception as exc:
        L.log(f"[DV] Error in requestDataAccessForFileData flow: {exc}")
        L.show_error("DataVault Error", str(exc))
        return None

    L.log("[REQ] Access request created. Waiting for Guardians to publish PRE partials on-chain...")
    L.log("=== Flow finished. Waiting for on-chain PRE partials... ===")
    return "new"


# ── PRE partial polling ───────────────────────────────────────────────────────

def wait_for_pre_partials_sync(request_id: int, max_attempts: int = 60, delay_sec: int = 5) -> bool:
    for attempt in range(1, max_attempts + 1):
        # There is no count of guardians who have answered to show here -- the
        # partials are only usable once enough of them combine -- so the bar
        # moves with the wait itself, which is the honest thing it knows.
        PROG.step("guardian partials", attempt - 1, max_attempts)
        if attempt == 1:
            L.log(f"[Wait] Checking on-chain PRE partials for requestId {request_id}...")
        elif attempt % 6 == 0:
            L.log(f"[Wait] Still checking PRE partials for requestId {request_id} (poll {attempt}/{max_attempts})...")

        try:
            if CH.build_reenc_cids_from_pre_partials(request_id):
                L.log(f"[Wait] PRE partials combined by REQ for requestId {request_id}.")
                PROG.step("guardian partials", max_attempts, max_attempts)
                return True
        except Exception as exc:
            L.log_state(("req-wait-pre-error", int(request_id)), str(exc), f"[Wait] PRE aggregation error: {exc}")
            return False

        time.sleep(delay_sec)

    L.log(f"[Wait] No enough PRE partials after {max_attempts} attempts.")
    return False


def wait_for_reenc_sync(request_id: int, max_attempts: int = 60, delay_sec: int = 5) -> bool:
    for attempt in range(1, max_attempts + 1):
        L.log(f"[Wait] Poll {attempt}: checking re-encrypted CIDs for requestId {request_id}...")
        w3 = C.new_web3(C.config)
        if not w3.is_connected():
            L.log("[Wait] Web3 not connected while waiting.")
            return False
        try:
            dv = C.load_contract_from_config(w3, C.config.DV_ADDRESS, C.config.DV_JSON)
            cidIdx_on, _, _, _ = dv.functions.getReencryptedCids(request_id).call()
            if cidIdx_on:
                L.log(f"[Wait] Re-encrypted CIDs ready for requestId {request_id}.")
                return True
        except Exception as exc:
            L.log(f"[Wait] Error while polling re-encrypted CIDs: {exc}")
            return False
        time.sleep(delay_sec)

    L.log(f"[Wait] No re-encrypted CIDs after {max_attempts} attempts.")
    return False


# ── decrypt CIDs ──────────────────────────────────────────────────────────────

def run_decrypt_cids() -> None:
    """Decrypt K from PRE partials, then use K to decrypt ctSym -> VaultMesh payload."""
    if S.current_request_id is None:
        L.log("[Decrypt] No current requestId. Run Request Data + Download first.")
        L.show_warning("No Request ID", "Please request data first.")
        return

    in_file = R.reenc_cids_path(S.current_request_id)
    if not in_file.exists():
        L.log(f"[Decrypt] File not found: {in_file}")
        L.show_error("File Missing", f"{in_file} not found.")
        return

    L.log(f"[Decrypt] Using input file: {in_file}")
    try:
        data = json.loads(in_file.read_text(encoding="utf-8"))
    except Exception as exc:
        L.log(f"[Decrypt] Error reading {in_file}: {exc}")
        L.show_error("Read Error", str(exc))
        return

    batch = data.get("batch", {})
    items = data.get("items", [])
    is_v2_payload = data.get("mode") == "ZKDKG_V2" or any(
        e.get("mode") == "ZKDKG_V2" for e in items if isinstance(e, dict)
    )

    x_req = 0
    if not is_v2_payload:
        if S.requester_keys is None:
            L.log("[Decrypt] No requester keys loaded. Generate/load keys first.")
            L.show_warning("No Keys", "Please generate/load keys first.")
            return
        try:
            x_req = int(data.get("x_req", S.requester_keys["x_req"]))
        except Exception as exc:
            L.log(f"[Decrypt] Cannot determine x_req: {exc}")
            L.show_error("Key Error", "Unable to load x_req for decryption.")
            return

    try:
        w3 = C.new_web3(C.config)
        if not w3.is_connected():
            L.log("[Decrypt] Web3 not connected.")
            L.show_error("Web3 Error", "Cannot connect to RPC endpoint.")
            return
        dv = C.load_contract_from_config(w3, C.config.DV_ADDRESS, C.config.DV_JSON)
    except Exception as exc:
        L.log(f"[Decrypt] Error preparing DV contract: {exc}")
        L.show_error("DV Error", str(exc))
        return

    items_sorted = sorted(items, key=lambda e: int(e["cidIndex"]))
    dec_list: list[dict] = []
    aes_obj: dict = {}

    try:
        for entry in items_sorted:
            cid_index = int(entry["cidIndex"])

            if data.get("mode") == "ZKDKG_V2" or entry.get("mode") == "ZKDKG_V2":
                try:
                    K_bytes = bytes.fromhex(str(entry["K_hex"]).strip())
                except Exception as exc:
                    L.log(f"[Decrypt] cidIndex={cid_index}: invalid V2 decrypted K: {exc}")
                    L.show_error("Decrypt Error", f"Invalid V2 decrypted key for cidIndex={cid_index}.")
                    return
            else:
                k_plain = CRY.decrypt_entry(entry, x_req)
                try:
                    K_bytes = bytes.fromhex(k_plain.decode("utf-8").strip())
                except Exception as exc:
                    L.log(f"[Decrypt] cidIndex={cid_index}: invalid decrypted K: {exc}")
                    L.show_error("Decrypt Error", f"Invalid decrypted key for cidIndex={cid_index}.")
                    return

            try:
                _C1x, _C1y, _C2, ctSym = VM.get_enc_cid_tuple(dv, cid_index)
            except Exception as exc:
                L.log(f"[Decrypt] getEncCid({cid_index}) failed: {exc}")
                L.show_error("DV Error", f"getEncCid({cid_index}) failed: {exc}")
                return

            try:
                payload_bytes = CRY.xor_stream_encrypt(ctSym, K_bytes)
                payload = R._decode_storage_payload(payload_bytes)
            except Exception as exc:
                L.log(f"[Decrypt] cidIndex={cid_index}: error decrypting ctSym payload: {exc}")
                L.show_error("Decrypt Error", f"Could not decrypt payload for cidIndex={cid_index}.")
                return

            if payload.get("kind") == "aes":
                aes_obj = payload.get("aes", {}) if isinstance(payload.get("aes", {}), dict) else {}
                L.log(f"[Decrypt] cidIndex={cid_index}: AES metadata decrypted.")
                continue

            if payload.get("kind") != "piece":
                L.log(f"[Decrypt] cidIndex={cid_index}: unknown payload skipped: {payload}")
                continue

            piece_root = (
                payload.get("pieceRoot") or payload.get("piece_root") or
                payload.get("pieceId") or payload.get("cid")
            )
            peer_id = payload.get("peerId", "")
            piece_index = payload.get("pieceIndex", payload.get("piece_index", len(dec_list) + 1))

            if not piece_root:
                L.log(f"[Decrypt] cidIndex={cid_index}: payload has no pieceRoot. Skipping.")
                continue

            local_name = R._default_piece_filename({**payload, "pieceRoot": piece_root})
            item_out = {
                "cidIndex": cid_index,
                "fileId": batch.get("fileId", ""),
                "pieceIndex": int(piece_index) if str(piece_index).isdigit() else piece_index,
                "pieceRoot": str(piece_root),
                "peerId": peer_id,
                "size": payload.get("size", 0),
                "name": payload.get("name", local_name),
                "localFileName": local_name,
                "storage": payload.get("storage", "vaultmesh"),
            }
            dec_list.append(item_out)
            L.log(f"[Decrypt] cidIndex={cid_index}, pieceIndex={piece_index}, pieceRoot={piece_root}, peerId={peer_id}")

    except Exception as exc:
        L.log(f"[Decrypt] Error while decrypting payloads: {exc}")
        L.show_error("Decrypt Error", str(exc))
        return

    aes_out_file = R.aes_key_path(S.current_request_id)
    cids_out_file = R.decrypted_cids_path(S.current_request_id)

    try:
        dec_list = sorted(dec_list, key=lambda x: int(x.get("pieceIndex", 0)))
        out_obj = {
            "requestId": data.get("requestId"),
            "storage": "vaultmesh",
            "batch": batch,
            "cids": dec_list,
            "pieces": dec_list,
        }
        cids_out_file.write_text(json.dumps(out_obj, indent=2), encoding="utf-8")

        if aes_obj:
            aes_out_file.write_text(json.dumps(aes_obj, indent=2), encoding="utf-8")
            L.log(f"[Decrypt] AES info written to: {aes_out_file}")

        L.log(f"[Decrypt] Decrypted VaultMesh payloads written to: {cids_out_file}")
    except Exception as exc:
        L.log(f"[Decrypt] Error writing output files: {exc}")
        L.show_error("Write Error", str(exc))


# ── VaultMesh download ────────────────────────────────────────────────────────

def run_vaultmesh_download() -> bool:
    if S.current_request_id is None:
        L.log("[VaultMesh] No requestId available. Run Request Data + Decrypt first.")
        L.show_warning("No Request ID", "Please request data and decrypt payloads first.")
        return False

    cids_file = R.decrypted_cids_path(S.current_request_id)
    if not cids_file.exists():
        L.log(f"[VaultMesh] Payload file not found: {cids_file}")
        L.show_error("File Missing", f"{cids_file} not found.")
        return False

    try:
        payload_file_data = json.loads(cids_file.read_text(encoding="utf-8"))
        batch_file_id = R.normalize_file_id_hex(payload_file_data.get("batch", {}).get("fileId", ""))
        entries = R.load_storage_entries(str(cids_file))
    except Exception as exc:
        L.log(f"[VaultMesh] Error loading decrypted payloads from {cids_file}: {exc}")
        L.show_error("VaultMesh Payload Error", str(exc))
        return False

    if not entries:
        L.log("[VaultMesh] No piece payloads found in file.")
        L.show_warning("No Pieces", "No VaultMesh pieces found to download.")
        return False

    C.PIECES_DIR.mkdir(parents=True, exist_ok=True)
    L.log(f"[VaultMesh] Found {len(entries)} piece(s). Downloading into {C.PIECES_DIR}...")
    updated_entries = []
    reused_count = 0
    downloaded_count = 0
    failed_count = 0

    def _download_one(position: int, source_item: dict):
        item = dict(source_item)
        piece_root = VM._normalize_piece_root(item.get("pieceRoot", ""))
        peer_id = item.get("peerId", "")
        local_name = item.get("localFileName") or R._default_piece_filename(item)
        output_path = str(C.PIECES_DIR / local_name)

        try:
            # Smart retry: if a previously downloaded share is still present and valid,
            # reuse it instead of downloading again.
            if os.path.exists(output_path):
                existing_piece_root = VM.compute_piece_root_file(output_path)
                if existing_piece_root == piece_root:
                    item["pieceRoot"] = piece_root
                    item["localPath"] = output_path
                    item["localFileName"] = local_name
                    item["verifiedPieceRoot"] = existing_piece_root
                    item["downloadSource"] = "local_cache"
                    L.log(
                        f"[VaultMesh] REUSE: pieceIndex={item.get('pieceIndex')} "
                        f"pieceRoot={piece_root} -> {output_path}"
                    )
                    return position, "reused", item
                L.log(
                    f"[VaultMesh] Cached share invalid for pieceIndex={item.get('pieceIndex')} "
                    f"(expected {piece_root}, got {existing_piece_root}); re-downloading."
                )

            resolved_peer = VM.resolve_vk_multiaddr(peer_id)
            multiaddr = resolved_peer["multiaddr"]

            # Off-chain deletion check: ask VK if piece still exists before downloading.
            has_info = VM.check_vk_has_piece(piece_root, multiaddr)
            if has_info.get("deletionPending"):
                L.log(
                    f"[VaultMesh] SKIP pieceIndex={item.get('pieceIndex')} "
                    f"pieceRoot={piece_root}: authorized deletion pending"
                )
                return position, "skipped", None
            if has_info.get("deleted"):
                ch = has_info.get("commitmentHash", "")
                cn = has_info.get("commitmentNonce", "")
                if ch and cn and CH.is_deletion_confirmed_onchain(ch, piece_root, cn):
                    L.log(
                        f"[VaultMesh] SKIP pieceIndex={item.get('pieceIndex')} "
                        f"pieceRoot={piece_root}: deletion confirmed on-chain"
                    )
                    return position, "skipped", None
                else:
                    L.log(
                        f"[VaultMesh] WARNING pieceIndex={item.get('pieceIndex')} "
                        f"pieceRoot={piece_root}: VK claims deleted but on-chain confirmation failed — "
                        f"attempting download anyway"
                    )

            VM.vaultmesh_get(piece_root, multiaddr, output_path, item.get("fileId") or batch_file_id)
            actual_piece_root = VM.compute_piece_root_file(output_path)

            if actual_piece_root != piece_root:
                raise RuntimeError(
                    f"PieceRoot mismatch for pieceIndex={item.get('pieceIndex')}\n"
                    f"Expected: {piece_root}\nActual  : {actual_piece_root}"
                )

            item["pieceRoot"] = piece_root
            item["peerId"] = resolved_peer["peerId"]
            item["resolvedMultiaddr"] = multiaddr
            item["discoverySource"] = resolved_peer["source"]
            item["vkAddress"] = resolved_peer.get("vkAddress", "")
            item["localPath"] = output_path
            item["localFileName"] = local_name
            item["verifiedPieceRoot"] = actual_piece_root
            item["downloadSource"] = "network"
            L.log(
                f"[VaultMesh] OK: pieceIndex={item.get('pieceIndex')} "
                f"pieceRoot={piece_root} peerID={resolved_peer['peerId']} -> {output_path}"
            )
            return position, "downloaded", item
        except VM.XFER.TransferPaused:
            raise
        except Exception as exc:
            L.log(f"[VaultMesh] ERROR fetching pieceRoot={piece_root} from peerId={peer_id}: {exc}")
            return position, "failed", None

    max_downloads = max(1, int(getattr(C.config, "MAX_PARALLEL_PIECE_DOWNLOADS", 4)))
    completed: dict[int, dict] = {}
    outcomes: dict[int, str] = {}
    try:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(max_downloads, len(entries))
        ) as executor:
            futures = [
                executor.submit(_download_one, position, item)
                for position, item in enumerate(entries)
            ]
            for future in concurrent.futures.as_completed(futures):
                position, status, item = future.result()
                outcomes[position] = status
                if item is not None:
                    completed[position] = item
                if status == "reused":
                    reused_count += 1
                elif status == "downloaded":
                    downloaded_count += 1
                elif status == "failed":
                    failed_count += 1
                # Every piece that lands moves the bar. This is the one place
                # that knows a piece is really on this disk and verified.
                PROG.step("pieces downloaded", len(outcomes), len(entries))
    except VM.XFER.TransferPaused as exc:
        L.log(f"[VaultMesh] {exc}")
        L.set_status("VaultMesh downloads paused", "waiting")
        return False

    updated_entries = [completed[index] for index in sorted(completed)]
    persisted_entries = []
    for index, original in enumerate(entries):
        persisted = completed.get(index, dict(original))
        persisted["downloadStatus"] = outcomes.get(index, "pending")
        persisted_entries.append(persisted)

    try:
        data = json.loads(cids_file.read_text(encoding="utf-8"))
        # Preserve failed obligations so Resume can retry them later.
        data["cids"] = persisted_entries
        data["pieces"] = persisted_entries
        cids_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception as exc:
        L.log(f"[VaultMesh] Warning: could not update local paths in {cids_file}: {exc}")

    L.log(
        "[VaultMesh] Download finished. "
        f"ok={len(updated_entries)}/{len(entries)} "
        f"(reused={reused_count}, downloaded={downloaded_count}, failed={failed_count})"
    )
    return True


def continue_unfinished_downloads() -> None:
    """Finish a download that was interrupted, without being asked.

    A piece already on disk is verified against its pieceRoot and reused, so
    continuing costs nothing when there is nothing to continue -- which is why
    this needs no button and no question. There is also nothing to decide: the
    access request is already paid for and the pieces are already owed.
    """
    VM.XFER.resume_downloads()

    request_id = S.current_request_id
    if request_id is None:
        return
    try:
        cids_file = R.decrypted_cids_path(request_id)
        if not cids_file.exists():
            return
        data = json.loads(cids_file.read_text(encoding="utf-8"))
    except Exception as exc:
        L.log(f"[transfer] could not read the saved pieces: {exc}")
        return

    pieces = data.get("pieces") or data.get("cids") or []
    unfinished = [
        piece for piece in pieces
        if str(piece.get("downloadStatus", "")) not in ("reused", "downloaded")
    ]
    if not unfinished:
        return

    L.log(
        f"[transfer] continuing {len(unfinished)} unfinished piece(s) from the "
        "last run"
    )

    def _resume() -> None:
        PROG.start("Continuing download", [
            ("pieces downloaded", 0.7),
            ("file rebuilt", 0.3),
        ])
        done = False
        try:
            if run_vaultmesh_download():
                run_ida_reconstruct()
                run_aes_decrypt()
                refresh_files_list()
                done = True
                L.set_status("Done", "done")
        finally:
            if PROG.is_running():
                if done:
                    PROG.step("file rebuilt", 1, 1)
                    PROG.finish("Download complete")
                else:
                    PROG.finish("Download did not finish", ok=False)

    threading.Thread(target=_resume, daemon=True).start()


# ── IDA reconstruct ───────────────────────────────────────────────────────────

def run_ida_reconstruct() -> bool:
    # Every reconstruction belongs to exactly one request. Clear the previous
    # output before any validation so early returns cannot leak stale success.
    S.last_reconstructed_path = None
    if S.current_request_id is None:
        L.log("[IDA] No current requestId. Run Request Data + VaultMesh download first.")
        L.show_warning("No Request ID", "Please complete request and VaultMesh download first.")
        return False

    if S.current_t is None:
        L.log("[IDA] Threshold t unknown. Download CIDs first to get n,t.")
        L.show_warning("No Threshold", "Please download CIDs first (to get n,t).")
        return False

    cids_file = R.decrypted_cids_path(S.current_request_id)
    if not cids_file.exists():
        L.log(f"[IDA] CIDs file not found: {cids_file}")
        L.show_error("File Missing", f"{cids_file} not found.")
        return False

    try:
        entries = R.load_storage_entries(str(cids_file))
    except Exception as exc:
        L.log(f"[IDA] Error loading VaultMesh payloads from {cids_file}: {exc}")
        L.show_error("Payload Error", str(exc))
        return False

    share_paths = []
    for item in entries:
        path = item.get("localPath") or str(
            C.PIECES_DIR / (item.get("localFileName") or R._default_piece_filename(item))
        )
        if not os.path.exists(path):
            L.log(f"[IDA] Missing share file for pieceIndex={item.get('pieceIndex')}. Run VaultMesh download first.")
            continue
        share_paths.append(path)

    if len(share_paths) < S.current_t:
        L.log(f"[IDA] Not enough verified local shares: have {len(share_paths)}, need t={S.current_t}.")
        L.show_error(
            "Not Enough Shares",
            f"Have {len(share_paths)} downloaded shares, need at least t={S.current_t}.",
        )
        return False
    share_paths = share_paths[: S.current_t]
    L.log(f"[IDA] Using {len(share_paths)} shares (t={S.current_t}) for reconstruction.")

    C.DATA_DIR.mkdir(parents=True, exist_ok=True)
    file_ext = ".dat"
    try:
        meta = json.loads(cids_file.read_text(encoding="utf-8"))
        ext = meta.get("batch", {}).get("fileExt", "")
        if isinstance(ext, str) and ext:
            file_ext = ext if ext.startswith(".") else f".{ext}"
    except Exception as exc:
        L.log(f"[IDA] Could not read fileExt from {cids_file}: {exc}")

    out_name = f"data_{S.current_request_id}{file_ext}"
    output_path = str(C.DATA_DIR / out_name)

    try:
        CRY.ida_reconstruct_file(output_path, share_paths)
        S.last_reconstructed_path = output_path
        L.log(f"[IDA] Reconstructed file written to: {output_path}")
        if not R.aes_key_path(S.current_request_id).exists():
            extract_zip_if_needed(output_path)
        refresh_files_list()
        return True
    except Exception as exc:
        S.last_reconstructed_path = None
        L.log(f"[IDA] Reconstruction error: {exc}")
        L.show_error("IDA Error", str(exc))
        return False


# ── AES decrypt ───────────────────────────────────────────────────────────────

def run_aes_decrypt() -> None:
    if S.current_request_id is None:
        L.log("[AES] No current requestId. Run previous steps first.")
        L.show_warning("No Request ID", "Please complete request / IDA first.")
        return

    if not S.last_reconstructed_path or not os.path.exists(S.last_reconstructed_path):
        L.log("[AES] No reconstructed file remembered. Run IDA Reconstruct first.")
        L.show_warning("No Reconstructed File", "Please run IDA Reconstruct before AES Decrypt.")
        return

    key_json_path = R.aes_key_path(S.current_request_id)
    if not key_json_path.exists():
        L.log(f"[AES] No AES key file for requestId {S.current_request_id}. Skipping AES decrypt.")
        return

    dir_name, fname = os.path.split(S.last_reconstructed_path)
    base, ext = os.path.splitext(fname)
    out_path = os.path.join(dir_name, f"{base}_dec{ext}")

    try:
        L.log(f"[AES] Decrypting {S.last_reconstructed_path} -> {out_path} using {key_json_path}")
        CRY.decrypt_file(S.last_reconstructed_path, out_path, str(key_json_path))
        L.log(f"[AES] Decrypted file written to: {out_path}")
        extract_zip_if_needed(out_path)
        refresh_files_list()
    except Exception as exc:
        L.log(f"[AES] Decryption error: {exc}")
        L.show_error("AES Error", str(exc))


# ── combined download pipeline ────────────────────────────────────────────────

def run_all(sync_label: str = "") -> bool:
    """Ask for access, wait for the guardians, fetch the pieces, rebuild.

    *sync_label* marks a download the app started by itself, from a trusted
    owner: the bar names the file, and the "finished" dialog is not shown,
    because nobody is sitting there having pressed anything.
    """
    # Weighted by effort: waiting for guardians to answer on chain is the long
    # pole, fetching the pieces is the second, and rebuilding is quick.
    PROG.start(f"Downloading {sync_label}".strip(), [
        ("access requested", 0.10),
        ("guardian partials", 0.35),
        ("pieces downloaded", 0.40),
        ("file rebuilt", 0.15),
    ])
    try:
        return bool(_run_all_impl(quiet=bool(sync_label)))
    finally:
        if PROG.is_running():
            PROG.finish("Download did not finish", ok=False)


def _run_all_impl(quiet: bool = False) -> bool:
    L.set_status("Requesting access", "running")
    result = run_request_data_flow()

    if S.current_request_id is None:
        L.log("[Flow] No requestId after request flow. Aborting.")
        L.set_status("No request", "error")
        return False
    PROG.step("access requested", 1, 1)

    if result in ("new", "pending"):
        max_attempts = int(getattr(C.config, "PRE_PARTIAL_WAIT_MAX_ATTEMPTS", 24))
        delay_sec = int(getattr(C.config, "PRE_PARTIAL_WAIT_DELAY_SEC", 2))
        if not wait_for_pre_partials_sync(S.current_request_id, max_attempts=max_attempts, delay_sec=delay_sec):
            w3_exp = C.new_web3(C.config)
            if w3_exp.is_connected():
                expired = CH.expire_pre_request_onchain(w3_exp, S.current_request_id)
                if expired:
                    S.current_request_id = None
                    L.log("[Flow] PRE request expired. Escrow refunded. Please try requesting again.")
                    L.show_warning(
                        "Request Expired",
                        "Guardians did not respond in time.\nYour escrow has been refunded.\nPlease try requesting the file again."
                    )
                    L.set_status("Request expired — retry", "waiting")
                    return False
            L.show_warning(
                "Timeout",
                "Not enough on-chain PRE partials received yet. Try again later."
            )
            L.set_status("Waiting timed out", "error")
            return False

        run_decrypt_cids()
        L.log("[Pieces] Preserving existing pieces/.part files for resumable VaultMesh download.")
        if not run_vaultmesh_download():
            return False
        run_ida_reconstruct()
        run_aes_decrypt()
        refresh_files_list()
        PROG.step("file rebuilt", 1, 1)
        PROG.finish("Download complete")
        L.set_status("Done", "done")
        if not quiet:
            L.show_info("Download Complete", "File downloaded and decrypted successfully.")
        return True

    elif result == "reuse":
        L.log(f"[Flow] Reusing request #{S.current_request_id} — skipping on-chain request and guardian re-encryption.")
        L.set_status("Reusing existing request", "running")
        run_decrypt_cids()
        L.log("[Pieces] Preserving existing pieces/.part files for resumable VaultMesh download.")
        if not run_vaultmesh_download():
            return False
        run_ida_reconstruct()
        run_aes_decrypt()
        refresh_files_list()
        PROG.step("file rebuilt", 1, 1)
        PROG.finish("Download complete")
        L.set_status("Done", "done")
        if not quiet:
            L.show_info("Download Complete", "File downloaded and decrypted successfully.")
        return True

    L.log("[Flow] Request flow failed or was cancelled.")
    L.set_status("Request failed", "error")
    return False
