# req_trusted.py — the owners this requester chose to trust, and what has
# already been fetched from them.
#
# Downloading a file is not free: the request deposits escrow on chain before
# anything can be checked, and nothing refunds a file whose contents turn out
# to be rubbish. Anyone can create a policy and add this address to it, so
# automatic downloading of whatever is shared would hand a stranger a way to
# spend this balance. Trust is therefore per owner and switched on by hand.
#
# Both files live beside the app's other local state. Neither is on chain:
# whom you trust is yours, and the chain has no opinion about it.

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from pathlib import Path

from . import req_config as C
from . import req_log as L

_lock = threading.Lock()

# An entry that failed is not retried for this long, so a file that can never
# be fetched cannot turn the sync into a loop that spends gas on every pass.
RETRY_AFTER_SECONDS = 6 * 3600
MAX_ATTEMPTS = 3


def owners_path() -> Path:
    return Path(C.BASE_DIR) / "trusted_owners.json"


def sync_state_path() -> Path:
    return Path(C.BASE_DIR) / "sync_state.json"


def _read(path: Path, default):
    try:
        if not path.is_file():
            return default
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        L.log(f"[trusted] could not read {path.name}: {exc}")
        return default


def _write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=str(path.parent),
        prefix=f".{path.name}.", suffix=".tmp", delete=False,
    )
    try:
        with handle:
            json.dump(value, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    except Exception:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
        raise


# ── the owners ────────────────────────────────────────────────────────────────

def load_owners() -> list[dict]:
    """[{address, name, autoSync}], in the order they were added."""
    raw = _read(owners_path(), [])
    if not isinstance(raw, list):
        return []
    owners = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        address = str(item.get("address", "") or "").strip()
        if not address:
            continue
        owners.append({
            "address": address,
            "name": str(item.get("name", "") or ""),
            "autoSync": bool(item.get("autoSync", False)),
        })
    return owners


def save_owners(owners: list[dict]) -> None:
    with _lock:
        _write(owners_path(), owners)


def add_owner(address: str, name: str = "") -> tuple[bool, str]:
    """Add an owner, switched off. Trust is granted by the toggle, not by this."""
    address = str(address or "").strip()
    if not address:
        return False, "Enter the owner's address."
    try:
        from web3 import Web3
        address = Web3.to_checksum_address(address)
    except Exception:
        return False, f"{address} is not a valid address."
    owners = load_owners()
    for owner in owners:
        if owner["address"].lower() == address.lower():
            if name:
                owner["name"] = name
                save_owners(owners)
                return True, "Name updated."
            return False, "That owner is already in the list."
    owners.append({"address": address, "name": name, "autoSync": False})
    save_owners(owners)
    return True, "Added."


def remove_owner(address: str) -> bool:
    owners = load_owners()
    kept = [o for o in owners if o["address"].lower() != str(address).lower()]
    if len(kept) == len(owners):
        return False
    save_owners(kept)
    return True


def set_auto_sync(address: str, enabled: bool) -> bool:
    owners = load_owners()
    for owner in owners:
        if owner["address"].lower() == str(address).lower():
            owner["autoSync"] = bool(enabled)
            save_owners(owners)
            return True
    return False


def auto_sync_addresses() -> set[str]:
    """Lower-case addresses whose files may be fetched without asking."""
    return {
        owner["address"].lower()
        for owner in load_owners()
        if owner.get("autoSync")
    }


# ── what has already been fetched ─────────────────────────────────────────────

def _entry_key(file_id: str, batch_id) -> str:
    return f"{str(file_id).lower()}:{int(batch_id or 0)}"


def load_sync_state() -> dict:
    raw = _read(sync_state_path(), {})
    return raw if isinstance(raw, dict) else {}


def is_done(file_id: str, batch_id) -> bool:
    entry = load_sync_state().get(_entry_key(file_id, batch_id)) or {}
    return str(entry.get("status", "")) == "done"


def mark_done(file_id: str, batch_id) -> None:
    state = load_sync_state()
    state[_entry_key(file_id, batch_id)] = {
        "status": "done",
        "at": int(time.time()),
    }
    with _lock:
        _write(sync_state_path(), state)


def mark_failed(file_id: str, batch_id, reason: str = "") -> None:
    key = _entry_key(file_id, batch_id)
    state = load_sync_state()
    entry = state.get(key) or {}
    state[key] = {
        "status": "failed",
        "at": int(time.time()),
        "attempts": int(entry.get("attempts", 0)) + 1,
        "reason": str(reason)[:200],
    }
    with _lock:
        _write(sync_state_path(), state)


def should_try(file_id: str, batch_id) -> bool:
    """Is this one worth attempting now?

    Never again once it is done, and not for a while after a failure -- a file
    that cannot be fetched must not be retried on every pass, because every
    attempt can cost gas.
    """
    entry = load_sync_state().get(_entry_key(file_id, batch_id)) or {}
    status = str(entry.get("status", ""))
    if status == "done":
        return False
    if status != "failed":
        return True
    if int(entry.get("attempts", 0)) >= MAX_ATTEMPTS:
        return False
    return (time.time() - int(entry.get("at", 0))) >= RETRY_AFTER_SECONDS
