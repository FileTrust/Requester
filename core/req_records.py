# req_records.py - local cache paths, per-request output paths, and row normalization.

import datetime
import json
import time
from pathlib import Path

from web3 import Web3

from . import req_config as C
from . import req_log as L


# ── per-request output path helpers ──────────────────────────────────────────

def request_output_path(filename: str) -> Path:
    C.REQUEST_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    return C.REQUEST_OUTPUT_DIR / filename


def reenc_cids_path(request_id: int) -> Path:
    return request_output_path(f"reenc_cids_{int(request_id)}.json")


def decrypted_cids_path(request_id: int) -> Path:
    return request_output_path(f"cids_{int(request_id)}.json")


def aes_key_path(request_id: int) -> Path:
    return request_output_path(f"aes_key_{int(request_id)}.json")


# ── normalisation helpers ─────────────────────────────────────────────────────

def normalize_file_id_hex(value) -> str:
    if value is None:
        raise ValueError("fileId is missing")
    if isinstance(value, (bytes, bytearray)):
        return Web3.to_hex(value)

    text = str(value).strip()
    if not text.startswith("0x"):
        text = "0x" + text
    if len(text) != 66:
        raise ValueError(f"Bad fileId length: {text}")
    return Web3.to_hex(Web3.to_bytes(hexstr=text))


def policy_mode_label(mode: int) -> str:
    return "ZKDKG_V2" if int(mode) == 1 else "Legacy"


def date_from_ts(ts: int) -> str:
    if int(ts or 0) <= 0:
        return ""
    return datetime.datetime.fromtimestamp(int(ts)).astimezone().strftime("%Y-%m-%d")


def datetime_from_ts(ts: int) -> str:
    if int(ts or 0) <= 0:
        return ""
    return datetime.datetime.fromtimestamp(int(ts)).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def normalize_policy_row(row: dict) -> dict | None:
    try:
        file_id_hex = normalize_file_id_hex(row.get("fileId", ""))
    except Exception:
        return None

    owner = str(row.get("owner", "")).strip()
    try:
        owner = Web3.to_checksum_address(owner) if owner else ""
    except Exception:
        pass

    threshold = int(row.get("threshold", 0) or 0)
    guardian_count = int(row.get("guardianCount", len(row.get("guardians", []) or [])) or 0)
    mode = int(row.get("mode", 0) or 0)
    latest_ts = int(row.get("latestTimestamp", row.get("timestamp", 0)) or 0)
    shared_ts = int(row.get("sharedTimestamp", row.get("blockTimestamp", 0)) or 0)
    latest_batch_id = int(row.get("latestBatchId", row.get("batchId", 0)) or 0)
    ida_n = int(row.get("n", 0) or 0)
    ida_t = int(row.get("t", 0) or 0)
    index = int(row.get("index", 0) or 0)
    row_id = str(row.get("rowId", "") or "").strip()
    if not row_id:
        row_id = f"{file_id_hex}:batch:{latest_batch_id}" if latest_batch_id else f"{file_id_hex}:policy:{index}"

    normalized = {
        "rowId": row_id,
        "fileId": file_id_hex,
        "owner": owner,
        "threshold": threshold,
        "guardianCount": guardian_count,
        "guardians": list(row.get("guardians", []) or []),
        "mode": mode,
        "modeLabel": row.get("modeLabel") or policy_mode_label(mode),
        "index": index,
        "latestBatchId": latest_batch_id,
        "latestDataId": str(row.get("latestDataId", row.get("dataId", "")) or ""),
        "latestDate": str(row.get("latestDate", "") or date_from_ts(latest_ts)),
        "latestTimestamp": latest_ts,
        "sharedDateTime": str(row.get("sharedDateTime", "") or datetime_from_ts(shared_ts)),
        "sharedTimestamp": shared_ts,
        "n": ida_n,
        "t": ida_t,
        "fileExt": str(row.get("fileExt", "") or ""),
        "keyEpoch": int(row.get("keyEpoch", 0) or 0),
        "pieceCount": int(row.get("pieceCount", 0) or 0),
        "active": bool(row.get("active", True)),
        "lastSeenAt": int(row.get("lastSeenAt", time.time()) or time.time()),
    }
    normalized["access"] = f"{threshold}/{guardian_count}" if threshold or guardian_count else ""
    normalized["ida"] = f"{ida_t}/{ida_n}" if ida_t or ida_n else ""
    return normalized


# ── policy cache ──────────────────────────────────────────────────────────────

def load_policy_cache(requester_checksum: str = "", quiet: bool = False) -> list[dict]:
    if not C.POLICY_CACHE_FILE.exists():
        return []

    try:
        data = json.loads(C.POLICY_CACHE_FILE.read_text(encoding="utf-8").strip() or "{}")
        if isinstance(data, list):
            raw_rows = data
            cached_requester = ""
        else:
            raw_rows = data.get("policies", [])
            cached_requester = str(data.get("requester", "") or "")

        if requester_checksum and cached_requester and cached_requester.lower() != requester_checksum.lower():
            if not quiet:
                L.log(f"[Policy] Ignoring {C.POLICY_CACHE_FILE.name}: cached requester does not match current REQ account.")
            return []

        rows = []
        for row in raw_rows:
            if not isinstance(row, dict):
                continue
            normalized = normalize_policy_row(row)
            if normalized is not None:
                rows.append(normalized)
        return rows
    except Exception as exc:
        if not quiet:
            L.log(f"[Policy] Could not read local {C.POLICY_CACHE_FILE.name}: {exc}")
        return []


def save_policy_cache(rows: list[dict], requester_checksum: str) -> None:
    payload = {
        "requester": requester_checksum,
        "updatedAt": int(time.time()),
        "updatedAtIso": datetime.datetime.now().astimezone().isoformat(),
        "policies": rows,
    }
    C.POLICY_CACHE_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")


# ── decoded storage payload helpers ──────────────────────────────────────────

from . import req_state as S  # noqa: E402  (state for META_PIECE_INDEX)


def _decode_storage_payload(payload_bytes: bytes) -> dict:
    """Decode the encrypted ctSym payload from DataVault.

    Handles VaultMesh JSON (pieceRoot + peerId), AES key bundles,
    and legacy CID strings.
    """
    text_value = payload_bytes.decode("utf-8").strip()

    try:
        obj = json.loads(text_value)
    except Exception:
        return {
            "kind": "piece",
            "storage": "legacy-cid",
            "cid": text_value,
            "pieceId": text_value,
            "peerId": "",
        }

    if not isinstance(obj, dict):
        return {
            "kind": "piece",
            "storage": "legacy-cid",
            "cid": str(obj),
            "pieceId": str(obj),
            "peerId": "",
        }

    if "enc_key" in obj and "mac_key" in obj and "iv" in obj:
        return {"kind": "aes", "aes": obj}

    kind = str(obj.get("kind", obj.get("type", ""))).lower()
    piece_index = obj.get("pieceIndex", obj.get("piece_index"))

    if kind in {"aes", "aes_info", "__aes_info__"} or str(piece_index) == str(S.META_PIECE_INDEX):
        aes_obj = obj.get("aes") or obj.get("aesInfo") or obj.get("aes_info") or obj
        return {"kind": "aes", "aes": aes_obj}

    piece_root = (
        obj.get("pieceRoot") or obj.get("piece_root") or
        obj.get("pieceId") or obj.get("cid") or obj.get("CID")
    )
    peer_id = obj.get("peerId") or obj.get("vkPeer") or obj.get("peer") or obj.get("vk_peer") or ""

    if piece_root:
        obj["kind"] = "piece"
        obj["storage"] = obj.get("storage", "vaultmesh")
        obj["pieceRoot"] = str(piece_root)
        obj.pop("pieceId", None)
        obj.pop("cid", None)
        obj.pop("CID", None)
        obj["peerId"] = peer_id
        return obj

    return {"kind": "unknown", "raw": obj}


def _safe_filename(value: str) -> str:
    """A single, ordinary filename -- whatever was handed in.

    Separators, null bytes and anything else outside a small alphabet become
    underscores, so the result cannot address a directory. Dots survive because
    extensions matter, which leaves the two names made entirely of them: "." is
    the directory itself and ".." is its parent, and joining either to a folder
    does not name a file inside it. A leading "~" is dropped for the same
    reason -- it is a location, not a name.
    """
    value = str(value or "").strip()
    if not value:
        return "piece.bin"
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value)
    cleaned = cleaned.lstrip("~")
    if cleaned.strip(".") == "":
        return "piece.bin"
    return cleaned or "piece.bin"


def _default_piece_filename(item: dict) -> str:
    name = item.get("name") or item.get("filename") or item.get("fileName")
    if name:
        return _safe_filename(name)
    piece_index = item.get("pieceIndex", item.get("piece_index", 0))
    piece_root = (
        item.get("pieceRoot") or item.get("piece_root") or
        item.get("pieceId") or item.get("cid") or "piece"
    )
    try:
        return f"piece_{int(piece_index):03d}_{_safe_filename(piece_root)}"
    except Exception:
        return _safe_filename(piece_root)


def load_storage_entries(path: str) -> list[dict]:
    """Load decrypted VaultMesh piece entries from cids_<requestId>.json."""
    with open(path, "r", encoding="utf-8") as f:
        content = f.read().strip()

    data = json.loads(content)
    raw_items: list = []

    if isinstance(data, dict):
        raw_items = data.get("pieces") or data.get("cids") or []
    elif isinstance(data, list):
        raw_items = data

    entries: list[dict] = []
    for i, item in enumerate(raw_items, start=1):
        if isinstance(item, str):
            entries.append({
                "pieceRoot": item.strip(),
                # No local fallback: the keeper comes from the record, and the
                # record's peer id is resolved through discovery. A peer named
                # in a settings file is not one this app can verify.
                "peerId": "",
                "pieceIndex": i,
                "localFileName": _safe_filename(item.strip()),
                "storage": "legacy-piece-root",
            })
            continue

        if not isinstance(item, dict):
            continue

        piece_root = (
            item.get("pieceRoot") or item.get("piece_root") or
            item.get("pieceId") or item.get("cid") or item.get("CID")
        )
        if not piece_root:
            continue

        out = dict(item)
        out["pieceRoot"] = str(piece_root)
        out.pop("pieceId", None)
        out.pop("cid", None)
        out.pop("CID", None)
        out["peerId"] = (
            out.get("peerId") or out.get("vkPeer") or out.get("peer") or ""
        )
        out["pieceIndex"] = out.get("pieceIndex", i)
        # Sanitised even when the manifest supplies one. The manifest is
        # decoded from the data owner's payload on chain, so a name taken from
        # it and joined to the pieces directory is an arbitrary write on this
        # machine, as whichever user is running the app. Where a file lands is
        # the requester's decision, not the sender's.
        out["localFileName"] = _safe_filename(
            out.get("localFileName") or _default_piece_filename(out)
        )
        entries.append(out)

    return sorted(entries, key=lambda x: int(x.get("pieceIndex", 0)))


def load_cids(path: str) -> list[str]:
    """Backward-compatible helper — returns pieceRoot strings from the decrypted manifest."""
    try:
        return [x["pieceRoot"] for x in load_storage_entries(path)]
    except Exception:
        with open(path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f.read().splitlines() if line.strip()]
