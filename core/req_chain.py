# req_chain.py - blockchain reads needed by the requester migration UI.

import time
from pathlib import Path

from web3 import Web3

from . import req_config as C
from . import req_log as L
from . import req_records as R
from . import req_txlog as TX
from . import req_state as S

from .req_v2_crypto import (
    baby_is_on_curve,
    baby_neg,
    baby_add,
    baby_mul,
    v2_combine_partials,
    v2_decrypt_with_shared,
    v2_elgamal_decrypt,
)


# ── requester identity ────────────────────────────────────────────────────────

_checksum_for_key: tuple[str, str] = ("", "")


def get_requester_checksum() -> str:
    """This requester's address, derived from the key that signs for it.

    Always from the key currently in the config, never from the address the
    module worked out at import: the load-test harness runs several requesters
    in one process and swaps the key on the config object between them, so a
    value cached at import would hand every worker the first one's identity.

    Deriving costs a key-expansion, which is wasteful per call, so the answer is
    kept for as long as the key it came from is still the key in use.
    """
    global _checksum_for_key
    key = str(getattr(C.config, "REQ_PRIVATE_KEY", "") or "").strip()
    if not key:
        return ""
    if _checksum_for_key[0] == key:
        return _checksum_for_key[1]
    try:
        address = Web3.to_checksum_address(Web3().eth.account.from_key(key).address)
    except Exception:
        return ""
    _checksum_for_key = (key, address)
    return address


# ── batch helpers ─────────────────────────────────────────────────────────────

def collect_logs_windowed(w3, event, argument_filters=None, window: int = 9_000):
    """Collect every matching log, in ranges the chain will actually serve.

    One request for all of history is refused by chains that cap log ranges --
    Cosmos allows 10,000 blocks, which a one-second chain passes in about three
    hours -- so page through and join the results instead.
    """
    head = int(w3.eth.block_number)
    out = []
    from_block = 0
    while from_block <= head:
        to_block = min(head, from_block + window - 1)
        out.extend(
            event.get_logs(
                from_block=from_block,
                to_block=to_block,
                argument_filters=argument_filters or {},
            )
        )
        from_block = to_block + 1
    return out


def _batch_created_block_times(w3, dv) -> dict[int, dict]:
    block_times: dict[int, dict] = {}

    try:
        events = collect_logs_windowed(w3, dv.events.BatchCreated)
    except Exception as exc:
        L.log(f"[Policy] Could not read BatchCreated block timestamps: {exc}")
        return block_times

    timestamp_by_block: dict[int, int] = {}
    for event in events:
        try:
            args = event["args"]
            batch_id = int(args["batchId"])
            block_number = int(event["blockNumber"])
            if block_number not in timestamp_by_block:
                block = w3.eth.get_block(block_number)
                TX.log_eth_call(
                    C,
                    contract_name="eth",
                    function_name="getBlock",
                    status="success",
                    block_number=block_number,
                    block_timestamp=int(block["timestamp"]),
                )
                timestamp_by_block[block_number] = int(block["timestamp"])
            shared_ts = timestamp_by_block[block_number]
            block_times[batch_id] = {
                "sharedTimestamp": shared_ts,
                "sharedDateTime": R.datetime_from_ts(shared_ts),
            }
        except Exception:
            continue

    return block_times


def _batch_ids_for_files(w3, dv, file_ids) -> tuple[set[int], dict[int, dict]]:
    """Batch ids belonging to these files, and when each was created.

    BatchCreated indexes the file, so one filtered query returns every batch of
    every file we care about -- and the same logs carry the block each was
    created in, which is what the timestamps are read from. The alternative,
    reading every batch on the chain and discarding the ones for other people's
    files, cost fourteen seconds of an eighteen-second refresh.
    """
    wanted: set[int] = set()
    shared_times: dict[int, dict] = {}
    if not file_ids:
        return wanted, shared_times

    try:
        logs = collect_logs_windowed(
            w3, dv.events.BatchCreated(), {"fileId": list(file_ids)}
        )
    except Exception as exc:
        L.log(f"[Policy] Could not read BatchCreated for this requester: {exc}")
        return wanted, shared_times

    timestamp_by_block: dict[int, int] = {}
    for log in logs:
        try:
            batch_id = int(log["args"]["batchId"])
            block_number = int(log["blockNumber"])
            wanted.add(batch_id)
            if block_number not in timestamp_by_block:
                block = w3.eth.get_block(block_number)
                timestamp_by_block[block_number] = int(block["timestamp"])
            shared_ts = timestamp_by_block[block_number]
            shared_times[batch_id] = {
                "sharedTimestamp": shared_ts,
                "sharedDateTime": R.datetime_from_ts(shared_ts),
            }
        except Exception:
            continue
    return wanted, shared_times


def _batches_by_file(w3, dv, file_ids=None) -> dict[str, list[dict]]:
    batches_by_file: dict[str, list[dict]] = {}

    if file_ids is not None:
        batch_ids, shared_times = _batch_ids_for_files(w3, dv, file_ids)
        batch_range = sorted(batch_ids)
    else:
        try:
            max_batch_id = int(dv.functions.nextBatchId().call())
        except Exception as exc:
            L.log(f"[Policy] Could not read nextBatchId() while building table: {exc}")
            return batches_by_file
        shared_times = _batch_created_block_times(w3, dv)
        batch_range = range(1, max_batch_id + 1)

    for batch_id in batch_range:
        try:
            (
                file_id_on,
                _data_owner,
                data_id,
                ts,
                n_on,
                t_on,
                key_epoch,
                cid_indices,
            ) = dv.functions.getBatch(batch_id).call()
            file_id_hex = R.normalize_file_id_hex(file_id_on)
            ts = int(ts)
            shared = shared_times.get(int(batch_id), {})
            batches_by_file.setdefault(file_id_hex, []).append(
                {
                    "rowId": f"{file_id_hex}:batch:{int(batch_id)}",
                    "latestBatchId": int(batch_id),
                    "latestDataId": data_id,
                    "latestTimestamp": ts,
                    "latestDate": R.date_from_ts(ts),
                    "sharedTimestamp": int(shared.get("sharedTimestamp", 0) or 0),
                    "sharedDateTime": str(shared.get("sharedDateTime", "") or ""),
                    "n": int(n_on),
                    "t": int(t_on),
                    "fileExt": "",
                    "keyEpoch": int(key_epoch),
                    "pieceCount": len(cid_indices),
                }
            )
        except Exception:
            continue

    for file_batches in batches_by_file.values():
        file_batches.sort(key=lambda batch: int(batch.get("latestBatchId", 0) or 0), reverse=True)

    return batches_by_file


def file_ids_shared_with(acl, requester: str) -> list[bytes]:
    """The files this requester has access to, with the block that granted it.

    The contract indexes the requester on both membership events, so the node
    can answer "which files name this address" directly. Walking every policy
    on the chain and testing each one instead meant the work grew with everyone
    else's uploads: at eighty policies that was about three hundred and twenty
    calls and thirty-nine seconds, for a requester who could see none of them.

    Access can be granted, removed and granted again, so the events are replayed
    in order and the last one for each file decides. Membership is confirmed
    against the contract afterwards, because an event only says what happened,
    not what is true now.
    """
    granted: dict[bytes, tuple[int, int, bool]] = {}
    for allowed, event in (
        (True, acl.events.RequesterAddedToFile()),
        (False, acl.events.RequesterRemovedFromFile()),
    ):
        for log in collect_logs_windowed(C.w3, event, {"requester": requester}):
            file_id = bytes(log["args"]["fileId"])
            at = (int(log["blockNumber"]), int(log.get("logIndex", 0) or 0))
            if file_id not in granted or at > granted[file_id][:2]:
                granted[file_id] = (at[0], at[1], allowed)

    # The block that granted access comes back with each file: it orders the
    # list the way the chain-wide policy index used to, and it is stable across
    # runs, which the position in this list would not be -- row ids are built
    # from it, and an id that moves loses a saved selection.
    return [
        (file_id, block)
        for file_id, (block, _, allowed) in sorted(granted.items(), key=lambda kv: kv[1])
        if allowed
    ]


def fetch_accessible_file_rows() -> list[dict]:
    if not C.w3.is_connected():
        raise RuntimeError("Cannot connect to RPC endpoint.")

    acl = C.load_acl_contract()
    dv = C.load_dv_contract()
    requester = get_requester_checksum()
    shared = file_ids_shared_with(acl, requester)
    # Only this requester's files, so neither of the two chain reads below grows
    # with what everybody else uploads.
    batches_by_policy = _batches_by_file(C.w3, dv, [file_id for file_id, _ in shared])
    rows = []

    for file_id, index in shared:
        try:
            exists, active, owner, threshold, guardians = acl.functions.getFilePolicy(file_id).call()
            if not exists or not active:
                continue
            if not acl.functions.isRequesterForFile(file_id, requester).call():
                continue

            file_id_hex = R.normalize_file_id_hex(file_id)
            try:
                mode = int(acl.functions.getFilePolicyMode(file_id).call())
            except Exception:
                mode = 0

            policy_row = {
                "fileId": file_id_hex,
                "owner": Web3.to_checksum_address(owner),
                "threshold": int(threshold),
                "guardianCount": len(guardians),
                "guardians": [Web3.to_checksum_address(g) for g in guardians],
                "mode": mode,
                "index": index,
                "active": True,
                "lastSeenAt": int(time.time()),
            }

            for batch_row in batches_by_policy.get(file_id_hex, []):
                row = dict(policy_row)
                row.update(batch_row)
                normalized = R.normalize_policy_row(row)
                if normalized is not None:
                    rows.append(normalized)
        except Exception as exc:
            L.log(f"[Policy] Skipped policy index {index}: {exc}")

    return sorted(
        rows,
        key=lambda row: (
            int(row.get("sharedTimestamp", 0) or 0),
            int(row.get("latestBatchId", 0) or 0),
            int(row.get("index", 0) or 0),
        ),
        reverse=True,
    )


# ── batch lookup for request flow ─────────────────────────────────────────────

def find_batch_by_policy_data_date(dv, file_id: bytes, data_id: str, ts: int):
    """Return (exists, batch_id, batch_tuple) for the exact file+data+date combo."""
    exists, batch_id = dv.functions.getBatchIdForFileData(file_id, data_id, ts).call()

    if not exists or int(batch_id) == 0:
        return False, 0, None

    batch_tuple = dv.functions.getBatch(int(batch_id)).call()
    return True, int(batch_id), batch_tuple


def apply_latest_batch_defaults_for_file(file_id_hex: str) -> None:
    """Refresh the cached policy_rows entry with the latest DataVault batch for file_id_hex."""
    from datetime import datetime, timezone
    try:
        w3 = C.new_web3(C.config)
        if not w3.is_connected():
            L.log("[Policy] Web3 not connected; cannot load latest batch for selected policy.")
            return

        dv = C.load_contract_from_config(w3, C.config.DV_ADDRESS, C.config.DV_JSON)
        target_file_id = R.normalize_file_id_hex(file_id_hex)

        try:
            max_batch_id = int(dv.functions.nextBatchId().call())
        except Exception as exc:
            L.log(f"[Policy] Could not read nextBatchId(): {exc}")
            return

        latest = None
        for batch_id in range(1, max_batch_id + 1):
            try:
                (
                    file_id_on,
                    _data_owner,
                    data_id,
                    ts,
                    n_on,
                    t_on,
                    key_epoch,
                    cid_indices,
                ) = dv.functions.getBatch(batch_id).call()

                if R.normalize_file_id_hex(file_id_on) != target_file_id:
                    continue

                ts = int(ts)
                if latest is None or int(batch_id) > int(latest["batchId"]):
                    latest = {
                        "batchId": int(batch_id),
                        "dataId": data_id,
                        "ts": ts,
                        "n": int(n_on),
                        "t": int(t_on),
                        "fileExt": "",
                        "keyEpoch": int(key_epoch),
                        "pieceCount": len(cid_indices),
                    }
            except Exception:
                continue

        if latest is None:
            L.log("[Policy] No DataVault batch found yet for selected policy.")
            return

        date_str = datetime.fromtimestamp(latest["ts"], tz=timezone.utc).strftime("%Y-%m-%d")
        S.selected_data_tag = str(latest["dataId"] or "")
        S.selected_date_str = date_str

        target = R.normalize_file_id_hex(file_id_hex)
        for row in S.policy_rows:
            if R.normalize_file_id_hex(row.get("fileId", "")) != target:
                continue
            row.update(
                {
                    "latestBatchId": int(latest["batchId"]),
                    "latestDataId": str(latest["dataId"] or ""),
                    "latestTimestamp": int(latest["ts"]),
                    "latestDate": date_str,
                    "n": int(latest["n"]),
                    "t": int(latest["t"]),
                    "fileExt": str(latest.get("fileExt", "") or ""),
                    "keyEpoch": int(latest["keyEpoch"]),
                    "pieceCount": int(latest.get("pieceCount", 0) or 0),
                    "ida": f"{int(latest['t'])}/{int(latest['n'])}",
                }
            )
            break

        L.log(
            f"[Policy] Latest batch for selected policy: "
            f"batchId={latest['batchId']}, Data ID={latest['dataId']}, "
            f"Date={date_str}, IDA={latest['t']}/{latest['n']}, keyEpoch={latest['keyEpoch']}"
        )

    except Exception as exc:
        L.log(f"[Policy] Could not apply latest batch defaults: {exc}")


# ── PRE partial readers ───────────────────────────────────────────────────────

def read_pre_partials_from_chain(telg, request_id: int, required_t: int, request_share_version: int | None = None) -> list[dict]:
    guardians = telg.functions.getPrePartialGuardians(int(request_id)).call()
    partial_sets = []
    seen_share_indices: set[int] = set()

    for g in guardians:
        result = telg.functions.getPrePartial(
            int(request_id),
            Web3.to_checksum_address(g),
        ).call()

        if len(result) == 6:
            exists, pp_share_version, share_index, cid_indices, dx_values, dy_values = result
            pp_share_version = int(pp_share_version)
        elif len(result) == 5:
            exists, share_index, cid_indices, dx_values, dy_values = result
            pp_share_version = int(request_share_version or 1)
        else:
            raise RuntimeError(f"Unexpected getPrePartial return length: {len(result)}")

        if not exists:
            continue
        if request_share_version is not None and int(request_share_version) > 0:
            if pp_share_version != int(request_share_version):
                continue

        share_index = int(share_index)
        if share_index in seen_share_indices:
            continue
        seen_share_indices.add(share_index)

        partial_by_cid = {
            int(cid_idx): (int(dx_values[i]), int(dy_values[i]))
            for i, cid_idx in enumerate(cid_indices)
        }

        partial_sets.append(
            {
                "guardian": Web3.to_checksum_address(g),
                "share_version": pp_share_version,
                "share_index": share_index,
                "partials": partial_by_cid,
            }
        )

        if len(partial_sets) >= required_t:
            break

    return partial_sets


def read_v2_partials_from_chain(telg_v2, request_id: int, required_t: int) -> list[dict]:
    guardians = telg_v2.functions.getV2PartialGuardians(int(request_id)).call()
    partial_sets = []
    seen_share_indices: set[int] = set()

    for g in guardians:
        result = telg_v2.functions.getV2Partial(
            int(request_id),
            Web3.to_checksum_address(g),
        ).call()
        exists, share_index, _partials_hash, cid_indices, e1x_values, e1y_values, e2x_values, e2y_values = result
        if not exists:
            continue
        share_index = int(share_index)
        if share_index in seen_share_indices:
            continue
        seen_share_indices.add(share_index)

        # Store encrypted El-Gamal pairs per CID; decryption happens in the aggregator.
        partial_by_cid = {
            int(cid_idx): {
                "E1": (int(e1x_values[i]), int(e1y_values[i])),
                "E2": (int(e2x_values[i]), int(e2y_values[i])),
            }
            for i, cid_idx in enumerate(cid_indices)
        }
        partial_sets.append(
            {
                "guardian": Web3.to_checksum_address(g),
                "share_index": share_index,
                "partials": partial_by_cid,
            }
        )
        if len(partial_sets) >= required_t:
            break

    return partial_sets


def read_v2_batch_partials_from_chain(telg_v2, request_id: int, required_t: int) -> list[dict]:
    guardians = telg_v2.functions.getV2PartialGuardians(int(request_id)).call()
    partial_sets = []
    seen_share_indices: set[int] = set()

    for g in guardians:
        try:
            result = telg_v2.functions.getV2BatchPartial(
                int(request_id),
                Web3.to_checksum_address(g),
            ).call()
        except Exception:
            return []
        exists, share_index, _partial_hash, e1x, e1y, e2x, e2y = result
        if not exists:
            continue
        share_index = int(share_index)
        if share_index in seen_share_indices:
            continue
        seen_share_indices.add(share_index)
        partial_sets.append(
            {
                "guardian": Web3.to_checksum_address(g),
                "share_index": share_index,
                "E1": (int(e1x), int(e1y)),
                "E2": (int(e2x), int(e2y)),
            }
        )
        if len(partial_sets) >= required_t:
            break

    return partial_sets


# ── V2 PRE aggregation ────────────────────────────────────────────────────────

def build_v2_cids_from_pre_partials(
    request_id: int,
    dv,
    acl,
    telg_v2,
    coordinator_v2,
    request_tuple,
) -> bool:
    (
        _exists,
        file_id,
        _requester,
        batch_id,
        _data_id_req,
        _ts_req,
        key_epoch_req,
        _pk_req_x,
        _pk_req_y,
        _indices_req,
    ) = request_tuple

    (
        file_id_b,
        data_owner_b,
        data_id_b,
        ts_b,
        n_ida,
        t_ida,
        key_epoch_b,
        cid_indices_batch,
    ) = dv.functions.getBatch(int(batch_id)).call()

    (
        key_exists,
        finalized,
        _owner,
        required_t,
        _n_guardians,
        v2_key_epoch,
        share_version,
        _pkx,
        _pky,
    ) = coordinator_v2.functions.getV2Key(file_id).call()

    if not key_exists or not finalized or int(v2_key_epoch) != int(key_epoch_req):
        L.log("[REQ-V2] ZKDKG_V2 key is not finalized for this request.")
        return False

    S.current_n = int(n_ida)
    S.current_t = int(t_ida)
    S.current_file_ext = ""

    # Try batch partials first (single shared point per request), fall back to per-CID
    batch_c1_exists = False
    try:
        batch_c1_exists, _batch_c1x, _batch_c1y = dv.functions.getV2BatchC1(int(batch_id)).call()
    except Exception:
        pass

    batch_partial_sets: list[dict] = []
    if batch_c1_exists:
        batch_partial_sets = read_v2_batch_partials_from_chain(telg_v2, int(request_id), int(required_t))

    partial_sets = batch_partial_sets or read_v2_partials_from_chain(telg_v2, int(request_id), int(required_t))

    if len(partial_sets) < int(required_t):
        L.log_state(
            ("req-v2-aggregator-pre-partials", int(request_id)),
            (len(partial_sets), int(required_t)),
            f"[REQ-V2] Not enough proof-backed V2 partials yet: {len(partial_sets)}/{int(required_t)}",
        )
        return False

    L.log(
        f"[REQ-V2] Collected {len(partial_sets)} proof-backed V2 partials "
        f"from share indices {[p['share_index'] for p in partial_sets]}"
    )

    # Load the requester's Baby Jubjub secret key for El-Gamal decryption.
    if S.requester_keys is None:
        L.log("[REQ-V2] No requester keys loaded — cannot decrypt V2 partials.")
        return False
    try:
        x_req = int(S.requester_keys["x_req"])
    except (KeyError, TypeError, ValueError) as exc:
        L.log(f"[REQ-V2] Cannot load x_req from requester keys: {exc}")
        return False

    items_out = []
    batch_shared = None

    if batch_partial_sets:
        # Decrypt each guardian's El-Gamal pair to recover D_i, then combine.
        batch_points = []
        for ps in partial_sets[: int(required_t)]:
            d_i = v2_elgamal_decrypt(ps["E1"], ps["E2"], x_req)
            if d_i is None:
                L.log(f"[REQ-V2] El-Gamal decryption produced infinity for guardian {ps['guardian']}")
                return False
            batch_points.append((int(ps["share_index"]), d_i))
        batch_shared = v2_combine_partials(batch_points)
        if batch_shared is None:
            L.log("[REQ-V2] Combined V2 batch point is infinity.")
            return False

    for cid_idx in cid_indices_batch:
        cid_idx = int(cid_idx)
        C1x, C1y, C2_orig, _ctSym = dv.functions.getEncCid(cid_idx).call()
        c1 = (int(C1x), int(C1y))

        if not baby_is_on_curve(c1):
            L.log(f"[REQ-V2] C1 not on Baby Jubjub for cidIndex={cid_idx}")
            return False

        if batch_shared is not None:
            shared = batch_shared
        else:
            # Per-CID path: decrypt each partial's El-Gamal pair before combining.
            partial_points = []
            for ps in partial_sets:
                if cid_idx not in ps["partials"]:
                    continue
                enc = ps["partials"][cid_idx]
                d_i = v2_elgamal_decrypt(enc["E1"], enc["E2"], x_req)
                if d_i is None:
                    L.log(f"[REQ-V2] El-Gamal decryption produced infinity for cidIndex={cid_idx}")
                    return False
                partial_points.append((int(ps["share_index"]), d_i))
            if len(partial_points) < int(required_t):
                L.log(f"[REQ-V2] Not enough V2 partials for cidIndex={cid_idx}")
                return False
            shared = v2_combine_partials(partial_points[: int(required_t)])
            if shared is None:
                L.log(f"[REQ-V2] Combined V2 point is infinity for cidIndex={cid_idx}")
                return False

        k_plain = v2_decrypt_with_shared(shared, bytes(C2_orig))
        try:
            k_hex = k_plain.decode("utf-8").strip()
            bytes.fromhex(k_hex)
        except Exception as exc:
            L.log(f"[REQ-V2] cidIndex={cid_idx}: invalid decrypted V2 key: {exc}")
            return False

        items_out.append({"cidIndex": cid_idx, "mode": "ZKDKG_V2", "K_hex": k_hex})
        L.log(f"[REQ-V2] Decrypted V2 payload key for cidIndex={cid_idx}")

    out_obj = {
        "requestId": int(request_id),
        "mode": "ZKDKG_V2",
        "shareVersion": int(share_version),
        "batch": {
            "fileId": file_id_b.hex(),
            "dataOwner": data_owner_b,
            "batchId": int(batch_id),
            "dataId": data_id_b,
            "timestamp": int(ts_b),
            "n": int(n_ida),
            "t": int(t_ida),
            "fileExt": "",
            "keyEpoch": int(key_epoch_b),
            "cidIndices": [int(x) for x in cid_indices_batch],
        },
        "items": items_out,
    }
    out_file = R.reenc_cids_path(request_id)
    out_file.write_text(__import__("json").dumps(out_obj, indent=2), encoding="utf-8")
    L.log(f"[REQ-V2] Saved decrypted V2 CID keys to: {out_file}")
    return True


def build_reenc_cids_from_pre_partials(request_id: int) -> bool:
    """Top-level aggregator: reads access request, dispatches to V2 path."""
    w3 = C.new_web3(C.config)
    if not w3.is_connected():
        L.log("[REQ-Aggregator] Web3 not connected.")
        return False

    dv = C.load_contract_from_config(w3, C.config.DV_ADDRESS, C.config.DV_JSON)
    acl = C.load_contract_from_config(w3, C.config.ACL_ADDRESS, C.config.ACL_JSON)

    request_tuple = dv.functions.getAccessRequest(int(request_id)).call()
    exists = request_tuple[0]
    file_id = request_tuple[1]

    if not exists:
        L.log(f"[REQ-Aggregator] Access request {request_id} does not exist.")
        return False

    try:
        mode = int(acl.functions.getFilePolicyMode(file_id).call())
    except Exception:
        mode = 0

    if mode == 1:
        telg_v2_address = getattr(C.config, "TELG_V2_ADDRESS", "")
        telg_v2_json = getattr(C.config, "TELG_V2_JSON", "")
        coord_address = getattr(C.config, "ZKDKG_COORDINATOR_V2_ADDRESS", "")
        coord_json = getattr(C.config, "ZKDKG_COORDINATOR_V2_JSON", "")
        if not telg_v2_address or not telg_v2_json or not coord_address or not coord_json:
            L.log("[REQ-V2] TElGv2 or ZkDkgCoordinatorV2 config is missing.")
            return False
        telg_v2 = C.load_contract_from_config(w3, telg_v2_address, telg_v2_json)
        coordinator_v2 = C.load_contract_from_config(w3, coord_address, coord_json)
        return build_v2_cids_from_pre_partials(
            int(request_id), dv, acl, telg_v2, coordinator_v2, request_tuple
        )

    L.log("[REQ] Legacy TElG/DKG mode is disabled. This app is V2-only.")
    return False


# ── PRE expiry ───────────────────────────────────────────────────────────────

def expire_pre_request_onchain(w3, request_id: int) -> bool:
    telg_v2_address = getattr(C.config, "TELG_V2_ADDRESS", "")
    telg_v2_json = getattr(C.config, "TELG_V2_JSON", "")
    if not telg_v2_address or not telg_v2_json:
        L.log("[REQ] TElGv2 config missing — cannot expire PRE request.")
        return False
    try:
        req_account = w3.eth.account.from_key(C.config.REQ_PRIVATE_KEY)
        telg_v2 = C.load_contract_from_config(w3, telg_v2_address, telg_v2_json)
        fn = telg_v2.functions.expirePreRequest(int(request_id))
        try:
            gas_est = fn.estimate_gas({"from": req_account.address})
            TX.log_eth_call(
                C,
                contract_name="eth",
                function_name="estimateGas",
                contract_address=telg_v2.address,
                actor_address=req_account.address,
                status="success",
                gas_estimate=gas_est,
                target_function="expirePreRequest",
                request_id=int(request_id),
            )
        except Exception as e:
            TX.log_eth_call(
                C,
                contract_name="eth",
                function_name="estimateGas",
                contract_address=telg_v2.address,
                actor_address=req_account.address,
                status="failed",
                error=str(e),
                target_function="expirePreRequest",
                request_id=int(request_id),
            )
            msg = str(e)
            if "deadline not passed" in msg:
                L.log(f"[REQ] PRE request {request_id}: deadline not yet passed.")
                return False
            if "threshold met" in msg:
                L.log(f"[REQ] PRE request {request_id}: threshold was already met.")
                return False
            if "already expired" in msg:
                L.log(f"[REQ] PRE request {request_id}: already expired.")
                return True
            L.log(f"[REQ] expirePreRequest gas estimate failed for request {request_id}: {e}")
            return False
        nonce = w3.eth.get_transaction_count(req_account.address)
        TX.log_eth_call(
            C,
            contract_name="eth",
            function_name="getTransactionCount",
            actor_address=req_account.address,
            status="success",
            nonce=nonce,
            target_function="expirePreRequest",
            request_id=int(request_id),
        )
        gas_price = C.gas_price_wei()
        TX.log_eth_call(
            C,
            contract_name="eth",
            function_name="gasPrice",
            actor_address=req_account.address,
            status="success",
            result=gas_price,
            target_function="expirePreRequest",
            request_id=int(request_id),
        )
        tx = fn.build_transaction({
            "from": req_account.address,
            "nonce": nonce,
            "gas": gas_est + 100_000,
            "gasPrice": gas_price,
        })
        signed = req_account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        L.log(f"[REQ] expirePreRequest request {request_id} tx: {tx_hash.hex()}")
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        TX.log_contract_transaction(
            C,
            w3,
            actor_address=req_account.address,
            contract_name="TElGv2",
            function_name="expirePreRequest",
            contract_address=telg_v2.address,
            tx=tx,
            tx_hash=tx_hash,
            receipt=receipt,
            request_id=int(request_id),
        )
        L.log(f"[REQ] expirePreRequest request {request_id} status: {receipt.status}")
        return receipt.status == 1
    except Exception as exc:
        L.log(f"[REQ] expirePreRequest failed for request {request_id}: {exc}")
        return False


# ── V2 PRE pricing helpers ────────────────────────────────────────────────────

def _req_default_su(reward_manager, action_name: str) -> int:
    try:
        if action_name == "pre_batch_partial":
            return int(reward_manager.functions.preBatchPartialSu().call())
    except Exception:
        pass
    return 30_542


def _req_su_to_wei(reward_manager) -> int:
    try:
        return int(reward_manager.functions.suToWeiRate().call())
    except Exception:
        return int(getattr(C.config, "SU_TO_WEI_RATE", "1000000000000") or 1000000000000)


def _req_format_su(reward_manager, su: int) -> str:
    ftu = (int(su) * _req_su_to_wei(reward_manager)) / 10 ** 18
    return f"{su} SU ({ftu:.6f} FTU)"


def log_v2_pre_price_estimate(w3, acl, reward_manager, file_id) -> None:
    try:
        _exists, _active, _owner, threshold, guardians = acl.functions.getFilePolicy(file_id).call()
        registry = None
        if getattr(C.config, "GUARDIAN_REGISTRY_ADDRESS", "") and getattr(C.config, "GUARDIAN_REGISTRY_JSON", ""):
            registry = C.load_contract_from_config(w3, C.config.GUARDIAN_REGISTRY_ADDRESS, C.config.GUARDIAN_REGISTRY_JSON)

        rows = []
        for guardian in guardians:
            price = _req_default_su(reward_manager, "pre_batch_partial")
            source = "default RewardManager price"
            if registry is not None:
                try:
                    p = registry.functions.getGuardianServicePricingWithStatus(
                        Web3.to_checksum_address(guardian)
                    ).call()
                    if bool(p[3]):
                        price = int(p[2])
                        source = "Guardian-specific on-chain price"
                except Exception:
                    pass
            rows.append((Web3.to_checksum_address(guardian), price, source))

        L.log("[REQ-V2] Guardian PRE price estimate:")
        L.log("[REQ-V2] REQ uses the Guardians already selected in the file policy.")
        L.log("[REQ-V2] PRE cost uses each Guardian's latest on-chain price at reward time.")
        for guardian, price, source in rows:
            L.log(f"[REQ-V2] {guardian}: PRE={price} SU ({source})")

        cheapest = sorted(price for _g, price, _s in rows)[: int(threshold)]
        L.log(
            f"[REQ-V2] Estimated PRE service incentive for threshold {threshold}: "
            f"{_req_format_su(reward_manager, sum(cheapest))}"
        )
        try:
            safe_escrow = int(reward_manager.functions.estimateV2PreEscrow(file_id, 0).call())
            cheap_escrow = int(reward_manager.functions.estimateV2PreEscrowCheapest(file_id, 0).call())
            L.log(
                f"[REQ-V2] Conservative escrow estimate: {safe_escrow} wei; "
                f"cheapest-threshold estimate: {cheap_escrow} wei"
            )
        except Exception:
            pass
    except Exception as exc:
        L.log(f"[REQ-V2] Guardian PRE price estimate unavailable: {exc}")


def is_deletion_confirmed_onchain(commitment_hash: str, piece_root_hex: str, commitment_nonce: str) -> bool:
    """Verify that a deletion is confirmed on-chain.

    Two checks:
    1. Local math: keccak256(pieceRoot || nonce) must equal commitmentHash (prevents VK lying).
    2. On-chain: FileRegistrationSC.isDeletionConfirmed(commitmentHash) must be True.

    Returns True only if both checks pass. Logs and returns False on any error.
    """
    try:
        from eth_abi.packed import encode_packed
        from web3 import Web3 as _W3

        h = commitment_hash.lower()
        pr = piece_root_hex.lower()
        nonce = commitment_nonce.lower()
        pr_bytes = bytes.fromhex(pr[2:] if pr.startswith("0x") else pr)
        nonce_bytes = bytes.fromhex(nonce[2:] if nonce.startswith("0x") else nonce)
        computed = _W3.keccak(encode_packed(["bytes32", "bytes32"], [pr_bytes, nonce_bytes])).hex()
        expected = h[2:] if h.startswith("0x") else h
        if computed != expected:
            L.log(f"[deletion-check] commitmentHash mismatch: computed=0x{computed} expected=0x{expected}")
            return False

        w3 = C.new_web3(C.config)
        if not w3.is_connected():
            L.log("[deletion-check] RPC not connected — skipping on-chain check")
            return False

        addr = getattr(C.config, "FILE_REGISTRATION_ADDRESS", "")
        json_path = getattr(C.config, "FILE_REGISTRATION_JSON", "contracts/FileRegistrationSC.json")
        if not addr:
            L.log("[deletion-check] FILE_REGISTRATION_ADDRESS not configured — skipping on-chain check")
            return False

        contract = C.load_contract_from_config(w3, addr, json_path)
        ch_bytes = bytes.fromhex(h[2:] if h.startswith("0x") else h)
        confirmed = contract.functions.isDeletionConfirmed(ch_bytes).call()
        return bool(confirmed)
    except Exception as exc:
        L.log(f"[deletion-check] error: {exc}")
        return False
