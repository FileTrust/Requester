# req_vaultmesh.py - VaultMesh piece download: signed GET auth, binary invocation,
#                    Merkle pieceRoot verification.

import hashlib
import json
import os
import subprocess
import datetime
import time
import urllib.parse
import urllib.request

from eth_account.messages import encode_defunct
from web3 import Web3

from . import req_config as C
from . import req_log as L
from . import req_records as R
from . import req_state as S
from . import req_transfer_manager as XFER

_DISCOVERY_RECORD_CACHE: dict[str, dict] = {}

# ── low-level helpers ─────────────────────────────────────────────────────────

def _run_cmd(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result.stdout.strip()


def _normalize_piece_root(root_value: str) -> str:
    clean = str(root_value or "").strip().lower()
    if not clean:
        return ""
    if not clean.startswith("0x"):
        clean = "0x" + clean
    return clean


def _hash_piece_leaf(data: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(b"\x00")
    h.update(data)
    return h.digest()


def _hash_piece_node(left: bytes, right: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(b"\x01")
    h.update(left)
    h.update(right)
    return h.digest()


def compute_piece_root_file(path: str, block_size: int = S.PIECE_ROOT_BLOCK_SIZE) -> str:
    """Compute the Merkle pieceRoot of a downloaded piece file."""
    leaves = []
    with open(path, "rb") as f:
        while True:
            chunk = f.read(int(block_size))
            if not chunk:
                break
            leaves.append(_hash_piece_leaf(chunk))

    if not leaves:
        leaves = [_hash_piece_leaf(b"")]

    level = leaves
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(_hash_piece_node(left, right))
        level = nxt
    return "0x" + level[0].hex()


def get_enc_cid_tuple(dv, cid_index: int):
    """Return (C1x, C1y, C2, ctSym) tolerating old/new DataVault ABIs."""
    try:
        result = dv.functions.getEncCidV2(int(cid_index)).call()
        if len(result) >= 8 and isinstance(result[0], bool):
            if not result[0]:
                raise RuntimeError(f"encCid {cid_index} does not exist")
            return result[1], result[2], result[3], result[4]
        if len(result) >= 4:
            return result[0], result[1], result[2], result[3]
    except Exception:
        pass
    return dv.functions.getEncCid(int(cid_index)).call()


# ── VK discovery ─────────────────────────────────────────────────────────────

# Registration verdict per VK address, so a keeper is looked up once and not on
# every piece. Short-lived on purpose: a keeper that leaves or is deactivated
# must stop being used quickly.
_VK_STATUS_CACHE: dict[str, dict] = {}
_VK_STATUS_TTL_SECONDS = 60.0
_VK_ENDPOINT_CACHE: dict[str, dict] = {}


def peer_id_from_peer(peer: str) -> str:
    """Return the stable peerID from either a bare peerID or a full multiaddr."""
    value = str(peer or "").strip()
    if "/p2p/" in value:
        return value.rsplit("/p2p/", 1)[-1].strip()
    return value


def _discovery_urls() -> list[str]:
    """The user's own directory servers first, then the network's."""
    from . import ft_discovery

    return ft_discovery.urls(C.config)


def _discovery_timeout() -> float:
    try:
        return float(getattr(C.config, "DISCOVERY_TIMEOUT_SECONDS", 2) or 2)
    except Exception:
        return 2.0


def _discovery_message(record: dict) -> str:
    return "\n".join(
        [
            "FileTrust VK Discovery Record",
            "version=1",
            f"peerId={record.get('peerId', '')}",
            f"multiaddr={record.get('multiaddr', '')}",
            f"vkAddress={record.get('vkAddress', '')}",
            f"seq={int(record.get('seq', 0))}",
            f"expiresAt={int(record.get('expiresAt', 0))}",
        ]
    )


def _endpoint_message(record: dict) -> str:
    return "\n".join(
        [
            "FileTrust VK Discovery Endpoint",
            "version=1",
            f"peerId={record.get('peerId', '')}",
            f"multiaddr={record.get('multiaddr', '')}",
            f"vkAddress={record.get('vkAddress', '')}",
            f"seq={int(record.get('seq', 0))}",
        ]
    )


def _endpoint_hash(record: dict) -> str:
    value = Web3.keccak(text=_endpoint_message(record)).hex()
    return value if str(value).startswith("0x") else "0x" + str(value)


def _normalize_bytes32_hex(value) -> str:
    if isinstance(value, (bytes, bytearray)):
        return "0x" + bytes(value).hex()
    text = str(value or "").strip()
    if not text:
        return "0x" + ("0" * 64)
    if text.startswith("0x") and len(text) == 66:
        return text.lower()
    clean = text.removeprefix("0x")
    if len(clean) <= 64:
        return "0x" + clean.rjust(64, "0").lower()
    return text.lower()


def _is_endpoint_unsupported_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return (
        "function selector" in text
        or "not recognized" in text
        or "function does not exist" in text
        or "could not decode" in text
        or "return data: b''" in text
    )


def _discovery_verify_endpoint_hash_enabled() -> bool:
    return True


def _discovery_require_endpoint_hash() -> bool:
    return True


def _endpoint_cache_ttl() -> int:
    try:
        return max(1, int(getattr(C.config, "DISCOVERY_ENDPOINT_CACHE_SECONDS", 30) or 30))
    except Exception:
        return 30


def _registry_supports_endpoint_hash() -> bool:
    registry = getattr(C, "vault_keeper_registry", None)
    if registry is None:
        return False
    try:
        return any(
            item.get("type") == "function" and item.get("name") == "getVaultKeeperEndpoint"
            for item in getattr(registry, "abi", [])
            if isinstance(item, dict)
        )
    except Exception:
        return False


def _get_registry_endpoint(vk_addr: str) -> tuple[str, int]:
    registry = getattr(C, "vault_keeper_registry", None)
    if registry is None:
        raise RuntimeError("VaultKeeperRegistry is not configured")
    checksum = Web3.to_checksum_address(vk_addr)
    now = int(time.time())
    cached = _VK_ENDPOINT_CACHE.get(checksum.lower())
    if cached and now - int(cached.get("loadedAt", 0)) < _endpoint_cache_ttl():
        return str(cached.get("endpointHash", "")), int(cached.get("seq", 0))
    endpoint = registry.functions.getVaultKeeperEndpoint(checksum).call()
    endpoint_hash = _normalize_bytes32_hex(endpoint[0] if len(endpoint) > 0 else "")
    seq = int(endpoint[1] if len(endpoint) > 1 else 0)
    _VK_ENDPOINT_CACHE[checksum.lower()] = {
        "endpointHash": endpoint_hash,
        "seq": seq,
        "loadedAt": now,
    }
    return endpoint_hash, seq


def _verify_discovery_endpoint(record: dict, vk_addr: str) -> tuple[bool, str]:
    if not _discovery_verify_endpoint_hash_enabled():
        return False, "endpoint hash verification is required"
    if not _registry_supports_endpoint_hash():
        return False, "registry does not support endpoint hashes"

    computed_hash = _endpoint_hash(record)
    announced_hash = str(record.get("endpointHash", "") or "").strip()
    if announced_hash and announced_hash.lower() != computed_hash.lower():
        return False, f"endpointHash mismatch: announced={announced_hash} computed={computed_hash}"

    try:
        chain_hash, chain_seq = _get_registry_endpoint(vk_addr)
        record_seq = int(record.get("seq", 0))
    except Exception as exc:
        return False, f"endpoint hash lookup failed: {exc}"

    zero_hash = "0x" + ("0" * 64)
    if chain_seq <= 0 or chain_hash.lower() == zero_hash:
        return False, "on-chain endpoint hash is not set"
    if chain_seq != record_seq:
        return False, f"endpoint seq mismatch: record={record_seq} chain={chain_seq}"
    if chain_hash.lower() != computed_hash.lower():
        return False, f"endpoint hash mismatch: record={computed_hash} chain={chain_hash}"
    return True, "ok"


def _vk_is_registered_and_active(vk_addr: str) -> tuple[bool, str]:
    """Check one address on the registry: registered, and still active?

    Two current-state reads the first time, then cached per address. Nothing
    grows with the size of the registry or the age of the chain.

    This replaces a scan that listed every Vault Keeper and searched all chain
    history for each one's peer id, just to learn which address a peer belongs
    to. That mapping is already proven elsewhere without any history: the
    keeper signs its peer id and address together, and the hash of that pairing
    is published in registry state, which is what the record check below
    compares against. The scan was redundant -- and on a chain that caps log
    queries it starts failing outright a few hours in, taking every keeper with
    it.
    """
    registry = getattr(C, "vault_keeper_registry", None)
    if registry is None:
        return False, "VaultKeeperRegistry is not configured"

    try:
        checksum = Web3.to_checksum_address(vk_addr)
    except Exception:
        return False, f"invalid vkAddress: {vk_addr}"

    key = checksum.lower()
    now = time.time()
    cached = _VK_STATUS_CACHE.get(key)
    if cached and now - float(cached.get("checkedAt", 0.0)) < _VK_STATUS_TTL_SECONDS:
        return bool(cached.get("ok")), str(cached.get("reason", ""))

    try:
        registered = bool(registry.functions.isRegisteredVaultKeeper(checksum).call())
        active = False
        if registered:
            vk = registry.functions.getVaultKeeper(checksum).call()
            active = bool(vk[3]) if len(vk) > 3 else True
    except Exception as exc:
        # Could not ask is not the same as "no". A keeper the chain already
        # vouched for keeps its verdict; an unknown one is not admitted on faith.
        if cached:
            return bool(cached.get("ok")), str(cached.get("reason", ""))
        L.log(f"[Discovery] VK status lookup failed for {checksum}: {exc}")
        return False, f"registry unreachable and {checksum} was never verified"

    if not registered:
        result = (False, "peerID is not registered in VaultKeeperRegistry")
    elif not active:
        result = (False, "registered Vault Keeper is not active")
    else:
        result = (True, "ok")

    _VK_STATUS_CACHE[key] = {"ok": result[0], "reason": result[1], "checkedAt": now}
    return result


def _verify_discovery_record(record: dict, peer_id: str, vk_addr: str) -> tuple[bool, str]:
    try:
        from eth_account import Account
        from eth_account.messages import encode_defunct as _encode_defunct
    except Exception as exc:
        return False, f"eth_account unavailable: {exc}"

    if not isinstance(record, dict):
        return False, "record is not an object"
    rec_peer = str(record.get("peerId", "")).strip()
    rec_addr = str(record.get("vkAddress", "")).strip()
    multiaddr = str(record.get("multiaddr", "")).strip()
    sig = str(record.get("signature", "")).strip()

    if rec_peer != peer_id:
        return False, f"peerId mismatch: {rec_peer}"
    if rec_addr.lower() != str(vk_addr).lower():
        return False, f"vkAddress mismatch: {rec_addr}"
    if f"/p2p/{peer_id}" not in multiaddr:
        return False, "multiaddr does not contain peerId"
    if not sig:
        return False, "missing signature"
    try:
        expires_at = int(record.get("expiresAt", 0))
        if expires_at <= int(datetime.datetime.now(datetime.timezone.utc).timestamp()):
            return False, "record expired"
    except Exception:
        return False, "invalid expiresAt"

    try:
        recovered = Account.recover_message(_encode_defunct(text=_discovery_message(record)), signature=sig)
    except Exception as exc:
        return False, f"signature recovery failed: {exc}"
    if recovered.lower() != str(vk_addr).lower():
        return False, f"signature recovered {recovered}"
    ok, reason = _verify_discovery_endpoint(record, vk_addr)
    if not ok:
        return False, reason
    return True, "ok"


def _query_discovery_node(url: str, peer_id: str) -> dict | None:
    peer_path = urllib.parse.quote(peer_id, safe="")
    endpoint = f"{url}/v1/peers/{peer_path}"
    # Named, because a discovery node behind Cloudflare answers 403 to
    # Python's default user agent and the lookup would simply find nothing.
    request = urllib.request.Request(endpoint, headers={"User-Agent": "FileTrust-REQ"})
    with urllib.request.urlopen(request, timeout=_discovery_timeout()) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if not data.get("ok"):
        return None
    return data.get("record")


def resolve_vk_multiaddr(peer_value: str) -> dict:
    """Resolve stored VK peerID to today's signed multiaddr."""
    raw_peer = str(peer_value or "").strip()
    peer_id = peer_id_from_peer(raw_peer)
    if not peer_id:
        raise RuntimeError("Missing VaultMesh peerID for this piece.")

    urls = _discovery_urls()
    if not urls:
        from . import ft_discovery

        raise RuntimeError(ft_discovery.NO_SERVERS)

    vk_addr = ""
    for attempt in range(2):
        for url in urls:
            try:
                record = _query_discovery_node(url, peer_id)
                if not record:
                    continue
                # Discovery may lie about which address owns this peer, so the
                # address it claims is only a starting point. The record check
                # below settles it: the signature must come from that address,
                # and the hash of the pairing must match what that address
                # published in registry state.
                claimed_addr = str(record.get("vkAddress", "")).strip()
                if not claimed_addr:
                    continue
                ok, status_reason = _vk_is_registered_and_active(claimed_addr)
                if not ok:
                    L.log(f"[Discovery] rejected record from {url} peerID={peer_id}: {status_reason}")
                    continue
                ok, verify_reason = _verify_discovery_record(record, peer_id, claimed_addr)
                if not ok:
                    L.log(f"[Discovery] rejected record from {url} peerID={peer_id}: {verify_reason}")
                    continue
                vk_addr = claimed_addr
                _DISCOVERY_RECORD_CACHE[peer_id] = dict(record)
                multiaddr = str(record.get("multiaddr", "")).strip()
                L.log(f"[Discovery] resolved peerID={peer_id} via {url} -> {multiaddr}")
                return {
                    "peerId": peer_id,
                    "multiaddr": multiaddr,
                    "vkAddress": vk_addr,
                    "source": url,
                }
            except Exception as exc:
                if attempt == 1:
                    L.log(f"[Discovery] query failed url={url} peerID={peer_id}: {exc}")
        if attempt == 0:
            time.sleep(0.25)

    cached = _DISCOVERY_RECORD_CACHE.get(peer_id)
    if cached:
        cached_addr = str(cached.get("vkAddress", "")).strip()
        ok, verify_reason = _verify_discovery_record(cached, peer_id, cached_addr)
        if ok:
            return {
                "peerId": peer_id,
                "multiaddr": str(cached.get("multiaddr", "")).strip(),
                "vkAddress": cached_addr,
                "source": "verified-cache",
            }
        _DISCOVERY_RECORD_CACHE.pop(peer_id, None)
        L.log(f"[Discovery] cached record rejected peerID={peer_id}: {verify_reason}")

    raise RuntimeError(f"Discovery could not resolve a live multiaddr for peerID={peer_id}.")


# ── signed GET authorization ──────────────────────────────────────────────────

def build_vaultmesh_get_auth(file_id: str, piece_root: str) -> tuple[str, int, str]:
    """Create the signed authorization that VaultKeeper verifies before serving a piece."""
    import time as _time

    if not file_id:
        raise RuntimeError("Missing fileId for VaultMesh access authorization.")

    account = Web3().eth.account.from_key(C.config.REQ_PRIVATE_KEY)
    requester = Web3.to_checksum_address(account.address)
    file_id_hex = R.normalize_file_id_hex(file_id)
    issued_at = int(_time.time())

    message = (
        "FileTrust VaultMesh GET\n"
        f"fileId={file_id_hex}\n"
        f"pieceRoot={_normalize_piece_root(piece_root)}\n"
        f"requester={requester}\n"
        f"issuedAt={issued_at}"
    )

    signed = account.sign_message(encode_defunct(text=message))
    return requester, issued_at, signed.signature.hex()


# ── piece download ────────────────────────────────────────────────────────────

def vaultmesh_get(piece_root: str, peer_id: str, output_path: str, file_id: str) -> dict:
    """Download one piece from VaultMesh and return the JSON response."""
    if not peer_id:
        raise RuntimeError("Missing VaultMesh peerId for this piece.")

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    piece_root = _normalize_piece_root(piece_root)
    job = XFER.get_or_create_download_job(
        C.BASE_DIR, piece_root, peer_id, output_path, file_id,
    )
    if job.get("status") == "completed" and os.path.isfile(output_path):
        if compute_piece_root_file(output_path) == piece_root:
            return {"ok": True, "resumed": True}
        XFER.update_download_job(
            C.BASE_DIR,
            job,
            status="pending",
            lastError="completed output failed PieceRoot verification",
        )
    requester, issued_at, sig = build_vaultmesh_get_auth(file_id, piece_root)

    cmd = [
        C.config.VAULTMESH_CMD,
        "--mode", "get",
        "--peer", peer_id,
        "--piece-root", piece_root,
        "--file", output_path,
        "--file-id", R.normalize_file_id_hex(file_id),
        "--requester", requester,
        "--issued-at", str(issued_at),
        "--sig", sig,
    ]

    out = XFER.run_download_process(C.BASE_DIR, job, cmd)
    try:
        return json.loads(out) if out.startswith("{") else {"ok": True, "raw": out}
    except Exception:
        return {"ok": True, "raw": out}


def check_vk_has_piece(piece_root: str, peer_id: str) -> dict:
    """Ask a VK whether it still holds a piece (off-chain ping via has-piece protocol).

    Returns the HasPieceResp dict with keys: has, deleted, deletionPending,
    commitmentHash, commitmentNonce, error.
    Never raises — errors are returned in the dict so callers can decide how to handle them.
    """
    piece_root = _normalize_piece_root(piece_root)
    try:
        cmd = [
            C.config.VAULTMESH_CMD,
            "--mode", "has-piece",
            "--peer", peer_id,
            "--piece-root", piece_root,
        ]
        out = _run_cmd(cmd)
        return json.loads(out) if out else {"error": "empty response"}
    except Exception as exc:
        return {"error": str(exc)}
