# req_crypto.py - cryptographic primitives for the requester:
#   GF(2^8) arithmetic, Cauchy-matrix IDA reconstruction,
#   secp256k1 EC math (for legacy PRE path),
#   XOR-stream encrypt/decrypt, AES-CTR + HMAC-SHA256 file decrypt.

import base64
import hashlib
import json
import os
import secrets
import struct

import numpy as np
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import req_state as S


# ── secp256k1 parameters ──────────────────────────────────────────────────────

_p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_a  = 0
_b  = 7
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_G  = (_Gx, _Gy)
_n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

Point = tuple[int, int] | None


def _mod_inv(x: int, m: int) -> int:
    return pow(x, m - 2, m)


def point_add(P: Point, Q: Point) -> Point:
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 != y2:
        return None
    if P == Q:
        if y1 == 0:
            return None
        s = (3 * x1 * x1 + _a) * _mod_inv(2 * y1 % _p, _p) % _p
    else:
        if x1 == x2:
            return None
        s = (y2 - y1) * _mod_inv((x2 - x1) % _p, _p) % _p
    x3 = (s * s - x1 - x2) % _p
    y3 = (s * (x1 - x3) - y1) % _p
    return (x3, y3)


def scalar_mult(k: int, P: Point) -> Point:
    if k % _n == 0 or P is None:
        return None
    k = k % _n
    result: Point = None
    addend = P
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def is_on_curve(P: Point) -> bool:
    if P is None:
        return True
    x, y = P
    return (y * y - (x * x * x + _a * x + _b)) % _p == 0


def lagrange_coeff(x_j: int, x_set: list[int]) -> int:
    xj = x_j % _n
    num = 1
    den = 1
    for xm in x_set:
        xm_mod = xm % _n
        if xm_mod == xj:
            continue
        num = (num * (-xm_mod)) % _n
        den = (den * (xj - xm_mod)) % _n
    return (num * _mod_inv(den, _n)) % _n


def combine_partial_points(partials: list[tuple[int, Point]]) -> Point:
    x_list = [x for x, _ in partials]
    acc: Point = None
    for xj, Dj in partials:
        lam = lagrange_coeff(xj, x_list)
        term = scalar_mult(lam, Dj)
        acc = point_add(acc, term)
    return acc


# ── GF(2^8) arithmetic ────────────────────────────────────────────────────────

_POLY = 0x11b  # Rijndael field: x^8 + x^4 + x^3 + x + 1


def _gf_mul_bitwise(a: int, b: int) -> int:
    res = 0
    while b:
        if b & 1:
            res ^= a
        a <<= 1
        if a & 0x100:
            a ^= _POLY
        b >>= 1
    return res & 0xFF


def _build_gf_tables():
    mul = np.zeros((256, 256), dtype=np.uint8)
    for a in range(256):
        for b in range(256):
            mul[a, b] = _gf_mul_bitwise(a, b)
    inv = np.zeros(256, dtype=np.uint8)
    inv[0] = 0
    for a in range(1, 256):
        row = mul[a]
        idx = np.where(row == 1)[0]
        if idx.size == 0:
            raise RuntimeError(f"No inverse for {a} in GF(256)")
        inv[a] = idx[0]
    return mul, inv


GF_MUL_TABLE, INV_TABLE = _build_gf_tables()


def gf_mul(a: int, b: int) -> int:
    return int(GF_MUL_TABLE[a, b])


def gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("No inverse for 0 in GF(256)")
    return int(INV_TABLE[a])


# ── Cauchy-matrix IDA ─────────────────────────────────────────────────────────

def _build_generator_matrix(n: int, m: int) -> np.ndarray:
    if n + m > 255:
        raise ValueError("Cauchy matrix requires n + m <= 255")
    x = list(range(1, n + 1))
    y = [n + 1 + j for j in range(m)]
    C = np.empty((n, m), dtype=np.uint8)
    for i in range(n):
        xi = x[i]
        for j in range(m):
            diff = xi ^ y[j]
            if diff == 0:
                raise RuntimeError("x and y collided")
            C[i, j] = INV_TABLE[diff]
    return C


def _gf_mat_inv(M: np.ndarray) -> np.ndarray:
    M = M.astype(np.uint8, copy=True)
    m = M.shape[0]
    A = np.zeros((m, 2 * m), dtype=np.uint8)
    A[:, :m] = M
    for i in range(m):
        A[i, m + i] = 1

    for col in range(m):
        pivots = np.nonzero(A[col:, col])[0]
        if pivots.size == 0:
            raise ValueError("Matrix not invertible")
        pivot = col + pivots[0]
        if pivot != col:
            A[[col, pivot]] = A[[pivot, col]]

        inv_pivot = gf_inv(int(A[col, col]))
        row = A[col]
        for c in range(2 * m):
            row[c] = GF_MUL_TABLE[inv_pivot, row[c]]

        for r in range(m):
            if r == col:
                continue
            factor = int(A[r, col])
            if factor:
                src = A[col]
                dst = A[r]
                for c in range(2 * m):
                    dst[c] ^= GF_MUL_TABLE[factor, src[c]]

    return A[:, m:]


def ida_reconstruct_file(output_path: str, share_paths) -> None:
    """Reconstruct the original file from t-of-n RIDA shares."""
    if len(share_paths) == 0:
        raise ValueError("No share files given")

    headers = []
    payloads = []
    for path in share_paths:
        with open(path, "rb") as f:
            header = f.read(16)
            if len(header) < 16:
                raise ValueError(f"Share {path} has invalid header length")
            if header[:4] != b"RIDA":
                raise ValueError(f"Share {path} has invalid magic")
            version = header[4]
            n = header[5]
            m = header[6]
            share_index = header[7]
            (orig_size,) = struct.unpack(">Q", header[8:16])
            data = f.read()
        headers.append((path, version, n, m, share_index, orig_size))
        payloads.append(data)

    _, v0, n0, m0, _, size0 = headers[0]
    for (path, v, n, m, idx, sz) in headers:
        if v != v0 or n != n0 or m != m0 or sz != size0:
            raise ValueError(f"Inconsistent share: {path}")

    n_val = n0
    m_val = m0
    orig_size = size0

    if len(share_paths) < m_val:
        raise ValueError(f"Need at least {m_val} shares, got {len(share_paths)}")

    used_headers = headers[:m_val]
    used_payloads = payloads[:m_val]
    share_indices = [h[4] for h in used_headers]

    share_len = len(used_payloads[0])
    for d in used_payloads:
        if len(d) != share_len:
            raise ValueError("Share payload lengths differ (corrupted shares?)")

    num_blocks = share_len
    data_shares = np.vstack([
        np.frombuffer(p, dtype=np.uint8, count=num_blocks) for p in used_payloads
    ])

    G = _build_generator_matrix(n_val, m_val)
    A = G[share_indices, :]
    A_inv = _gf_mat_inv(A)

    blocks = np.zeros((num_blocks, m_val), dtype=np.uint8)
    for j in range(m_val):
        acc = np.zeros(num_blocks, dtype=np.uint8)
        row = A_inv[j]
        for i in range(m_val):
            coef = int(row[i])
            acc ^= GF_MUL_TABLE[coef, data_shares[i]]
        blocks[:, j] = acc

    out_bytes = blocks.reshape(-1).tobytes()[:orig_size]
    with open(output_path, "wb") as f:
        f.write(out_bytes)


# ── XOR-stream encrypt/decrypt ────────────────────────────────────────────────

def xor_stream_encrypt(data: bytes, key_material: bytes) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < len(data):
        h = hashlib.sha256(key_material + counter.to_bytes(4, "big")).digest()
        out.extend(h)
        counter += 1
    ks = bytes(out[: len(data)])
    return bytes(d ^ k for d, k in zip(data, ks))


# ── legacy PRE decrypt (secp256k1 ElGamal) ───────────────────────────────────

def decrypt_entry(entry: dict, x_req: int) -> bytes:
    """Decrypt a legacy re-encrypted CID entry using the requester secret key."""
    C1x = int(entry["C1x_prime"])
    C1y = int(entry["C1y_prime"])
    C2_hex = entry["C2_hex_prime"]

    C1 = (C1x, C1y)
    S_point = scalar_mult(x_req, C1)
    if S_point is None:
        raise RuntimeError(
            f"S * C1 is infinity for cidIndex {entry.get('cidIndex', '<no index>')}"
        )

    Sx, _ = S_point
    key_material = Sx.to_bytes((Sx.bit_length() + 7) // 8, "big")
    C2_bytes = bytes.fromhex(C2_hex)
    return xor_stream_encrypt(C2_bytes, key_material)


# ── requester EC key generation ───────────────────────────────────────────────

# Baby Jubjub parameters (same curve as ZKDKG_V2 and PRE El-Gamal)
_BABY_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
_BABY_Q = 21888242871839275222246405745257275088614511777268538073601725287587578984328
_BABY_L = _BABY_Q // 8
_BABY_A = 168700
_BABY_D = 168696
_BABY_G = (
    16540640123574156134436876038791482806971768689494387082833631921987005038935,
    20819045374670962167435360035096875258406992893633759881276124905556507972311,
)


def _bjj_mod(x: int) -> int:
    return x % _BABY_P


def _bjj_inv(x: int) -> int:
    return pow(x % _BABY_P, _BABY_P - 2, _BABY_P)


def _bjj_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    x1x2 = _bjj_mod(x1 * x2)
    y1y2 = _bjj_mod(y1 * y2)
    dxxyy = _bjj_mod(_BABY_D * x1x2 * y1y2)
    x3 = _bjj_mod((_bjj_mod(x1 * y2) + _bjj_mod(y1 * x2)) * _bjj_inv(1 + dxxyy))
    y3 = _bjj_mod((y1y2 - _bjj_mod(_BABY_A * x1x2)) * _bjj_inv(1 - dxxyy))
    return x3, y3


def _bjj_mul(scalar: int, point=_BABY_G):
    if point is None:
        return None
    k = int(scalar) % _BABY_L
    if k == 0:
        return None
    result = None
    addend = point
    while k:
        if k & 1:
            result = _bjj_add(result, addend)
        k >>= 1
        if k:
            addend = _bjj_add(addend, addend)
    return result


def generate_requester_ec_keys(json_filename: str) -> dict:
    """Generate a Baby Jubjub key pair for V2 PRE El-Gamal decryption.

    pkReq = x_req * G (Baby Jubjub) is stored on-chain in the access request.
    Guardians encrypt each partial D_i as (E1=r*G, E2=D_i+r*pkReq).
    Only the holder of x_req can recover D_i = E2 - x_req*E1.

    NOTE: existing secp256k1 key files must be regenerated — they are
    incompatible with the V2 El-Gamal scheme.
    """
    x_req = secrets.randbelow(_BABY_L - 1) + 1
    PK_req = _bjj_mul(x_req, _BABY_G)
    if PK_req is None:
        raise RuntimeError("Failed to generate Baby Jubjub requester public key.")
    PKreq_x, PKreq_y = PK_req

    data = {
        "curve": "babyjubjub",
        "x_req": x_req,
        "PK_req_x": PKreq_x,
        "PK_req_y": PKreq_y,
    }
    with open(json_filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return data


# ── AES payload unwrap ────────────────────────────────────────────────────────

def unwrap_aes_payload(aes_plain: bytes) -> dict:
    try:
        obj = json.loads(aes_plain.decode("utf-8"))
        if isinstance(obj, dict) and "enc_key" in obj and "mac_key" in obj and "iv" in obj:
            return obj
    except Exception:
        pass

    inner_b64 = aes_plain.decode("utf-8").strip()
    try:
        key_bytes = base64.b64decode(inner_b64)
    except Exception:
        return {"raw": base64.b64encode(aes_plain).decode("utf-8")}

    if len(key_bytes) < 64:
        return {"raw": base64.b64encode(aes_plain).decode("utf-8")}

    enc_key_bytes = key_bytes[0:32]
    mac_key_bytes = key_bytes[32:64]
    iv_bytes      = key_bytes[64:80] if len(key_bytes) >= 80 else b""

    return {
        "enc_key": base64.b64encode(enc_key_bytes).decode("utf-8"),
        "mac_key": base64.b64encode(mac_key_bytes).decode("utf-8"),
        "iv":      base64.b64encode(iv_bytes).decode("utf-8") if iv_bytes else "",
        "tag_size": 32,
        "cipher": {"algorithm": "AES", "mode": "CTR", "key_size_bits": 256},
        "mac":    {"algorithm": "HMAC", "hash": "SHA256"},
    }


# ── AES-CTR + HMAC-SHA256 file decrypt ───────────────────────────────────────

def decrypt_file(enc_path: str, out_path: str, key_json_path: str) -> None:
    with open(key_json_path, "r", encoding="utf-8") as f:
        key_info = json.load(f)

    enc_key  = base64.b64decode(key_info["enc_key"])
    mac_key  = base64.b64decode(key_info["mac_key"])
    tag_size = key_info.get("tag_size", 32)

    file_size = os.path.getsize(enc_path)
    if file_size < 16 + tag_size:
        raise ValueError("Encrypted file too small / corrupted")

    with open(enc_path, "rb") as fin, open(out_path, "wb") as fout:
        iv = fin.read(16)

        cipher = Cipher(
            algorithms.AES(enc_key),
            modes.CTR(iv),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())

        ct_bytes_left = file_size - 16 - tag_size
        while ct_bytes_left > 0:
            to_read = min(S.CHUNK_SIZE, ct_bytes_left)
            chunk = fin.read(to_read)
            if not chunk:
                raise ValueError("Unexpected end of file during ciphertext read")
            h.update(chunk)
            fout.write(decryptor.update(chunk))
            ct_bytes_left -= len(chunk)

        tag = fin.read(tag_size)
        if len(tag) != tag_size:
            raise ValueError("Could not read authentication tag")
        try:
            h.verify(tag)
        except InvalidSignature:
            raise ValueError("Authentication failed: wrong key or file tampered")

        pt_final = decryptor.finalize()
        if pt_final:
            fout.write(pt_final)
