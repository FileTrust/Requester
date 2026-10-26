# req_config.py - configuration loading, paths, Web3, and contract helpers.
# No imports from other requester migration modules.

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

from web3 import Web3
from . import req_txlog as TX
from . import ft_keyvault as KEYVAULT
from .req_rpc import new_web3

# --- the wallet key on disk ---------------------------------------------------

def secret_file_is_private(path) -> tuple[bool, str]:
    """Is this file readable only by the account running the app?

    The runtime data around it -- receipts, transfer state, records -- is all
    written 0600 inside 0700 directories. The wallet key is not: it lives in the
    config file, written with whatever the umask gives, and nothing looked. A
    key every local account can read defeats every signature check built on top
    of it at once, because whoever reads it simply becomes this identity.

    The mode is read back rather than inferred from chmod returning cleanly. On
    a filesystem that cannot store permissions -- NTFS or exFAT, common when an
    application lives on a second drive -- chmod succeeds and changes nothing, so
    trusting it would report every key on such a disk as protected.
    """
    import stat as _stat

    p = Path(path)
    try:
        mode = _stat.S_IMODE(os.stat(p).st_mode)
    except OSError as exc:
        return False, f"cannot read the permissions of {p}: {exc}"
    if mode & 0o077:
        return False, (
            f"{p} is mode {mode:04o}: other accounts on this machine can "
            f"read the wallet key. Move it to a filesystem that keeps "
            f"permissions and set it to 0600."
        )
    return True, "ok"


def restrict_secret_file(path) -> tuple[bool, str]:
    """Ask for 0600, then check whether it was actually granted."""
    try:
        os.chmod(Path(path), 0o600)
    except OSError:
        pass  # reported by the read-back below, with the mode that resulted
    return secret_file_is_private(path)


CORE_DIR = Path(__file__).resolve().parent        # App/REQ/core
BASE_DIR = CORE_DIR.parent                        # App/REQ
REQ_DIR = BASE_DIR                                # App/REQ (no migration layer)
APP_DIR = BASE_DIR.parent                         # App/
ROOT_DIR = APP_DIR.parent                         # FileTrust
DEFAULT_CONFIG_PATH = BASE_DIR / "config.json"

DATA_DIR = BASE_DIR / "data"
UNZIPPED_DATA_DIR = BASE_DIR / "data_unzipped"
PIECES_DIR = BASE_DIR / "pieces"
LOG_DIR = BASE_DIR / "log"
POLICY_CACHE_FILE = BASE_DIR / "policies.json"
REQUESTER_KEYS_FILE = BASE_DIR / "requester_keys.json"  # legacy fallback only
KEYS_DIR = BASE_DIR / "keys"


def key_path_for_policy(file_id: str) -> Path:
    """Return the path to the key file for a given fileId (policy-bound key)."""
    normalized = file_id.lower().replace("0x", "")
    return KEYS_DIR / f"{normalized}.json"


def _resolve_config_path(value: str | os.PathLike, base: Path) -> str:
    raw = Path(str(value)).expanduser()
    if raw.is_absolute():
        return str(raw)
    candidates = [
        (CORE_DIR / raw).resolve(),
        (base / raw).resolve(),
        (REQ_DIR / raw).resolve(),
        (ROOT_DIR / raw).resolve(),
        (Path.cwd() / raw).resolve(),
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return str(candidates[0])


def _load_req_config() -> SimpleNamespace:
    config_path = Path(os.getenv("REQ_CONFIG_PATH", DEFAULT_CONFIG_PATH)).expanduser()
    if not config_path.is_absolute():
        config_path = (BASE_DIR / config_path).resolve()

    defaults = {
        "RPC_URL": "https://rpc.filetrust.io",
        "RPC_TIMEOUT_SECONDS": 30,
        "RPC_READ_ATTEMPTS": 4,
        "RPC_RETRY_INITIAL_SECONDS": 0.25,
        "RPC_RETRY_MAX_SECONDS": 2.0,
        "GUARDIAN_REGISTRY_ADDRESS": "",
        "VAULT_KEEPER_REGISTRY_ADDRESS": "",
        "ACL_ADDRESS": "",
        "DV_ADDRESS": "",
        "DKG_ADDRESS": "",
        "TELG_ADDRESS": "",
        "TELG_V2_ADDRESS": "",
        "ZKDKG_COORDINATOR_V2_ADDRESS": "",
        "REWARD_MANAGER_ADDRESS": "",
        "GUARDIAN_REGISTRY_JSON": "contracts/GuardianRegistry.json",
        "VAULT_KEEPER_REGISTRY_JSON": "contracts/VaultKeeperRegistry.json",
        "ACL_JSON": "contracts/AccessControlFT.json",
        "DV_JSON": "contracts/DataVault.json",
        "DKG_JSON": "",
        "TELG_JSON": "",
        "TELG_V2_JSON": "contracts/TElGv2.json",
        "ZKDKG_COORDINATOR_V2_JSON": "contracts/ZkDkgCoordinatorV2.json",
        "REWARD_MANAGER_JSON": "contracts/RewardManager.json",
        "FILE_REGISTRATION_ADDRESS": "",
        "FILE_REGISTRATION_JSON": "contracts/FileRegistrationSC.json",
        # Addresses only, no ABI: REQ never calls these two contracts, it only
        # needs to recognise them by address so the transaction log can name
        # them instead of logging a bare hex string.
        "VK_ESCROW_ADDRESS": "",
        "STORAGE_RECEIPT_DISPUTE_ADDRESS": "",
        "REQ_PRIVATE_KEY": "",
        # Where this app asks for the deployed contract addresses, the RPC URL
        # and the discovery nodes: during install, and afterwards only when the
        # user asks for it from the tray. Whatever answers this URL decides
        # which chain the app talks to, so it is a setting rather than a
        # constant. The default uses HTTPS at config.filetrust.io, with
        # certificate verification enabled. Empty means
        # "never ask", for an install pinned by hand.
        "NETWORK_CONFIG_URL": "https://config.filetrust.io/v1/network-config",
        "VAULTMESH_CMD": "./vaultmesh",
        # No built-in list. These come from the network config service during
        # install, and from "Update network settings" in the tray after that.
        # The old default pointed at 127.0.0.1, which answers on a developer's
        # machine and nowhere else -- a user whose list went missing got
        # "cannot reach discovery" with no hint that the addresses were never
        # real.
        "DISCOVERY_URLS": [],
        # Yours, and never written by the app: "Update network settings"
        # replaces discovery_urls above, so anything typed there would be
        # lost. These are asked first, and anyone will be able to run a
        # directory server. Set use_only_my_discovery_urls to ignore the
        # network's list entirely.
        "MY_DISCOVERY_URLS": [],
        "USE_ONLY_MY_DISCOVERY_URLS": False,
        "DISCOVERY_TIMEOUT_SECONDS": 2,
        "DISCOVERY_VERIFY_ENDPOINT_HASH": True,
        "DISCOVERY_REQUIRE_ENDPOINT_HASH": True,
        "DISCOVERY_ENDPOINT_CACHE_SECONDS": 30,
        "REQUEST_OUTPUT_DIR": "pid_records",
        "SU_TO_WEI_RATE": "1000000000000",
        "FILETRUST_FIXED_GAS_PRICE_WEI": "1000000",
        "TRANSACTION_LOG_PATH": str(BASE_DIR / "log" / "req_transactions.jsonl"),
        "PRE_PARTIAL_WAIT_MAX_ATTEMPTS": 24,
        "PRE_PARTIAL_WAIT_DELAY_SEC": 2,
        "MAX_PARALLEL_PIECE_DOWNLOADS": 4,
    }
    aliases = {
        "rpc_url": "RPC_URL",
        "rpc_timeout_seconds": "RPC_TIMEOUT_SECONDS",
        "rpc_read_attempts": "RPC_READ_ATTEMPTS",
        "rpc_retry_initial_seconds": "RPC_RETRY_INITIAL_SECONDS",
        "rpc_retry_max_seconds": "RPC_RETRY_MAX_SECONDS",
        "guardian_registry_address": "GUARDIAN_REGISTRY_ADDRESS",
        "vault_keeper_registry_address": "VAULT_KEEPER_REGISTRY_ADDRESS",
        "acl_address": "ACL_ADDRESS",
        "dv_address": "DV_ADDRESS",
        "dkg_address": "DKG_ADDRESS",
        "telg_address": "TELG_ADDRESS",
        "telg_v2_address": "TELG_V2_ADDRESS",
        "zkdkg_coordinator_v2_address": "ZKDKG_COORDINATOR_V2_ADDRESS",
        "reward_manager_address": "REWARD_MANAGER_ADDRESS",
        "guardian_registry_json": "GUARDIAN_REGISTRY_JSON",
        "vault_keeper_registry_json": "VAULT_KEEPER_REGISTRY_JSON",
        "acl_json": "ACL_JSON",
        "dv_json": "DV_JSON",
        "dkg_json": "DKG_JSON",
        "telg_json": "TELG_JSON",
        "telg_v2_json": "TELG_V2_JSON",
        "zkdkg_coordinator_v2_json": "ZKDKG_COORDINATOR_V2_JSON",
        "reward_manager_json": "REWARD_MANAGER_JSON",
        "file_registration_address": "FILE_REGISTRATION_ADDRESS",
        "file_registration_json": "FILE_REGISTRATION_JSON",
        # Without these two the transaction log asked for the upper-case names
        # above, the loader stored the values under their lower-case spelling,
        # and the lookup silently returned "" for both contracts.
        "vk_escrow_address": "VK_ESCROW_ADDRESS",
        "storage_receipt_dispute_address": "STORAGE_RECEIPT_DISPUTE_ADDRESS",
        "req_private_key": "REQ_PRIVATE_KEY",
        "network_config_url": "NETWORK_CONFIG_URL",
        "vaultmesh_cmd": "VAULTMESH_CMD",
        "discovery_urls": "DISCOVERY_URLS",
        "my_discovery_urls": "MY_DISCOVERY_URLS",
        "use_only_my_discovery_urls": "USE_ONLY_MY_DISCOVERY_URLS",
        "discovery_timeout_seconds": "DISCOVERY_TIMEOUT_SECONDS",
        "discovery_verify_endpoint_hash": "DISCOVERY_VERIFY_ENDPOINT_HASH",
        "discovery_require_endpoint_hash": "DISCOVERY_REQUIRE_ENDPOINT_HASH",
        "discovery_endpoint_cache_seconds": "DISCOVERY_ENDPOINT_CACHE_SECONDS",
        "request_output_dir": "REQUEST_OUTPUT_DIR",
        "su_to_wei_rate": "SU_TO_WEI_RATE",
        "filetrust_fixed_gas_price_wei": "FILETRUST_FIXED_GAS_PRICE_WEI",
        "transaction_log_path": "TRANSACTION_LOG_PATH",
        "pre_partial_wait_max_attempts": "PRE_PARTIAL_WAIT_MAX_ATTEMPTS",
        "pre_partial_wait_delay_sec": "PRE_PARTIAL_WAIT_DELAY_SEC",
        "max_parallel_piece_downloads": "MAX_PARALLEL_PIECE_DOWNLOADS",
    }

    raw = {}
    if config_path.is_file():
        raw = json.loads(config_path.read_text(encoding="utf-8"))

    values = dict(defaults)
    for key, value in raw.items():
        canonical = aliases.get(str(key), str(key))
        values[canonical] = value

    for key in list(values):
        v = values[key]
        if v and (key.endswith("_JSON") or key in {"VAULTMESH_CMD", "REQUEST_OUTPUT_DIR"}):
            values[key] = _resolve_config_path(v, BASE_DIR)
    values["TRANSACTION_LOG_PATH"] = str(Path(values["TRANSACTION_LOG_PATH"]).expanduser())
    if not Path(values["TRANSACTION_LOG_PATH"]).is_absolute():
        values["TRANSACTION_LOG_PATH"] = str((BASE_DIR / values["TRANSACTION_LOG_PATH"]).resolve())

    values["CONFIG_PATH"] = str(config_path)
    return SimpleNamespace(**values)


config = _load_req_config()

KEYVAULT_PATH = KEYVAULT.vault_path(BASE_DIR)
KEYVAULT_IN_USE = KEYVAULT.exists(KEYVAULT_PATH)

# The requester's wallet key is the one secret whose loss cannot be recovered
# from by any check downstream: whoever reads it simply becomes this requester.
# Checked at startup because a file that is never rewritten is never otherwise
# looked at. With a vault in use the key is not in config.json at all, so it is
# the vault's permissions that matter -- and there the warning is milder,
# because the file is encrypted even when a stranger can read it.
if KEYVAULT_IN_USE:
    # Ask for 0600 and say nothing. On a disk that cannot keep permissions the
    # file stays readable, and that was printed at every start -- a line about
    # a file nobody can read the key out of, in front of a user who can do
    # nothing about their filesystem. The README says it once instead.
    restrict_secret_file(KEYVAULT_PATH)
    _key_private, _key_reason = True, ""
elif str(getattr(config, "REQ_PRIVATE_KEY", "") or "").strip():
    _key_private, _key_reason = restrict_secret_file(
        getattr(config, "CONFIG_PATH", DEFAULT_CONFIG_PATH)
    )
else:
    # No vault and no key: nothing secret is on disk yet, so there is nothing
    # to warn about. install.sh is what tells the user they have no account.
    _key_private, _key_reason = True, ""
if not _key_private:
    # A readable *encrypted* file is a note, not a warning: it can be copied
    # and attacked offline, which is worth saying, but nobody reads the key out
    # of it. Keeping the louder word for the case where the key really is in
    # the clear is the only way either line stays meaningful.
    print(f"[{'NOTE' if KEYVAULT_IN_USE else 'WARN'}] {_key_reason}")
w3 = new_web3(config)
TX.install_contract_call_logger(sys.modules[__name__])

# ── This account ──────────────────────────────────────────────────────────────
# The private key decides the address, so the address is derived rather than
# stored. It used to sit beside the key as `req_address`, a second copy of
# something the key already fixes; get_requester_checksum() already preferred
# the key and only read the stored value when the key failed, so the stored one
# existed to be out of date.
#
# A missing key is not an error here: install.sh offers to generate an account
# and a user may decline, and this module is imported before anything can say
# so. REQ.py checks ACCOUNT_READY and explains what to do.
REQ_ACCOUNT = None
REQ_ADDRESS = ""
ACCOUNT_READY = False
ACCOUNT_PROBLEM = "no account yet"
#
# Where the key comes from, in order: the vault REQ.py already unlocked, a
# vault plus FILETRUST_KEY_PASSWORD for scripts that import this module
# directly, then config.json for an install that has not chosen a password.
try:
    _raw_key = KEYVAULT.unlocked_key()
    if not _raw_key and KEYVAULT_IN_USE:
        try:
            _raw_key = KEYVAULT.key_without_prompt(KEYVAULT_PATH)
        except KEYVAULT.VaultError as _vault_exc:
            _raw_key = ""
            ACCOUNT_PROBLEM = f"the key vault could not be opened: {_vault_exc}"
    if not _raw_key:
        _raw_key = str(getattr(config, "REQ_PRIVATE_KEY", "") or "").strip()
    if not _raw_key and KEYVAULT_IN_USE and ACCOUNT_PROBLEM == "no account yet":
        ACCOUNT_PROBLEM = (
            "the account key is protected. Start the app with REQ.py to be "
            "asked for the password, or set "
            f"{KEYVAULT.PASSWORD_ENV} for a command-line run"
        )
    if not _raw_key:
        if ACCOUNT_PROBLEM == "no account yet":
            ACCOUNT_PROBLEM = (
                "config.json has no req_private_key, so this app has no account yet"
            )
    else:
        REQ_ACCOUNT = w3.eth.account.from_key(_raw_key)
        REQ_ADDRESS = w3.to_checksum_address(REQ_ACCOUNT.address)
        ACCOUNT_READY = True
        ACCOUNT_PROBLEM = ""
except (ValueError, TypeError) as exc:
    ACCOUNT_PROBLEM = f"the req_private_key in config.json cannot be used: {exc}"

_gas_price_wei: int | None = None


def gas_price_wei() -> int:
    """The price per unit of gas to put in the transactions this app signs.

    Gas price is a bid: it is a field inside a signed transaction, so the app
    has to choose a number before the chain ever sees it. Every call site used
    to read the number straight out of config.json, which means a node that
    raises its minimum rejects everything this app sends until somebody edits a
    file -- and nothing in the app would say why.

    So ask the node what it wants, once, and keep the configured number as the
    answer for when it cannot be reached. Deliberately not capped against the
    configured value: refusing a higher price the node has just asked for would
    recreate exactly the rejection this avoids. The chosen value is printed so
    an unexpected one is visible rather than merely paid.
    """
    global _gas_price_wei
    if _gas_price_wei is not None:
        return _gas_price_wei

    configured = 1_000_000
    try:
        configured = int(getattr(config, "FILETRUST_FIXED_GAS_PRICE_WEI", "1000000"))
    except (TypeError, ValueError):
        pass

    chosen, source = configured, "config.json"
    try:
        asked = int(w3.eth.gas_price)
        # A node that answers 0 is not telling us a price; some development
        # chains do that, and signing with 0 gets the transaction dropped.
        if asked > 0:
            chosen, source = asked, "the node"
    except Exception as exc:
        print(f"[gas] the node did not give a price ({exc}); using config.json")

    # Two threads racing here both ask the node and store the same answer.
    _gas_price_wei = chosen
    if source != "config.json" and chosen != configured:
        print(f"[gas] using {chosen} wei per gas from {source} "
              f"(config.json says {configured})")
    return chosen

REQUEST_OUTPUT_DIR = Path(config.REQUEST_OUTPUT_DIR)
for path in (DATA_DIR, UNZIPPED_DATA_DIR, PIECES_DIR, LOG_DIR, REQUEST_OUTPUT_DIR):
    path.mkdir(parents=True, exist_ok=True)


def load_contract(address: str, json_path: str):
    artifact = json.loads(Path(json_path).read_text(encoding="utf-8"))
    return w3.eth.contract(
        address=Web3.to_checksum_address(address),
        abi=artifact["abi"],
    )


def load_contract_from_config(w3_instance, address: str, json_path: str):
    """Load a contract and verify code exists at the address."""
    artifact = json.loads(Path(json_path).read_text(encoding="utf-8"))
    checksum = Web3.to_checksum_address(address)
    code = w3_instance.eth.get_code(checksum)
    TX.log_eth_call(
        sys.modules[__name__],
        contract_name="eth",
        function_name="getCode",
        contract_address=checksum,
        status="success",
        code_size=len(code),
        artifact_path=json_path,
    )
    if len(code) == 0:
        raise RuntimeError(
            f"No contract code at {checksum}. Check the configured address for artifact {json_path}."
        )
    return w3_instance.eth.contract(address=checksum, abi=artifact["abi"])


def load_acl_contract():
    return load_contract(config.ACL_ADDRESS, config.ACL_JSON)


def load_dv_contract():
    return load_contract(config.DV_ADDRESS, config.DV_JSON)


vault_keeper_registry = None
try:
    if getattr(config, "VAULT_KEEPER_REGISTRY_ADDRESS", "") and getattr(config, "VAULT_KEEPER_REGISTRY_JSON", ""):
        vault_keeper_registry = load_contract(config.VAULT_KEEPER_REGISTRY_ADDRESS, config.VAULT_KEEPER_REGISTRY_JSON)
except Exception:
    vault_keeper_registry = None

