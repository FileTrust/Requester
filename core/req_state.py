# req_state.py - mutable state shared by requester migration modules.
# Import this module as S and mutate attributes on S; avoid "from req_state import *".

root = None
status_var = None
status_label = None
result_text = None
log_window = None       # Network Results, opened from the tray
about_window = None
files_window = None     # Files, opened from the tray
progress_box = None     # the frame holding bar + caption
progress_bar = None
progress_var = None

# Trusted Data Owners tab
trusted_table = None
trusted_name_entry = None
trusted_address_entry = None
files_listbox = None   # bootstrap UI (Listbox)
files_table = None     # ctk UI (Treeview with name + size)
files_table_paths = {}
policies_table = None

selected_file_var = None
selected_datetime_var = None

policy_rows = []
selected_policy_row_id = None
selected_policy_file_id = None
selected_policy_owner = None
selected_data_tag = ""
selected_date_str = ""
policy_sort_column = "latestBatchId"
policy_sort_reverse = True
policy_table_rendering = False

requester_keys = None
requester_key_file_id = None
policy_auto_refresh_interval_ms = 10_000
policy_auto_refresh_after_id = None
policy_refresh_in_progress = False

tree_ind_plus  = None   # PIL PhotoImage for collapsed group row
tree_ind_minus = None   # PIL PhotoImage for expanded  group row

# System tray integration
tray_icon = None
tray_thread = None
tray_available: bool = False

# Active download session
current_request_id = None
current_n = None
current_t = None
current_file_ext = None
last_reconstructed_path = None

# Constants shared across download modules
META_PIECE_INDEX = 65535
CHUNK_SIZE = 4 * 1024 * 1024       # 4 MB — AES decrypt read chunk
PIECE_ROOT_BLOCK_SIZE = 64 * 1024  # must match VaultMesh pieceBlockSize
KEY_FILE = "requester_keys.json"

_LOG_LAST_TIME = {}

POLICY_TABLE_COLUMNS = (
    ("rowNumber", "#", 48, "center"),
    ("owner", "Owner Address", 310, "center"),
    ("fileId", "Policy ID", 430, "center"),
    ("access", "Guardians", 86, "center"),
    ("ida", "VaultKeepers", 104, "center"),
    ("latestDataId", "Data ID", 130, "center"),
    ("latestDate", "Data Date", 94, "center"),
    ("sharedDateTime", "Shared At", 156, "center"),
    ("fileExt", "Type", 70, "center"),
    ("latestBatchId", "Batch", 70, "center"),
    ("keyEpoch", "Epoch", 68, "center"),
)

account_balance_var = None     # StringVar for the header balance label
