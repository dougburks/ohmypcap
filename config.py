"""Application-wide configuration constants for OhMyPCAP.

All tunable numeric values (size limits, timeouts, thresholds) are centralized
here so they can be adjusted for different deployments without scattering edits
across the codebase.
"""

# Size limits
MAX_UPLOAD_SIZE = 1000 * 1024 * 1024       # 1000 MB
MAX_EVE_SIZE = 1000 * 1024 * 1024          # 1000 MB
MAX_REQUEST_BODY_SIZE = 1024 * 1024        # 1 MB
MAX_TRANSCRIPT_SIZE = 100000               # characters

# Query / display limits
MAX_QUERY_LIMIT = 5000
MAX_TRANSCRIPT_LINES = 500
MAX_HEXDUMP_PACKETS = 500

# Timeouts (seconds)
STREAM_TIMEOUT_SECONDS = 60
URL_DOWNLOAD_TIMEOUT = 30
SQLITE_TIMEOUT_SECONDS = 30
FILE_COMMAND_TIMEOUT = 10
YARA_DOWNLOAD_TIMEOUT = 60
YARA_CLONE_TIMEOUT = 120
YARA_SCAN_TIMEOUT = 300
SURICATA_UPDATE_TIMEOUT = 60

# Thresholds
STALE_THRESHOLD_SECONDS = 600              # 10 minutes
