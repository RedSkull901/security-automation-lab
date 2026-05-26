"""
security_core/config.py
Central configuration — override via environment variables or config files.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).parent

# ── Paths ──────────────────────────────────────────────
LOG_FILE            = os.getenv("SAL_LOG_FILE",        "/var/log/auth.log")
ALLOWLIST_FILE      = os.getenv("SAL_ALLOWLIST_FILE",  str(BASE_DIR.parent / "config/allowlist_ips.txt"))
API_KEY_FILE        = os.getenv("SAL_API_KEY_FILE",    str(BASE_DIR.parent / "config/api_keys.env"))
WEBHOOK_ENV_FILE    = os.getenv("SAL_WEBHOOK_FILE",    str(BASE_DIR.parent / "config/webhook.env"))
EVENTS_DB_FILE      = os.getenv("SAL_EVENTS_DB",       str(BASE_DIR.parent / "data/events.jsonl"))

# ── Detection ──────────────────────────────────────────
BRUTE_FORCE_THRESHOLD   = int(os.getenv("SAL_THRESHOLD",       "5"))
BRUTE_FORCE_WINDOW_MIN  = int(os.getenv("SAL_WINDOW_MIN",      "10"))

# ── Rate limiter ───────────────────────────────────────
# Strategy: "sliding_window" | "token_bucket"
RATE_LIMIT_STRATEGY     = os.getenv("SAL_RL_STRATEGY",         "sliding_window")
RATE_LIMIT_MAX_HITS     = int(os.getenv("SAL_RL_MAX_HITS",     "100"))   # per window
RATE_LIMIT_WINDOW_SEC   = int(os.getenv("SAL_RL_WINDOW_SEC",   "60"))    # seconds

# ── Response ───────────────────────────────────────────
BLOCK_DURATION_MIN      = int(os.getenv("SAL_BLOCK_DURATION",  "30"))
DRY_RUN                 = os.getenv("SAL_DRY_RUN", "false").lower() == "true"

# ── Enrichment ─────────────────────────────────────────
ABUSEIPDB_URL           = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_MAX_AGE_DAYS  = 90

# ── Risk scoring ───────────────────────────────────────
# risk = (failed_attempts * ATTEMPT_WEIGHT) + abuse_score
ATTEMPT_WEIGHT          = 10
HIGH_RISK_THRESHOLD     = 71
MEDIUM_RISK_THRESHOLD   = 31
