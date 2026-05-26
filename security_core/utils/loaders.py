"""
security_core/utils/loaders.py

File-based config loaders.
All return safe defaults so the detector runs even with missing files.
"""
from typing import Optional


def load_allowlist(path: str) -> set:
    allowlist = set()
    try:
        with open(path, "r") as f:
            for line in f:
                ip = line.strip()
                if ip and not ip.startswith("#"):
                    allowlist.add(ip)
    except FileNotFoundError:
        pass
    return allowlist


def _load_env_key(path: str, key_name: str) -> Optional[str]:
    """Read KEY=VALUE lines from a flat env file."""
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith(key_name):
                    parts = line.split("=", 1)
                    if len(parts) == 2:
                        return parts[1].strip()
    except FileNotFoundError:
        pass
    return None


def load_api_key(path: str) -> Optional[str]:
    return _load_env_key(path, "ABUSEIPDB_API_KEY")


def load_webhook_url(path: str) -> Optional[str]:
    return _load_env_key(path, "WEBHOOK_URL")
