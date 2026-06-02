"""
Detector: sudo authentication failure brute force.

Parses local Linux auth logs for repeated sudo failures by user.
Maps to MITRE ATT&CK T1548.003: Sudo and Sudo Caching.
"""

from __future__ import annotations

import ipaddress
import re
import sys
from collections import defaultdict
from pathlib import Path

from security_core import config
from security_core.engine.scoring import score
from security_core.enrichment.abuseipdb import AbuseIPDBEnricher
from security_core.response.actions import block_ip
from security_core.response.notify import send_webhook
from security_core.store.events import EventStore
from security_core.utils.loaders import load_allowlist, load_api_key, load_webhook_url

CURSOR_FILE = Path("/tmp/sal_sudo_bruteforce_cursor.txt")
DETECTOR_NAME = "sudo_bruteforce"
MITRE_TECHNIQUE = "T1548.003"

SUDO_FAILURE_RE = re.compile(
    r"sudo\[\d+\]:\s+(?P<user>\S+)\s*:.*?"
    r"(?P<reason>incorrect password attempts|authentication failure)",
    re.IGNORECASE,
)

IP_RE = re.compile(r"\b(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b")


def _read_cursor() -> int:
    try:
        return int(CURSOR_FILE.read_text().strip())
    except (FileNotFoundError, ValueError):
        return 0


def _write_cursor(position: int) -> None:
    CURSOR_FILE.write_text(str(position))


def _safe_seek_position(path: Path, cursor: int) -> int:
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return 0
    return cursor if cursor <= size else 0


def _extract_source_ip(line: str) -> str:
    match = IP_RE.search(line)
    return match.group("ip") if match else "127.0.0.1"


def _should_enrich_ip(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return parsed.is_global


def detect() -> list[dict]:
    """
    Process new auth.log lines since the last cursor position.

    Contract:
      - registry calls only this function
      - returns emitted event dictionaries
      - persisted events include top-level detector and mitre fields
    """
    log_path = Path(config.LOG_FILE)
    if not log_path.exists():
        print(f"[sudo_bruteforce] log file not found: {log_path}", file=sys.stderr)
        return []

    allowlist = load_allowlist(config.ALLOWLIST_FILE)
    api_key = load_api_key(config.API_KEY_FILE)
    webhook_url = load_webhook_url(config.WEBHOOK_ENV_FILE)

    enricher = AbuseIPDBEnricher(api_key)
    store = EventStore(config.EVENTS_DB_FILE)

    cursor = _safe_seek_position(log_path, _read_cursor())
    emitted: list[dict] = []

    with log_path.open("r", encoding="utf-8", errors="replace") as handle:
        handle.seek(cursor)
        lines = handle.readlines()
        new_cursor = handle.tell()

    failures_by_user: dict[str, list[str]] = defaultdict(list)
    source_ip_by_user: dict[str, str] = {}

    for line in lines:
        match = SUDO_FAILURE_RE.search(line)
        if not match:
            continue

        user = match.group("user").strip()
        source_ip = _extract_source_ip(line)

        # Do not suppress local sudo failures just because localhost is allowlisted.
        # For sudo, the username is the primary entity and source_ip is usually 127.0.0.1.
        if source_ip in allowlist and source_ip != "127.0.0.1":
            continue

        failures_by_user[user].append(line.strip())
        source_ip_by_user[user] = source_ip

    for user, failures in failures_by_user.items():
        failure_count = len(failures)
        if failure_count < config.BRUTE_FORCE_THRESHOLD:
            continue

        # Note: source_ip is taken from the last matching line per user.
        # sudo failures are typically local; IP is usually 127.0.0.1.
        source_ip = source_ip_by_user.get(user, "127.0.0.1")
        intel = enricher.enrich(source_ip) if _should_enrich_ip(source_ip) else None

        scored = score(
            failed_attempts=failure_count,
            abuse_confidence_score=intel.abuse_confidence_score if intel else 0,
        )

        event = {
            "detector": DETECTOR_NAME,
            "mitre": MITRE_TECHNIQUE,
            "vector": "sudo",
            "event_type": "sudo_auth_failure_burst",
            "user": user,
            "source_ip": source_ip,
            "ip": source_ip,
            "failed_attempts": failure_count,
            "failure_count": failure_count,
            "abuse_confidence_score": intel.abuse_confidence_score if intel else 0,
            "country": intel.country if intel else None,
            "is_whitelisted": intel.is_whitelisted if intel else None,
            "total_reports": intel.total_reports if intel else 0,
            "last_reported_at": intel.last_reported_at if intel else None,
            "risk_score": scored.risk_score,
            "severity": scored.severity,
            "action": "alert_only",
            "sample_line": failures[-1],
            "evidence": failures[-5:],
        }

        stored_event = store.append(event["event_type"], event)
        wh_result = send_webhook(stored_event, webhook_url)
        if not wh_result.success and wh_result.error != "no_webhook_url":
            print(f"[sudo_bruteforce] webhook failed for {user}: {wh_result.error}", file=sys.stderr)

        if not config.DRY_RUN and event["action"] == "block_temp":
            response = block_ip(source_ip)
            stored_event["response"] = response.to_dict()

        emitted.append(stored_event)

    _write_cursor(new_cursor)
    return emitted


if __name__ == "__main__":
    events = detect()
    print(f"[sudo_bruteforce] {len(events)} event(s) emitted")
