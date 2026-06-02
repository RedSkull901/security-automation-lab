"""
Detector: port scan from local Linux firewall logs.

Parses UFW, kern.log, or syslog entries for one source IP touching many ports.
Maps to MITRE ATT&CK T1046: Network Service Discovery.
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

CURSOR_FILE = Path("/tmp/sal_port_scan_cursor.txt")
DETECTOR_NAME = "port_scan"
MITRE_TECHNIQUE = "T1046"

LOG_CANDIDATES = [
    Path("/var/log/ufw.log"),
    Path("/var/log/kern.log"),
    Path("/var/log/syslog"),
]

UFW_BLOCK_RE = re.compile(r"\[UFW BLOCK\].*?SRC=(?P<src>\S+).*?DPT=(?P<dpt>\d+)")
IPTABLES_DROP_RE = re.compile(r"SRC=(?P<src>\S+).*?DPT=(?P<dpt>\d+)")

PORT_SCAN_THRESHOLD = int(getattr(config, "PORT_SCAN_THRESHOLD", 5))


def _get_log_path() -> Path | None:
    for path in LOG_CANDIDATES:
        if path.exists():
            return path
    return None


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


def _should_enrich_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def detect() -> list[dict]:
    """
    Process new firewall log lines since the last cursor position.

    Contract:
      - registry calls only this function
      - returns emitted event dictionaries
      - persisted events include top-level detector and mitre fields
    """
    log_path = _get_log_path()
    if log_path is None:
        print("[port_scan] no firewall log found", file=sys.stderr)
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

    ports_by_ip: dict[str, set[int]] = defaultdict(set)
    evidence_by_ip: dict[str, list[str]] = defaultdict(list)

    for line in lines:
        match = UFW_BLOCK_RE.search(line) or IPTABLES_DROP_RE.search(line)
        if not match:
            continue

        source_ip = match.group("src")
        destination_port = int(match.group("dpt"))

        if source_ip in allowlist:
            continue

        ports_by_ip[source_ip].add(destination_port)
        evidence_by_ip[source_ip].append(line.strip())

    for source_ip, ports in ports_by_ip.items():
        port_count = len(ports)
        if port_count < PORT_SCAN_THRESHOLD:
            continue

        intel = enricher.enrich(source_ip) if _should_enrich_ip(source_ip) else None
        scored = score(
            failed_attempts=port_count,
            abuse_confidence_score=intel.abuse_confidence_score if intel else 0,
        )

        event = {
            "detector": DETECTOR_NAME,
            "mitre": MITRE_TECHNIQUE,
            "vector": "port_scan",
            "event_type": "multi_port_connection_attempt",
            "source_ip": source_ip,
            "ip": source_ip,
            "ports_scanned": sorted(ports),
            "port_count": port_count,
            "failed_attempts": port_count,
            "abuse_confidence_score": intel.abuse_confidence_score if intel else 0,
            "country": intel.country if intel else None,
            "is_whitelisted": intel.is_whitelisted if intel else None,
            "total_reports": intel.total_reports if intel else 0,
            "last_reported_at": intel.last_reported_at if intel else None,
            "risk_score": scored.risk_score,
            "severity": scored.severity,
            "action": "alert_only",
            "sample_line": evidence_by_ip[source_ip][-1],
            "evidence": evidence_by_ip[source_ip][-5:],
            "log_source": str(log_path),
        }

        stored_event = store.append(event["event_type"], event)
        wh_result = send_webhook(stored_event, webhook_url)
        if not wh_result.success and wh_result.error != "no_webhook_url":
            print(f"[port_scan] webhook failed for {source_ip}: {wh_result.error}", file=sys.stderr)

        if not config.DRY_RUN and event["action"] == "block_temp":
            response = block_ip(source_ip)
            stored_event["response"] = response.to_dict()

        emitted.append(stored_event)

    _write_cursor(new_cursor)
    return emitted


if __name__ == "__main__":
    events = detect()
    print(f"[port_scan] {len(events)} event(s) emitted")
