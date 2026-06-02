"""
security_core/detectors/ssh_bruteforce.py

SSH brute-force detector.
Reads auth.log, applies the full pipeline:
  parse -> rate-limit check -> enrich -> score -> respond -> store -> notify
"""
import datetime
import json
import sys
from collections import defaultdict
from typing import Optional

from security_core import config
from security_core.engine.rate_limiter import build_rate_limiter
from security_core.engine.scoring import score
from security_core.enrichment.abuseipdb import AbuseIPDBEnricher
from security_core.response.actions import dispatch
from security_core.response.notify import send_webhook
from security_core.store.events import EventStore
from security_core.utils.loaders import load_allowlist, load_api_key, load_webhook_url

DETECTOR_NAME = "ssh_bruteforce"
MITRE_TECHNIQUE = "T1110.001"


def _parse_log_time(line: str) -> Optional[datetime.datetime]:
    parts = line.split()
    if len(parts) < 3:
        return None
    try:
        ts = " ".join(parts[0:3])
        year = datetime.datetime.now().year
        return datetime.datetime.strptime(f"{ts} {year}", "%b %d %H:%M:%S %Y")
    except ValueError:
        return None


def _extract_ip(line: str) -> Optional[str]:
    parts = line.split()
    try:
        from_idx = parts.index("from")
        return parts[from_idx + 1]
    except (ValueError, IndexError):
        return parts[-4] if len(parts) >= 4 else None


def _parse_failed_attempts(
    log_file: str,
    window_start: datetime.datetime,
    allowlist: set,
) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    try:
        with open(log_file, "r") as f:
            for line in f:
                if "Failed password" not in line:
                    continue
                ts = _parse_log_time(line)
                if ts is None or ts < window_start:
                    continue
                ip = _extract_ip(line)
                if ip and ip not in allowlist:
                    counts[ip] += 1
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {log_file}", file=sys.stderr)
    return counts


def run_detector() -> dict:
    now = datetime.datetime.now()
    window_start = now - datetime.timedelta(minutes=config.BRUTE_FORCE_WINDOW_MIN)

    allowlist = load_allowlist(config.ALLOWLIST_FILE)
    api_key = load_api_key(config.API_KEY_FILE)
    webhook_url = load_webhook_url(config.WEBHOOK_ENV_FILE)

    enricher = AbuseIPDBEnricher(api_key)
    rate_limiter = build_rate_limiter(
        strategy=config.RATE_LIMIT_STRATEGY,
        max_hits=config.RATE_LIMIT_MAX_HITS,
        window_sec=config.RATE_LIMIT_WINDOW_SEC,
    )
    store = EventStore(config.EVENTS_DB_FILE)

    failed = _parse_failed_attempts(config.LOG_FILE, window_start, allowlist)
    alerts = []

    for ip, attempt_count in failed.items():
        if attempt_count < config.BRUTE_FORCE_THRESHOLD:
            continue

        rl_result = rate_limiter.check(ip)
        intel = enricher.enrich(ip)

        scored = score(
            failed_attempts=attempt_count,
            abuse_confidence_score=intel.abuse_confidence_score,
        )

        alert = {
            "detector": DETECTOR_NAME,
            "mitre": MITRE_TECHNIQUE,
            "vector": "ssh",
            "event_type": "ssh_bruteforce",
            "ip": ip,
            "source_ip": ip,
            "failed_attempts": attempt_count,
            "abuse_confidence_score": intel.abuse_confidence_score,
            "country": intel.country,
            "is_whitelisted": intel.is_whitelisted,
            "total_reports": intel.total_reports,
            "last_reported_at": intel.last_reported_at,
            "risk_score": scored.risk_score,
            "severity": scored.severity,
            "action": scored.action,
            "rate_limited": not rl_result.allowed,
            "rate_limit_hits": rl_result.current_hits,
            "timestamp": now.isoformat(),
        }

        response = dispatch(ip, scored.action, scored.severity)
        if response:
            alert["response"] = response.to_dict()
            print(f"[RESPONSE] {response.message}")

        stored_event = store.append("ssh_bruteforce", alert)

        wh_result = send_webhook(stored_event, webhook_url)
        if not wh_result.success and wh_result.error != "no_webhook_url":
            print(f"[WARN] Webhook failed for {ip}: {wh_result.error}", file=sys.stderr)

        alerts.append(stored_event)

    return {
        "detector": DETECTOR_NAME,
        "mitre": MITRE_TECHNIQUE,
        "window_minutes": config.BRUTE_FORCE_WINDOW_MIN,
        "generated_at": now.isoformat(),
        "dry_run": config.DRY_RUN,
        "alert_count": len(alerts),
        "rate_limiter": rate_limiter.stats(),
        "alerts": alerts,
    }


def detect() -> list[dict]:
    """Detector registry contract wrapper."""
    return run_detector().get("alerts", [])


if __name__ == "__main__":
    result = run_detector()
    print(json.dumps(result, indent=2))
