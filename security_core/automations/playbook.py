"""
security_core/automations/playbook.py  (updated for Day 18)

SOAR-style playbook: poll → triage → notify → respond.

Modes:
  python -m security_core.automations.playbook            # run once
  python -m security_core.automations.playbook --watch    # poll every N seconds
  python -m security_core.automations.playbook --dry-run  # no real calls
  python -m security_core.automations.playbook --digest   # send daily digest
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from security_core import config
from security_core.automations.discord_notify import send_alert, send_digest
from security_core.automations.triage import TriageEngine
from security_core.store.events import EventStore


API_BASE_URL     = os.getenv("SAL_API_URL",      "http://localhost:8000")
POLL_INTERVAL    = int(os.getenv("SAL_POLL_SEC", "60"))
CURSOR_FILE      = os.getenv("SAL_CURSOR_FILE",  "data/playbook_cursor.txt")
ALERT_SEVERITIES = {"high", "medium"}
BLOCK_SEVERITIES = {"high"}
TRIAGE_SEVERITIES = {"high", "medium"}   # only triage these — skip low


def read_cursor() -> str:
    try:
        return Path(CURSOR_FILE).read_text().strip()
    except FileNotFoundError:
        return "1970-01-01T00:00:00+00:00"


def write_cursor(timestamp: str) -> None:
    Path(CURSOR_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(CURSOR_FILE).write_text(timestamp)


def call_api_block(ip: str, duration_min: int = config.BLOCK_DURATION_MIN) -> dict:
    try:
        resp = requests.post(
            f"{API_BASE_URL}/block/{ip}",
            json={"duration_min": duration_min},
            timeout=5,
        )
        return {"success": resp.ok, "status_code": resp.status_code, "body": resp.json()}
    except requests.RequestException as exc:
        return {"success": False, "error": str(exc)}


def fetch_api_stats() -> dict:
    try:
        resp = requests.get(f"{API_BASE_URL}/stats", timeout=5)
        return resp.json() if resp.ok else {}
    except requests.RequestException:
        return {}


def run_once(store: EventStore, triage_engine: TriageEngine,
             dry_run: bool = False) -> dict:
    cursor     = read_cursor()
    new_events = store.read_since(cursor)

    detections = [
        e for e in new_events
        if e.get("type") == "ssh_bruteforce"
        and e.get("timestamp", "") > cursor
    ]

    results = {
        "run_at":           datetime.now(timezone.utc).isoformat(),
        "cursor_was":       cursor,
        "new_events_found": len(detections),
        "notified":         [],
        "blocked":          [],
        "triaged":          [],
        "errors":           [],
    }

    if not detections:
        print(f"[PLAYBOOK] No new events since {cursor}")
        return results

    latest_ts = cursor

    for event in detections:
        ip       = event.get("ip")
        severity = event.get("severity", "low")
        ts       = event.get("timestamp", "")

        if ts > latest_ts:
            latest_ts = ts

        # ── AI triage ──
        triage_summary = None
        if severity in TRIAGE_SEVERITIES and triage_engine.is_available():
            print(f"[PLAYBOOK] Triaging {ip} ({severity})...")
            if not dry_run:
                triage_result = triage_engine.analyze(event)
                if triage_result.success:
                    triage_summary = triage_result.summary
                    results["triaged"].append({
                        "ip":           ip,
                        "duration_sec": triage_result.duration_sec,
                    })
                    print(f"[TRIAGE] {ip} — {triage_result.duration_sec:.0f}s")
                else:
                    print(f"[TRIAGE] Failed for {ip}: {triage_result.error}")
            else:
                print(f"  [DRY RUN] Would triage {ip}")
                triage_summary = "[DRY RUN] AI triage skipped"

        # ── Notify Discord ──
        if severity in ALERT_SEVERITIES:
            print(f"[PLAYBOOK] Notifying Discord: {ip} ({severity})")
            if not dry_run:
                notify_result = send_alert(event, triage_summary=triage_summary)
                if not notify_result["success"]:
                    results["errors"].append({"ip": ip, "step": "discord",
                                              "error": notify_result.get("error")})
                else:
                    results["notified"].append(ip)
            else:
                print(f"  [DRY RUN] Would send Discord alert for {ip}")
                results["notified"].append(f"{ip} (dry run)")

        # ── Auto-block ──
        if severity in BLOCK_SEVERITIES:
            print(f"[PLAYBOOK] Requesting API block: {ip}")
            if not dry_run:
                block_result = call_api_block(ip)
                if not block_result["success"]:
                    results["errors"].append({"ip": ip, "step": "api_block",
                                              "error": block_result.get("error")})
                else:
                    results["blocked"].append(ip)
            else:
                print(f"  [DRY RUN] Would call POST /block/{ip}")
                results["blocked"].append(f"{ip} (dry run)")

    write_cursor(latest_ts)
    results["cursor_now"] = latest_ts

    print(f"[PLAYBOOK] Done. Notified: {len(results['notified'])} | "
          f"Blocked: {len(results['blocked'])} | "
          f"Triaged: {len(results['triaged'])} | "
          f"Errors: {len(results['errors'])}")

    return results


def watch(store: EventStore, triage_engine: TriageEngine,
          dry_run: bool = False) -> None:
    print(f"[PLAYBOOK] Watching every {POLL_INTERVAL}s. Ctrl+C to stop.")
    while True:
        try:
            run_once(store, triage_engine, dry_run=dry_run)
        except Exception as exc:
            print(f"[PLAYBOOK] Error: {exc}", file=sys.stderr)
        time.sleep(POLL_INTERVAL)


def main():
    parser = argparse.ArgumentParser(description="Security Core automation playbook")
    parser.add_argument("--watch",   action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--digest",  action="store_true")
    args = parser.parse_args()

    store         = EventStore(config.EVENTS_DB_FILE)
    triage_engine = TriageEngine()
    dry_run       = args.dry_run or config.DRY_RUN

    if args.digest:
        stats  = fetch_api_stats()
        result = send_digest(stats)
        print(json.dumps(result, indent=2))
        return

    if args.watch:
        watch(store, triage_engine, dry_run=dry_run)
    else:
        result = run_once(store, triage_engine, dry_run=dry_run)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
