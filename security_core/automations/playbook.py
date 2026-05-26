"""
security_core/automations/playbook.py

SOAR-style playbook: poll → filter → notify → respond.

This is the Python equivalent of the n8n workflow.
Run it as a cron job or a long-running watcher.

Modes:
  python -m security_core.automations.playbook          # run once
  python -m security_core.automations.playbook --watch  # poll every N seconds

The playbook maintains a cursor (data/playbook_cursor.txt) — the timestamp
of the last event it processed. On each run it only acts on new events,
so alerts are never double-sent.
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
from security_core.store.events import EventStore


# ── Config ─────────────────────────────────────────────────────────────────────

API_BASE_URL    = os.getenv("SAL_API_URL",       "http://localhost:8000")
POLL_INTERVAL   = int(os.getenv("SAL_POLL_SEC",  "60"))    # seconds between polls
CURSOR_FILE     = os.getenv("SAL_CURSOR_FILE",   "data/playbook_cursor.txt")

# Which severities trigger a Discord alert
ALERT_SEVERITIES = {"high", "medium"}

# Which severities trigger an automatic API block call
BLOCK_SEVERITIES = {"high"}


# ── Cursor — "where did I leave off?" ─────────────────────────────────────────

def read_cursor() -> str:
    """Return the ISO timestamp of the last processed event, or epoch start."""
    try:
        return Path(CURSOR_FILE).read_text().strip()
    except FileNotFoundError:
        return "1970-01-01T00:00:00+00:00"


def write_cursor(timestamp: str) -> None:
    Path(CURSOR_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(CURSOR_FILE).write_text(timestamp)


# ── API calls ──────────────────────────────────────────────────────────────────

def call_api_block(ip: str, duration_min: int = config.BLOCK_DURATION_MIN) -> dict:
    """
    Tell the security-core API to block an IP.
    Requires the API to be running (docker compose up or uvicorn).
    """
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
    """Pull current stats from the API for digest messages."""
    try:
        resp = requests.get(f"{API_BASE_URL}/stats", timeout=5)
        return resp.json() if resp.ok else {}
    except requests.RequestException:
        return {}


# ── Core playbook logic ────────────────────────────────────────────────────────

def run_once(store: EventStore, dry_run: bool = False) -> dict:
    """
    One playbook execution:
    1. Read new events since cursor
    2. For each qualifying event → notify Discord
    3. For high severity → call API block
    4. Advance cursor to latest processed timestamp
    """
    cursor     = read_cursor()
    new_events = store.read_since(cursor)

    # Filter to detection events only (skip manual_block, manual_unblock)
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

        # Track latest timestamp seen
        if ts > latest_ts:
            latest_ts = ts

        # ── Notify Discord ──
        if severity in ALERT_SEVERITIES:
            print(f"[PLAYBOOK] Notifying Discord: {ip} ({severity})")
            if not dry_run:
                notify_result = send_alert(event)
                if not notify_result["success"]:
                    results["errors"].append({
                        "ip": ip, "step": "discord", "error": notify_result.get("error")
                    })
                else:
                    results["notified"].append(ip)
            else:
                print(f"  [DRY RUN] Would send Discord alert for {ip}")
                results["notified"].append(f"{ip} (dry run)")

        # ── Auto-block via API ──
        if severity in BLOCK_SEVERITIES:
            print(f"[PLAYBOOK] Requesting API block: {ip}")
            if not dry_run:
                block_result = call_api_block(ip)
                if not block_result["success"]:
                    results["errors"].append({
                        "ip": ip, "step": "api_block", "error": block_result.get("error")
                    })
                else:
                    results["blocked"].append(ip)
            else:
                print(f"  [DRY RUN] Would call POST /block/{ip}")
                results["blocked"].append(f"{ip} (dry run)")

    # Advance cursor
    write_cursor(latest_ts)
    results["cursor_now"] = latest_ts

    print(f"[PLAYBOOK] Done. Notified: {len(results['notified'])} | "
          f"Blocked: {len(results['blocked'])} | "
          f"Errors: {len(results['errors'])}")

    return results


def watch(store: EventStore, dry_run: bool = False) -> None:
    """Poll the event store in a loop."""
    print(f"[PLAYBOOK] Watching every {POLL_INTERVAL}s. Ctrl+C to stop.")
    while True:
        try:
            run_once(store, dry_run=dry_run)
        except Exception as exc:
            print(f"[PLAYBOOK] Error during run: {exc}", file=sys.stderr)
        time.sleep(POLL_INTERVAL)


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Security Core automation playbook")
    parser.add_argument("--watch",   action="store_true", help="Poll continuously")
    parser.add_argument("--dry-run", action="store_true", help="No real notifications or blocks")
    parser.add_argument("--digest",  action="store_true", help="Send daily digest and exit")
    args = parser.parse_args()

    store   = EventStore(config.EVENTS_DB_FILE)
    dry_run = args.dry_run or config.DRY_RUN

    if args.digest:
        print("[PLAYBOOK] Sending daily digest...")
        stats  = fetch_api_stats()
        result = send_digest(stats)
        print(json.dumps(result, indent=2))
        return

    if args.watch:
        watch(store, dry_run=dry_run)
    else:
        result = run_once(store, dry_run=dry_run)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
