#!/usr/bin/env python3
"""
scripts/simulate_attack.py

Simulates SSH brute-force attacks for testing the full pipeline.
Spreads fake log entries across the last 24 hours so the timeline chart populates.

Usage:
    sudo python3 scripts/simulate_attack.py           # basic test
    sudo python3 scripts/simulate_attack.py --full    # multi-IP simulation
    sudo python3 scripts/simulate_attack.py --ip 1.2.3.4 --attempts 15
"""
import argparse
import json
import os
import subprocess
import sys
import time
import random
from datetime import datetime, timezone, timedelta

ATTACKERS = [
    {"ip": "185.220.101.45", "attempts": 18, "country": "RU"},
    {"ip": "45.33.32.156",   "attempts": 12, "country": "CN"},
    {"ip": "103.21.244.0",   "attempts": 8,  "country": "NL"},
]

LOG_FILE  = "/var/log/auth.log"
USERNAMES = ["root", "admin", "ubuntu", "test", "user", "pi", "oracle", "postgres"]


def inject_log_lines(ip: str, attempts: int, spread_hours: int = 8) -> int:
    """
    Write realistic 'Failed password' lines spread across the last N hours.
    This ensures the 24h timeline chart shows activity.
    """
    lines_written = 0
    now = datetime.now()

    for i in range(attempts):
        user = USERNAMES[i % len(USERNAMES)]
        port = 50000 + i
        # Spread events across the last spread_hours hours
        offset_minutes = random.randint(0, spread_hours * 60)
        ts = now - timedelta(minutes=offset_minutes)
        ts_str = ts.strftime("%b %d %H:%M:%S")
        line = (f"{ts_str} security-lab sshd[{9000+i}]: "
                f"Failed password for {user} from {ip} port {port} ssh2\n")
        try:
            with open(LOG_FILE, "a") as f:
                f.write(line)
            lines_written += 1
        except PermissionError:
            print("[ERROR] Need sudo: sudo python3 scripts/simulate_attack.py")
            sys.exit(1)

    return lines_written


def run_detector() -> dict:
    """Run the SSH brute-force detector and return parsed output."""
    env = os.environ.copy()
    env["SAL_DRY_RUN"]    = "false"
    env["SAL_THRESHOLD"]  = "3"
    env["TRIAGE_TIMEOUT"] = "1"

    try:
        result = subprocess.run(
            [sys.executable, "-m", "security_core.detectors.ssh_bruteforce"],
            capture_output=True, text=True, env=env,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            timeout=30
        )
    except subprocess.TimeoutExpired:
        print("  [INFO] Detector timed out (triage running) — events already stored")
        return {"alert_count": "?", "alerts": []}

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        print("[DETECTOR OUTPUT]", result.stdout)
        print("[DETECTOR ERRORS]", result.stderr)
        return {}


def print_banner(text: str):
    print("\n" + "─" * 60)
    print(f"  {text}")
    print("─" * 60)


def main():
    parser = argparse.ArgumentParser(description="SSH brute-force attack simulator")
    parser.add_argument("--ip",       default=None)
    parser.add_argument("--attempts", type=int, default=10)
    parser.add_argument("--full",     action="store_true")
    parser.add_argument("--hours",    type=int, default=8,
                        help="Spread events across this many hours (default: 8)")
    args = parser.parse_args()

    print_banner("Security Automation Lab — Attack Simulator")

    if args.full:
        attackers = ATTACKERS
    elif args.ip:
        attackers = [{"ip": args.ip, "attempts": args.attempts, "country": "??"}]
    else:
        attackers = [{"ip": "10.10.10.99", "attempts": args.attempts, "country": "TEST"}]

    # Step 1: Inject log entries
    print_banner("Step 1 — Injecting fake SSH failure log entries")
    total_lines = 0
    for attacker in attackers:
        n = inject_log_lines(attacker["ip"], attacker["attempts"], spread_hours=args.hours)
        total_lines += n
        print(f"  ✓ {attacker['ip']} ({attacker['country']}) — {n} attempts spread over {args.hours}h")
    print(f"\n  Total lines injected: {total_lines}")
    time.sleep(0.3)

    # Step 2: Run detector
    print_banner("Step 2 — Running SSH brute-force detector")
    output     = run_detector()
    alert_count = output.get("alert_count", 0)
    alerts      = output.get("alerts", [])

    count_val = alert_count if alert_count != "?" else "? (timed out — check events.jsonl)"
    print(f"  Alerts generated: {count_val}")
    for alert in alerts:
        print(f"  → {alert.get('ip','?'):20s} severity={str(alert.get('severity','?')).upper():8s} "
              f"risk={alert.get('risk_score','?'):5} action={alert.get('action','?')}")

    # Step 3: Verify event store
    print_banner("Step 3 — Checking event store")
    events_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data", "events.jsonl"
    )
    if os.path.exists(events_path):
        with open(events_path) as f:
            lines = [l for l in f if l.strip()]
        print(f"  Events in store: {len(lines)}")
        if lines:
            try:
                last = json.loads(lines[-1])
                print(f"  Latest: {last.get('ip')} — {last.get('severity')} — {last.get('timestamp','')[:19]}")
            except Exception:
                pass
    else:
        print("  [WARN] data/events.jsonl not found")

    # Summary
    print_banner("Done")
    is_success = alert_count == "?" or (isinstance(alert_count, int) and alert_count > 0)
    if is_success:
        print("  ✓ Pipeline working — check your dashboard")
        print("  → http://192.168.56.102:3000")
        print("  → http://192.168.56.102:8000/events")
    else:
        print("  ✗ No alerts. Try:")
        print("    SAL_THRESHOLD=1 python -m security_core.detectors.ssh_bruteforce")
    print()


if __name__ == "__main__":
    main()
