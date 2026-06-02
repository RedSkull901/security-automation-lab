#!/usr/bin/env python3
"""
Multi-vector attack simulator for the Security Automation Lab.

Writes synthetic Linux log entries for:
  - SSH brute force
  - sudo authentication failures
  - port scan firewall logs

Usage:
    sudo python3 scripts/simulate_attack.py --full
    sudo python3 scripts/simulate_attack.py --vector ssh
    sudo python3 scripts/simulate_attack.py --vector sudo
    sudo python3 scripts/simulate_attack.py --vector portscan
    sudo python3 scripts/simulate_attack.py --ip 203.0.113.42 --full
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from datetime import datetime
from pathlib import Path

AUTH_LOG = Path("/var/log/auth.log")
UFW_LOG = Path("/var/log/ufw.log")

ATTACKER_IPS = [
    "203.0.113.42",
    "198.51.100.17",
    "192.0.2.99",
    "45.33.32.156",
    "104.21.14.88",
]

SSH_USERS = ["root", "admin", "ubuntu", "deploy", "git", "oracle", "postgres"]
SUDO_USERS = ["www-data", "ubuntu", "deploy", "git"]
PORTS = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017]


def _now() -> str:
    return datetime.now().strftime("%b %d %H:%M:%S")


def _ensure_log(path: Path) -> None:
    """Create log file if it does not exist. Intended for lab/test environments only."""
    if not path.exists():
        path.touch()
        print(f"[sim] created missing log file: {path}")


def _write_line(path: Path, line: str) -> None:
    try:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except PermissionError:
        print(f"[ERROR] Permission denied writing {path}. Run with sudo.", file=sys.stderr)
        raise SystemExit(1)


def simulate_ssh(attempts: int = 12, attacker_ip: str | None = None) -> int:
    _ensure_log(AUTH_LOG)
    ip = attacker_ip or random.choice(ATTACKER_IPS)
    user = random.choice(SSH_USERS)
    hostname = "seclab"

    print(f"[sim] ssh brute force: {attempts} attempts from {ip} as {user}")

    for index in range(attempts):
        port = random.randint(40000, 65000)
        line = (
            f"{_now()} {hostname} sshd[{9000 + index}]: "
            f"Failed password for {user} from {ip} port {port} ssh2"
        )
        _write_line(AUTH_LOG, line)
        time.sleep(0.03)

    return attempts


def simulate_sudo(attempts: int = 7, user: str | None = None) -> int:
    _ensure_log(AUTH_LOG)
    sudo_user = user or random.choice(SUDO_USERS)
    hostname = "seclab"

    print(f"[sim] sudo brute force: {attempts} failures as {sudo_user}")

    for index in range(attempts):
        line = (
            f"{_now()} {hostname} sudo[{8000 + index}]: "
            f"{sudo_user} : {random.randint(1, 5)} incorrect password attempts ; "
            f"TTY=pts/0 ; PWD=/home/{sudo_user} ; USER=root ; COMMAND=/bin/bash"
        )
        _write_line(AUTH_LOG, line)
        time.sleep(0.03)

    return attempts


def simulate_portscan(port_count: int = 15, attacker_ip: str | None = None) -> int:
    _ensure_log(UFW_LOG)
    ip = attacker_ip or random.choice(ATTACKER_IPS)
    hostname = "seclab"
    selected_ports = random.sample(PORTS * 3, min(port_count, len(PORTS * 3)))

    print(f"[sim] port scan: {len(selected_ports)} ports from {ip}")

    for index, destination_port in enumerate(selected_ports):
        source_port = random.randint(40000, 65000)
        line = (
            f"{_now()} {hostname} kernel: [UFW BLOCK] "
            f"IN=eth0 OUT= MAC=00:00:00:00:00:00 "
            f"SRC={ip} DST=192.168.56.102 LEN=44 TOS=0x00 "
            f"PREC=0x00 TTL=64 ID={7000 + index} "
            f"PROTO=TCP SPT={source_port} DPT={destination_port} "
            f"WINDOW=1024 RES=0x00 SYN URGP=0"
        )
        _write_line(UFW_LOG, line)
        time.sleep(0.02)

    return len(selected_ports)


def main() -> None:
    parser = argparse.ArgumentParser(description="Multi-vector attack simulator")
    parser.add_argument("--full", action="store_true", help="Run SSH, sudo, and port scan simulations")
    parser.add_argument("--vector", choices=["ssh", "sudo", "portscan"], help="Run one vector")
    parser.add_argument("--ip", help="Override source IP for remote vectors")
    parser.add_argument("--attempts", type=int, default=12, help="SSH attempt count")
    parser.add_argument("--sudo-attempts", type=int, default=7, help="sudo failure count")
    parser.add_argument("--ports", type=int, default=15, help="port scan destination port count")
    args = parser.parse_args()

    if not args.full and not args.vector:
        parser.print_help()
        return

    totals: dict[str, int] = {}

    if args.full or args.vector == "ssh":
        totals["ssh"] = simulate_ssh(attempts=args.attempts, attacker_ip=args.ip)

    if args.full or args.vector == "sudo":
        totals["sudo"] = simulate_sudo(attempts=args.sudo_attempts)

    if args.full or args.vector == "portscan":
        totals["portscan"] = simulate_portscan(port_count=args.ports, attacker_ip=args.ip)

    print("[sim] done")
    for vector, count in totals.items():
        print(f"[sim]   {vector}: {count} line(s)")


if __name__ == "__main__":
    main()
