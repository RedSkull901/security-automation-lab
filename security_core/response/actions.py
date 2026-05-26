"""
security_core/response/actions.py

Response actions: block, unblock, alert.
- DRY_RUN=true → logs intent, never touches iptables
- All actions return a ResponseResult so callers can log/store outcomes
"""
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from security_core.config import BLOCK_DURATION_MIN, DRY_RUN


@dataclass
class ResponseResult:
    ip:         str
    action:     str
    success:    bool
    dry_run:    bool
    message:    str
    executed_at: str = ""

    def __post_init__(self):
        if not self.executed_at:
            self.executed_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "ip":          self.ip,
            "action":      self.action,
            "success":     self.success,
            "dry_run":     self.dry_run,
            "message":     self.message,
            "executed_at": self.executed_at,
        }


def _run(cmd: list[str]) -> tuple[bool, str]:
    """Run a shell command, return (success, output/error)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            return False, result.stderr.strip()
        return True, result.stdout.strip()
    except Exception as exc:
        return False, str(exc)


def block_ip(ip: str, duration_min: int = BLOCK_DURATION_MIN) -> ResponseResult:
    """
    Block IP via iptables INPUT DROP.
    Schedules automatic unblock after duration_min.
    """
    if DRY_RUN:
        return ResponseResult(
            ip=ip, action="block_temp", success=True, dry_run=True,
            message=f"[DRY RUN] Would block {ip} for {duration_min} min via iptables",
        )

    ok, msg = _run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
    if not ok:
        return ResponseResult(
            ip=ip, action="block_temp", success=False, dry_run=False,
            message=f"iptables INSERT failed: {msg}",
        )

    # Async rollback — subprocess.Popen detaches
    subprocess.Popen(
        f"sleep {duration_min * 60} && iptables -D INPUT -s {ip} -j DROP",
        shell=True,
    )

    return ResponseResult(
        ip=ip, action="block_temp", success=True, dry_run=False,
        message=f"Blocked {ip} for {duration_min} min. Rollback scheduled.",
    )


def unblock_ip(ip: str) -> ResponseResult:
    """Manual immediate unblock — for dashboard use later."""
    if DRY_RUN:
        return ResponseResult(
            ip=ip, action="unblock", success=True, dry_run=True,
            message=f"[DRY RUN] Would unblock {ip}",
        )

    ok, msg = _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
    return ResponseResult(
        ip=ip, action="unblock", success=ok, dry_run=False,
        message=msg if not ok else f"Unblocked {ip}",
    )


def alert_only(ip: str, severity: str) -> ResponseResult:
    return ResponseResult(
        ip=ip, action="alert_only", success=True, dry_run=DRY_RUN,
        message=f"Alert raised for {ip} (severity={severity}). No block applied.",
    )


def dispatch(ip: str, action: str, severity: str) -> Optional[ResponseResult]:
    """Route a scored action to the correct response function."""
    if action == "block_temp":
        return block_ip(ip)
    if action == "alert_only":
        return alert_only(ip, severity)
    # "ignore" → no action
    return None
