"""
security_core/automations/discord_notify.py

Sends rich Discord embed alert cards for security events.

Discord embeds are structured message blocks with titles, fields,
colours, and timestamps — much more readable than plain text webhooks.

Colour codes (Discord uses decimal integers for embed colours):
  Red    = 15158332  → high severity / block
  Orange = 15105570  → medium severity / alert
  Green  = 3066993   → low / info
"""
import os
import requests
from datetime import datetime, timezone
from typing import Optional


SEVERITY_COLOURS = {
    "high":   15158332,   # red
    "medium": 15105570,   # orange
    "low":    3066993,    # green
}

SEVERITY_EMOJI = {
    "high":   "🔴",
    "medium": "🟠",
    "low":    "🟢",
}

ACTION_LABELS = {
    "block_temp":  "🔒 Blocked (auto)",
    "alert_only":  "⚠️  Alert only",
    "ignore":      "✅ Ignored",
}


def _load_discord_url() -> Optional[str]:
    """Read DISCORD_WEBHOOK_URL from config/webhook.env or environment."""
    # Check env first (Docker / CI)
    url = os.getenv("DISCORD_WEBHOOK_URL")
    if url:
        return url

    # Fall back to file
    try:
        with open("config/webhook.env") as f:
            for line in f:
                if line.startswith("DISCORD_WEBHOOK_URL"):
                    return line.strip().split("=", 1)[1]
    except FileNotFoundError:
        pass
    return None


def build_embed(alert: dict) -> dict:
    """
    Build a Discord embed object from an alert dict.

    Discord embed structure:
    {
        "title":       string,
        "description": string,
        "color":       int,       ← decimal colour
        "fields":      [{"name": str, "value": str, "inline": bool}],
        "footer":      {"text": str},
        "timestamp":   ISO8601 string
    }
    """
    severity = alert.get("severity", "low")
    action   = alert.get("action", "ignore")
    ip       = alert.get("ip", "unknown")
    emoji    = SEVERITY_EMOJI.get(severity, "⚪")

    fields = [
        {
            "name":   "IP Address",
            "value":  f"`{ip}`",
            "inline": True,
        },
        {
            "name":   "Severity",
            "value":  f"{emoji} {severity.upper()}",
            "inline": True,
        },
        {
            "name":   "Action taken",
            "value":  ACTION_LABELS.get(action, action),
            "inline": True,
        },
        {
            "name":   "Failed attempts",
            "value":  str(alert.get("failed_attempts", "?")),
            "inline": True,
        },
        {
            "name":   "Risk score",
            "value":  str(alert.get("risk_score", "?")),
            "inline": True,
        },
        {
            "name":   "Abuse confidence",
            "value":  f"{alert.get('abuse_confidence_score', 0)}%",
            "inline": True,
        },
    ]

    # Add country if present
    country = alert.get("country")
    if country:
        fields.append({
            "name":   "Country",
            "value":  f":flag_{country.lower()}: {country}",
            "inline": True,
        })

    # Add AbuseIPDB report count if present
    total_reports = alert.get("total_reports")
    if total_reports:
        fields.append({
            "name":   "Total AbuseIPDB reports",
            "value":  str(total_reports),
            "inline": True,
        })

    return {
        "title":       f"{emoji} SSH Brute-Force Detected",
        "description": f"Suspicious activity from **{ip}** exceeded detection threshold.",
        "color":       SEVERITY_COLOURS.get(severity, 3066993),
        "fields":      fields,
        "footer":      {"text": "security-automation-lab · security-core"},
        "timestamp":   datetime.now(timezone.utc).isoformat(),
    }


def send_alert(alert: dict, webhook_url: Optional[str] = None) -> dict:
    """
    Send a Discord embed for a single alert.
    Returns {"success": bool, "status_code": int|None, "error": str|None}
    """
    url = webhook_url or _load_discord_url()

    if not url:
        return {"success": False, "error": "no_discord_webhook_url"}

    payload = {
        "username": "Security Core",
        "embeds":   [build_embed(alert)],
    }

    try:
        resp = requests.post(url, json=payload, timeout=5)
        # Discord returns 204 No Content on success
        return {
            "success":     resp.status_code in (200, 204),
            "status_code": resp.status_code,
            "error":       None,
        }
    except Exception as exc:
        return {"success": False, "status_code": None, "error": str(exc)}


def send_digest(stats: dict, webhook_url: Optional[str] = None) -> dict:
    """
    Send a daily digest summary embed.
    Called by the scheduled playbook — not per-alert.
    """
    url = webhook_url or _load_discord_url()
    if not url:
        return {"success": False, "error": "no_discord_webhook_url"}

    total   = stats.get("total_events", 0)
    high    = stats.get("high_severity", 0)
    medium  = stats.get("medium_severity", 0)
    blocked = stats.get("blocked_ips", 0)

    embed = {
        "title":       "📊 Daily Security Digest",
        "description": "Summary of the last 24 hours.",
        "color":       3447003,   # blue
        "fields": [
            {"name": "Total events",    "value": str(total),   "inline": True},
            {"name": "High severity",   "value": str(high),    "inline": True},
            {"name": "Medium severity", "value": str(medium),  "inline": True},
            {"name": "IPs blocked",     "value": str(blocked), "inline": True},
        ],
        "footer":    {"text": "security-automation-lab · daily digest"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    payload = {"username": "Security Core", "embeds": [embed]}

    try:
        resp = requests.post(url, json=payload, timeout=5)
        return {"success": resp.status_code in (200, 204), "status_code": resp.status_code}
    except requests.RequestException as exc:
        return {"success": False, "error": str(exc)}
