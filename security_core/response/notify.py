"""
security_core/response/notify.py

Webhook notification.
Payload is standardised so Slack/Discord/n8n/custom all receive the same schema.
"""
import requests
from dataclasses import dataclass
from typing import Optional


@dataclass
class WebhookResult:
    success: bool
    status_code: Optional[int] = None
    error: Optional[str] = None


def send_webhook(alert: dict, webhook_url: Optional[str]) -> WebhookResult:
    if not webhook_url:
        return WebhookResult(success=False, error="no_webhook_url")

    payload = {
        "event":                  "ssh_bruteforce_detected",
        "ip":                     alert.get("ip"),
        "severity":               alert.get("severity"),
        "risk_score":             alert.get("risk_score"),
        "failed_attempts":        alert.get("failed_attempts"),
        "action":                 alert.get("action"),
        "abuse_confidence_score": alert.get("abuse_confidence_score", 0),
        "country":                alert.get("country"),
        "timestamp":              alert.get("timestamp"),
    }

    try:
        resp = requests.post(webhook_url, json=payload, timeout=5)
        return WebhookResult(success=resp.ok, status_code=resp.status_code)
    except requests.RequestException as exc:
        return WebhookResult(success=False, error=str(exc))
