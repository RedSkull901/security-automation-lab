"""
security_core/automations/triage.py

AI-powered alert triage using Ollama (local LLM — free, no API key needed).

Takes a structured alert dict from the event store and returns a human-readable
incident report with risk assessment and recommended actions.

Ollama must be running: systemctl status ollama
Model must be pulled:   ollama pull llama3.2:3b

Usage:
    from security_core.automations.triage import TriageEngine
    engine = TriageEngine()
    result = engine.analyze(alert)
    print(result.summary)
"""
import json
import os
import time
from dataclasses import dataclass
from typing import Optional

import requests


# ── Config ─────────────────────────────────────────────────────────────────────

OLLAMA_URL   = os.getenv("OLLAMA_URL",   "http://localhost:11434")
TRIAGE_MODEL = os.getenv("TRIAGE_MODEL", "llama3.2:3b")
TIMEOUT_SEC  = int(os.getenv("TRIAGE_TIMEOUT", "120"))


# ── Result ─────────────────────────────────────────────────────────────────────

@dataclass
class TriageResult:
    ip:           str
    model:        str
    summary:      str           # full LLM response
    duration_sec: float
    success:      bool
    error:        Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "ip":           self.ip,
            "model":        self.model,
            "summary":      self.summary,
            "duration_sec": round(self.duration_sec, 1),
            "success":      self.success,
            "error":        self.error,
        }


# ── Prompt builder ─────────────────────────────────────────────────────────────

def build_prompt(alert: dict) -> str:
    """
    Build a structured prompt from an alert dict.
    Clear structure = consistent output from smaller models.
    """
    ip             = alert.get("ip", "unknown")
    attempts       = alert.get("failed_attempts", "?")
    abuse_score    = alert.get("abuse_confidence_score", 0)
    country        = alert.get("country") or "unknown"
    risk_score     = alert.get("risk_score", "?")
    severity       = alert.get("severity", "unknown").upper()
    action         = alert.get("action", "unknown")
    total_reports  = alert.get("total_reports", 0)
    last_reported  = alert.get("last_reported_at") or "unknown"

    action_label = {
        "block_temp":  "Auto-blocked for 30 minutes via iptables",
        "alert_only":  "Alert raised, no block applied",
        "ignore":      "No action taken (below threshold)",
    }.get(action, action)

    return f"""You are a SOC analyst writing a concise incident report.
Respond in exactly this format, nothing else:

INCIDENT: [one sentence describing what happened]
RISK: [severity level and key reason why]
ACTIONS TAKEN: [what the automated system already did]
RECOMMENDED NEXT STEPS:
1. [specific action]
2. [specific action]
3. [specific action]

Alert data:
- IP address: {ip}
- Failed SSH login attempts: {attempts} in 10 minutes
- AbuseIPDB confidence score: {abuse_score}%
- AbuseIPDB total reports: {total_reports}
- Last reported on AbuseIPDB: {last_reported}
- Origin country: {country}
- Internal risk score: {risk_score}
- Severity: {severity}
- Automated action: {action_label}

Write the report now:"""


# ── Engine ─────────────────────────────────────────────────────────────────────

class TriageEngine:
    def __init__(self, model: str = TRIAGE_MODEL, ollama_url: str = OLLAMA_URL):
        self.model      = model
        self.ollama_url = ollama_url.rstrip("/")

    def is_available(self) -> bool:
        """Check if Ollama is running and the model is loaded."""
        try:
            resp = requests.get(f"{self.ollama_url}/api/tags", timeout=5)
            if not resp.ok:
                return False
            models = [m["name"] for m in resp.json().get("models", [])]
            return any(self.model in m for m in models)
        except Exception:
            return False

    def analyze(self, alert: dict) -> TriageResult:
        """
        Send alert to Ollama and return a structured triage result.
        Uses the /api/generate endpoint (non-streaming for simplicity).
        """
        ip     = alert.get("ip", "unknown")
        prompt = build_prompt(alert)
        start  = time.time()

        try:
            resp = requests.post(
                f"{self.ollama_url}/api/generate",
                json={
                    "model":  self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.2,   # low = more consistent, less creative
                        "num_predict": 300,   # max tokens — enough for the report
                    },
                },
                timeout=TIMEOUT_SEC,
            )
            resp.raise_for_status()
            data    = resp.json()
            summary = data.get("response", "").strip()
            elapsed = time.time() - start

            return TriageResult(
                ip=ip,
                model=self.model,
                summary=summary,
                duration_sec=elapsed,
                success=bool(summary),
                error=None if summary else "empty_response",
            )

        except requests.Timeout:
            return TriageResult(
                ip=ip, model=self.model, summary="",
                duration_sec=time.time() - start,
                success=False, error=f"timeout after {TIMEOUT_SEC}s",
            )
        except Exception as exc:
            return TriageResult(
                ip=ip, model=self.model, summary="",
                duration_sec=time.time() - start,
                success=False, error=str(exc),
            )

    def batch_analyze(self, alerts: list[dict]) -> list[TriageResult]:
        """Triage multiple alerts sequentially."""
        return [self.analyze(a) for a in alerts]


# ── CLI entry point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Quick test with a synthetic alert
    test_alert = {
        "ip":                     "1.2.3.4",
        "failed_attempts":        12,
        "abuse_confidence_score": 87,
        "country":                "CN",
        "risk_score":             207,
        "severity":               "high",
        "action":                 "block_temp",
        "total_reports":          42,
        "last_reported_at":       "2026-05-25T10:00:00+00:00",
    }

    engine = TriageEngine()

    if not engine.is_available():
        print(f"[ERROR] Ollama not available or model '{TRIAGE_MODEL}' not pulled.")
        print("Run: ollama pull llama3.2:3b")
        exit(1)

    print(f"[TRIAGE] Analyzing {test_alert['ip']} with {engine.model}...")
    result = engine.analyze(test_alert)
    print(json.dumps(result.to_dict(), indent=2))
