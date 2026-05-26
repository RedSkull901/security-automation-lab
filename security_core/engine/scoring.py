"""
security_core/engine/scoring.py

Risk scoring and SOAR-style decision engine.
Isolated here so thresholds and logic can be tuned and unit-tested
independently of detection or response code.
"""
from dataclasses import dataclass
from typing import Literal

from security_core.config import (
    ATTEMPT_WEIGHT,
    HIGH_RISK_THRESHOLD,
    MEDIUM_RISK_THRESHOLD,
)

Severity = Literal["low", "medium", "high"]
Action   = Literal["ignore", "alert_only", "block_temp"]


@dataclass
class ScoringResult:
    risk_score: int
    severity:   Severity
    action:     Action

    def to_dict(self) -> dict:
        return {
            "risk_score": self.risk_score,
            "severity":   self.severity,
            "action":     self.action,
        }


def score(failed_attempts: int, abuse_confidence_score: int) -> ScoringResult:
    """
    risk_score  = (failed_attempts × ATTEMPT_WEIGHT) + abuse_confidence_score
    severity    = high  if risk >= HIGH_RISK_THRESHOLD   (default 71)
                  medium if risk >= MEDIUM_RISK_THRESHOLD (default 31)
                  low   otherwise
    action      = block_temp → alert_only → ignore
    """
    risk = (failed_attempts * ATTEMPT_WEIGHT) + abuse_confidence_score

    if risk >= HIGH_RISK_THRESHOLD:
        severity: Severity = "high"
        action:   Action   = "block_temp"
    elif risk >= MEDIUM_RISK_THRESHOLD:
        severity = "medium"
        action   = "alert_only"
    else:
        severity = "low"
        action   = "ignore"

    return ScoringResult(risk_score=risk, severity=severity, action=action)
