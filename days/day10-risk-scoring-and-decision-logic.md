# Day 10 - Risk Scoring and Decision Logic



## Objective

Enhance SSH brute-force detection by applying risk scoring,

dynamic severity assignment, and decision logic.



---



## Risk Model

Risk score is calculated using:

- Number of failed login attempts

- AbuseIPDB confidence score



Formula:

risk_score = (failed_attempts * 10) + abuse_confidence_score



---



## Severity Mapping

- Low: 0 to 30

- Medium: 31 to 70

- High: 71 and above



---



## Decision Logic

- Low: ignore

- Medium: alert

- High: alert_and_escalate



---



## Security Engineering Notes

- Risk-based alerting reduces alert fatigue

- Decision logic enables SOAR workflows

- Thresholds should be tuned per environment



---



## Next Steps

- Automate response actions

- Integrate notifications

- Build orchestration workflows
