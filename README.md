# Security Automation Lab (SOAR-Style)

This repository documents my hands-on journey into **Security Automation and SOAR-style workflows**, built step by step with a strong focus on **real-world engineering practices**.

The project goes beyond basic detections and explores how security teams can:
- Reduce alert fatigue
- Add context using threat intelligence
- Apply risk-based decision logic
- Automate responses safely with guardrails and rollback

Everything here is built incrementally, documented day by day, and designed to reflect how detection and response systems are implemented in real environments.

---

## What this lab covers

- SSH brute-force detection using system logs
- Time-window based detection logic
- Detection tuning and allowlists
- Python-based security automation
- Structured JSON outputs for automation pipelines
- Threat intelligence enrichment (AbuseIPDB)
- Risk scoring and dynamic severity mapping
- SOAR-style decision logic (ignore / alert / escalate)
- Automated response actions with safety controls and rollback

---

## Why this project exists

This lab is part of my effort to move beyond traditional SOC analyst work and build **hands-on Security Engineering and Automation skills**.

The focus is not on tools alone, but on **thinking in pipelines**:
detection → enrichment → decision → response.

---

## Repository structure (high level)

- `scripts/` – Detection and automation logic  
- `config/` – Tuning, allowlists, and secrets (not committed)  
- `days/` – Day-by-day documentation of design decisions and learnings  

Each day builds on the previous one to show **progression**, not just a final result.

---

## Feedback welcome

I’m actively learning and iterating.
Feedback, suggestions, and alternative approaches are always welcome.

If you found this repo via LinkedIn — thanks for stopping by.
