# Security Automation Lab (SOAR-Style)

A self-hosted security automation and detection engineering platform built on Linux.

This repository documents my hands-on journey into Security Automation, Detection Engineering, and SOAR-style workflows through a project built incrementally from the ground up using real-world engineering concepts.

What originally started as a simple SSH brute-force detection script gradually evolved into a broader monitoring, enrichment, and automated response framework focused on how modern blue-team operations actually function.

The project explores how security teams can:

- Reduce alert fatigue
- Add context using threat intelligence
- Apply risk-based decision making
- Automate response actions safely
- Correlate events across detections
- Improve operational visibility
- Build scalable security workflows

Everything here is developed step by step, documented day by day, and designed to reflect practical security engineering concepts rather than isolated scripts.

---

# Current Capabilities

## Detection & Monitoring
- SSH brute-force detection using Linux authentication logs
- Time-window based detection logic
- Detection tuning and allowlists
- Structured JSON event generation
- Real-time event monitoring

## Threat Enrichment
- AbuseIPDB integration
- Dynamic risk scoring
- Severity mapping
- AI-assisted alert triage

## Automated Response
- Temporary IP blocking with rollback safeguards
- Discord alerting integration
- Event-driven response workflows
- Rate limiting and suppression logic

## Dashboard & APIs
- React-based monitoring dashboard
- Live event feed and timeline tracking
- Severity analytics and visualization
- IP block management interface
- REST API integration
- Manual block/unblock workflows

---

# Platform Workflow

Detection → Enrichment → Correlation → Decision → Response → Visibility

The focus of this project is not just on detecting threats, but on understanding how modern security pipelines are designed, automated, and operationalized.

---

# Planned Enhancements

The platform is actively evolving into a broader detection engineering and SOAR-style framework.

Planned features currently being explored include:

## Multi-Vector Detection
Expanding beyond SSH-based detections into:
- Failed sudo attempts
- Port scanning activity
- Web brute-force detection from nginx/apache logs

Each detector will feed into the same centralized pipeline.

---

## Threat Feed Integration
Integration with free threat intelligence feeds such as:
- Abuse.ch
- Emerging Threats
- Community threat feeds

Including:
- Automated enrichment
- Dynamic blocklist generation
- Threat correlation workflows

---

## Alert Correlation Engine
Cross-event correlation logic to automatically escalate severity when the same IP triggers multiple detections within a defined time window.

Example:
- SSH brute force + Port scan activity from the same IP
→ Higher confidence and automated escalation.

---

## Smart Whitelisting
Trusted IPs can bypass enforcement actions while still generating visibility events for monitoring and auditing purposes.

---

# Why This Project Exists

This project is part of my effort to move beyond traditional SOC workflows and build hands-on experience in:

- Security Engineering
- Detection Engineering
- Security Automation
- Incident Response
- SOAR-style workflows
- Blue Team Operations

The focus is not only on identifying threats, but on thinking in complete operational pipelines:

Detection → Enrichment → Decision → Response

---

# Repository Structure

```text
scripts/     - Detection and automation logic
dashboard/   - React frontend
api/         - Backend APIs
config/      - Tuning, allowlists, and secrets
days/        - Day-by-day documentation and progression
```

Each day builds on the previous one to show progression, architecture decisions, and operational thinking rather than only a final product.

---

# Screenshots

(Add dashboard screenshots here)

- Overview Dashboard
- Event Monitoring
- Block Management

---

# Tech Stack

- Python
- Linux
- React
- REST APIs
- Discord Webhooks
- AbuseIPDB
- JSON-based event pipelines

---

# Project Philosophy

The goal of this project is not to replicate enterprise tools, but to better understand how modern security systems are built, automated, correlated, and operationalized.

---

# Feedback Welcome

This project is actively evolving and I’m continuously learning while building it.

Suggestions, feedback, and alternative approaches are always welcome.

If you found this repository through LinkedIn — thanks for stopping by.
