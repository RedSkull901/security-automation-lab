# Day 12 - Real Automated Response with Rollback



## Objective

Implement real automated response actions with safety

controls and automatic rollback.



---



## Response Design

- High-risk IPs are temporarily blocked

- Blocking uses iptables

- Rules auto-expire after fixed duration



---



## Safety Controls

- Localhost is allowlisted

- Blocks are time-limited

- No permanent firewall changes



---



## Security Engineering Notes

- Automation must always be reversible

- Guardrails prevent self-inflicted outages

- This mirrors enterprise SOAR practices


