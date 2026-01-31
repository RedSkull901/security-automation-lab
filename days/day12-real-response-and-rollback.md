# Day 12 - Real Automated Response with Rollback

<img width="801" height="404" alt="image" src="https://github.com/user-attachments/assets/ae0a63fb-1a06-4a77-b228-7a6340967f2b" />


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


