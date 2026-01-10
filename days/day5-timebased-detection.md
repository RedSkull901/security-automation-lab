# Day 5 - Time-Based SSH Brute-force Detection



## Objective

Improve brute-force detection accuracy by applying time-based

analysis to Linux authentication logs.



---



## Detection Logic

- Event: Failed SSH login

- Threshold: >= 5 failures

- Time window: Last 10 minutes

- Log source: `/var/log/auth.log`



---



## Improvements Over Static Detection

- Reduces false positives from old events

- Mimics SIEM-style sliding time windows

- More suitable for production use



---



## Script

`detect_bruteforce_timebased.sh`



Key techniques:

- Date comparison

- Time window filtering

- Conditional alerting



---



## Security Engineer Notes

- Time-based logic is essential for accurate detections

- Thresholds must be tuned per environment

- This logic can be ported to Python or SIEM rules



---



## Next Steps

- Add allowlist for trusted IPs

- Export alerts to JSON

- Convert logic to Python
