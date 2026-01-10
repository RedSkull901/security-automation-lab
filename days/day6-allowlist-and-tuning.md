# Day 6 - Detection Tuning with Allowlists



## Objective

Improve SSH brute-force detection accuracy by reducing false positives

using allowlists and tuned detection logic.



---



## Problem with Naive Detection

A simple threshold-based detection alerts on every source that exceeds

a fixed number of failed login attempts. This causes problems such as:

- Alerts triggered by trusted admin IPs

- Noise from localhost testing activity

- Alert fatigue in real environments



---



## Improvements Implemented

The detection logic was enhanced with the following improvements:

- Introduced an allowlist for trusted IP addresses

- Separated configuration from detection logic

- Retained time-based detection to limit historical noise



---



## Detection Logic

- Log source: /var/log/auth.log

- Event type: Failed SSH login

- Threshold: 5 failed attempts

- Time window: Last 10 minutes

- Trusted sources ignored via allowlist



---



## Files Used

- scripts/detect_bruteforce_timebased_allowlist.sh

- config/allowlists_ips.txt

---



## Security Engineering Notes

- Detection tuning is critical in production environments

- Poorly tuned alerts can be worse than no alerts

- Allowlists must be reviewed and updated regularly

- Configuration files allow safer and faster tuning



---



## Next Steps

- Externalize all detection parameters into config files

- Add structured output formats such as JSON

- Convert Bash-based detection logic to Python
