# Day 7 - Python Conversion of SSH Brute-force Detection



## Objective

Convert Bash-based SSH brute-force detection logic into Python

to improve readability, maintainability, and extensibility.



---



## Why Python

- Better error handling

- Easier time-based logic

- Cleaner parsing of logs

- Suitable for security automation and SOAR workflows



---



## Detection Logic

- Log source: /var/log/auth.log

- Event: Failed SSH login

- Threshold: 5 failures

- Time window: Last 10 minutes

- Allowlist applied



---



## Files Used

- scripts/detect_bruteforce_timebased.py

- config/allowlist_ips.txt



---



## Security Engineering Notes

- Python is preferred for scalable security automation

- This script can be extended with APIs and alerting

- Logic can be reused across platforms



---



## Next Steps

- Export alerts in JSON format

- Integrate threat intelligence APIs

- Build multi-step automation workflows


