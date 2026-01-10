# Day 4 - Bash Automation: SSH Brute-force detection
## Objective

Automate detection of SSH brute-force attacks by parsing Linux authentication logs using Bash scripting.
---
## Detection Rule

- Log source: `/var/log/auth.log`
- Event: Failed SSH login
- Threshold: > 5 failures per IP

---

## Script Details

Script: `detect_bruteforce.sh`


Techniques used:

- grep for log filtering

- awk for field extraction

- sort & uniq for aggregation

- conditional logic for alerting

---

## Sample Output

```text

[ALERT] 127.0.0.1 -> 7 failed logi attempts
