#!/bin/bash

LOG_FILE="/var/log/auth.log"
THRESHOLD=5

echo "==============================="
echo " SSH Brute-Force Detection Report"
echo " Scan Time: $(date)"
echo "==============================="

grep "Failed password" "$LOG_FILE" \
| awk {'print $(NF-3)}' \
| sort \
| uniq -c \
| sort -nr \
| while read count ip
do
	if [ "$count" -ge "$THRESHOLD" ]; then
		echo "[ALERT] $ip -> $count failed login attempts"
	fi
done
