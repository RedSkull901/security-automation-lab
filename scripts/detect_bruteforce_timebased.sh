#!/bin/bash



LOG_FILE="/var/log/auth.log"

THRESHOLD=5

WINDOW_MINUTES=10



CURRENT_TIME=$(date +"%b %e %H:%M")

WINDOW_START=$(date -d "$WINDOW_MINUTES minutes ago" +"%b %e %H:%M")



echo "===================================="

echo " SSH Brute-force Detection (Time Based)"

echo " Time Window: Last $WINDOW_MINUTES minutes"

echo " Scan Time: $(date)"

echo "===================================="



grep "Failed password" "$LOG_FILE" | \

awk -v start="$WINDOW_START" -v end="$CURRENT_TIME" '{

    log_time = $1 " " $2 " " substr($3,1,5)

    if (log_time >= start && log_time <= end)

        print $(NF-3)

}' | \

sort | uniq -c | while read count ip

do

    if [ "$count" -ge "$THRESHOLD" ]; then

        echo "[ALERT] $ip has $count failed SSH login attempts in last $WINDOW_MINUTES minutes"

    fi

done


