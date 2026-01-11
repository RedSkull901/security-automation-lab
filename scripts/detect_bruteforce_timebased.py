#!/usr/bin/env python3



import datetime

from collections import defaultdict



LOG_FILE = "/var/log/auth.log"

ALLOWLIST_FILE = "config/allowlist_ips.txt"

THRESHOLD = 5

WINDOW_MINUTES = 10



def load_allowlist(path):

    allowlist = set()

    try:

        with open(path, "r") as f:

            for line in f:

                allowlist.add(line.strip())

    except FileNotFoundError:

        pass

    return allowlist



def parse_log_time(line):

    parts = line.split()

    timestamp_str = " ".join(parts[0:3])

    current_year = datetime.datetime.now().year

    return datetime.datetime.strptime(

        f"{timestamp_str} {current_year}",

        "%b %d %H:%M:%S %Y"

    )



def main():

    now = datetime.datetime.now()

    window_start = now - datetime.timedelta(minutes=WINDOW_MINUTES)

    failed_attempts = defaultdict(int)



    allowlist = load_allowlist(ALLOWLIST_FILE)



    with open(LOG_FILE, "r") as log:

        for line in log:

            if "Failed password" not in line:

                continue



            try:

                log_time = parse_log_time(line)

            except ValueError:

                continue



            if log_time < window_start:

                continue



            parts = line.split()

            ip = parts[-4]



            if ip in allowlist:

                continue



            failed_attempts[ip] += 1



    print("====================================")

    print(" SSH Brute-force Detection (Python)")

    print(f" Time Window: Last {WINDOW_MINUTES} minutes")

    print(f" Scan Time: {now}")

    print("====================================")



    for ip, count in failed_attempts.items():

        if count >= THRESHOLD:

            print(f"[ALERT] {ip} has {count} failed SSH login attempts")



if __name__ == "__main__":

    main()
