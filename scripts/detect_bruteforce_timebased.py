#!/usr/bin/env python3



import datetime

import json

import requests

from collections import defaultdict



# ---------------- CONFIG ----------------



LOG_FILE = "/var/log/auth.log"

ALLOWLIST_FILE = "config/allowlist_ips.txt"

API_KEY_FILE = "config/api_keys.env"



THRESHOLD = 5

WINDOW_MINUTES = 10



ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"



# ---------------- HELPERS ----------------



def load_allowlist(path):

    allowlist = set()

    try:

        with open(path, "r") as f:

            for line in f:

                allowlist.add(line.strip())

    except FileNotFoundError:

        pass

    return allowlist





def load_api_key(path):

    try:

        with open(path, "r") as f:

            for line in f:

                if line.startswith("ABUSEIPDB_API_KEY"):

                    return line.strip().split("=", 1)[1]

    except FileNotFoundError:

        pass

    return None





def parse_log_time(line):

    parts = line.split()

    timestamp_str = " ".join(parts[0:3])

    current_year = datetime.datetime.now().year

    return datetime.datetime.strptime(

        f"{timestamp_str} {current_year}",

        "%b %d %H:%M:%S %Y"

    )





def enrich_ip(ip, api_key):

    if not api_key:

        return {

            "abuse_confidence_score": 0,

            "country": None,

            "is_whitelisted": None

        }



    headers = {

        "Key": api_key,

        "Accept": "application/json"

    }

    params = {

        "ipAddress": ip,

        "maxAgeInDays": 90

    }



    try:

        response = requests.get(

            ABUSEIPDB_URL,

            headers=headers,

            params=params,

            timeout=10

        )

        data = response.json().get("data", {})

        return {

            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),

            "country": data.get("countryCode"),

            "is_whitelisted": data.get("isWhitelisted")

        }

    except Exception:

        return {

            "abuse_confidence_score": 0,

            "country": None,

            "is_whitelisted": None

        }


def calculate_risk(failed_attempts, abuse_score):

    return (failed_attempts * 10) + abuse_score





def map_severity(risk_score):

    if risk_score >= 71:

        return "high"

    elif risk_score >= 31:

        return "medium"

    return "low"





def decide_action(severity):

    if severity == "high":

        return "alert_and_escalate"

    elif severity == "medium":

        return "alert_only"

    return "ignore"





def simulate_block(ip):

    print(f"[SIMULATION] Blocking IP {ip} (no real action taken)")





def respond_to_alert(alert):

    ip = alert["ip"]

    action = alert["action"]



    if action == "alert_only":

        print(f"[RESPONSE] Alert generated for {ip}")



    elif action == "alert_and_escalate":

        print(f"[RESPONSE] Escalation triggered for {ip}")

        simulate_block(ip)





def main():

    now = datetime.datetime.now()

    window_start = now - datetime.timedelta(minutes=WINDOW_MINUTES)



    allowlist = load_allowlist(ALLOWLIST_FILE)

    api_key = load_api_key(API_KEY_FILE)



    failed_attempts = defaultdict(int)



    # ---- LOG PARSING ----

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


    # ---- BUILD ALERTS ----

    alerts = []



    for ip, count in failed_attempts.items():

        if count < THRESHOLD:

            continue



        intel = enrich_ip(ip, api_key)

        abuse_score = intel.get("abuse_confidence_score", 0)



        risk_score = calculate_risk(count, abuse_score)

        severity = map_severity(risk_score)

        action = decide_action(severity)



        alert = {

            "ip": ip,

            "failed_attempts": count,

            "abuse_confidence_score": abuse_score,

            "risk_score": risk_score,

            "severity": severity,

            "action": action,

            "threat_intel": intel

        }



        alerts.append(alert)

    # ---- RESPOND ----

    for alert in alerts:

        respond_to_alert(alert)



    # ---- OUTPUT ----

    output = {

        "detection": "ssh_bruteforce",

        "window_minutes": WINDOW_MINUTES,

        "generated_at": now.isoformat(),

        "alert_count": len(alerts),

        "alerts": alerts

    }


    print(json.dumps(output, indent=2))



if __name__ == "__main__":

    main()
