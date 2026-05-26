# Day 17 — Automation Playbook: Discord Alerts + n8n

## What this day covers

Two complementary things:

1. **A Python playbook** (`automations/playbook.py`) — polls the event store,
   sends Discord alerts, and calls the API to block high-severity IPs.
   Runs as a cron job or a long-running watcher. No external dependencies beyond `requests`.

2. **n8n setup** — the visual workflow tool that does the same job graphically.
   Good for non-code integrations and future workflows (email, ticketing, Slack, etc.)

Both are useful. The Python playbook is the reliable foundation.
n8n is the extensible layer on top.

---

## New concept: the cursor pattern

The playbook runs repeatedly. The event store grows over time.
The problem: how does the playbook know which events are new since the last run?

The answer is a **cursor** — a file that stores the timestamp of the last
processed event.

```
Run 1:  cursor = epoch (never run before)
        reads events: [A, B, C]
        processes all three
        writes cursor = timestamp of C

Run 2:  cursor = timestamp of C
        reads events since C: [D, E]
        processes D and E only
        writes cursor = timestamp of E

Run 3:  cursor = timestamp of E
        reads events since E: []
        nothing to do
```

This pattern — sometimes called a **checkpoint** or **watermark** — is used
everywhere in data engineering. Kafka consumer offsets, database replication
slots, webhook event IDs — all the same idea. Track where you left off,
resume from there.

Without a cursor, you'd either reprocess every event on every run
(double alerts, double blocks) or miss events entirely.

---

## The playbook pipeline

```
Every N seconds (or on-demand):
    │
    ▼
read_cursor()
    │  "last processed timestamp"
    ▼
store.read_since(cursor)
    │  new detection events only
    ▼
for each event:
    │
    ├── severity in {high, medium} → send_alert() → Discord embed
    │
    └── severity in {high} → call_api_block() → POST /block/{ip}
    │
    ▼
write_cursor(latest_timestamp)
```

The playbook talks to two things:
- The **event store** directly (reads `data/events.jsonl`)
- The **API** (calls `POST /block/{ip}`)

It never touches iptables itself — that's the API's job.
Separation of concerns: the playbook decides *when* to act,
the API decides *how* to act.

---

## Discord embeds

Plain webhook POST sends a text string. Discord embeds are structured blocks —
title, fields, colours, timestamps — rendered as a card in the channel.

```python
{
    "username": "Security Core",
    "embeds": [{
        "title":  "🔴 SSH Brute-Force Detected",
        "color":  15158332,           # decimal — red
        "fields": [
            {"name": "IP",       "value": "`1.2.3.4`",  "inline": True},
            {"name": "Severity", "value": "🔴 HIGH",     "inline": True},
            {"name": "Action",   "value": "🔒 Blocked",  "inline": True},
            ...
        ],
        "timestamp": "2026-05-06T14:22:01+00:00"
    }]
}
```

Colours are decimal integers — not hex. `#E74C3C` (red) = `15158332` in decimal.
Discord uses this across their entire API; you'll see it in their docs.

Why embeds over plain text?
At a glance in Discord you see: red card, IP, severity, action taken.
No parsing. No reading. Immediate situational awareness.

---

## Running the playbook

```bash
# Add your Discord webhook URL
echo "DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR/URL" >> config/webhook.env

# Run once — processes any new events and exits
python -m security_core.automations.playbook

# Dry run — shows what would happen, no real calls
python -m security_core.automations.playbook --dry-run

# Watch mode — polls every 60 seconds
python -m security_core.automations.playbook --watch

# Send a daily digest summary
python -m security_core.automations.playbook --digest

# Custom poll interval
SAL_POLL_SEC=30 python -m security_core.automations.playbook --watch
```

To run as a cron job (every 5 minutes):
```bash
# crontab -e
*/5 * * * * cd /path/to/security-automation-lab && python -m security_core.automations.playbook >> logs/playbook.log 2>&1
```

---

## n8n setup

n8n is a self-hosted workflow automation tool. Think of it as a visual
pipeline builder — each node is a step, each connection is data flowing forward.

### Install via Docker (one command)

```bash
# Add to docker-compose.yml services section, or run standalone:
docker run -d \
  --name n8n \
  -p 5678:5678 \
  -v n8n_data:/home/node/.n8n \
  n8nio/n8n
```

Open `http://localhost:5678` — n8n's UI appears.

### The equivalent n8n workflow

```
[Schedule Trigger]          every 60 seconds
        │
        ▼
[HTTP Request]              GET http://localhost:8000/events?severity=high
        │
        ▼
[If node]                   events.length > 0 ?
        │
    yes │
        ▼
[Loop over items]           for each event
        │
        ▼
[HTTP Request]              POST Discord webhook
        │                   body: build embed from event data
        ▼
[HTTP Request]              POST http://localhost:8000/block/{{event.ip}}
```

You build this visually by dragging nodes onto a canvas and connecting them.
No code required for the workflow itself — only the HTTP request payloads
need some JSON templating using n8n's expression syntax (`{{$json.ip}}`).

### When to use n8n vs the Python playbook

| | Python playbook | n8n |
|---|---|---|
| Setup | Zero (already written) | Docker + UI config |
| Code required | Yes | Minimal |
| Adding new integrations | Write code | Drag a node |
| Reliability | Depends on cron | Built-in scheduling |
| Visibility | Logs only | Visual execution history |
| Best for | Core logic, CI testing | Non-code integrations |

For this project: **run the Python playbook as the reliable core**,
use n8n when you want to add integrations without writing new code
(email, Jira tickets, PagerDuty, etc.)

---

## Testing

```bash
# Run just the automation tests
python -m pytest security_core/tests/test_automations.py -v

# Full suite (49 tests)
python -m pytest security_core/tests/ -v
```

The tests mock all external calls — Discord webhook, API block endpoint.
No network calls, no credentials needed to run the test suite.

**The cursor test specifically verifies:**
- First run with no cursor → processes all events
- Second run → processes only new events (cursor advanced correctly)
- Nothing is double-processed

---

## Lessons

**The cursor pattern beats polling without state.**
Stateless polling means either reprocessing everything (expensive, noisy)
or tracking "seen" event IDs in a set (memory grows unboundedly).
A single timestamp cursor is cheap, persistent, and trivially debuggable —
`cat data/playbook_cursor.txt` tells you exactly where the playbook left off.

**Keep the playbook dumb. Keep logic in the API.**
The playbook decides *which* events to act on and *when*.
It delegates the *how* to the API (`POST /block/{ip}`).
This means you can change the blocking logic (switch from iptables to firewalld,
add rate limiting, add audit logs) in one place — the API — without touching
the playbook. The playbook never needs to know what "block" actually does.

**Mock external calls in tests. Always.**
Tests that hit real Discord webhooks or real APIs are slow, flaky,
and require credentials in CI. Mock the HTTP layer — test that the right
payload is sent with the right structure. The network is someone else's problem.
