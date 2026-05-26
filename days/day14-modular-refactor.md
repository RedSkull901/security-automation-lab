# Day 14 — Modular Refactor: From Script to Product

## What changed and why

Up to Day 13, the entire pipeline lived in a single file:
`scripts/detect_bruteforce_timebased.py`

That file worked. But it had a problem: **everything was coupled to everything else.**
The log parser knew about webhooks. The enrichment code lived next to the iptables logic.
To test the risk scoring, you had to run the whole script.

This is normal for a learning project. It stops being acceptable when you want to:
- Write unit tests for individual pieces
- Swap out a component (e.g. replace in-memory rate limiting with Redis)
- Expose the pipeline over an API
- Build a dashboard that reads the same data

Day 14 is the architectural shift that makes all of that possible.

---

## The refactor: one script → one module per responsibility

The pipeline hasn't changed. The boundaries have.

```
Before                              After
──────────────────────────────      ──────────────────────────────────────────
detect_bruteforce_timebased.py      security_core/
  ├── load_allowlist()                ├── config.py            ← all settings
  ├── load_api_key()                  ├── detectors/
  ├── parse_log_time()                │   └── ssh_bruteforce.py ← orchestrates
  ├── enrich_ip()                     ├── engine/
  ├── calculate_risk()                │   ├── rate_limiter.py   ← new
  ├── map_severity()                  │   └── scoring.py        ← was inline
  ├── decide_action()                 ├── enrichment/
  ├── block_ip_temp()                 │   └── abuseipdb.py      ← was inline
  ├── respond()                       ├── response/
  ├── send_webhook()                  │   ├── actions.py        ← was inline
  └── main()                          │   └── notify.py         ← was inline
                                      ├── store/
                                      │   └── events.py         ← new
                                      └── utils/
                                          └── loaders.py        ← was inline
```

Every module has one job. Changes to scoring don't touch enrichment.
Changes to how alerts are stored don't touch how IPs are blocked.

---

## New concept: rate limiting

The original script had no concept of rate limiting. If the same IP triggered
100 detections in 10 minutes, you'd make 100 AbuseIPDB API calls and run
100 iptables commands.

A rate limiter solves this: track how many times you've acted on an IP within
a time window, and skip redundant actions if the limit is reached.

Two strategies are implemented, both with the same interface:

### Sliding window
Tracks timestamps of every event in a rolling window.
Most accurate — no burst tolerance, no approximation.

```
Window: 60 seconds, max 5 hits

t=0s  IP hits → [0]           count=1 ✓
t=10s IP hits → [0, 10]       count=2 ✓
t=30s IP hits → [0, 10, 30]   count=3 ✓
t=61s IP hits → [10, 30, 61]  count=3 ✓  (t=0 fell off)
```

### Token bucket
A bucket starts full. Each request costs a token. Tokens refill at a steady rate.
Allows short bursts without blocking legitimate spikes.

```
Capacity: 5 tokens, refill: 1/sec

t=0s  5 tokens → request uses 1 → 4 remaining ✓
t=0s  4 tokens → request uses 1 → 3 remaining ✓
t=0s  0 tokens → blocked ✗
t=5s  5 tokens → refilled → allowed ✓
```

**Which to use:** Sliding window for strict enforcement (security events).
Token bucket for APIs where short bursts are legitimate (user-facing endpoints).

For this project, `SAL_RL_STRATEGY=sliding_window` is the default.

---

## New concept: event store

The original script printed JSON to stdout and discarded it.
Every run was stateless — no memory of what happened before.

The event store solves this: every alert is appended to `data/events.jsonl`
as a single JSON line.

```jsonl
{"id":1,"type":"ssh_bruteforce","timestamp":"2026-05-06T14:22:01+00:00","ip":"1.2.3.4","severity":"high",...}
{"id":2,"type":"ssh_bruteforce","timestamp":"2026-05-06T14:28:44+00:00","ip":"5.6.7.8","severity":"medium",...}
```

Why JSONL (one JSON object per line) instead of a single JSON array?

- `tail -f data/events.jsonl` streams live events in the terminal
- `grep "high" data/events.jsonl` filters without loading everything into memory
- Appending never rewrites the whole file — safe under concurrent writes
- Drop-in replaceable with SQLite or Postgres later by changing one class

This file becomes the single source of truth that the API, dashboard,
and automation playbooks all read from.

---

## New concept: configuration via environment variables

The original script had constants at the top of the file:

```python
THRESHOLD = 5
WINDOW_MINUTES = 10
BLOCK_DURATION_MINUTES = 30
```

Changing these meant editing source code. That's a problem when:
- You want different settings in dev vs production
- You're running inside Docker (can't edit files easily)
- You want to test with different values without modifying files

`config.py` reads from environment variables with sensible defaults:

```python
BRUTE_FORCE_THRESHOLD = int(os.getenv("SAL_THRESHOLD", "5"))
```

Now changing the threshold is:
```bash
SAL_THRESHOLD=10 python -m security_core.detectors.ssh_bruteforce
```

Or in `docker-compose.yml`:
```yaml
environment:
  SAL_THRESHOLD: "10"
  SAL_DRY_RUN: "true"
```

No code changes needed. This is the standard pattern for any deployable service —
the [12-factor app](https://12factor.net/config) methodology calls this
"store config in the environment."

---

## What the pipeline looks like now

```
auth.log
    │
    ▼
parse_failed_attempts()
    │  time-windowed, allowlist-filtered
    ▼
rate_limiter.check(ip)
    │  sliding window — skip if already acted on recently
    ▼
enricher.enrich(ip)
    │  AbuseIPDB lookup, TTL-cached (1 hour per IP)
    ▼
score(attempts, abuse_score)
    │  risk_score → severity → action
    │
    ├── ignore     → nothing
    ├── alert_only → log + webhook
    └── block_temp → iptables DROP + scheduled rollback + webhook
    │
    ▼
store.append("ssh_bruteforce", alert)
    │  → data/events.jsonl
    ▼
send_webhook(alert, url)
    │  Slack / Discord / n8n
```

Same pipeline as Day 11–13. Now each box is a separate, testable module.

---

## Running it

```bash
# Dry run — no real iptables calls
SAL_DRY_RUN=true python -m security_core.detectors.ssh_bruteforce

# With custom threshold
SAL_DRY_RUN=true SAL_THRESHOLD=3 python -m security_core.detectors.ssh_bruteforce

# Run the test suite
python -m pytest security_core/tests/ -v
```

---

## What this unlocks

With this structure in place, the next steps become straightforward:

- **Day 15** — wrap the event store in a FastAPI REST API (`GET /events`, `GET /stats`, `POST /block/{ip}`)
- **Day 16** — containerise with Docker + add GitHub Actions CI so tests run on every push
- **Day 17** — swap in Redis-backed rate limiting (one file change, same interface)
- **Day 18+** — automation playbooks, Slack alerts, scheduled reports

The refactor wasn't about adding features. It was about building a foundation
that doesn't resist the features that come next.

---

## Lessons

**Separation of concerns is not about elegance — it's about replaceability.**
When AbuseIPDB changes its API, you edit one file. When you add a second
threat intel source, you add one file. When you want to test scoring logic,
you import one function.

**Interfaces matter more than implementations.**
The rate limiter exposes `.check(key)` and `.reset(key)`.
The underlying strategy (sliding window or token bucket) is an implementation detail.
The caller — `ssh_bruteforce.py` — never needs to know which one is running.
This is how you build things that are easy to change later.

**Dry-run mode is not optional for security tooling.**
Any code that touches iptables, sends webhooks, or blocks IPs
must have a safe mode for development and testing.
`SAL_DRY_RUN=true` makes the entire pipeline testable without root access
or a real network.
