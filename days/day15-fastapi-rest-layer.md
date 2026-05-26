# Day 15 — FastAPI REST Layer: Giving the Engine an Interface

## Why an API?

After Day 14, the detection pipeline writes structured events to `data/events.jsonl`.
That file is useful — but only if you can read it.

Right now, reading it means SSH-ing into the server and running `cat` or `grep`.
That's fine for a script. It's not fine for a product.

An API turns the event store into something any client can talk to:
a dashboard, a mobile app, a Slack bot, an n8n workflow, `curl` from your laptop.
You write the interface once. Everything else just calls it.

---

## Why FastAPI specifically

Three reasons over Flask or Django:

**1. Automatic documentation.**
FastAPI reads your function signatures and Pydantic models and generates
interactive API docs at `/docs` (Swagger UI) and `/redoc` with zero extra work.
Every endpoint is immediately testable in a browser.

**2. Type safety through Pydantic.**
You define what a request or response looks like as a Python class.
FastAPI validates incoming JSON against it automatically — wrong types,
missing fields, out-of-range values all return clear error messages
before your code ever runs.

**3. Modern Python.**
FastAPI is built on `async` Python. You don't need async for this project yet,
but the foundation is there when you add WebSockets for a live event feed.

---

## New concept: Pydantic models

Pydantic is a data validation library. You describe the shape of your data
as a class, and Pydantic enforces it.

```python
from pydantic import BaseModel

class BlockRequest(BaseModel):
    duration_min: int = 30

# FastAPI uses this automatically:
# POST /block/1.2.3.4
# Body: {"duration_min": 60}   → valid, duration_min = 60
# Body: {"duration_min": "hi"} → 422 Unprocessable Entity, clear error
# Body: {}                     → valid, duration_min = 30 (default used)
```

This replaces manual `request.json.get(...)` calls and the defensive checks
you'd normally write around them.

Two kinds of Pydantic models in this project:

- **Request models** — validate what comes *in* (`BlockRequest`)
- **Response models** — define what goes *out* (`StatsResponse`, `BlockResponse`)

Response models do something subtle but important: they guarantee your API
never accidentally leaks internal fields. If a field isn't in the model, it
doesn't appear in the response, no matter what your code returns.

---

## New concept: dependency injection (light version)

FastAPI has a full dependency injection system. We're using the simplest form:
module-level singletons.

```python
# Initialised once when the app starts
store        = EventStore(config.EVENTS_DB_FILE)
rate_limiter = build_rate_limiter(...)
```

Both are shared across every request. This matters for the rate limiter —
if each request created its own instance, the hit counts would reset on
every call and the limiter would be useless.

When you add Redis later, you'll swap the rate limiter initialisation here.
No other code changes.

---

## New concept: CORS

CORS (Cross-Origin Resource Sharing) is a browser security policy.
By default, a browser running on `localhost:3000` (your React dashboard)
is not allowed to call an API on `localhost:8000` — different port = different origin.

FastAPI's `CORSMiddleware` adds the right HTTP headers to tell the browser it's allowed:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)
```

This is only needed for browser clients. `curl`, Python scripts, and n8n
don't enforce CORS — they're not browsers.

In production, you'd replace `*` with specific origins. For local dev, this is fine.

---

## The endpoints

| Method | Path | What it does |
|--------|------|--------------|
| `GET` | `/health` | Heartbeat — Docker and CI use this |
| `GET` | `/events` | List alerts, filterable by severity / IP / since |
| `GET` | `/stats` | Summary counts + rate limiter state |
| `POST` | `/block/{ip}` | Manually block an IP via iptables |
| `DELETE` | `/block/{ip}` | Manually unblock an IP |
| `GET` | `/rate-limiter/stats` | Current rate limiter state |
| `POST` | `/rate-limiter/reset/{ip}` | Clear tracking for a specific IP |

### Query parameters

FastAPI makes query parameters trivial:

```python
@app.get("/events")
def get_events(
    severity: Optional[str] = Query(None),
    ip:       Optional[str] = Query(None),
    limit:    int           = Query(100, ge=1, le=1000),
):
```

`ge=1, le=1000` means "greater than or equal to 1, less than or equal to 1000."
FastAPI enforces this and returns a 422 if violated — you write no validation code.

Calling the endpoint:
```
GET /events                          → all events
GET /events?severity=high            → high severity only
GET /events?ip=1.2.3.4              → one IP's history
GET /events?severity=high&limit=10  → top 10 high severity
GET /events?since=2026-05-01T00:00:00 → since a timestamp
```

---

## Running it

```bash
# Install dependencies
pip install -r requirements.txt

# Start the server (from repo root)
uvicorn security_core.api.main:app --reload --port 8000

# --reload watches for file changes and restarts automatically (dev only)
# Remove --reload in production
```

Then open `http://localhost:8000/docs` in a browser.
You'll see every endpoint, its parameters, its response schema,
and a "Try it out" button that lets you call it live.

```bash
# Or use curl
curl http://localhost:8000/health
curl http://localhost:8000/stats
curl "http://localhost:8000/events?severity=high&limit=5"
curl -X POST http://localhost:8000/block/1.2.3.4 \
     -H "Content-Type: application/json" \
     -d '{"duration_min": 15}'
```

---

## Testing the API

FastAPI ships with a `TestClient` that runs your app in-process —
no server needed, no network calls, tests run instantly.

```python
from fastapi.testclient import TestClient
from security_core.api.main import app

client = TestClient(app)

def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
```

The test suite covers all 7 endpoints with 14 test cases.
`SAL_DRY_RUN=true` is set in the test environment so no real iptables calls
are made during testing.

```bash
python -m pytest security_core/tests/test_api.py -v
```

---

## What the API enables

With this running, every other piece of the system becomes simpler:

- **Dashboard** calls `GET /events` on a timer and renders the results — no file access needed
- **n8n playbook** calls `POST /block/{ip}` when a threshold is crossed — no Python needed
- **Slack bot** queries `GET /stats` for a daily digest — one HTTP call
- **External monitoring** hits `GET /health` to confirm the service is alive

The detector writes to the event store. The API reads from it.
Everything else talks to the API. This is the pattern that makes
the whole system composable.

---

## Lessons

**An API is a contract, not an implementation.**
The endpoint `GET /events` returns a list of events. How those events
are stored — JSONL today, SQLite next month, Postgres eventually —
is invisible to the caller. This is why we put the storage logic
in `store/events.py` instead of directly in the API handler.
Callers never change when the implementation changes.

**Validate at the boundary, trust inside.**
Pydantic models catch bad input at the API layer before it reaches
your business logic. Inside `score()`, `block_ip()`, `enrich()` —
you can trust the data is already the right shape.
Don't write the same validation twice.

**`/health` is not optional.**
Every service that runs in a container or behind a load balancer
needs a health endpoint. Docker uses it to know when to restart the container.
The CI pipeline uses it to know the service started correctly.
It's three lines of code and it makes operations dramatically easier.
