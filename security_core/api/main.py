"""
security_core/api/main.py

FastAPI REST layer over security-core.

Run:
    uvicorn security_core.api.main:app --reload --port 8000

Docs auto-generated at:
    http://localhost:8000/docs     (Swagger UI)
    http://localhost:8000/redoc    (ReDoc)
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from security_core import config
from security_core.engine.rate_limiter import build_rate_limiter
from security_core.response.actions import block_ip, unblock_ip
from security_core.store.events import EventStore


# ── App setup ──────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Security Core API",
    description="REST interface for the Security Automation Lab detection engine.",
    version="0.1.0",
)

# Allow the React dashboard (any localhost port) during development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Singletons — shared across requests
store        = EventStore(config.EVENTS_DB_FILE)
rate_limiter = build_rate_limiter(
    config.RATE_LIMIT_STRATEGY,
    config.RATE_LIMIT_MAX_HITS,
    config.RATE_LIMIT_WINDOW_SEC,
)


# ── Request / Response models ──────────────────────────────────────────────────
# Pydantic models do two things: validate incoming JSON and document the API.

class BlockRequest(BaseModel):
    duration_min: int = config.BLOCK_DURATION_MIN


class BlockResponse(BaseModel):
    ip:          str
    action:      str
    success:     bool
    dry_run:     bool
    message:     str
    executed_at: str


class StatsResponse(BaseModel):
    total_events:   int
    high_severity:  int
    medium_severity: int
    low_severity:   int
    blocked_ips:    int
    rate_limiter:   dict
    generated_at:   str


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    """Heartbeat — used by Docker HEALTHCHECK and CI."""
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/events")
def get_events(
    severity: Optional[str] = Query(None, description="Filter: low | medium | high"),
    ip:       Optional[str] = Query(None, description="Filter by specific IP"),
    since:    Optional[str] = Query(None, description="ISO timestamp lower bound"),
    limit:    int           = Query(100, ge=1, le=1000, description="Max results"),
):
    """
    Return stored detection events.

    Examples:
        GET /events
        GET /events?severity=high
        GET /events?ip=1.2.3.4
        GET /events?since=2026-05-01T00:00:00&limit=50
    """
    events = store.read_since(since) if since else store.read_all()

    if severity:
        events = [e for e in events if e.get("severity") == severity]
    if ip:
        events = [e for e in events if e.get("ip") == ip]

    # Most recent first
    events = sorted(events, key=lambda e: e.get("timestamp", ""), reverse=True)

    return {
        "count":  min(len(events), limit),
        "events": events[:limit],
    }


@app.get("/stats", response_model=StatsResponse)
def get_stats():
    """Summary counts — used by the dashboard overview panel."""
    events = store.read_all()

    blocked = [
        e for e in events
        if e.get("response", {}).get("action") == "block_temp"
        and e.get("response", {}).get("success") is True
    ]

    return StatsResponse(
        total_events    = len(events),
        high_severity   = sum(1 for e in events if e.get("severity") == "high"),
        medium_severity = sum(1 for e in events if e.get("severity") == "medium"),
        low_severity    = sum(1 for e in events if e.get("severity") == "low"),
        blocked_ips     = len({e["ip"] for e in blocked}),
        rate_limiter    = rate_limiter.stats(),
        generated_at    = datetime.now(timezone.utc).isoformat(),
    )


@app.post("/block/{ip}", response_model=BlockResponse)
def manual_block(ip: str, body: BlockRequest = BlockRequest()):
    """
    Manually block an IP via iptables.
    Respects SAL_DRY_RUN — safe to call in dev.
    """
    result = block_ip(ip, duration_min=body.duration_min)
    if not result.success:
        raise HTTPException(status_code=500, detail=result.message)

    # Log it as a manual event
    store.append("manual_block", {
        "ip":           ip,
        "duration_min": body.duration_min,
        "dry_run":      result.dry_run,
    })

    return BlockResponse(**result.to_dict())


@app.delete("/block/{ip}", response_model=BlockResponse)
def manual_unblock(ip: str):
    """Immediately remove an iptables DROP rule for this IP."""
    result = unblock_ip(ip)
    if not result.success:
        raise HTTPException(status_code=500, detail=result.message)

    store.append("manual_unblock", {"ip": ip, "dry_run": result.dry_run})

    return BlockResponse(**result.to_dict())


@app.get("/rate-limiter/stats")
def rate_limiter_stats():
    """Current rate limiter state — strategy, window, active tracked IPs."""
    return rate_limiter.stats()


@app.post("/rate-limiter/reset/{ip}")
def rate_limiter_reset(ip: str):
    """Clear rate limit tracking for a specific IP (useful after a manual unblock)."""
    rate_limiter.reset(ip)
    return {"message": f"Rate limit cleared for {ip}"}
