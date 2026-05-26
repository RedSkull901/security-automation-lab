"""
security_core/tests/test_api.py

FastAPI endpoint tests using TestClient — no real server needed.
Run: python -m pytest security_core/tests/ -v
"""
import json
import sys
import os
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

# Point the event store at a temp file before importing the app
tmp = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
os.environ["SAL_EVENTS_DB"] = tmp.name
os.environ["SAL_DRY_RUN"]   = "true"

from fastapi.testclient import TestClient
from security_core.api.main import app, store

client = TestClient(app)


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clear_store():
    """Wipe the event store before each test."""
    open(tmp.name, "w").close()
    yield


def _seed(event_type="ssh_bruteforce", **kwargs):
    defaults = {
        "ip": "1.2.3.4", "severity": "high",
        "risk_score": 80, "action": "block_temp",
        "failed_attempts": 8,
        "response": {"action": "block_temp", "success": True, "dry_run": True},
    }
    store.append(event_type, {**defaults, **kwargs})


# ── /health ────────────────────────────────────────────────────────────────────

def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ── /events ────────────────────────────────────────────────────────────────────

def test_events_empty():
    r = client.get("/events")
    assert r.status_code == 200
    assert r.json()["count"] == 0

def test_events_returns_seeded():
    _seed()
    r = client.get("/events")
    assert r.json()["count"] == 1
    assert r.json()["events"][0]["ip"] == "1.2.3.4"

def test_events_filter_severity():
    _seed(severity="high")
    _seed(ip="5.5.5.5", severity="low")
    r = client.get("/events?severity=high")
    assert r.json()["count"] == 1
    assert r.json()["events"][0]["severity"] == "high"

def test_events_filter_ip():
    _seed(ip="9.9.9.9")
    _seed(ip="8.8.8.8")
    r = client.get("/events?ip=9.9.9.9")
    assert r.json()["count"] == 1

def test_events_limit():
    for _ in range(5):
        _seed()
    r = client.get("/events?limit=3")
    assert r.json()["count"] == 3


# ── /stats ─────────────────────────────────────────────────────────────────────

def test_stats_empty():
    r = client.get("/stats")
    assert r.status_code == 200
    data = r.json()
    assert data["total_events"] == 0
    assert "rate_limiter" in data

def test_stats_counts():
    _seed(severity="high")
    _seed(ip="2.2.2.2", severity="medium",
          response={"action": "alert_only", "success": True, "dry_run": True})
    _seed(ip="3.3.3.3", severity="low",
          response={"action": "ignore", "success": True, "dry_run": True})
    r = client.get("/stats")
    data = r.json()
    assert data["total_events"] == 3
    assert data["high_severity"] == 1
    assert data["medium_severity"] == 1
    assert data["low_severity"] == 1
    assert data["blocked_ips"] == 1   # only the high one was block_temp+success


# ── /block & /block DELETE ─────────────────────────────────────────────────────

def test_manual_block(monkeypatch):
    r = client.post("/block/10.0.0.1", json={"duration_min": 5})
    assert r.status_code == 200
    data = r.json()
    assert data["ip"] == "10.0.0.1"
    assert data["dry_run"] is True       # SAL_DRY_RUN=true
    assert data["success"] is True

def test_manual_unblock():
    r = client.delete("/block/10.0.0.1")
    assert r.status_code == 200
    assert r.json()["action"] == "unblock"


# ── /rate-limiter ──────────────────────────────────────────────────────────────

def test_rate_limiter_stats():
    r = client.get("/rate-limiter/stats")
    assert r.status_code == 200
    assert "strategy" in r.json()

def test_rate_limiter_reset():
    r = client.post("/rate-limiter/reset/1.2.3.4")
    assert r.status_code == 200
    assert "cleared" in r.json()["message"]
