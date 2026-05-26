"""
security_core/tests/test_automations.py

Tests for Discord notifier and playbook logic.
All external calls (Discord webhook, API block) are mocked —
no real network calls during testing.
"""
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from security_core.automations.discord_notify import build_embed, send_alert, send_digest
from security_core.automations.playbook import run_once, read_cursor, write_cursor
from security_core.store.events import EventStore


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_alert():
    return {
        "ip":                     "1.2.3.4",
        "severity":               "high",
        "action":                 "block_temp",
        "failed_attempts":        12,
        "risk_score":             145,
        "abuse_confidence_score": 87,
        "country":                "CN",
        "total_reports":          42,
        "timestamp":              datetime.now(timezone.utc).isoformat(),
    }


@pytest.fixture
def temp_store(tmp_path):
    store = EventStore(str(tmp_path / "events.jsonl"))
    return store


@pytest.fixture
def temp_cursor(tmp_path, monkeypatch):
    cursor_path = str(tmp_path / "cursor.txt")
    monkeypatch.setenv("SAL_CURSOR_FILE", cursor_path)
    return cursor_path


# ══════════════════════════════════════════════════════
# Discord embed builder
# ══════════════════════════════════════════════════════

class TestBuildEmbed:
    def test_has_required_fields(self, sample_alert):
        embed = build_embed(sample_alert)
        assert "title" in embed
        assert "color" in embed
        assert "fields" in embed
        assert "timestamp" in embed

    def test_high_severity_is_red(self, sample_alert):
        embed = build_embed(sample_alert)
        assert embed["color"] == 15158332   # red

    def test_medium_severity_is_orange(self, sample_alert):
        sample_alert["severity"] = "medium"
        embed = build_embed(sample_alert)
        assert embed["color"] == 15105570   # orange

    def test_ip_appears_in_fields(self, sample_alert):
        embed = build_embed(sample_alert)
        field_values = [f["value"] for f in embed["fields"]]
        assert any("1.2.3.4" in v for v in field_values)

    def test_country_field_included_when_present(self, sample_alert):
        embed = build_embed(sample_alert)
        field_names = [f["name"] for f in embed["fields"]]
        assert "Country" in field_names

    def test_country_field_omitted_when_absent(self, sample_alert):
        del sample_alert["country"]
        embed = build_embed(sample_alert)
        field_names = [f["name"] for f in embed["fields"]]
        assert "Country" not in field_names


# ══════════════════════════════════════════════════════
# Discord send_alert
# ══════════════════════════════════════════════════════

class TestSendAlert:
    def test_returns_error_when_no_url(self, sample_alert, monkeypatch):
        monkeypatch.delenv("DISCORD_WEBHOOK_URL", raising=False)
        # Ensure config file doesn't exist either
        with patch("builtins.open", side_effect=FileNotFoundError):
            result = send_alert(sample_alert, webhook_url=None)
        assert result["success"] is False
        assert result["error"] == "no_discord_webhook_url"

    def test_sends_with_explicit_url(self, sample_alert):
        mock_resp = MagicMock()
        mock_resp.status_code = 204

        with patch("requests.post", return_value=mock_resp) as mock_post:
            result = send_alert(sample_alert, webhook_url="https://discord.com/fake")

        assert result["success"] is True
        assert result["status_code"] == 204
        # Verify payload structure
        call_kwargs = mock_post.call_args
        payload = call_kwargs[1]["json"]
        assert "embeds" in payload
        assert payload["username"] == "Security Core"

    def test_handles_request_exception(self, sample_alert):
        with patch("requests.post", side_effect=Exception("timeout")):
            result = send_alert(sample_alert, webhook_url="https://discord.com/fake")
        assert result["success"] is False
        assert result["error"] is not None


# ══════════════════════════════════════════════════════
# Playbook cursor
# ══════════════════════════════════════════════════════

class TestCursor:
    def test_read_returns_epoch_when_missing(self, tmp_path, monkeypatch):
        cursor_path = str(tmp_path / "nonexistent_cursor.txt")
        monkeypatch.setenv("SAL_CURSOR_FILE", cursor_path)
        # Re-import to pick up new env var
        import importlib
        import security_core.automations.playbook as pb
        importlib.reload(pb)
        ts = pb.read_cursor()
        assert ts == "1970-01-01T00:00:00+00:00"

    def test_write_then_read(self, tmp_path, monkeypatch):
        cursor_path = str(tmp_path / "cursor.txt")
        monkeypatch.setenv("SAL_CURSOR_FILE", cursor_path)
        import importlib
        import security_core.automations.playbook as pb
        importlib.reload(pb)
        ts = "2026-05-06T12:00:00+00:00"
        pb.write_cursor(ts)
        assert pb.read_cursor() == ts


# ══════════════════════════════════════════════════════
# Playbook run_once
# ══════════════════════════════════════════════════════

class TestPlaybookRunOnce:
    def test_no_events_returns_zero(self, temp_store, temp_cursor):
        result = run_once(temp_store, dry_run=True)
        assert result["new_events_found"] == 0
        assert result["notified"] == []
        assert result["blocked"] == []

    def test_high_severity_triggers_notify_and_block(self, temp_store, temp_cursor):
        temp_store.append("ssh_bruteforce", {
            "ip": "9.9.9.9", "severity": "high",
            "action": "block_temp", "failed_attempts": 10,
            "risk_score": 130, "abuse_confidence_score": 80,
        })
        result = run_once(temp_store, dry_run=True)
        assert result["new_events_found"] == 1
        assert any("9.9.9.9" in str(n) for n in result["notified"])
        assert any("9.9.9.9" in str(b) for b in result["blocked"])

    def test_medium_severity_notifies_but_not_blocks(self, temp_store, temp_cursor):
        temp_store.append("ssh_bruteforce", {
            "ip": "8.8.8.8", "severity": "medium",
            "action": "alert_only", "failed_attempts": 6,
            "risk_score": 60, "abuse_confidence_score": 0,
        })
        result = run_once(temp_store, dry_run=True)
        assert any("8.8.8.8" in str(n) for n in result["notified"])
        assert not any("8.8.8.8" in str(b) for b in result["blocked"])

    def test_low_severity_ignored(self, temp_store, temp_cursor):
        temp_store.append("ssh_bruteforce", {
            "ip": "7.7.7.7", "severity": "low",
            "action": "ignore", "failed_attempts": 2,
            "risk_score": 20, "abuse_confidence_score": 0,
        })
        result = run_once(temp_store, dry_run=True)
        assert result["notified"] == []
        assert result["blocked"] == []

    def test_cursor_advances_after_run(self, temp_store, temp_cursor):
        temp_store.append("ssh_bruteforce", {
            "ip": "5.5.5.5", "severity": "high",
            "action": "block_temp", "failed_attempts": 8,
            "risk_score": 90, "abuse_confidence_score": 10,
        })
        before = read_cursor()
        run_once(temp_store, dry_run=True)
        after = read_cursor()
        assert after > before

    def test_does_not_reprocess_old_events(self, temp_store, temp_cursor):
        temp_store.append("ssh_bruteforce", {
            "ip": "6.6.6.6", "severity": "high",
            "action": "block_temp", "failed_attempts": 8,
            "risk_score": 90, "abuse_confidence_score": 10,
        })
        # Run once — processes the event
        first = run_once(temp_store, dry_run=True)
        # Run again — cursor advanced, nothing new
        second = run_once(temp_store, dry_run=True)
        assert first["new_events_found"] == 1
        assert second["new_events_found"] == 0
