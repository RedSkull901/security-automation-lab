"""
security_core/tests/test_triage.py

Tests for the AI triage module.
Mocks all Ollama HTTP calls — no real LLM needed in CI.
"""
import sys
import os
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from security_core.automations.triage import TriageEngine, TriageResult, build_prompt


@pytest.fixture
def sample_alert():
    return {
        "ip":                     "5.6.7.8",
        "failed_attempts":        15,
        "abuse_confidence_score": 92,
        "country":                "RU",
        "risk_score":             242,
        "severity":               "high",
        "action":                 "block_temp",
        "total_reports":          67,
        "last_reported_at":       "2026-05-25T10:00:00+00:00",
    }


class TestBuildPrompt:
    def test_contains_ip(self, sample_alert):
        prompt = build_prompt(sample_alert)
        assert "5.6.7.8" in prompt

    def test_contains_attempts(self, sample_alert):
        prompt = build_prompt(sample_alert)
        assert "15" in prompt

    def test_contains_abuse_score(self, sample_alert):
        prompt = build_prompt(sample_alert)
        assert "92%" in prompt

    def test_contains_country(self, sample_alert):
        prompt = build_prompt(sample_alert)
        assert "RU" in prompt

    def test_contains_structure_headers(self, sample_alert):
        prompt = build_prompt(sample_alert)
        assert "INCIDENT:" in prompt
        assert "RISK:" in prompt
        assert "RECOMMENDED NEXT STEPS:" in prompt

    def test_block_temp_label(self, sample_alert):
        prompt = build_prompt(sample_alert)
        assert "blocked" in prompt.lower()

    def test_alert_only_label(self, sample_alert):
        sample_alert["action"] = "alert_only"
        prompt = build_prompt(sample_alert)
        assert "no block" in prompt.lower()


class TestTriageEngine:
    def test_is_available_true(self):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = {
            "models": [{"name": "llama3.2:3b"}]
        }
        with patch("requests.get", return_value=mock_resp):
            engine = TriageEngine(model="llama3.2:3b")
            assert engine.is_available() is True

    def test_is_available_false_no_model(self):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = {"models": []}
        with patch("requests.get", return_value=mock_resp):
            engine = TriageEngine(model="llama3.2:3b")
            assert engine.is_available() is False

    def test_is_available_false_connection_error(self):
        with patch("requests.get", side_effect=Exception("connection refused")):
            engine = TriageEngine()
            assert engine.is_available() is False

    def test_analyze_success(self, sample_alert):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "response": "INCIDENT: Brute force detected.\nRISK: High.\nACTIONS TAKEN: Blocked.\nRECOMMENDED NEXT STEPS:\n1. Monitor.\n2. Review.\n3. Report."
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_resp):
            engine = TriageEngine()
            result = engine.analyze(sample_alert)

        assert result.success is True
        assert result.ip == "5.6.7.8"
        assert "INCIDENT" in result.summary
        assert result.error is None
        assert result.duration_sec >= 0

    def test_analyze_empty_response(self, sample_alert):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = {"response": ""}
        mock_resp.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_resp):
            engine = TriageEngine()
            result = engine.analyze(sample_alert)

        assert result.success is False
        assert result.error == "empty_response"

    def test_analyze_timeout(self, sample_alert):
        import requests as req
        with patch("requests.post", side_effect=req.Timeout()):
            engine = TriageEngine()
            result = engine.analyze(sample_alert)

        assert result.success is False
        assert "timeout" in result.error

    def test_analyze_connection_error(self, sample_alert):
        with patch("requests.post", side_effect=Exception("connection refused")):
            engine = TriageEngine()
            result = engine.analyze(sample_alert)

        assert result.success is False
        assert result.error is not None

    def test_to_dict_shape(self, sample_alert):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = {"response": "INCIDENT: Test."}
        mock_resp.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_resp):
            engine = TriageEngine()
            result = engine.analyze(sample_alert)

        d = result.to_dict()
        assert "ip" in d
        assert "model" in d
        assert "summary" in d
        assert "duration_sec" in d
        assert "success" in d

    def test_batch_analyze(self, sample_alert):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = {"response": "INCIDENT: Test."}
        mock_resp.raise_for_status = MagicMock()

        alerts = [sample_alert, {**sample_alert, "ip": "9.9.9.9"}]

        with patch("requests.post", return_value=mock_resp):
            engine = TriageEngine()
            results = engine.batch_analyze(alerts)

        assert len(results) == 2
        assert results[0].ip == "5.6.7.8"
        assert results[1].ip == "9.9.9.9"
