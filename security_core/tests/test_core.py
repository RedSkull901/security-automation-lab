"""
tests/test_rate_limiter.py  &  tests/test_scoring.py
Run with: python -m pytest tests/ -v
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import time
import pytest

from security_core.engine.rate_limiter import (
    SlidingWindowRateLimiter,
    TokenBucketRateLimiter,
    build_rate_limiter,
)
from security_core.engine.scoring import score


# ══════════════════════════════════════════════════════
# Sliding Window tests
# ══════════════════════════════════════════════════════

class TestSlidingWindow:
    def test_allows_up_to_max(self):
        limiter = SlidingWindowRateLimiter(max_hits=3, window_sec=60)
        for _ in range(3):
            assert limiter.check("1.1.1.1").allowed is True

    def test_blocks_on_exceed(self):
        limiter = SlidingWindowRateLimiter(max_hits=3, window_sec=60)
        for _ in range(3):
            limiter.check("1.1.1.1")
        result = limiter.check("1.1.1.1")
        assert result.allowed is False
        assert result.remaining == 0

    def test_different_keys_independent(self):
        limiter = SlidingWindowRateLimiter(max_hits=1, window_sec=60)
        limiter.check("1.1.1.1")
        assert limiter.check("2.2.2.2").allowed is True

    def test_reset_clears_key(self):
        limiter = SlidingWindowRateLimiter(max_hits=1, window_sec=60)
        limiter.check("1.1.1.1")
        assert limiter.check("1.1.1.1").allowed is False
        limiter.reset("1.1.1.1")
        assert limiter.check("1.1.1.1").allowed is True

    def test_window_expiry(self):
        limiter = SlidingWindowRateLimiter(max_hits=1, window_sec=1)
        limiter.check("1.1.1.1")
        assert limiter.check("1.1.1.1").allowed is False
        time.sleep(1.1)
        assert limiter.check("1.1.1.1").allowed is True

    def test_stats_shape(self):
        limiter = SlidingWindowRateLimiter(max_hits=5, window_sec=30)
        limiter.check("x.x.x.x")
        stats = limiter.stats()
        assert stats["strategy"] == "sliding_window"
        assert stats["active_keys"] == 1


# ══════════════════════════════════════════════════════
# Token Bucket tests
# ══════════════════════════════════════════════════════

class TestTokenBucket:
    def test_allows_burst(self):
        limiter = TokenBucketRateLimiter(max_hits=5, window_sec=60)
        for _ in range(5):
            assert limiter.check("1.1.1.1").allowed is True

    def test_blocks_after_burst(self):
        limiter = TokenBucketRateLimiter(max_hits=3, window_sec=60)
        for _ in range(3):
            limiter.check("1.1.1.1")
        assert limiter.check("1.1.1.1").allowed is False

    def test_refill_over_time(self):
        limiter = TokenBucketRateLimiter(max_hits=2, window_sec=1)
        limiter.check("1.1.1.1")
        limiter.check("1.1.1.1")
        assert limiter.check("1.1.1.1").allowed is False
        time.sleep(1.1)
        assert limiter.check("1.1.1.1").allowed is True

    def test_stats_shape(self):
        limiter = TokenBucketRateLimiter(max_hits=10, window_sec=60)
        stats = limiter.stats()
        assert stats["strategy"] == "token_bucket"
        assert "refill_rate" in stats


# ══════════════════════════════════════════════════════
# Factory
# ══════════════════════════════════════════════════════

class TestFactory:
    def test_builds_sliding_window(self):
        l = build_rate_limiter("sliding_window", 10, 60)
        assert isinstance(l, SlidingWindowRateLimiter)

    def test_builds_token_bucket(self):
        l = build_rate_limiter("token_bucket", 10, 60)
        assert isinstance(l, TokenBucketRateLimiter)

    def test_default_is_sliding_window(self):
        l = build_rate_limiter("unknown_strategy", 10, 60)
        assert isinstance(l, SlidingWindowRateLimiter)


# ══════════════════════════════════════════════════════
# Scoring tests
# ══════════════════════════════════════════════════════

class TestScoring:
    def test_low_severity(self):
        result = score(failed_attempts=1, abuse_confidence_score=0)
        assert result.severity == "low"
        assert result.action == "ignore"

    def test_medium_severity(self):
        # risk = 2*10 + 11 = 31 → medium
        result = score(failed_attempts=2, abuse_confidence_score=11)
        assert result.severity == "medium"
        assert result.action == "alert_only"

    def test_high_severity(self):
        # risk = 5*10 + 25 = 75 → high
        result = score(failed_attempts=5, abuse_confidence_score=25)
        assert result.severity == "high"
        assert result.action == "block_temp"

    def test_risk_score_formula(self):
        result = score(failed_attempts=3, abuse_confidence_score=20)
        assert result.risk_score == (3 * 10) + 20  # = 50

    def test_boundary_medium(self):
        # exactly 31 → medium
        result = score(failed_attempts=3, abuse_confidence_score=1)
        assert result.risk_score == 31
        assert result.severity == "medium"

    def test_boundary_high(self):
        # exactly 71 → high
        result = score(failed_attempts=7, abuse_confidence_score=1)
        assert result.risk_score == 71
        assert result.severity == "high"

    def test_to_dict(self):
        result = score(5, 30)
        d = result.to_dict()
        assert "risk_score" in d
        assert "severity" in d
        assert "action" in d
