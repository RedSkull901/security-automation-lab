"""
security_core/engine/rate_limiter.py

Two strategies, same interface:
  - SlidingWindowRateLimiter   (default, accurate)
  - TokenBucketRateLimiter     (burst-friendly)

Both work in-memory today.  When you add Redis, swap _store for a Redis
client and the public API stays identical — callers never change.

Usage:
    limiter = SlidingWindowRateLimiter(max_hits=100, window_sec=60)
    result  = limiter.check("1.2.3.4")

    result.allowed      → bool
    result.current_hits → int
    result.remaining    → int
    result.reset_at     → datetime (when the oldest hit falls off)
"""
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol


# ── Result object ──────────────────────────────────────────────────────────────

@dataclass
class RateLimitResult:
    key:          str
    allowed:      bool
    current_hits: int
    max_hits:     int
    remaining:    int
    window_sec:   int
    reset_at:     datetime | None = None

    def to_dict(self) -> dict:
        return {
            "key":          self.key,
            "allowed":      self.allowed,
            "current_hits": self.current_hits,
            "max_hits":     self.max_hits,
            "remaining":    self.remaining,
            "window_sec":   self.window_sec,
            "reset_at":     self.reset_at.isoformat() if self.reset_at else None,
        }


# ── Strategy protocol (easy to mock in tests) ─────────────────────────────────

class RateLimiterProtocol(Protocol):
    def check(self, key: str) -> RateLimitResult: ...
    def reset(self, key: str) -> None: ...
    def stats(self) -> dict: ...


# ── Sliding Window ─────────────────────────────────────────────────────────────

class SlidingWindowRateLimiter:
    """
    Tracks timestamps of every hit inside a rolling time window.
    Most accurate — no burst bias.

    Storage: { key: deque([timestamp, ...]) }
    """

    def __init__(self, max_hits: int = 100, window_sec: int = 60):
        self.max_hits   = max_hits
        self.window_sec = window_sec
        self._store: dict[str, deque] = defaultdict(deque)

    def check(self, key: str) -> RateLimitResult:
        now    = time.time()
        cutoff = now - self.window_sec
        hits   = self._store[key]

        # evict timestamps outside the window
        while hits and hits[0] < cutoff:
            hits.popleft()

        current = len(hits)
        allowed = current < self.max_hits

        reset_at = None
        if hits:
            reset_at = datetime.fromtimestamp(hits[0] + self.window_sec, tz=timezone.utc)

        if allowed:
            hits.append(now)
            current += 1

        return RateLimitResult(
            key=key,
            allowed=allowed,
            current_hits=current,
            max_hits=self.max_hits,
            remaining=max(0, self.max_hits - current),
            window_sec=self.window_sec,
            reset_at=reset_at,
        )

    def reset(self, key: str) -> None:
        self._store.pop(key, None)

    def stats(self) -> dict:
        return {
            "strategy":   "sliding_window",
            "max_hits":   self.max_hits,
            "window_sec": self.window_sec,
            "active_keys": len(self._store),
        }


# ── Token Bucket ───────────────────────────────────────────────────────────────

class TokenBucketRateLimiter:
    """
    Classic token bucket — allows short bursts up to capacity,
    then refills at a steady rate.

    refill_rate = max_hits / window_sec  (tokens per second)

    Storage: { key: (tokens: float, last_refill_ts: float) }
    """

    def __init__(self, max_hits: int = 100, window_sec: int = 60):
        self.capacity    = float(max_hits)
        self.window_sec  = window_sec
        self.refill_rate = self.capacity / window_sec   # tokens/sec
        self._store: dict[str, list] = {}               # key → [tokens, last_ts]

    def _refill(self, key: str, now: float) -> float:
        if key not in self._store:
            self._store[key] = [self.capacity, now]
            return self.capacity
        tokens, last_ts = self._store[key]
        elapsed = now - last_ts
        tokens  = min(self.capacity, tokens + elapsed * self.refill_rate)
        self._store[key][0] = tokens
        self._store[key][1] = now
        return tokens

    def check(self, key: str) -> RateLimitResult:
        now    = time.time()
        tokens = self._refill(key, now)
        allowed = tokens >= 1.0

        if allowed:
            self._store[key][0] -= 1.0
            tokens -= 1.0

        return RateLimitResult(
            key=key,
            allowed=allowed,
            current_hits=int(self.capacity - tokens),
            max_hits=int(self.capacity),
            remaining=int(tokens),
            window_sec=self.window_sec,
        )

    def reset(self, key: str) -> None:
        self._store.pop(key, None)

    def stats(self) -> dict:
        return {
            "strategy":    "token_bucket",
            "capacity":    int(self.capacity),
            "refill_rate": round(self.refill_rate, 4),
            "window_sec":  self.window_sec,
            "active_keys": len(self._store),
        }


# ── Factory ────────────────────────────────────────────────────────────────────

def build_rate_limiter(strategy: str, max_hits: int, window_sec: int) -> RateLimiterProtocol:
    if strategy == "token_bucket":
        return TokenBucketRateLimiter(max_hits=max_hits, window_sec=window_sec)
    return SlidingWindowRateLimiter(max_hits=max_hits, window_sec=window_sec)
