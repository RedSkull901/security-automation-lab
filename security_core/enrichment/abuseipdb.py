"""
security_core/enrichment/abuseipdb.py

AbuseIPDB threat intelligence enrichment.
- In-memory TTL cache so we don't hammer the API on repeated IPs
- Returns a typed EnrichmentResult (easy to add more providers later)
"""
import time
from dataclasses import dataclass, field, asdict
from typing import Optional
import requests

from security_core.config import ABUSEIPDB_URL, ABUSEIPDB_MAX_AGE_DAYS


CACHE_TTL_SEC = 3600  # re-query after 1 hour


@dataclass
class EnrichmentResult:
    ip:                     str
    abuse_confidence_score: int   = 0
    country:                Optional[str] = None
    is_whitelisted:         Optional[bool] = None
    total_reports:          int   = 0
    last_reported_at:       Optional[str] = None
    source:                 str   = "abuseipdb"
    cached:                 bool  = False
    error:                  Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


class AbuseIPDBEnricher:
    def __init__(self, api_key: Optional[str]):
        self.api_key = api_key
        self._cache: dict[str, tuple[float, EnrichmentResult]] = {}

    def enrich(self, ip: str) -> EnrichmentResult:
        # ── Cache hit ──
        if ip in self._cache:
            cached_at, result = self._cache[ip]
            if time.time() - cached_at < CACHE_TTL_SEC:
                result.cached = True
                return result

        # ── No API key → neutral result ──
        if not self.api_key:
            result = EnrichmentResult(ip=ip, error="no_api_key")
            self._cache[ip] = (time.time(), result)
            return result

        # ── Live query ──
        try:
            resp = requests.get(
                ABUSEIPDB_URL,
                headers={"Key": self.api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": ABUSEIPDB_MAX_AGE_DAYS},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})

            result = EnrichmentResult(
                ip=ip,
                abuse_confidence_score=data.get("abuseConfidenceScore", 0),
                country=data.get("countryCode"),
                is_whitelisted=data.get("isWhitelisted"),
                total_reports=data.get("totalReports", 0),
                last_reported_at=data.get("lastReportedAt"),
            )

        except requests.RequestException as exc:
            result = EnrichmentResult(ip=ip, error=str(exc))

        self._cache[ip] = (time.time(), result)
        return result

    def cache_size(self) -> int:
        return len(self._cache)

    def flush_cache(self) -> None:
        self._cache.clear()
