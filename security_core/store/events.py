"""
security_core/store/events.py

Append-only JSONL event store.
Each line is one JSON event — easy to tail, grep, and later replace with
SQLite or Postgres without changing callers.
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class EventStore:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event_type: str, data: dict[str, Any]) -> dict:
        event = {
            "id":         self._next_id(),
            "type":       event_type,
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            **data,
        }
        with open(self.path, "a") as f:
            f.write(json.dumps(event) + "\n")
        return event

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        events = []
        with open(self.path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return events

    def read_since(self, since_iso: str) -> list[dict]:
        """Return events with timestamp >= since_iso."""
        return [e for e in self.read_all() if e.get("timestamp", "") >= since_iso]

    def _next_id(self) -> int:
        try:
            lines = self.path.read_text().strip().splitlines()
            return len(lines) + 1
        except FileNotFoundError:
            return 1
