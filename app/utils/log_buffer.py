"""
In-memory ring buffer of recent log records, so the super admin portal can
show "general web app logs" (the developer's own request) without needing
shell/SSH access to the server to `tail` a file.

Deliberately in-memory and bounded (not written to disk, not a replacement
for real log aggregation in a multi-instance production deployment) -- for a
single-process final-year-project deployment this is enough to see recent
errors/warnings (e.g. the IMAP timeout messages) straight from the browser.
"""

from __future__ import annotations

import logging
from collections import deque
from datetime import datetime, timezone

_MAX_RECORDS = 500
_buffer: deque[dict] = deque(maxlen=_MAX_RECORDS)


class RingBufferHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            _buffer.appendleft({
                "time": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="seconds"),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            })
        except Exception:  # pragma: no cover - a logging handler must never raise
            pass


def install(app_logger_names: tuple[str, ...] = ("ietds",)) -> None:
    """Attach the ring buffer to the app's own loggers (the `ietds.*` hierarchy)."""
    handler = RingBufferHandler()
    handler.setLevel(logging.INFO)
    for name in app_logger_names:
        logging.getLogger(name).addHandler(handler)


def recent(limit: int = 200, level: str | None = None) -> list[dict]:
    records = list(_buffer)
    if level:
        records = [r for r in records if r["level"] == level.upper()]
    return records[:limit]


def clear() -> None:  # pragma: no cover - convenience for tests
    _buffer.clear()
