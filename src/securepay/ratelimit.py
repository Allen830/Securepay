from __future__ import annotations

import json
import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from securepay import config
from securepay.errors import RateLimitError

__all__ = ["AttemptTracker", "TokenBucket", "generate_passphrase"]


def generate_passphrase() -> str:
    return uuid.uuid4().hex + uuid.uuid4().hex[:8]


class TokenBucket:

    def __init__(
        self,
        rate_per_second: float,
        capacity: int,
        now_fn: Callable[[], float] = time.monotonic,
    ) -> None:
        if rate_per_second <= 0 or capacity <= 0:
            raise ValueError("rate and capacity must be positive")
        self._rate = float(rate_per_second)
        self._capacity = float(capacity)
        self._tokens = float(capacity)
        self._now = now_fn
        self._last = now_fn()
        self._lock = threading.Lock()

    def allow(self, amount: float = 1.0) -> bool:
        with self._lock:
            current_time = self._now()
            elapsed_seconds = max(0.0, current_time - self._last)
            self._last = current_time
            self._tokens = min(self._capacity, self._tokens + elapsed_seconds * self._rate)
            if self._tokens >= amount:
                self._tokens -= amount
                return True
            return False


class AttemptTracker:

    def __init__(
        self,
        path: Path | None,
        *,
        max_failures: int | None = None,
        lockout_seconds: int | None = None,
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        self._path = path
        self._max_failures = config.UNLOCK_MAX_FAILURES if max_failures is None else max_failures
        self._lockout_seconds = (
            config.UNLOCK_LOCKOUT_SECONDS if lockout_seconds is None else lockout_seconds
        )
        self._now = now_fn
        self._lock = threading.Lock()


    def _load(self) -> dict[str, Any]:
        if self._path is None or not self._path.exists():
            return {"failures": 0, "locked_until": 0}
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            failures = int(data["failures"])
            locked_until = float(data["locked_until"])
            if failures < 0 or locked_until < 0:
                raise ValueError("negative values")
            return {"failures": failures, "locked_until": locked_until}
        except (ValueError, KeyError, TypeError, OSError):
            return {
                "failures": self._max_failures,
                "locked_until": self._now() + self._lockout_seconds,
            }

    def _save(self, state: dict[str, Any]) -> None:
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = self._path.with_suffix(".tmp")
        temporary_path.write_text(json.dumps(state), encoding="utf-8")
        temporary_path.replace(self._path)


    def locked_for_seconds(self) -> int:
        with self._lock:
            state = self._load()
            remaining = state["locked_until"] - self._now()
            return max(0, int(remaining))

    def ensure_unlocked(self) -> None:
        with self._lock:
            remaining = self._load()["locked_until"] - self._now()
            if remaining > 0:
                raise RateLimitError(
                    f"locked out for another {int(remaining)}s after repeated failures"
                )

    def record_failure(self) -> int:
        with self._lock:
            state = self._load()
            state["failures"] += 1
            if state["failures"] >= self._max_failures:
                state["locked_until"] = self._now() + self._lockout_seconds
                state["failures"] = 0
            self._save(state)
            return state["failures"]

    def record_success(self) -> None:
        with self._lock:
            self._save({"failures": 0, "locked_until": 0})
