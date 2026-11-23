from __future__ import annotations

from pathlib import Path

import pytest

from securepay.errors import RateLimitError
from securepay.ratelimit import AttemptTracker, TokenBucket, generate_passphrase


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_token_bucket_allows_burst_then_throttles() -> None:
    clock = FakeClock()
    bucket = TokenBucket(rate_per_second=1.0, capacity=3, now_fn=clock)
    assert bucket.allow()
    assert bucket.allow()
    assert bucket.allow()
    assert not bucket.allow()
    clock.advance(0.5)
    assert not bucket.allow()
    clock.advance(0.5)
    assert bucket.allow()


def test_token_bucket_caps_refill_at_capacity() -> None:
    clock = FakeClock()
    bucket = TokenBucket(rate_per_second=10.0, capacity=2, now_fn=clock)
    clock.advance(100.0)
    assert bucket.allow()
    assert bucket.allow()
    assert not bucket.allow()


def test_attempt_tracker_locks_out(tmp_path: Path) -> None:
    tracker = AttemptTracker(tmp_path / "vault.attempts", max_failures=3, lockout_seconds=60)
    for _ in range(3):
        tracker.record_failure()
    with pytest.raises(RateLimitError):
        tracker.ensure_unlocked()
    assert 0 < tracker.locked_for_seconds() <= 60


def test_attempt_tracker_resets_on_success(tmp_path: Path) -> None:
    tracker = AttemptTracker(tmp_path / "vault.attempts", max_failures=3, lockout_seconds=60)
    tracker.record_failure()
    tracker.record_failure()
    tracker.record_success()
    assert tracker.record_failure() == 1


def test_attempt_tracker_state_persists(tmp_path: Path) -> None:
    path = tmp_path / "vault.attempts"
    first = AttemptTracker(path, max_failures=2, lockout_seconds=60)
    first.record_failure()
    second = AttemptTracker(path, max_failures=2, lockout_seconds=60)
    second.record_failure()
    with pytest.raises(RateLimitError):
        second.ensure_unlocked()


def test_attempt_tracker_fails_closed_on_corrupt_state(tmp_path: Path) -> None:
    path = tmp_path / "vault.attempts"
    path.write_text("{not json", encoding="utf-8")
    tracker = AttemptTracker(path, max_failures=2, lockout_seconds=60)
    with pytest.raises(RateLimitError):
        tracker.ensure_unlocked()


def test_generate_passphrase_is_long_and_unique() -> None:
    a, b = generate_passphrase(), generate_passphrase()
    assert a != b
    assert len(a) >= 32
    assert all(ch in "0123456789abcdef" for ch in a)
