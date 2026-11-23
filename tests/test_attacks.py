from __future__ import annotations

import logging

import pytest

from securepay.attacks import simulator
from securepay.attacks.simulator import (
    CASES,
    HIGH_IMPACT,
    LogCapture,
    result_level,
    run_all,
    run_case,
)
from securepay.errors import FramingError, ReplayError


@pytest.mark.slow
def test_all_attacks_blocked() -> None:
    results = run_all(fast=True)
    failed = [(r.name, r.detail) for r in results if not r.passed]
    assert not failed, f"attacks that were NOT blocked: {failed}"
    assert len(results) == len(CASES)


@pytest.mark.slow
@pytest.mark.parametrize("name", sorted(CASES))
def test_single_attack(name: str) -> None:
    result = run_case(name, fast=True)
    assert result.passed, f"{name}: {result.detail}"


def test_severity_tables_cover_the_registry() -> None:
    assert set(CASES) >= HIGH_IMPACT
    assert set(simulator._PROPERTY) == set(CASES)


def test_result_level_tiers() -> None:
    assert result_level("bit-flip", True, "ok") == logging.WARNING
    assert result_level("downgrade", True, "ok") == logging.ERROR
    assert result_level("bit-flip", False, "attack was NOT blocked") == logging.ERROR
    assert result_level("bit-flip", False, "harness error: boom") == logging.ERROR


def test_log_capture_waits_for_the_expected_event() -> None:
    capture = LogCapture()
    log = logging.getLogger("securepay.test_capture")
    log.addHandler(capture)
    try:
        assert "expected log not seen" in capture.expect("code=replay_detected", timeout=0.1)
        log.warning("event=session_failed peer=%s code=%s", "902101", "replay_detected")
        log.info("event=session_open")
        assert capture.expect("event=session_failed", "code=replay_detected") == ""
        assert "need 2" in capture.expect("code=replay_detected", count=2, timeout=0.1)
    finally:
        log.removeHandler(capture)


def test_a_timeout_is_not_counted_as_a_block() -> None:
    def times_out() -> None:
        raise FramingError("frame transport timeout")

    def rejected() -> None:
        raise ReplayError("counter 1 already consumed")

    def accepted() -> None:
        return None

    assert "timed out" in simulator._expect_blocked(times_out)
    assert simulator._expect_blocked(rejected) == ""
    assert "NOT blocked" in simulator._expect_blocked(accepted)
