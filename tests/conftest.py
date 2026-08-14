"""Pytest wiring for the detection test layer.

The harness itself lives in tests/harness.py; importing it here means a broken
engine configuration fails at collection rather than degrading to skips.
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from harness import REQUIRE_HAYABUSA, count_hits

_skipped: list[str] = []


@pytest.fixture
def hit_counter() -> Callable[[Path, Path], int]:
    return count_hits


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    if report.skipped and report.when == "setup":
        _skipped.append(report.nodeid)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Under DETKIT_REQUIRE_HAYABUSA, any skip fails the run.

    Guards the case the import-time check cannot see: a rule quietly marked
    `@pytest.mark.skip` to get a red build green again.
    """
    if REQUIRE_HAYABUSA and _skipped:
        print(f"\nERROR: {len(_skipped)} test(s) skipped while DETKIT_REQUIRE_HAYABUSA is set:")
        for nodeid in _skipped:
            print(f"  - {nodeid}")
        session.exitstatus = 1
