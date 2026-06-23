"""Shared pytest fixtures for the detection test layer.

Locates the Hayabusa binary (env override HAYABUSA_BIN, else PATH) and exposes
a runner that executes a single Sigma rule against one EVTX file and returns the
parsed JSON detections.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
DETECTIONS = REPO / "detections"
FIXTURES = REPO / "tests" / "fixtures"


def _find_hayabusa() -> str | None:
    return os.environ.get("HAYABUSA_BIN") or shutil.which("hayabusa")


HAYABUSA = _find_hayabusa()
requires_hayabusa = pytest.mark.skipif(
    HAYABUSA is None, reason="hayabusa binary not found (set HAYABUSA_BIN or add to PATH)"
)


def run_rule_against_evtx(rule: Path, evtx: Path) -> list[dict]:
    """Run a single rule over one EVTX, return Hayabusa JSON detections."""
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "out.json"
        cmd = [
            HAYABUSA, "json-timeline",
            "-f", str(evtx),
            "-r", str(rule),
            "-o", str(out),
            "-J", "-w", "-q",
            "--no-wizard",
        ]
        subprocess.run(cmd, cwd=REPO, check=True, capture_output=True, text=True)
        if not out.exists() or out.stat().st_size == 0:
            return []
        records = []
        for line in out.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                records.append(json.loads(line))
        return records


@pytest.fixture
def rule_runner():
    return run_rule_against_evtx
