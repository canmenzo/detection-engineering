"""Shared pytest fixtures for the detection test layer.

Test data is NOT vendored. Each rule's tests/fixtures/<stem>/sample_sources.yml
pins public EVTX samples to an immutable commit + sha256; conftest downloads them
to a local cache and runs Hayabusa against the rule. See docs/adr/0002.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
DETECTIONS = REPO / "detections"
FIXTURES = REPO / "tests" / "fixtures"
CACHE = REPO / "tests" / ".sample_cache"

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
HITS_RE = re.compile(r"Events with hits\s*/\s*Total events:\s*(\d+)\s*/\s*(\d+)")


def _find_hayabusa() -> str | None:
    return os.environ.get("HAYABUSA_BIN") or shutil.which("hayabusa")


HAYABUSA = _find_hayabusa()
requires_hayabusa = pytest.mark.skipif(
    HAYABUSA is None, reason="hayabusa binary not found (set HAYABUSA_BIN or add to PATH)"
)


def fetch_sample(sample: dict) -> Path:
    """Download a pinned sample to the cache (keyed by sha256) and verify it."""
    sha = sample["sha256"].lower()
    CACHE.mkdir(parents=True, exist_ok=True)
    dest = CACHE / f"{sha}.evtx"
    if dest.exists() and hashlib.sha256(dest.read_bytes()).hexdigest() == sha:
        return dest
    quoted = urllib.parse.quote(sample["path"])
    url = f"https://raw.githubusercontent.com/{sample['repo']}/{sample['commit']}/{quoted}"
    with urllib.request.urlopen(url, timeout=60) as resp:
        data = resp.read()
    got = hashlib.sha256(data).hexdigest()
    if got != sha:
        raise AssertionError(f"sha256 mismatch for {sample['path']}: {got} != {sha}")
    dest.write_bytes(data)
    return dest


def count_hits(rule: Path, evtx: Path) -> int:
    """Run one rule against one EVTX and return the number of events with hits.

    Channel filtering is disabled (-a): each test targets a single rule at a
    single curated sample, so we let the rule's field logic decide matches.
    """
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "out.json"
        # Run from the binary's dir so Hayabusa finds its bundled ./rules/config.
        hb_dir = Path(HAYABUSA).resolve().parent
        proc = subprocess.run(
            [HAYABUSA, "json-timeline", "-f", str(evtx), "-r", str(rule),
             "-o", str(out), "-w", "-a", "-C", "-K"],
            cwd=hb_dir, capture_output=True, text=True,
            encoding="utf-8", errors="replace",
        )
    text = ANSI_RE.sub("", proc.stdout + proc.stderr)
    m = HITS_RE.search(text)
    if not m:
        raise AssertionError(f"could not parse Hayabusa summary:\n{text[-2000:]}")
    return int(m.group(1))


@pytest.fixture
def hit_counter():
    return count_hits
