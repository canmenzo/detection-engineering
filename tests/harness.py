"""The Hayabusa test harness: locating the engine, fetching samples, counting hits.

Test data is NOT vendored. Each rule's tests/fixtures/<stem>/sample_sources.yml
pins public EVTX samples to an immutable commit + sha256; samples are downloaded
to a local cache and Hayabusa is run against the rule. See docs/adr/0002.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from detkit.paths import REPO

CACHE = REPO / "tests" / ".sample_cache"

FETCH_ATTEMPTS = 3
FETCH_BACKOFF_SECONDS = 2

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
HITS_RE = re.compile(r"Events with hits\s*/\s*Total events:\s*(\d+)\s*/\s*(\d+)")

# CI sets this. When set, a missing test engine is a build failure rather than a
# silent skip — without it, `pytest` exits 0 having verified nothing at all.
REQUIRE_HAYABUSA = os.environ.get("DETKIT_REQUIRE_HAYABUSA", "").lower() in {"1", "true", "yes"}


def _find_hayabusa() -> str | None:
    explicit = os.environ.get("HAYABUSA_BIN")
    if explicit:
        # A set-but-wrong path is a broken harness, not a missing one. Fail loudly
        # even when Hayabusa is optional, or a bad CI install degrades to "skipped".
        if not Path(explicit).is_file():
            raise RuntimeError(f"HAYABUSA_BIN is set but not a file: {explicit!r}")
        return explicit
    return shutil.which("hayabusa")


HAYABUSA = _find_hayabusa()

if HAYABUSA is None and REQUIRE_HAYABUSA:
    raise RuntimeError(
        "DETKIT_REQUIRE_HAYABUSA is set but no hayabusa binary was found. "
        "Set HAYABUSA_BIN or put hayabusa on PATH. Refusing to report a green "
        "run for a detection suite that never executed."
    )

requires_hayabusa = pytest.mark.skipif(
    HAYABUSA is None, reason="hayabusa binary not found (set HAYABUSA_BIN or add to PATH)"
)


def fetch_sample(sample: dict[str, Any]) -> Path:
    """Download a pinned sample to the cache (keyed by sha256) and verify it."""
    sha = str(sample["sha256"]).lower()
    CACHE.mkdir(parents=True, exist_ok=True)
    dest = CACHE / f"{sha}.evtx"
    if dest.exists() and hashlib.sha256(dest.read_bytes()).hexdigest() == sha:
        return dest
    quoted = urllib.parse.quote(str(sample["path"]))
    url = f"https://raw.githubusercontent.com/{sample['repo']}/{sample['commit']}/{quoted}"

    # These tests depend on a live fetch from GitHub. A transient network blip is
    # not a detection failure, so retry with backoff — but distinguish the two in
    # the message, or a flaky build gets blamed on the rule.
    last: Exception | None = None
    for attempt in range(FETCH_ATTEMPTS):
        try:
            with urllib.request.urlopen(url, timeout=60) as resp:
                data = resp.read()
            break
        except OSError as exc:
            last = exc
            if attempt < FETCH_ATTEMPTS - 1:
                time.sleep(FETCH_BACKOFF_SECONDS * (2**attempt))
    else:
        raise AssertionError(
            f"could not fetch {sample['path']} after {FETCH_ATTEMPTS} attempts: {last}\n"
            f"This is a sample-availability problem, not a rule failure. If the "
            f"upstream repo removed or rewrote the pinned commit, re-pin the sample."
        )

    got = hashlib.sha256(data).hexdigest()
    if got != sha:
        raise AssertionError(
            f"sha256 mismatch for {sample['path']}: {got} != {sha}\n"
            f"The pinned sample changed upstream. Verify the new content before re-pinning."
        )
    dest.write_bytes(data)
    return dest


def count_hits(rule: Path, evtx: Path) -> int:
    """Run one rule against one EVTX and return the number of events with hits.

    Channel filtering is disabled (-a): each test targets a single rule at a
    single curated sample, so we let the rule's field logic decide matches.

    Output goes to the null device. json-timeline requires -o, but we only ever
    parse the stdout summary — and the JSON it writes contains the sample's
    attacker artifacts verbatim (encoded PowerShell, credential-dumper strings),
    which endpoint AV signature-matches and quarantines mid-run. Never
    materialising it removes the race entirely.
    """
    if HAYABUSA is None:
        raise RuntimeError("count_hits called without a hayabusa binary")
    # Run from the binary's dir so Hayabusa finds its bundled ./rules/config.
    hb_dir = Path(HAYABUSA).resolve().parent
    proc = subprocess.run(
        [HAYABUSA, "json-timeline", "-f", str(evtx), "-r", str(rule),
         "-o", os.devnull, "-w", "-a", "-C", "-K"],
        cwd=hb_dir, capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=False,
    )
    text = ANSI_RE.sub("", proc.stdout + proc.stderr)
    match = HITS_RE.search(text)
    if not match:
        raise AssertionError(f"could not parse Hayabusa summary:\n{text[-2000:]}")
    return int(match.group(1))
