"""Repository paths.

detkit operates on the corpus of the repository it ships in, so the root is
resolved relative to this file rather than a working directory or an env var.
"""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

DETECTIONS = REPO / "detections"
VENDORED = REPO / "vendored"
VENDORED_REPORT = VENDORED / "report.json"

EVALS = REPO / "evals"
EVAL_RESULTS = EVALS / "results.json"

FIXTURES = REPO / "tests" / "fixtures"
CONVERSION_ONLY = REPO / "tests" / "conversion_only.txt"

COVERAGE_PNG = REPO / "coverage" / "coverage.png"
NAVIGATOR_LAYER = REPO / "coverage" / "navigator_layer.json"
SITE = REPO / "site"
SITE_INDEX = SITE / "index.html"

ATTACK_VERSION_FILE = REPO / ".attack-version"
HAYABUSA_VERSION_FILE = REPO / ".hayabusa-version"
