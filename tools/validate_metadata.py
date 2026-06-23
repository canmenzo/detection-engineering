#!/usr/bin/env python3
"""Enforce detection metadata discipline.

Two hard rules, either failure breaks CI:
  1. Every rule carries the full required Sigma frontmatter, including at least
     one ATT&CK technique tag (attack.tXXXX[.XXX]).
  2. Every rule has a test-fixture directory under tests/fixtures/<rule_stem>/.

Run: python tools/validate_metadata.py
Exit code 0 = clean, 1 = one or more violations.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
DETECTIONS = REPO / "detections"
FIXTURES = REPO / "tests" / "fixtures"
CONVERSION_ONLY = REPO / "tests" / "conversion_only.txt"

REQUIRED_FIELDS = [
    "title", "id", "status", "description", "references", "author",
    "date", "modified", "tags", "logsource", "detection",
    "falsepositives", "level",
]

TECHNIQUE_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$", re.IGNORECASE)


def has_technique_tag(tags) -> bool:
    return isinstance(tags, list) and any(
        isinstance(t, str) and TECHNIQUE_RE.match(t.strip()) for t in tags
    )


def _conversion_only() -> set[str]:
    if not CONVERSION_ONLY.exists():
        return set()
    out = set()
    for line in CONVERSION_ONLY.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.add(line)
    return out


def has_fixture(rule_path: Path) -> bool:
    """A rule satisfies the test gate if it has a sample manifest with at least
    one pinned sample, or is explicitly listed as conversion-only."""
    if rule_path.stem in _conversion_only():
        return True
    manifest = FIXTURES / rule_path.stem / "sample_sources.yml"
    if not manifest.is_file():
        return False
    doc = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
    return bool(doc.get("samples"))


def validate(rule_path: Path) -> list[str]:
    errors: list[str] = []
    try:
        doc = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [f"YAML parse error: {exc}"]
    if not isinstance(doc, dict):
        return ["not a YAML mapping"]

    for field in REQUIRED_FIELDS:
        if field not in doc or doc[field] in (None, "", []):
            errors.append(f"missing required field: {field}")

    if not has_technique_tag(doc.get("tags")):
        errors.append("no ATT&CK technique tag (need at least one attack.tXXXX)")

    if not has_fixture(rule_path):
        errors.append(
            f"no test fixture: add tests/fixtures/{rule_path.stem}/sample_sources.yml "
            f"with >=1 pinned sample, or list '{rule_path.stem}' in tests/conversion_only.txt"
        )
    return errors


def main() -> int:
    rules = sorted(DETECTIONS.rglob("*.yml")) + sorted(DETECTIONS.rglob("*.yaml"))
    if not rules:
        print("no detection rules found under detections/", file=sys.stderr)
        return 1

    failed = 0
    for rule in rules:
        errors = validate(rule)
        rel = rule.relative_to(REPO)
        if errors:
            failed += 1
            print(f"FAIL {rel}")
            for e in errors:
                print(f"     - {e}")
        else:
            print(f"OK   {rel}")

    print(f"\n{len(rules)} rule(s), {failed} failing.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
