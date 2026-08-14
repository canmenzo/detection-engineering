#!/usr/bin/env python3
"""Enforce detection metadata discipline.

Hard rules, any failure breaks CI:
  1. Every rule carries the full required Sigma frontmatter, including at least
     one ATT&CK technique tag (attack.tXXXX[.XXX]).
  2. Every rule has a test-fixture directory under tests/fixtures/<rule_stem>/.
  3. Every attack.* tag resolves against the pinned ATT&CK release: technique
     IDs must exist, tactic tokens must be real ATT&CK shortnames.

On (3): pySigma resolves ATT&CK from MITRE's live STIX feed, so the vocabulary
moves under the repo with no commit of ours. .attack-version pins the release we
validated against; a mismatch fails here rather than silently changing what
"valid tag" means. Bumping it is a deliberate act: update the file, re-run, fix
whatever the new release retired.

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
ATTACK_VERSION_FILE = REPO / ".attack-version"

REQUIRED_FIELDS = [
    "title", "id", "status", "description", "references", "author",
    "date", "modified", "tags", "logsource", "detection",
    "falsepositives", "level",
]

TECHNIQUE_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$", re.IGNORECASE)
ATTACK_TAG_RE = re.compile(r"^attack\.(.+)$", re.IGNORECASE)


def attack_vocabulary() -> tuple[set[str], set[str]]:
    """(technique IDs, tactic shortnames) from the pinned ATT&CK release."""
    from sigma.data.mitre_attack import (
        mitre_attack_tactics,
        mitre_attack_techniques,
        mitre_attack_version,
    )

    pinned = ATTACK_VERSION_FILE.read_text(encoding="utf-8").strip()
    if mitre_attack_version != pinned:
        raise SystemExit(
            f"ATT&CK version drift: .attack-version pins {pinned!r} but pySigma "
            f"resolved {mitre_attack_version!r}.\n"
            f"MITRE published a new release. Re-validate the rule tags against it, "
            f"then update .attack-version to {mitre_attack_version!r}."
        )
    return set(mitre_attack_techniques), set(mitre_attack_tactics.values())


def check_attack_tags(tags, techniques: set[str], tactics: set[str]) -> list[str]:
    """Every attack.* tag must resolve to a real technique or tactic."""
    errors = []
    for tag in tags if isinstance(tags, list) else []:
        if not isinstance(tag, str):
            continue
        m = ATTACK_TAG_RE.match(tag.strip())
        if not m:
            continue
        token = m.group(1)
        if TECHNIQUE_RE.match(tag.strip()):
            if token.upper() not in techniques:
                errors.append(f"unknown ATT&CK technique in tag: {tag}")
        elif token.lower() not in tactics:
            errors.append(
                f"unknown ATT&CK tactic in tag: {tag} "
                f"(shortnames are hyphenated, e.g. attack.credential-access)"
            )
    return errors


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


def validate(rule_path: Path, techniques: set[str], tactics: set[str]) -> list[str]:
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

    errors.extend(check_attack_tags(doc.get("tags"), techniques, tactics))

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

    techniques, tactics = attack_vocabulary()
    print(f"ATT&CK {ATTACK_VERSION_FILE.read_text(encoding='utf-8').strip()} "
          f"({len(techniques)} techniques, {len(tactics)} tactics)\n")

    failed = 0
    for rule in rules:
        errors = validate(rule, techniques, tactics)
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
