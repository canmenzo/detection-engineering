#!/usr/bin/env python3
"""Run the vendored SigmaHQ corpus through convert + coverage, tolerantly.

Vendored rules are third-party and are NOT held to the fixture gate. This tool
proves two cheaper things at scale:

  1. Convertibility — each rule is fed through the Splunk backend in-process; we
     count how many convert cleanly. Failures are expected (correlation rules,
     unsupported modifiers) and are reported, not fatal.
  2. Coverage — every ATT&CK technique/tactic tag is extracted so the corpus can
     be folded into the coverage matrix.

Writes vendored/report.json. Exit 0 unless the corpus is empty.

Run: python tools/vendored_report.py
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
VENDORED = REPO / "vendored"
OUT = VENDORED / "report.json"

TECHNIQUE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
# Must allow hyphens: ATT&CK shortnames are hyphenated (credential-access), and a
# [a-z_]+ pattern silently dropped every multi-word tactic in the corpus — the
# report claimed 8 tactics where the corpus carries 15.
TACTIC_RE = re.compile(r"^attack\.([a-z_-]+)$", re.IGNORECASE)

TACTIC_ALIASES = {"defense-evasion": "stealth"}


def norm_tactic(token: str) -> str:
    token = token.lower().replace("_", "-")
    return TACTIC_ALIASES.get(token, token)


def _tags(doc) -> tuple[list[str], list[str]]:
    techs, tactics = [], []
    for tag in doc.get("tags") or []:
        if not isinstance(tag, str):
            continue
        mt = TECHNIQUE_RE.match(tag.strip())
        if mt:
            techs.append(mt.group(1).upper())
            continue
        ma = TACTIC_RE.match(tag.strip())
        if ma:
            tactics.append(norm_tactic(ma.group(1)))
    return techs, tactics


def _backend():
    """Return a Splunk backend instance.

    pySigma is a declared dependency. Swallowing an import failure here used to
    leave attempted=0 and a null convert rate while still exiting 0 — the report
    looked fine and had measured nothing.
    """
    from sigma.backends.splunk import SplunkBackend

    return SplunkBackend()


def main() -> int:
    rules = sorted(VENDORED.rglob("*.yml")) + sorted(VENDORED.rglob("*.yaml"))
    if not rules:
        print("no vendored rules found under vendored/", file=sys.stderr)
        return 1

    backend = _backend()
    from sigma.collection import SigmaCollection

    from_yaml = SigmaCollection.from_yaml

    tech_counts: Counter = Counter()
    pairs: set[tuple[str, str]] = set()
    convertible = attempted = 0
    error_counts: Counter = Counter()
    error_samples: list[str] = []

    for path in rules:
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise SystemExit(f"{path}: unparseable YAML: {exc}") from exc
        if not isinstance(doc, dict):
            raise SystemExit(f"{path}: not a YAML mapping")
        techs, tactics = _tags(doc)
        for t in techs:
            tech_counts[t] += 1
            for tac in tactics:
                pairs.add((tac, t))

        attempted += 1
        try:
            backend.convert(from_yaml(path.read_text(encoding="utf-8")))
            convertible += 1
        except Exception as exc:
            # Conversion failures are expected here (correlation rules,
            # unsupported modifiers) and are reported rather than fatal — but
            # every one is counted, not just the first 15.
            error_counts[type(exc).__name__] += 1
            if len(error_samples) < 15:
                rel = path.relative_to(REPO).as_posix()
                error_samples.append(f"{rel}: {type(exc).__name__}")

    by_tactic: dict[str, list[str]] = defaultdict(set)
    for tac, tech in pairs:
        by_tactic[tac].add(tech)

    report = {
        "source": "SigmaHQ vendored corpus (see vendored/SOURCE.txt)",
        "total_rules": len(rules),
        "techniques": sorted(tech_counts),
        "technique_counts": dict(sorted(tech_counts.items())),
        "tactics": sorted(by_tactic),
        "tactic_techniques": {k: sorted(v) for k, v in sorted(by_tactic.items())},
        "convert": {
            "attempted": attempted,
            "convertible": convertible,
            "rate": round(convertible / attempted, 4) if attempted else None,
            "error_counts": dict(error_counts.most_common()),
            "error_samples": error_samples,
        },
    }
    OUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    pct = f"{100 * convertible / attempted:.1f}%" if attempted else "n/a"
    print(
        f"{len(rules)} vendored rules · {len(tech_counts)} techniques · "
        f"{len(by_tactic)} tactics · convert {convertible}/{attempted} ({pct})"
    )
    print(f"Wrote {OUT.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
