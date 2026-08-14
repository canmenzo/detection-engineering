"""Run the vendored SigmaHQ corpus through convert + coverage, tolerantly.

Vendored rules are third-party and are NOT held to the fixture gate. This proves
two cheaper things at scale:

  1. Convertibility — each rule is fed through the Splunk backend in-process.
     Failures are expected (correlation rules, unsupported modifiers) and are
     counted and reported, not fatal.
  2. Coverage — every ATT&CK tag is extracted so the corpus can be folded into
     the coverage matrix.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from typing import Any

from detkit.paths import REPO, VENDORED, VENDORED_REPORT
from detkit.rules import load_rule, rule_paths


def _backend() -> Any:
    """Return a Splunk backend instance.

    pySigma is a declared dependency. Swallowing an import failure here used to
    leave attempted=0 and a null convert rate while still exiting 0 — the report
    looked fine and had measured nothing.
    """
    from sigma.backends.splunk import SplunkBackend

    return SplunkBackend()


def run() -> int:
    paths = rule_paths(VENDORED)
    if not paths:
        print("no vendored rules found under vendored/")
        return 1

    backend = _backend()
    from sigma.collection import SigmaCollection

    tech_counts: Counter[str] = Counter()
    pairs: set[tuple[str, str]] = set()
    convertible = attempted = 0
    error_counts: Counter[str] = Counter()
    error_samples: list[str] = []

    for path in paths:
        rule = load_rule(path)
        for technique in rule.techniques:
            tech_counts[technique] += 1
            for tactic in rule.tactics:
                pairs.add((tactic, technique))

        attempted += 1
        try:
            backend.convert(SigmaCollection.from_yaml(path.read_text(encoding="utf-8")))
            convertible += 1
        except Exception as exc:
            error_counts[type(exc).__name__] += 1
            if len(error_samples) < 15:
                rel = path.relative_to(REPO).as_posix()
                error_samples.append(f"{rel}: {type(exc).__name__}")

    by_tactic: dict[str, set[str]] = defaultdict(set)
    for tactic, technique in pairs:
        by_tactic[tactic].add(technique)

    report = {
        "source": "SigmaHQ vendored corpus (see vendored/SOURCE.txt)",
        "total_rules": len(paths),
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
    VENDORED_REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    pct = f"{100 * convertible / attempted:.1f}%" if attempted else "n/a"
    print(
        f"{len(paths)} vendored rules · {len(tech_counts)} techniques · "
        f"{len(by_tactic)} tactics · convert {convertible}/{attempted} ({pct})"
    )
    print(f"Wrote {VENDORED_REPORT.relative_to(REPO)}")
    return 0
