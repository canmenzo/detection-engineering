"""Run the golden dataset and report per-rule detection quality."""
from __future__ import annotations

import json
from typing import Any

from detkit.evaluation.cases import CaseError, CaseSet, load_all
from detkit.evaluation.engine import compile_rule, matching_indices
from detkit.evaluation.metrics import Metrics, score
from detkit.paths import DETECTIONS, EVAL_RESULTS, REPO
from detkit.rules import rule_paths


def evaluate(case_set: CaseSet, rule_path: Any) -> Metrics:
    query, fields = compile_rule(rule_path)
    matched = matching_indices(query, fields, case_set.events)
    labels = [c.is_malicious for c in case_set.cases]
    names = [c.name for c in case_set.cases]
    return score(labels, matched, names)


def _fmt(value: float | None) -> str:
    return "  n/a" if value is None else f"{value:5.2f}"


def run() -> int:
    rules = {p.stem: p for p in rule_paths(DETECTIONS)}
    case_sets = load_all()
    if not case_sets:
        print("no eval cases found under evals/")
        return 1

    orphans = sorted({cs.stem for cs in case_sets} - set(rules))
    if orphans:
        raise CaseError(f"eval case set(s) with no matching rule: {orphans}")

    results: dict[str, Any] = {}
    print(f"{'rule':<46} {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>3}  "
          f"{'prec':>5} {'recall':>6} {'fp rate':>7}")
    print("-" * 92)

    for case_set in sorted(case_sets, key=lambda c: c.stem):
        metrics = evaluate(case_set, rules[case_set.stem])
        results[case_set.stem] = metrics.as_dict()
        print(
            f"{case_set.stem:<46} {metrics.tp:>3} {metrics.fp:>3} {metrics.fn:>3} "
            f"{metrics.tn:>3}  {_fmt(metrics.precision)} {_fmt(metrics.recall):>6} "
            f"{_fmt(metrics.fp_rate):>7}"
        )

    print("-" * 92)
    covered = len(case_sets)
    print(f"{covered}/{len(rules)} rules have eval cases "
          f"({sum(len(c.cases) for c in case_sets)} labelled events)")

    uncovered = sorted(set(rules) - {c.stem for c in case_sets})
    if uncovered:
        print(f"\nno eval cases yet: {', '.join(uncovered)}")

    EVAL_RESULTS.parent.mkdir(parents=True, exist_ok=True)
    EVAL_RESULTS.write_text(
        json.dumps({"rules": dict(sorted(results.items()))}, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {EVAL_RESULTS.relative_to(REPO)}")
    return 0
