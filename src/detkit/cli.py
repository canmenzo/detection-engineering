"""Command-line entry point: ``detkit <command>``."""
from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence

from detkit import (
    coverage,
    dashboard,
    hayabusa,
    navigator,
    pipeline,
    probe,
    readme,
    validate,
    vendored,
)
from detkit.attack import AttackDriftError
from detkit.evaluation import runner as evaluation
from detkit.evaluation.cases import CaseError
from detkit.evaluation.engine import EvaluationError
from detkit.hayabusa import HayabusaError
from detkit.readme import ReadmeError
from detkit.rules import RuleError
from detkit.samples import SampleError

COMMANDS: dict[str, tuple[Callable[[], int], str]] = {
    "ci": (pipeline.run, "run every gate in one go, the way CI does"),
    "validate": (validate.run, "metadata + fixture + ATT&CK tag discipline (authored rules)"),
    "eval": (evaluation.run, "score every rule against its labelled events"),
    "hayabusa": (hayabusa.run, "install the pinned Hayabusa release, checksum-verified"),
    "vendored": (vendored.run, "batch convert + coverage report over the vendored corpus"),
    "navigator": (navigator.run, "write coverage/navigator_layer.json"),
    "coverage": (coverage.run, "render coverage/coverage.png"),
    "dashboard": (dashboard.run, "render site/index.html"),
    "readme": (readme.run, "inject the measured eval table into README.md"),
}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="detkit", description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name, (_, help_text) in COMMANDS.items():
        subparsers.add_parser(name, help=help_text)

    probe_parser = subparsers.add_parser(
        "probe", help="inspect a rule against its pinned EVTX samples"
    )
    probe_parser.add_argument("rule", help="rule stem, e.g. security_win_service_installed")
    probe_parser.add_argument(
        "--show", nargs="*", default=[], metavar="FIELD",
        help="fields to print for matching events (default: a useful set)",
    )
    probe_parser.add_argument(
        "--limit", type=int, default=3, help="events to print per sample (default 3)"
    )

    args = parser.parse_args(argv)
    try:
        if args.command == "probe":
            return probe.run(args.rule, tuple(args.show), args.limit)
        run, _ = COMMANDS[args.command]
        return run()
    except (
        AttackDriftError, RuleError, CaseError, EvaluationError, HayabusaError,
        ReadmeError, SampleError,
    ) as exc:
        print(exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
