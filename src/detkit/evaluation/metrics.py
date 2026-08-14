"""Per-rule detection metrics."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Metrics:
    tp: int
    fp: int
    fn: int
    tn: int
    missed: tuple[str, ...] = ()
    false_alarms: tuple[str, ...] = ()

    @property
    def precision(self) -> float | None:
        """Of everything the rule alerted on, how much was real. None if silent."""
        alerts = self.tp + self.fp
        return self.tp / alerts if alerts else None

    @property
    def recall(self) -> float | None:
        actual = self.tp + self.fn
        return self.tp / actual if actual else None

    @property
    def fp_rate(self) -> float | None:
        """Share of benign events that alerted."""
        benign = self.fp + self.tn
        return self.fp / benign if benign else None

    def as_dict(self) -> dict[str, Any]:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "precision": _round(self.precision),
            "recall": _round(self.recall),
            "fp_rate": _round(self.fp_rate),
            "missed": list(self.missed),
            "false_alarms": list(self.false_alarms),
        }


def _round(value: float | None) -> float | None:
    return None if value is None else round(value, 4)


def score(labels: list[bool], matched: set[int], names: list[str]) -> Metrics:
    """labels[i] is True when case i is malicious; matched holds matching indices."""
    tp = fp = fn = tn = 0
    missed: list[str] = []
    false_alarms: list[str] = []
    for index, is_malicious in enumerate(labels):
        hit = index in matched
        if is_malicious and hit:
            tp += 1
        elif is_malicious:
            fn += 1
            missed.append(names[index])
        elif hit:
            fp += 1
            false_alarms.append(names[index])
        else:
            tn += 1
    return Metrics(
        tp=tp, fp=fp, fn=fn, tn=tn,
        missed=tuple(missed), false_alarms=tuple(false_alarms),
    )
