"""Evaluate a Sigma rule against labelled events.

Rules are rendered to SQL by pySigma's SQLite backend and run against an
in-memory table of events. See ADR 0003 for why this engine, and for the three
semantics it pins down — all of which are implemented here.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection

TABLE = "events"
INDEX_COLUMN = "__case_index__"

# Windows carries UInt64 keyword masks that overflow SQLite's signed INTEGER.
SQLITE_INT_MAX = 2**63 - 1


class EvaluationError(Exception):
    """A rule could not be evaluated."""


def _detection_fields(detection: Any) -> set[str]:
    fields: set[str] = set()
    for item in getattr(detection, "detection_items", []):
        field = getattr(item, "field", None)
        if field:
            fields.add(field)
        if hasattr(item, "detection_items"):
            fields |= _detection_fields(item)
    return fields


def referenced_fields(collection: SigmaCollection) -> set[str]:
    """Every field name the rule addresses.

    These are materialised as NULL columns so a field the data never carries
    simply does not match, instead of raising "no such column".
    """
    fields: set[str] = set()
    for rule in collection.rules:
        # Correlation rules carry no detection of their own; they aggregate
        # others. None exist in this corpus yet, and one would need its own
        # evaluation path rather than falling through silently here.
        detections = getattr(rule, "detection", None)
        if detections is None:
            continue
        for detection in detections.detections.values():
            fields |= _detection_fields(detection)
    return fields


def compile_rule(rule_path: Path) -> tuple[str, set[str]]:
    """Render a rule to SQL, with the field names it references."""
    try:
        collection = SigmaCollection.from_yaml(rule_path.read_text(encoding="utf-8"))
        queries = sqliteBackend().convert(collection)
    except Exception as exc:
        raise EvaluationError(f"{rule_path}: cannot convert to SQL: {exc}") from exc
    if not queries:
        raise EvaluationError(f"{rule_path}: backend produced no query")
    return queries[0], referenced_fields(collection)


def normalise(value: Any) -> Any:
    """Coerce an event value to what SQLite can compare against rule literals.

    EVTX EventData is string-typed, so PreAuthType arrives as "0" while the rule
    (and SigmaHQ's own) says 0. Hayabusa compares loosely; SQLite does not, and
    without this the AS-REP rule silently stops matching. ADR 0003 records that
    this makes the evaluator as lenient as Hayabusa, and more lenient than a
    strictly-typed backend.
    """
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int) and abs(value) > SQLITE_INT_MAX:
        return str(value)
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.lstrip("-").isdigit():
            return int(stripped)
    return value


def matching_indices(query: str, fields: set[str], events: list[dict[str, Any]]) -> set[int]:
    """Indices of the events the rule matches."""
    if not events:
        return set()

    columns = sorted({key for event in events for key in event} | fields)
    conn = sqlite3.connect(":memory:")
    try:
        quoted = ", ".join(f'"{c}"' for c in [INDEX_COLUMN, *columns])
        conn.execute(f"CREATE TABLE {TABLE} ({quoted})")
        placeholders = ", ".join("?" * (len(columns) + 1))
        conn.executemany(
            f"INSERT INTO {TABLE} VALUES ({placeholders})",
            [
                (index, *(normalise(event.get(c)) for c in columns))
                for index, event in enumerate(events)
            ],
        )
        cursor = conn.execute(query.replace("<TABLE_NAME>", TABLE))
        position = [d[0] for d in cursor.description].index(INDEX_COLUMN)
        return {row[position] for row in cursor.fetchall()}
    except sqlite3.Error as exc:
        raise EvaluationError(f"evaluating query failed: {exc}\n  query: {query}") from exc
    finally:
        conn.close()
