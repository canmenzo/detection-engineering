"""Compile the corpus to each target, and check the output is deployable.

Syntactic validity is not deployability. A Splunk search with no `source=` runs
against every index the reader can see, which is not a detection — so the
binding is checked, not assumed.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from detkit.paths import DETECTIONS, REPO

OUT = REPO / "out"
SPLUNK_SPL = OUT / "splunk.spl"
XDR_KQL = OUT / "xdr.kql"

SPLUNK_PIPELINES = ("splunk_windows", "pipelines/splunk_sysmon_source.yml")


class ConversionError(Exception):
    """The corpus did not compile, or compiled to something undeployable."""


def _sigma(*args: str) -> None:
    executable = shutil.which("sigma", path=str(Path(sys.executable).parent)) or "sigma"
    proc = subprocess.run([executable, *args], cwd=REPO, check=False)
    if proc.returncode != 0:
        raise ConversionError(f"sigma {' '.join(args)} failed with {proc.returncode}")


def queries(text: str) -> list[list[str]]:
    """Split backend output into queries.

    Queries are separated by blank lines, and an SPL query can span several
    physical lines — the `regex` command renders as a `| regex ...` continuation.
    Treating every line as a query is what made the first version of this check
    report a correctly-bound rule as unbound.
    """
    blocks: list[list[str]] = []
    current: list[str] = []
    for line in text.splitlines():
        if line.strip():
            current.append(line)
        elif current:
            blocks.append(current)
            current = []
    if current:
        blocks.append(current)
    return blocks


def unbound(text: str) -> list[str]:
    """Queries with no source binding, by their first line."""
    return [
        block[0]
        for block in queries(text)
        if not any("source=" in line for line in block)
    ]


def run() -> int:
    OUT.mkdir(parents=True, exist_ok=True)

    _sigma("convert", "-t", "splunk",
           "-p", SPLUNK_PIPELINES[0], "-p", SPLUNK_PIPELINES[1],
           str(DETECTIONS), "-o", str(SPLUNK_SPL))

    text = SPLUNK_SPL.read_text(encoding="utf-8")
    all_queries = queries(text)
    loose = unbound(text)
    if loose:
        print(f"{len(loose)} Splunk query/queries have no source binding:")
        for line in loose:
            print(f"  {line}")
        return 1
    print(f"Splunk: {len(all_queries)} queries, all source-bound")

    # Only the process_creation subset. Defender XDR has no table equivalent for
    # the Windows Security-log events the rest of the corpus targets, and
    # Sentinel's SecurityEvent schema does not surface fields like PreAuthType.
    _sigma("convert", "-t", "kusto", "-p", "microsoft_xdr",
           str(DETECTIONS / "windows" / "process_creation"), "-o", str(XDR_KQL))

    kql = XDR_KQL.read_text(encoding="utf-8")
    if "DeviceProcessEvents" not in kql:
        print("XDR output is not bound to a table")
        return 1
    print(f"Microsoft XDR: {len(queries(kql))} queries, table-bound")
    return 0
