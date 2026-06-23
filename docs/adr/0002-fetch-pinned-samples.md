# ADR 0002 — Fetch pinned public EVTX samples instead of vendoring them

**Status:** accepted
**Date:** 2026-06-23

## Context
Detection tests need real adversary telemetry (EVTX). Three ways to supply it:
vendor binary EVTX into the repo, capture in a lab, or fetch public samples at
test time. Constraints discovered during the build:

- Endpoint AV (Windows Defender) quarantines any file containing real malicious
  PowerShell — including EVTX-derived JSON and, on contributor machines, vendored
  malicious binaries — breaking local test runs.
- Synthetic hand-authored JSON fixtures do **not** work: Hayabusa's `-J` JSON
  input does not apply Sigma `process_creation`/`ps_script` matching the way EVTX
  input does (verified — see git history of this build).
- Lab captures embed hostnames/usernames (PII) and need scrubbing before commit.

## Decision
Do not vendor sample binaries. Each rule's
`tests/fixtures/<stem>/sample_sources.yml` pins public samples by
`repo + commit + path + sha256`. `conftest.py` downloads them to a gitignored
cache, verifies the hash, and runs Hayabusa with the channel filter disabled
(`-a`) — each test targets one rule against one curated sample.

Rules that cannot be EVTX-tested (no public sample; cloud/identity rules whose
data source isn't EVTX) are listed in `tests/conversion_only.txt` and are gated
by `sigma check` + SPL/KQL conversion instead. The exemption must be declared
explicitly, so the "every rule is verified" gate stays honest.

## Consequences
- **+** No malware binaries in the repo; AV-safe; small repo.
- **+** Reproducible — pinned commit + sha256 make samples immutable.
- **+** Respects upstream sample repos (EVTX-ATTACK-SAMPLES, hayabusa-sample-evtx).
- **−** Tests require network access (CI and first local run); cache makes reruns offline.
- **−** A pinned sample could be deleted upstream; the sha256 makes that a loud,
  obvious failure rather than a silent drift.
