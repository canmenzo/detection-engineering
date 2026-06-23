# ADR 0001 — Hayabusa for detection testing

**Status:** accepted
**Date:** 2026-06-23

## Context
We need to prove each Sigma rule fires on malicious telemetry and stays silent on
benign telemetry. The telemetry format for Windows detections is EVTX. Options:
write a custom Python Sigma matcher, stand up a full SIEM in CI, or use an
existing engine that runs Sigma against EVTX.

## Decision
Use **Hayabusa** (Yamato Security) as the test engine. It runs Sigma rules
directly against EVTX, is a single static binary, and emits JSON with rule title,
ATT&CK tags, and level. pytest drives it and asserts match / no-match.

## Consequences
- **+** No SIEM infrastructure in CI; fast, deterministic, single binary.
- **+** Tests exercise the *real* Sigma evaluation semantics, not a reimplementation.
- **+** Keeps the Python honest — glue only, no homegrown matcher to defend.
- **−** Windows/EVTX-centric. Cloud and identity rules can't be EVTX-tested; for
  those we rely on `sigma convert` validation, with an optional small custom
  matcher as a later enhancement.
- **−** Adds a binary dependency CI must download per run (pinned version).
