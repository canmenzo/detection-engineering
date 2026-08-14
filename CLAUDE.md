# Detection-as-Code — Project Memory

## What this is
Automated tests for threat-detection rules. Every Sigma detection ships with EVTX
test fixtures proving it (a) fires on the malicious behavior and (b) stays silent
on benign activity. CI re-runs everything on every commit and auto-generates a
MITRE ATT&CK coverage map. Demonstrates detection *engineering discipline* —
version control, testing, CI/CD, coverage tracking.

Python lives in `tools/` (5 generator/gate scripts) plus the pytest layer.
"Does this rule fire" testing is done by **Hayabusa** (Rust, runs Sigma against
EVTX), driven by pytest.

## Repo structure
- `detections/` — AUTHORED Sigma rules (the showcase); held to the fixture gate
- `vendored/` — pinned third-party SigmaHQ Windows corpus (~2,400, DRL 1.1); NOT
  gated — fed through convert + coverage only. `vendored_report.py` → `report.json`
- `tests/` — pytest drives Hayabusa; `fixtures/<rule_stem>/` holds TP + benign EVTX
- `pipelines/` — pySigma processing pipelines (field maps for Splunk + Sentinel/Kusto)
- `tools/` — Python glue scripts (validate_metadata, vendored_report, coverage png,
  dashboard, navigator layer)
- `coverage/` — committed Navigator layer JSON + screenshot
- `docs/` — detection lifecycle + ADRs
- `.github/workflows/ci.yml` — lint → (convert, test, vendored) → coverage

## Conventions
- **Required metadata on every rule:** title, id (UUID), status, description,
  references, author, date, modified, tags (≥1 `attack.tXXXX`), logsource,
  detection, falsepositives, level.
- **The enforced rule:** every rule must have ≥1 ATT&CK tag AND ≥1 test fixture,
  or CI fails. `validate_metadata.py` enforces this.
- **Naming:** `<logsource>_<platform>_<short_description>.yml`, mirroring Sigma-HQ.

## ATT&CK is a moving target — this bit matters
pySigma resolves ATT&CK from MITRE's **live** STIX feed (cached in
`~/.cache/pysigma/`), so the tag vocabulary changes with no commit here.
`.attack-version` pins the release we validated against (**19.1**);
`validate_metadata.py` fails if pySigma resolves anything else, and checks every
`attack.*` tag against it. To bump: update the file, re-run the gate, fix what
the new release retired.

v19.1 specifics that bit us: tactic shortnames are **hyphenated**
(`attack.credential-access`); TA0005 Defense Evasion is now **`stealth`** and
**`defense-impairment`** (TA0112) split out of it; **T1562 no longer exists**
(→ T1685 Disable or Modify Tools, T1686 Disable or Modify System Firewall);
T1070.001 Clear Windows Event Logs → **T1685.005**.

## Tooling
pySigma + sigma-cli (convert/check), pySigma backends (splunk, kusto — verify
package names at install), Hayabusa (EVTX testing), pytest, yamllint.

## Status
15 authored detections, fixture-backed (pinned public EVTX) and verified with
Hayabusa. `pytest` 20/20 (15 detection + 5 harness-integrity). Coverage:
**306 techniques across 15 tactics** (16 authored + 290 vendored-only) — the
vendored SigmaHQ Windows corpus converts 2399/2399 to Splunk.

### Production-grade engagement (6 phases, agreed 2026-08-14)
1. ✅ **Honest gates** (done, this file's changes) 2. Python foundation
(src layout, uv, ruff, mypy --strict, unit tests) 3. **Eval harness** — labelled
JSON events, precision/recall/FP per rule 4. Rule rewrite to idiomatic logsources
+ per-rule eval thresholds in CI 5. Reproducible local setup (justfile,
devcontainer, pinned Hayabusa) 6. README/dashboard rewrite with real numbers.

Phase 3 opens with a **timeboxed spike**: Zircolite vs. a small in-repo pySigma
matcher for evaluating rules against labelled JSON events. Do not build before
that spike reports. Open decisions: PRs-vs-direct-push for rule changes (Phase 4),
lsass allow-list + Kerberos domain model for eval data (Phase 3).

## Phase 1 hardening — what changed and why
- **The suite could not fail.** No Hayabusa → all tests skipped → `pytest` exit 0.
  CI now sets `DETKIT_REQUIRE_HAYABUSA=1`: missing engine, bogus `HAYABUSA_BIN`,
  or *any* skip fails the run. `tests/test_harness_integrity.py` (no engine
  needed) asserts collected cases == declared samples, and catches orphan
  manifests / stale `conversion_only.txt` entries.
- **Defender quarantines Hayabusa's JSON output.** `count_hits` wrote `out.json`
  to a temp dir and never read it; the file contains the sample's attacker
  artifacts verbatim, so AV signature-matches it (4 detections in one session).
  Output now goes to `os.devnull` — nothing on disk. **Do not reintroduce a
  file-backed `-o`**; `json-timeline` requires the flag but `NUL`/`/dev/null`
  works and the summary still prints to stdout.
- **Generators failed silently.** All four swallowed `yaml.YAMLError`; they now
  exit non-zero. `vendored_report.py` and `generate_dashboard.py` matched tactic
  tags with `[a-z_]+`, silently dropping every hyphenated (multi-word) tactic —
  the report claimed 8 of 15.
- **Committed artifacts can no longer drift.** Generator output is a pure
  function of the corpus (no timestamps); CI regenerates and `git diff
  --exit-code`s `navigator_layer.json`, `vendored/report.json`, `site/index.html`.
  PNGs excluded — matplotlib is not byte-stable across versions.
- `sigma check` is down from 20 issues to 2 (both `SpecificInsteadOfGeneric
  Logsource`, deferred to Phase 4) and is **still advisory** — `--fail-on-issues`
  goes on when the count is zero, not before. README says so out loud.
- LICENSE added (MIT for authored content; `vendored/` stays DRL 1.1).

Note on logsource: Hayabusa maps `category: process_creation` to Sysmon EID 1, so
4688 Security-log samples won't match those. Rules tested on Security-log samples
are authored as `service: security` with native fields (EventID + NewProcessName /
CommandLine / TargetSid / Properties), mirroring Sigma-HQ's windows/builtin/security
tree. `category: ps_script` (4104) and `category: process_access` (Sysmon 10) map
fine. Use scratchpad probe.py / dump.py pattern to verify a new rule fires before
committing.
