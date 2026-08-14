# Detection-as-Code — Project Memory

## What this is
Automated tests for threat-detection rules. Every Sigma detection ships with EVTX
test fixtures proving it (a) fires on the malicious behavior and (b) stays silent
on benign activity. CI re-runs everything on every commit and auto-generates a
MITRE ATT&CK coverage map. Demonstrates detection *engineering discipline* —
version control, testing, CI/CD, coverage tracking.

Python lives in `src/detkit/` (installed package, `detkit` CLI) plus the pytest
layer. "Does this rule fire" testing is done by **Hayabusa** (Rust, runs Sigma
against EVTX), driven by pytest.

## Repo structure
- `detections/` — AUTHORED Sigma rules (the showcase); held to the fixture gate
- `vendored/` — pinned third-party SigmaHQ Windows corpus (~2,400, DRL 1.1); NOT
  gated — fed through convert + coverage only. `vendored_report.py` → `report.json`
- `tests/` — pytest; `unit/` covers detkit, `harness.py` drives Hayabusa,
  `fixtures/<rule_stem>/` holds the pinned sample manifests
- `pipelines/` — pySigma processing pipelines (field maps for Splunk + Sentinel/Kusto)
- `src/detkit/` — the tooling package. `attack` (tag parsing + vocabulary),
  `rules` (corpus loading), `validate`, `coverage`, `navigator`, `dashboard`,
  `vendored`, `cli`
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
pySigma + sigma-cli (convert/check), pySigma backends (splunk, kusto), Hayabusa
(EVTX testing), pytest, yamllint, ruff, mypy --strict. Dependencies are locked
in `uv.lock`; `uv sync --all-extras` reproduces CI exactly. Commands are `uv run
detkit <validate|vendored|navigator|coverage|dashboard>`. Hayabusa's version is
pinned in `.hayabusa-version` and read by CI — bump it there, nowhere else.

**Do not run `uv sync` against the repo's existing pip-managed `.venv`** without
meaning to; set `UV_PROJECT_ENVIRONMENT` to a scratch path to test the lock.

## Status
15 authored detections, fixture-backed (pinned public EVTX) and verified with
Hayabusa. `pytest` 20/20 (15 detection + 5 harness-integrity). Coverage:
**306 techniques across 15 tactics** (16 authored + 290 vendored-only) — the
vendored SigmaHQ Windows corpus converts 2399/2399 to Splunk.

### Production-grade engagement (6 phases, agreed 2026-08-14)
1. ✅ **Honest gates** 2. ✅ **Python foundation** 3. ✅ **Eval harness** —
120 labelled events, precision/recall/FP per rule 4. Rule rewrite to idiomatic
logsources + per-rule eval thresholds and ratchet in CI 5. Reproducible local
setup (justfile, devcontainer, pinned Hayabusa) 6. README/dashboard rewrite,
with the eval numbers injected from results.json rather than hand-typed.

Open decision for Phase 4: PRs-vs-direct-push for rule changes. Outcome #4 wants
eval results attached before merge, which needs PRs; Can's standing rule is
commit straight to main. Suggested compromise: PRs for `detections/**` and
`evals/**` only. **Not yet answered — ask before wiring branch protection.**

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

## Phase 2 — Python foundation
- `tools/*.py` and `requirements.txt` are **gone**. Logic moved to `src/detkit/`
  behind the `detkit` CLI; deps live in `pyproject.toml` + `uv.lock`.
- The shared `attack` module exists because the same regex and alias table were
  copy-pasted into four generators, drifted, and two copies used `[a-z_]+` for
  tactic tags — which cannot match a hyphen. Don't re-inline that logic.
- **ruff + mypy --strict are green over 18 files and gate CI.** Two carve-outs,
  both deliberate: `E501` is ignored in `dashboard.py` (wrapping its embedded
  HTML/JS template would change the generated bytes), and `no_implicit_reexport`
  is off for `sigma.*`/`matplotlib.*` (they re-export through `__init__`).
- Tests: 60 total = 15 detection + 5 harness-integrity + 40 unit. Unit tests
  cover the arithmetic behind every published number. `tests/harness.py` holds
  the Hayabusa plumbing so nothing imports `conftest` any more.
- The refactor was verified by regenerating every artifact: `navigator_layer.json`,
  `vendored/report.json` and `coverage.png` came out **byte-identical**; the only
  diff was one dashboard footer line naming the new command.

## Phase 3 — eval harness
- `evals/<stem>/cases.yml` holds labelled events; `detkit eval` scores every rule and
  writes `evals/results.json` (drift-checked in CI like the other artifacts).
- Engine = pySigma's **SQLite backend**, rules rendered to SQL and run over an
  in-memory table. ADR 0003 has the reasoning and the 15/15 cross-check against
  Hayabusa on real EVTX. **Zircolite was rejected: not on PyPI, so unlockable.**
- Three semantics are load-bearing and tested: absent fields materialise as NULL
  columns (must not raise); numeric strings are coerced on load (without it the
  AS-REP rule silently stops matching); UInt64 keyword masks are stored as text.
- The case loader **rejects** a benign case whose EventID no malicious case uses
  — the old fixture set's only negative was a different channel and proved
  nothing. It also rejects a missing `why`, and any set lacking either label.
- **Read FP rate, not precision.** Precision moves with the authored
  malicious:benign ratio; FP rate and recall do not.
- Findings: 4 bare-EventID rules sit at **FP rate 1.00**; the 4104 obfuscation
  rule is at 0.67 (it fires on `-join`); `proc_creation_win_encoded_powershell`
  has a **real recall gap** — `powershell -e` is a valid abbreviation the rule
  does not cover. All are recorded in the case sets, not hidden.

Note on logsource: Hayabusa maps `category: process_creation` to Sysmon EID 1, so
4688 Security-log samples won't match those. Rules tested on Security-log samples
are authored as `service: security` with native fields (EventID + NewProcessName /
CommandLine / TargetSid / Properties), mirroring Sigma-HQ's windows/builtin/security
tree. `category: ps_script` (4104) and `category: process_access` (Sysmon 10) map
fine. Use scratchpad probe.py / dump.py pattern to verify a new rule fires before
committing.
