# Detection-as-Code — Project Memory

## What this is
Automated tests for threat-detection rules. Every Sigma detection ships with EVTX
test fixtures proving it (a) fires on the malicious behavior and (b) stays silent
on benign activity. CI re-runs everything on every commit and auto-generates a
MITRE ATT&CK coverage map. Demonstrates detection *engineering discipline* —
version control, testing, CI/CD, coverage tracking.

Python is confined to two glue scripts (`tools/generate_navigator_layer.py`,
`tools/validate_metadata.py`). "Does this rule fire" testing is done by
**Hayabusa** (Rust, runs Sigma against EVTX), driven by pytest.

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

## Tooling
pySigma + sigma-cli (convert/check), pySigma backends (splunk, kusto — verify
package names at install), Hayabusa (EVTX testing), pytest, yamllint.

## Status
15 authored detections, fixture-backed (pinned public EVTX) and verified with
Hayabusa; `pytest` green (15/15), `sigma check`/convert/metadata gate all pass.
Two-tier corpus added: `vendored/` holds the SigmaHQ Windows corpus (100% Splunk
convert) folded into the coverage map → 309 ATT&CK techniques across 14 tactics
(16 authored + 293 vendored-only). Dashboard + coverage PNG distinguish the tiers.

Note on logsource: Hayabusa maps `category: process_creation` to Sysmon EID 1, so
4688 Security-log samples won't match those. Rules tested on Security-log samples
are authored as `service: security` with native fields (EventID + NewProcessName /
CommandLine / TargetSid / Properties), mirroring Sigma-HQ's windows/builtin/security
tree. `category: ps_script` (4104) and `category: process_access` (Sysmon 10) map
fine. Use scratchpad probe.py / dump.py pattern to verify a new rule fires before
committing.
