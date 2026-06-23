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
- `detections/` — Sigma YAML rules, organized by data source (windows/cloud/identity)
- `tests/` — pytest drives Hayabusa; `fixtures/<rule_stem>/` holds TP + benign EVTX
- `pipelines/` — pySigma processing pipelines (field maps for Splunk + Sentinel/Kusto)
- `tools/` — the two Python glue scripts
- `coverage/` — committed Navigator layer JSON + screenshot
- `docs/` — detection lifecycle + ADRs
- `.github/workflows/ci.yml` — lint → convert → test → coverage

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
Phase 0 scaffolded: one complete detection (encoded PowerShell) + glue scripts +
test harness + CI. EVTX fixtures still need to be added (see fixture READMEs).
Backends not yet pip-installed — confirm current package names before installing.
