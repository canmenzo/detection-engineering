# Detection Engineering — Detection-as-Code

> Threat-detection rules with automated tests, CI, and ATT&CK coverage tracking.
> Every Sigma rule ships with fixtures proving it fires on the attack and stays
> silent on benign activity. CI re-runs everything on every commit.

**[🔎 Live dashboard →](https://canmenzo.github.io/detection-engineering/)** — browsable, filterable view of every detection and its test status.

![ATT&CK coverage](coverage/coverage.png)

## Why this exists

Most "detection work" lives in a SIEM console and disappears when you log out.
This repo treats detections like software: version-controlled rules, unit tests
against real adversary telemetry, CI/CD, and an auto-generated coverage map — so
a detection is only "done" when it's tested, mapped, and merged.

## Two tiers: authored vs. vendored

The corpus is deliberately split so quality and breadth are never conflated:

- **`detections/`** — my own rules. Each one is ATT&CK-mapped **and** unit-tested
  against real adversary EVTX via Hayabusa. This is the showcase; the fixture gate
  applies here and CI fails if any rule lacks a test.
- **`vendored/`** — a pinned, clearly-attributed copy of the public
  [SigmaHQ](https://github.com/SigmaHQ/sigma) Windows corpus (~2,400 rules, DRL 1.1).
  It is **not** my work and is **not** held to the fixture gate. It runs through the
  same conversion pipeline (a tolerant batch smoke-test — currently 100% convert to
  Splunk) and feeds the coverage map, demonstrating I can operate a large rule corpus
  through CI at scale. See [`vendored/README.md`](vendored/README.md).

The coverage matrix shows both: **green** cells are authored + fixture-tested,
**blue** cells are vendored-only (shaded by rule count).

## How it works

```
 Sigma rule (YAML)
        │
        ├── detkit validate ────── every rule needs a valid ATT&CK tag + a fixture, or CI fails
        │
        ├── sigma convert ──────── source-bound SPL + XDR KQL, or CI fails
        │
        ├── Hayabusa + pytest ──── TP fixture must fire, benign fixture must not
        │
        ├── detkit eval ────────── scored against labelled events: precision, recall, FP rate
        │
        └── coverage map ───────── coverage.png matrix + ATT&CK Navigator layer
```

## Run it locally

Dependencies are locked with [uv](https://docs.astral.sh/uv/); `uv sync` builds the
exact environment CI uses, from `uv.lock`.

```bash
uv sync --all-extras          # exact locked environment, incl. dev tooling

uv run detkit validate        # metadata + fixture + ATT&CK tag discipline (authored only)
uv run detkit eval            # precision / recall / FP rate per rule
uv run detkit vendored        # batch convert + coverage over the vendored SigmaHQ corpus
uv run detkit coverage        # writes coverage/coverage.png
uv run detkit navigator       # writes coverage/navigator_layer.json
uv run detkit dashboard       # writes site/index.html (the live dashboard)

uv run pytest -v              # unit tests + detection tests (fetches samples, runs Hayabusa)
uv run ruff check .           # lint
uv run mypy                   # type check (strict)
```

Hayabusa is a single binary from [Yamato Security](https://github.com/Yamato-Security/hayabusa);
download a release and point `HAYABUSA_BIN` at it (keep it next to its bundled
`rules/config`). Tests download pinned public EVTX samples on first run and cache
them locally — see [`docs/adr/0002`](docs/adr/0002-fetch-pinned-samples.md).

Without Hayabusa the detection tests skip so you can still work on the tooling;
the harness-integrity tests always run. CI sets `DETKIT_REQUIRE_HAYABUSA=1`,
which turns any skip into a build failure — a detection suite that did not
execute must never report green.

## Detection quality

Every rule is scored against a golden dataset of labelled events — true
positives *and* benign look-alikes that differ only where the rule's logic is
supposed to discriminate. `detkit eval` reports precision, recall and
false-positive rate per rule; run it yourself and get the numbers below.

Read **FP rate** first. Precision depends on the malicious-to-benign ratio in the
case set, which is authored, not observed — so it is comparable between runs but
is not a claim about a real event stream. FP rate (the share of benign events
that alert) and recall do not move with that ratio.

The four rules at FP rate 1.00 are bare single-EventID matches. They alert on
every benign event of that type because they contain no discriminating logic at
all. That is not a bug in the measurement; it is the measurement doing its job.

120 labelled events across 15 rules:

| rule | TP | FP | FN | TN | precision | recall | FP rate |
|---|---:|---:|---:|---:|---:|---:|---:|
| `proc_creation_win_encoded_powershell` | 4 | 0 | 1 | 4 | 1.00 | 0.80 | 0.00 |
| `proc_creation_win_impacket_wmiexec_output` | 3 | 0 | 0 | 4 | 1.00 | 1.00 | 0.00 |
| `security_win_dcsync_replication` | 3 | 0 | 0 | 4 | 1.00 | 1.00 | 0.00 |
| `security_win_firewall_disabled_netsh` | 3 | 1 | 0 | 5 | 0.75 | 1.00 | 0.17 |
| `security_win_kerberoasting_rc4_request` | 3 | 1 | 0 | 5 | 0.75 | 1.00 | 0.17 |
| `sysmon_proc_access_lsass_dump` | 4 | 1 | 0 | 4 | 0.80 | 1.00 | 0.20 |
| `security_win_asrep_roasting` | 3 | 1 | 0 | 3 | 0.75 | 1.00 | 0.25 |
| `security_win_certutil_download_decode` | 4 | 2 | 0 | 4 | 0.67 | 1.00 | 0.33 |
| `posh_ps_defender_tamper` | 5 | 2 | 0 | 3 | 0.71 | 1.00 | 0.40 |
| `security_win_user_added_to_privileged_group` | 3 | 2 | 0 | 2 | 0.60 | 1.00 | 0.50 |
| `posh_ps_susp_encoded_powershell_scriptblock` | 4 | 4 | 0 | 2 | 0.50 | 1.00 | 0.67 |
| `security_win_eventlog_cleared` | 3 | 2 | 0 | 0 | 0.60 | 1.00 | **1.00** |
| `security_win_local_user_created` | 3 | 4 | 0 | 0 | 0.43 | 1.00 | **1.00** |
| `security_win_scheduled_task_created` | 3 | 4 | 0 | 0 | 0.43 | 1.00 | **1.00** |
| `security_win_service_installed` | 3 | 4 | 0 | 0 | 0.43 | 1.00 | **1.00** |

Two results worth calling out rather than burying:

- **`proc_creation_win_encoded_powershell` misses a true positive** (recall 0.80).
  `powershell.exe` accepts `-e` as an abbreviation of `-EncodedCommand`, and the
  rule only tests `-enc`, `-encodedcommand` and `-ec`. The evasion is in the case
  set as a known miss.
- **`posh_ps_susp_encoded_powershell_scriptblock` fires on two thirds of benign
  PowerShell** in its set. `-join` and `[Convert]::ToInt` are ordinary
  administrative code. As written this rule is a hunting query, not an alert.

## Known gaps

Stated plainly, because a reviewer will find them anyway:

- **The benign events are authored, not captured.** They measure whether a rule's
  logic discriminates. They do not measure real-world base rates, so nothing here
  predicts alert volume on a live estate.
- **The evaluator coerces numeric strings**, matching Hayabusa's loose typing and
  therefore being more lenient than a strictly-typed backend. See
  [ADR 0003](docs/adr/0003-sql-evaluator-for-labelled-events.md).
- **Thresholds do not gate the build yet.** The eval runs on every PR and reports;
  per-rule bars and a regression ratchet are the next piece of work.
- **Sentinel coverage is partial, and that is a platform limit, not an oversight.**
  Splunk gets all 15 rules, source-bound. Microsoft XDR gets the
  `process_creation` subset — Defender XDR has no table equivalent for the
  Windows Security-log events the rest of the corpus targets. Sentinel's
  `SecurityEvent` table does not surface every field these rules use (`PreAuthType`
  is not a column), so those rules would need per-rule `EventData` parsing before
  they could run there. The Kusto pipeline refuses to emit a query it cannot bind
  to a table, which is the correct behaviour.

## The detection lifecycle

Hypothesis → Sigma rule → EVTX fixtures (TP + benign) → tested with Hayabusa →
converted to KQL/SPL → mapped to ATT&CK → shipped via PR.
Full walkthrough in [`docs/detection_lifecycle.md`](docs/detection_lifecycle.md).

## Coverage

The matrix at the top is rendered directly from the rule corpus by
[`detkit coverage`](src/detkit/coverage.py) — no external service needed. CI
regenerates every published artifact and fails if the committed copies differ,
so the dashboard cannot drift from the repo.

For an interactive view, [`coverage/navigator_layer.json`](coverage/navigator_layer.json)
can be loaded in the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
("Open Existing Layer" → "Upload from local"). The layer pins `attack: 16`; if the
hosted Navigator has moved to a newer ATT&CK release it may refuse the file, which
is why the committed PNG above is the canonical, dependency-free view.
