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
        ├── sigma convert ──────── valid KQL (Sentinel) and SPL (Splunk) or CI fails
        │
        ├── Hayabusa + pytest ──── TP fixture must fire, benign fixture must not
        │
        └── coverage map ───────── coverage.png matrix + ATT&CK Navigator layer
```

## Run it locally

Dependencies are locked with [uv](https://docs.astral.sh/uv/); `uv sync` builds the
exact environment CI uses, from `uv.lock`.

```bash
uv sync --all-extras          # exact locked environment, incl. dev tooling

uv run detkit validate        # metadata + fixture + ATT&CK tag discipline (authored only)
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

## Known gaps

Stated plainly, because a reviewer will find them anyway:

- **Detection quality is not measured yet.** Tests assert only that a rule fires
  on an attack sample and stays silent on a benign one. There is no precision,
  recall or false-positive rate per rule, and 14 of 15 rules currently have no
  benign counter-example at all. An eval harness over labelled events is the
  next piece of work.
- **`sigma check` is advisory, not a gate.** Two rules use `service: security`
  with raw EID 4688 fields instead of the generic `process_creation` logsource,
  because Hayabusa maps that category to Sysmon EID 1 and will not match the
  public 4688 samples. Until that is resolved the check runs and prints, but does
  not fail the build. It will, once the count is zero.
- **Converted SPL/KQL is validated for syntax, not deployability.** The pipelines
  only field-map `process_creation` rules, so most output carries raw Windows
  field names and no index/table binding. It parses; it is not drop-in.

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
