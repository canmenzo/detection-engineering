# Vendored detections — SigmaHQ

This directory is a **vendored, third-party** copy of the public
[SigmaHQ](https://github.com/SigmaHQ/sigma) rule corpus. It is **not** my own work
and is deliberately kept separate from the hand-authored, fixture-tested rules in
[`../detections/`](../detections/).

## Why it's here

The repo is two-tier on purpose:

| Tier | Path | What it proves |
|------|------|----------------|
| **Authored** | `detections/` | My own rules — each one ATT&CK-mapped *and* unit-tested against real adversary EVTX via Hayabusa. Quality + testing discipline. |
| **Vendored** | `vendored/` | The wider SigmaHQ corpus, run through the same conversion pipelines and folded into the coverage map. Shows I can operate a large rule corpus through CI at scale. |

The two are never conflated:

- The **metadata + fixture gate** (`tools/validate_metadata.py`) only scans
  `detections/`. Vendored rules are *not* held to the "every rule needs a fixture"
  bar — they're third-party and untested-by-me, and pretending otherwise would be
  dishonest.
- `yamllint` and `sigma check` in CI also run against `detections/` only.
- Vendored rules feed **convert** (a tolerant batch conversion smoke-test) and
  **coverage** (technique extraction) only — see `tools/vendored_report.py`.
- The dashboard and coverage matrix visually distinguish *authored/tested* cells
  from *vendored-only* cells.

## Source & pinning

- Upstream: <https://github.com/SigmaHQ/sigma>
- Pinned commit: `bbcae2453a6f396790272e82a357ba3779950a00`
- Subset vendored: `rules/windows/` (the project is Windows/EVTX-focused)
- Imported: 2026-06-24

To refresh against a newer SigmaHQ commit, see `tools/import_vendored.py`.

## License & attribution

The vendored rules are released by their authors under the
**Detection Rule License (DRL) 1.1** — full text in
[`LICENSE.Detection.Rules.md`](LICENSE.Detection.Rules.md). Each rule retains its
original `author` and `references` fields as required by the DRL. They are **not**
covered by this repository's own license.
