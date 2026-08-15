# How a detection gets built and tested here

1. **Hypothesis.** Start from an adversary behavior worth catching (e.g. "an
   attacker base64-encodes PowerShell to obfuscate intent"). Tie it to an ATT&CK
   technique (T1059.001).

2. **Write the rule.** Author a Sigma rule under `detections/<source>/...` with
   full metadata, including at least one `attack.tXXXX` tag. Follow the
   `<logsource>_<platform>_<short_description>.yml` naming convention.

2b. **Probe the real telemetry before finalising the logic.** `detkit probe
   <rule_stem>` parses the pinned EVTX, runs the rule's compiled SQL against it,
   and prints the matching events — or, when it should have matched and did not,
   the fields of the events that carry the referenced fields. Every discriminator
   in this repo was written this way. Writing a rule against imagined telemetry
   is how you end up with one that passes your own tests and misses the attack.

3. **Pin test samples.** Create `tests/fixtures/<rule_stem>/sample_sources.yml`
   listing public EVTX samples by `repo + commit + path + sha256`, each tagged
   `expect: fire` (true positive) or `expect: silent` (must not fire). Samples
   are fetched at test time, not vendored — see `docs/adr/0002`. Rules that can't
   be EVTX-tested are declared in `tests/conversion_only.txt`.

4. **Test.** `pytest` downloads the pinned samples and runs Hayabusa against the
   rule: `fire` samples must produce a hit, `silent` samples must produce none. A
   rule that fires on a `silent` sample is a failing build, not a shipped detection.

5. **Validate conversion.** `sigma convert` to KQL (Sentinel) and SPL (Splunk)
   using `pipelines/` proves the rule is syntactically valid against real backends.

6. **Map & ship.** Regenerate the coverage artifacts (`detkit navigator`,
   `detkit coverage`, `detkit dashboard`) and commit them with the rule — CI
   fails if the committed artifacts do not match what the generators produce.
   Changes land on `main` and CI must be green.

The discipline gate: `detkit validate` rejects any rule missing an ATT&CK tag or
a fixture, and rejects any `attack.*` tag that does not resolve against the live
ATT&CK release (`.attack-version` records the release last reviewed and fails the
build on a major bump). No exceptions — that gate is the whole point.

The harness gate: `tests/test_harness_integrity.py` asserts the suite actually
ran — collected cases must equal the samples the fixture manifests declare, and
every rule must have a fixture or an explicit `conversion_only.txt` entry.
