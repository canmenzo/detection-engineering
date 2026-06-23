# How a detection gets built and tested here

1. **Hypothesis.** Start from an adversary behavior worth catching (e.g. "an
   attacker base64-encodes PowerShell to obfuscate intent"). Tie it to an ATT&CK
   technique (T1059.001).

2. **Write the rule.** Author a Sigma rule under `detections/<source>/...` with
   full metadata, including at least one `attack.tXXXX` tag. Follow the
   `<logsource>_<platform>_<short_description>.yml` naming convention.

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

6. **Map & ship.** `generate_navigator_layer.py` adds the technique to the
   coverage map. Open a PR; CI must be green before merge.

The discipline gate: `validate_metadata.py` rejects any rule missing an ATT&CK
tag or a fixture. No exceptions — that gate is the whole point.
