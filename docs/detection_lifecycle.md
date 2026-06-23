# How a detection gets built and tested here

1. **Hypothesis.** Start from an adversary behavior worth catching (e.g. "an
   attacker base64-encodes PowerShell to obfuscate intent"). Tie it to an ATT&CK
   technique (T1059.001).

2. **Write the rule.** Author a Sigma rule under `detections/<source>/...` with
   full metadata, including at least one `attack.tXXXX` tag. Follow the
   `<logsource>_<platform>_<short_description>.yml` naming convention.

3. **Build fixtures.** Create `tests/fixtures/<rule_stem>/`:
   - `true_positive.evtx` — telemetry of the behavior firing (Atomic Red Team run
     or a labeled EVTX-ATTACK-SAMPLES capture).
   - `benign.evtx` — clean activity that must not trigger the rule.

4. **Test.** `pytest` runs Hayabusa against both fixtures: the TP must produce a
   detection, the benign must produce none. A rule that fires on benign telemetry
   is a failing build, not a shipped detection.

5. **Validate conversion.** `sigma convert` to KQL (Sentinel) and SPL (Splunk)
   using `pipelines/` proves the rule is syntactically valid against real backends.

6. **Map & ship.** `generate_navigator_layer.py` adds the technique to the
   coverage map. Open a PR; CI must be green before merge.

The discipline gate: `validate_metadata.py` rejects any rule missing an ATT&CK
tag or a fixture. No exceptions — that gate is the whole point.
