# Fixtures — proc_creation_win_encoded_powershell

This Sysmon (EID 1) process-creation rule is currently **conversion-only**
(listed in `tests/conversion_only.txt`): it is validated by `sigma check` and
SPL/KQL conversion in CI, but has no EVTX unit test because no public Sysmon
EID 1 sample containing `powershell -enc` is available, and a lab capture would
embed machine PII.

The same behavior **is** unit-tested via the ScriptBlock (EID 4104) rule
`posh_ps_susp_encoded_powershell_scriptblock`, whose `sample_sources.yml` pins a
real public Invoke-Obfuscation sample.

To promote this rule to fully-tested: add a `sample_sources.yml` here pointing at
a Sysmon EID 1 `powershell -enc` EVTX (lab capture, PII scrubbed) and remove the
stem from `tests/conversion_only.txt`.
