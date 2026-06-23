# Fixtures — proc_creation_win_encoded_powershell

Drop two EVTX files here:

- `true_positive.evtx` — must contain a process-creation event (Sysmon EID 1 or
  Security EID 4688) where `powershell.exe` runs with `-EncodedCommand`/`-enc`.
- `benign.evtx` — normal Windows activity that must **not** trigger the rule.

## Where to get them

- **True positive:** run the matching [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
  test for T1059.001 (encoded command) on a lab VM with Sysmon installed, then
  export the relevant window of `Microsoft-Windows-Sysmon/Operational`. Or pull a
  labeled sample from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES).
- **Benign:** a short clean capture of ordinary Windows usage from the same log
  channel.

Keep fixtures small and free of personal data — scrub hostnames/usernames if a
capture came from a real machine. These are committed binaries; do not include
anything sensitive.
