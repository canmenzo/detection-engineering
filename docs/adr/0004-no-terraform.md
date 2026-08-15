# ADR 0004 — Reproducibility without Terraform

**Status:** accepted
**Date:** 2026-08-15

## Context

The stated goal was that the whole pipeline should stand up from scratch with one
command, with Terraform as the assumed vehicle.

Terraform provisions infrastructure. This repository has none. It is a corpus of
Sigma rules plus the tooling that lints, tests, evaluates and compiles them; the
only "deployment" is a static dashboard on GitHub Pages. Three options were
considered:

1. **Terraform → Azure Sentinel.** Provision a Log Analytics workspace and push
   the converted KQL as analytics rules. The strongest artifact of the three, and
   it would force the compiled output to be genuinely deployable. It also costs
   money to run, needs a subscription to demonstrate, and — as the conversion
   work later showed — several rules cannot bind to Sentinel's `SecurityEvent`
   schema at all, so the apply would fail for reasons that have nothing to do
   with Terraform.
2. **Terraform + Docker → local Splunk.** Free and self-contained, but the Splunk
   container is heavy for CI and the value is mostly "we can run a container".
3. **No Terraform.** Make the *actual* reproducibility problem the target.

## Decision

Option 3. Terraform with no infrastructure behind it is a prop, and a reviewer
who opens it finds a module that provisions nothing.

What "reproducible" means for this repository is that any clean checkout produces
an identical, fully verified run. That is what was built:

- `uv.lock` pins every Python dependency exactly.
- `.hayabusa-version` pins the test engine's release **and the SHA-256 of each
  platform's archive**; `detkit hayabusa` refuses to execute an unverified binary.
  CI calls the same installer a human does, replacing a `curl | unzip | find`
  sequence whose empty result used to silently degrade the suite to "skipped".
- EVTX samples are pinned by repository, commit and SHA-256.
- `.attack-version` records the ATT&CK release the tags were validated against and
  fails the build on a major bump, because pySigma resolves ATT&CK from a live
  feed that moves without any commit here.
- A devcontainer pins the interpreter and sets `DETKIT_REQUIRE_HAYABUSA`.
- `detkit ci` runs every gate in CI's order, so a green local run and a green
  build mean the same thing.

## Consequences

- **+** Every input that can move is pinned, and each pin is verified rather than
  trusted.
- **+** Setup is `uv sync --all-extras && uv run detkit ci`.
- **−** No demonstration of infrastructure-as-code skills, which some job
  descriptions ask for. That is better shown by a project that actually has
  infrastructure than by a prop attached to one that does not.
- If a real SIEM target is ever added — a Sentinel workspace the rules genuinely
  deploy into — this decision should be revisited. The blocker is not Terraform;
  it is that the rules must first bind cleanly to that platform's schema.
