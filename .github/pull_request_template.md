## What this changes

<!-- One or two sentences. Which rules, and what behaviour changes. -->

## Detection quality

Rules and eval cases cannot merge without evaluation results. CI publishes the
full table to the run summary on every PR — link it or paste the affected rows.

| rule | precision | recall | FP rate | threshold |
|---|---:|---:|---:|---|
|  |  |  |  |  |

- [ ] `detkit eval` passes; every changed rule clears its declared thresholds
- [ ] If a threshold was **lowered**, the `justification` says why, and the reason
      is a property of the data or the technique — not "the rule failed the bar"
- [ ] New benign cases are genuine look-alikes (same event type, differing only
      where the rule's logic should discriminate)
- [ ] Every case has a `why`
- [ ] Regenerated artifacts committed (`detkit vendored|eval|navigator|coverage|dashboard`)

## Evidence

<!--
For a new or changed rule, say how you know it fires on real telemetry:
the pinned EVTX sample and its Hayabusa result, or why the rule is
conversion-only. "It looked right" is not evidence.
-->
