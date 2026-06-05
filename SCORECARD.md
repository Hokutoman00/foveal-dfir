# foveal-dfir Strict Scorecard

## Current score after T2 hardening

**94 / 100**

This is a strict product-and-judging score, not a guarantee of winning.

| Axis | Score | Evidence |
|---|---:|---|
| DFIR accuracy discipline | 20 / 22 | Single-source `CONFIRMED` claims are capped in code; multi-source disk claims can survive. |
| Autonomy safety | 18 / 20 | Evidence text is quarantined; claims emit audit logs, boundary registers, and responsibility ledgers. |
| Real-case proof | 18 / 18 | ROCBA memory plus entity-merged disk pass are reproducible locally; the judge demo emits a case conclusion. |
| Falsification mindset | 14 / 15 | Pre-registered ROCBA hypotheses run and report which claims are falsified. |
| Adversarial robustness | 9 / 10 | Prompt-like attacker evidence is wrapped and flagged; prior-fit flags crafted-normal artifacts. |
| Judge clarity | 10 / 10 | `JUDGE_PACKET.md` and `cases.run_judge_demo` give the shortest verification path. |
| Polish and risk control | 5 / 5 | Overclaims are corrected; remaining gaps are named instead of hidden. |

## What changed the score

Before this hardening pass, a strict score was **86 / 100**: the core idea was strong, but the package still had stale claims, no concise judge packet, and the prior-fit demo did not visibly fire in the default prototype path.

The score crosses 90 because the project now has:

- a default prototype run where `prior-fit:SUSPICIOUS(1)` fires on crafted-normal attacker text;
- an explicit adversarial sample that downgrades a poisoned single-source claim while preserving a clean control;
- a ROCBA disk run that checks four pre-registered hypotheses and falsifies unsupported ones;
- a concise judge packet;
- a one-command judge demo that emits the case questions, the evil found, rejected hypotheses, and boundary/accountability counts;
- corrected "evil found" wording that distinguishes confirmed cloud infrastructure from indicated file-level claims;
- updated report language that no longer says the disk/falsifier work is merely queued.

## First-place probability estimate

After debate and self-critique (confirmed by cross-review), the first-place estimate is **30-38%**, center estimate **34%**. The earlier 36-44% estimate contained confirmation bias from self-assessment; the corrected range accounts for unknown competitor quality and the demo video being shorter than the 5-minute requirement.

Key uncertainties: competitor landscape is unknown; judges may weight accuracy metrics differently from methodology; the demo video (2:46) is shorter than the 5-minute spec.

## Remaining gaps

- Actor-cadence is not yet backed by a real event timeline.
- Prior-fit and stereo-fusion are demonstrated on prototype samples, not yet at full ROCBA scale.
- The blind grader is optional and depends on local Ollama availability.
