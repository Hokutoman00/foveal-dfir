# foveal-dfir

A defensive digital-forensics / incident-response agent for the SANS **FIND EVIL!** hackathon, built on top of the Protocol SIFT / Valhuntir platform.

## Thesis

The hackathon names its own open problem: an autonomous DFIR agent that "just says find evil" hallucinates and needs a human to guide it. We take that at face value — the failure mode is **self-deception** — and answer it structurally rather than with more careful prompting.

Most submissions build a "more careful" agent. We build a structurally different one:

1. **Blind independent grader (A/B principle).** A separate model judges each finding **from the raw evidence only**. It never sees the investigating agent's reasoning trace and is never told the claimed confidence — no anchoring. It re-derives, from evidence alone, what confidence is justified. ([verifier/grader.py](verifier/grader.py))
2. **Rule-enforced confidence staging.** "CONFIRMED" requires **two or more independent corroborating sources actually present in the finding's evidence list**, counted in code, not in the LLM's mood. Self-graded labels are structurally downgraded when the structure doesn't support them. ([verifier/staging.py](verifier/staging.py))
3. **Structural adversarial-evidence quarantine.** Embedded text in artifacts (filenames, log lines, registry values, task descriptions) is wrapped as untrusted data before reaching any model, and instruction-like spans are detected and surfaced as a signal in the verdict, never silently obeyed. ([verifier/quarantine.py](verifier/quarantine.py))
4. **Divergence as the primary signal.** The investigator and the blind grader produce three explicit states — `AGREE_REAL`, `AGREE_FP`, `DISAGREE` — and `DISAGREE` is the escalate set. Inter-observer disagreement is treated as evidence of where the truth lives, not noise to reconcile. ([verifier/divergence.py](verifier/divergence.py))
5. **Boundary register: declared blind spots.** Areas the agent did *not* examine, or where it could not resolve to a verdict, are emitted as a first-class output. Missed evidence is reported as missed, never silently dropped. ([verifier/boundary_register.py](verifier/boundary_register.py))
6. **Actor-cadence analysis (agent-vs-agent).** The hackathon's stated motivation is Anthropic's GTG-1002: autonomous AI attackers. We model the adversary as an agent and exploit a structural property — machine-paced timing (near-constant cadence, 24/7 continuity, no fatigue or hesitation) — to distinguish a likely autonomous-AI actor from a human one. The cadence assessor emits `MACHINE_PACED` / `HUMAN_LIKELY` / `AMBIGUOUS` / `INSUFFICIENT` with explicit reasons (CoV, long-gap count, work-hour ratio); real case-log integration arrives with the sample dataset. Synthetic-data tests pass. ([verifier/actor_cadence.py](verifier/actor_cadence.py))
7. **Pre-registered falsifiers.** For every "evil" hypothesis, the killer evidence is **declared in advance** and actively hunted. Killers come in two modes (`found_falsifies` if the pattern is observed, `absent_falsifies` if it is missing); the engine reports which killers hit and whether the hypothesis is falsified. Anti-tunnel-vision made Popperian and structural. Synthetic-data tests pass. ([verifier/falsifier.py](verifier/falsifier.py))
8. **Responsibility ledger.** Each claim records which observer produced it (`investigator`, `structural_staging`, `quarantine`, `blind_grader`, `divergence_arbiter`, `consensus_verdict`), where observers diverged, and which entity carries each verdict (`consensus_verdict` on `AGREE_*`, escalated to `human_arbiter` on `DISAGREE`). Distributed contribution, traceable accountability — not diffuse responsibility. Aggregated per-finding records form the structured execution log. ([verifier/responsibility_ledger.py](verifier/responsibility_ledger.py))

See [ARCHITECTURE.md](ARCHITECTURE.md) for the module layout, how the layers compose, and the safety boundary.

## Relationship to Valhuntir / Protocol SIFT

This agent runs **on top of** the base Protocol SIFT / Valhuntir platform (https://github.com/AppliedIR/sift-mcp). Valhuntir provides the SANS SIFT tool surface, MCP routing, platform-level audit trail, and case management. `foveal-dfir` adds an independent verification + active-defense layer that does **not** trust the investigating agent's self-assessment.

## Try it out

The current prototype operates on a toy `samples/findings.json` (mock findings as a self-grading investigator would emit them). End-to-end runs over the official sample case will be added once the dataset is integrated.

Requirements: Python 3.10+, and (for the blind grader) a local Ollama with `qwen2.5:7b` pulled.

```bash
# Full pipeline (rule-based stages + quarantine + blind grader):
python run_prototype.py

# Rule-based stages + quarantine only (no model call):
python run_prototype.py --no-grader
```

Expected output:
- at least one finding is downgraded because its evidence has only one independent source;
- at least one quarantine-flagged finding (adversarial / instruction-like spans in the evidence);
- at least one self-graded over-claim caught by the independent grader.

## Submission deliverables

| Item                          | Where                       |
|-------------------------------|-----------------------------|
| Public repository             | this repo                   |
| Architecture diagram          | [ARCHITECTURE.md](ARCHITECTURE.md) (Mermaid pipeline diagram) |
| Try-it-out instructions       | this README                 |
| Structured execution log      | `audit_log.json` (run `python run_prototype.py --audit-json`) |
| Accuracy report               | template: [ACCURACY_REPORT_TEMPLATE.md](ACCURACY_REPORT_TEMPLATE.md); filled per case |
| 5-minute demo video           | **[Watch on YouTube](https://youtu.be/1zWZS-58hqY)** (unlisted, 2:47); screenplay [DEMO_SCRIPT.md](DEMO_SCRIPT.md); reproducer [demo/produce_demo.py](demo/produce_demo.py) |
| Dataset documentation         | generated per case          |
| MIT license                   | [LICENSE](LICENSE)          |

## License

MIT — see [LICENSE](LICENSE).
