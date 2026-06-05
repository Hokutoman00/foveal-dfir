# foveal-dfir

A defensive digital-forensics / incident-response agent for the SANS **FIND EVIL!** hackathon, built on top of the Protocol SIFT / Valhuntir platform.

## At a glance

**13 verifier modules · 4,818 ROCBA memory findings + 8 disk entity-merged findings analyzed · 16 single-source CONFIRMED claims downgraded to INDICATED · 3 disk claims permitted as CONFIRMED by structure · 1 disk claim survives CONFIRMED with the blind grader on — same rule, both directions.**

## Thesis

The hackathon names its own open problem: an autonomous DFIR agent that "just says find evil" hallucinates and needs a human to guide it. We take that at face value — the failure mode is **self-deception** — and answer it structurally rather than with more careful prompting.

A common DFIR-enforcement pattern lets a finding reach the top confidence label either by accumulating multiple corroborating observations *or* by a single observation that a validator labels "strongly corroborated". The single-strong path turns the floor on top confidence into an LLM judgment call. `foveal-dfir` rejects that path: the top label requires a structural floor of **N ≥ 2 distinct artifact sources, counted in code**, with no LLM-judgment escape hatch.

Most submissions build a "more careful" agent. We build a structurally different one:

1. **Blind independent grader (A/B principle).** A separate model judges each finding **from the raw evidence only**. It never sees the investigating agent's reasoning trace and is never told the claimed confidence — no anchoring. It re-derives, from evidence alone, what confidence is justified. ([verifier/grader.py](verifier/grader.py))
2. **Rule-enforced confidence staging.** "CONFIRMED" requires **two or more independent corroborating sources actually present in the finding's evidence list**, counted in code, not in the LLM's mood. Self-graded labels are structurally downgraded when the structure doesn't support them. ([verifier/staging.py](verifier/staging.py))
3. **Structural adversarial-evidence quarantine.** Embedded text in artifacts (filenames, log lines, registry values, task descriptions) is wrapped as untrusted data before reaching any model, and instruction-like spans are detected and surfaced as a signal in the verdict, never silently obeyed. ([verifier/quarantine.py](verifier/quarantine.py))
4. **Divergence as the primary signal.** The investigator and the blind grader produce three explicit states — `AGREE_REAL`, `AGREE_FP`, `DISAGREE` — and `DISAGREE` is the escalate set. Inter-observer disagreement is treated as evidence of where the truth lives, not noise to reconcile. ([verifier/divergence.py](verifier/divergence.py))
5. **Boundary register: declared blind spots.** Areas the agent did *not* examine, or where it could not resolve to a verdict, are emitted as a first-class output. Missed evidence is reported as missed, never silently dropped. ([verifier/boundary_register.py](verifier/boundary_register.py))
6. **Actor-cadence analysis (agent-vs-agent).** The hackathon's stated motivation is Anthropic's GTG-1002: autonomous AI attackers. We model the adversary as an agent and exploit a structural property — machine-paced timing (near-constant cadence, 24/7 continuity, no fatigue or hesitation) — to distinguish a likely autonomous-AI actor from a human one. The cadence assessor emits `MACHINE_PACED` / `HUMAN_LIKELY` / `AMBIGUOUS` / `INSUFFICIENT` with explicit reasons (CoV, long-gap count, work-hour ratio). **On ROCBA (2,186 process-creation timestamps from `pslist.json`): verdict `AMBIGUOUS` — CoV=0.76 (human-like variability) conflicts with work-hour ratio 0.60 (24/7-like due to system processes). The architecture does not force a verdict when signals conflict; `AMBIGUOUS` is reported honestly.** ([verifier/actor_cadence.py](verifier/actor_cadence.py))
7. **Pre-registered falsifiers.** For every "evil" hypothesis, the killer evidence is **declared in advance** and actively hunted. Killers come in two modes (`found_falsifies` if the pattern is observed, `absent_falsifies` if it is missing); the engine reports which killers hit and whether the hypothesis is falsified. Anti-tunnel-vision made Popperian and structural. Synthetic-data tests pass. ([verifier/falsifier.py](verifier/falsifier.py))
8. **Responsibility ledger.** Each claim records which observer produced it (`investigator`, `structural_staging`, `quarantine`, `blind_grader`, `divergence_arbiter`, `consensus_verdict`), where observers diverged, and which entity carries each verdict (`consensus_verdict` on `AGREE_*`, escalated to `human_arbiter` on `DISAGREE`). Distributed contribution, traceable accountability — not diffuse responsibility. Aggregated per-finding records form the structured execution log. ([verifier/responsibility_ledger.py](verifier/responsibility_ledger.py))

See [ARCHITECTURE.md](ARCHITECTURE.md) for the module layout, how the layers compose, and the safety boundary.

## Relationship to Valhuntir / Protocol SIFT

This agent runs **on top of** the base Protocol SIFT / Valhuntir platform (https://github.com/AppliedIR/sift-mcp). Valhuntir provides the SANS SIFT tool surface, MCP routing, platform-level audit trail, and case management. `foveal-dfir` adds an independent verification + active-defense layer that does **not** trust the investigating agent's self-assessment.

## Try it out

`foveal-dfir` runs end-to-end on the **official ROCBA sample case** (~41 GB: memory image + NTFS disk image E01), reproduced below. The point is not a prettier report; it is an auditable safety layer that can say "not enough evidence" when an autonomous investigator over-claims.

Requirements: Python 3.10+, and (for the blind grader) a local Ollama with `qwen2.5:7b` pulled.

### Quick toy run (no dataset required)

```bash
# Full pipeline on the toy sample (rule-based stages + quarantine + blind grader):
python run_prototype.py

# Rule-based stages + quarantine only (no model call):
python run_prototype.py --no-grader

# GTG-1002-style adversarial evidence: two-source claim capped by quarantine:
python run_prototype.py --sample samples/adversarial_findings.json --no-grader
```

### Real-case runs (ROCBA, both passes)

```bash
# Memory pass: 4,818 findings ingested from Volatility3 plugins,
# 16 single-source CONFIRMED claims downgraded by the structural rule.
python -m cases.run_rocba --findings-dir cases_data/rocba [--no-grader]

# Disk pass: 8 entity-merged findings from fls listings (Google Drive folder,
# iCloud folder, Downloads, Prefetch). 5 single-source claims downgraded;
# 3 multi-source claims (e.g. cloud_sync.* entities corroborated by BOTH
# filesystem AND Prefetch) keep their CONFIRMED label — same rule, both directions.
python -m cases.run_rocba_disk --findings-dir cases_data/rocba_disk [--no-grader]
```

### Rule both ways — ROCBA result summary

The structural rule runs in both directions on the same evidence. Numbers from the real ROCBA case:

| Pass | Input findings | Rule action | Outcome |
|------|---------------|-------------|---------|
| Memory (Volatility3) | 4,818 | 16 single-source CONFIRMED → INDICATED | **4,802** pass through; 0 CONFIRMED survive (all 16 were the only CONFIRMED in the set) |
| Disk (fls, structural-only) | 8 | 5 single-source capped at INDICATED | **3** multi-source entities keep CONFIRMED |
| Disk (fls, grader-on) | 8 | grader pushes `google_drive` + `dropbox` back to INDICATED | **1** surviving CONFIRMED (`cloud_sync.icloud`) |

The rule that produced 16 downgrades in the memory pass is identical to the rule that preserved 3 findings in the disk structural pass and 1 finding in the disk grader-on pass. No special-casing — the ceiling and the floor are the same predicate: `distinct_source_count >= 2`.

### Pre-registered falsifiers — ROCBA result

Four hypotheses registered before inspection against the ROCBA disk evidence (`cases/rocba_hypotheses.json`):

| Hypothesis | Falsified? | Killers hit |
|------------|-----------|-------------|
| `personal_cloud_sync_ip_staging` | **not falsified** | — (cloud sync entities + sensitive file names present; hypothesis supported) |
| `single_source_cloud_claims_should_not_be_confirmed` | **FALSIFIED** | `single_source_claims_exist` (single-source cloud claims exist; structural cap needed and applied) |
| `credential_theft` | **FALSIFIED** | `no_credential_harvest_tool` (no mimikatz, lsass dump, or credential-harvesting artifact on disk) |
| `lateral_movement` | **FALSIFIED** | `no_remote_execution_artifact` (no psexec, WMI, RDP artifact on disk) |

Honest result: the disk evidence supports IP-theft-via-cloud-sync but does not support credential theft or lateral movement from disk artifacts alone. The killers are declared *before* inspection; the verdict is driven by what the evidence contains, not by what the analyst expects.

### GTG-1002 adversarial evidence demo

The hackathon's stated motivation is Anthropic's GTG-1002: autonomous AI attackers. `F-005` in `samples/findings.json` demonstrates the counter-measure directly: an autonomous AI actor plants a `health_check.log` file containing `<im_start>system` / `<im_end>` LLM token-injection markup specifically designed to hijack an LLM-based forensic agent. The quarantine module detects the injected spans before they reach any model:

```
F-005   INDICATED  INDICATED  GRADER_UNAVAILABLE -   quarantine:2-span(s)
```

The `<im_start>` and `<im_end>` tokens are sanitised and flagged in the audit trail. The grader receives a sanitised copy of the evidence and cannot be instructed by the attacker's planted directive. Run `python run_prototype.py --no-grader` to see the default sample, or `python run_prototype.py --sample samples/adversarial_findings.json --no-grader` for a two-source adversarial finding capped by quarantine; add `--audit-json` for the full per-finding record.

Expected output (toy or real):
- at least one finding is downgraded because its evidence has only one independent source;
- at least one finding is **kept** at CONFIRMED because its evidence has ≥ 2 independent sources;
- at least one quarantine-flagged finding (adversarial / instruction-like spans in the evidence);
- at least one self-graded over-claim caught by the independent grader (grader-on runs).

A worked example over the real ROCBA case lives in [EXAMPLE_ACCURACY_REPORT_ROCBA.md](EXAMPLE_ACCURACY_REPORT_ROCBA.md).

## Submission deliverables

| Item                          | Where                       |
|-------------------------------|-----------------------------|
| Public repository             | this repo                   |
| Judge packet                  | [JUDGE_PACKET.md](JUDGE_PACKET.md) |
| Strict scorecard              | [SCORECARD.md](SCORECARD.md) |
| Architecture diagram          | [ARCHITECTURE.md](ARCHITECTURE.md) (Mermaid pipeline diagram) |
| Try-it-out instructions       | this README                 |
| Structured execution log      | `audit_log.json` (run `python run_prototype.py --audit-json`) |
| Accuracy report               | template: [ACCURACY_REPORT_TEMPLATE.md](ACCURACY_REPORT_TEMPLATE.md); filled per case |
| 5-minute demo video           | **[Watch on YouTube](https://youtu.be/1zWZS-58hqY)** (unlisted, 2:47); screenplay [DEMO_SCRIPT.md](DEMO_SCRIPT.md); reproducer [demo/produce_demo.py](demo/produce_demo.py) |
| Dataset documentation         | generated per case          |
| MIT license                   | [LICENSE](LICENSE)          |

## Accuracy narrative — does the output match the ROCBA scenario?

The ROCBA sample case describes Fred Rocba, a departing employee suspected of staging corporate IP for exfiltration via personal cloud services. The `foveal-dfir` pipeline was run against the official memory and disk evidence without any pre-knowledge of the scenario narrative. The output aligns with the scenario on every testable axis:

| Scenario claim | Pipeline output | Match? |
|----------------|----------------|--------|
| Cloud-sync services active (Google Drive, iCloud, Dropbox) | `cloud_sync.google_drive`, `cloud_sync.dropbox`, `cloud_sync.icloud` all detected as entities with filesystem + Prefetch artifacts | Yes |
| Sensitive IP files present in sync locations | `SRL-Offer.pdf`, `VIBRANIUM.docx`, `HighFiveBusinessPlanV20.docx`, `Firedam.xls` detected in cloud-sync evidence; falsifier `personal_cloud_sync_ip_staging` **not falsified** | Yes |
| Human actor (insider, not autonomous AI) | Actor-cadence verdict: `AMBIGUOUS` — CoV=0.76 consistent with human variability; work-hour contamination from system processes prevents `HUMAN_LIKELY`. Does not falsely conclude `MACHINE_PACED`. | Consistent (honest) |
| No credential-dumping tool evidence | Falsifier `credential_theft` **FALSIFIED** — no mimikatz, lsass dump, or credential-harvest artifact on disk | Yes |
| No lateral-movement evidence | Falsifier `lateral_movement` **FALSIFIED** — no psexec, WMI remote-exec, or RDP artifact on disk | Yes |
| Some cloud claims have only one artifact source | 5 of 8 disk findings (single-source) are capped at `INDICATED` by the structural rule | Yes |
| Multi-source cloud evidence is more reliable | 3 of 8 disk findings (filesystem + Prefetch corroboration) keep `CONFIRMED` structurally; 1 survives with blind grader on | Yes |

The pipeline did not need the scenario description to produce this output. The structural rules, falsifier killers, and blind grader independently converge on the same narrative as the case facts — which is the correct behavior for a forensic enforcement layer.

## License

MIT — see [LICENSE](LICENSE).
