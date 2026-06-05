# foveal-dfir Judge Packet

## One-line claim

`foveal-dfir` is a safety layer for autonomous DFIR: it turns self-graded findings into auditable, evidence-bounded claims.

## What to run first

```bash
python -m cases.run_judge_demo --findings-dir cases_data/rocba_disk --no-grader
python run_prototype.py --no-grader
python run_prototype.py --sample samples/adversarial_findings.json --no-grader
python -m cases.run_rocba_disk --findings-dir cases_data/rocba_disk --out-dir cases_outputs/rocba_disk_judge --no-grader
```

## Result signals

Strict product score after this hardening pass: **94 / 100**. See [SCORECARD.md](SCORECARD.md) for the rubric and remaining gaps.

| Signal | Where | Why it matters |
|---|---|---|
| Single-source CONFIRMED is downgraded | `run_prototype.py`, ROCBA memory/disk | Prevents confident hallucinated DFIR claims. |
| Multi-source CONFIRMED can survive | ROCBA disk pass | The rule is fair; it permits as well as caps. |
| Adversarial evidence is quarantined | `samples/adversarial_findings.json` | Evidence text is attacker-controlled data, never instructions. |
| Pre-registered killers are checked | `cases/rocba_hypotheses.json` | The agent hunts falsifiers, not only confirming evidence. |
| Responsibility ledger is emitted | `audit_log.json` | Every claim names contributors, dissenters, and verdict holder. |
| One-command case conclusion | `cases.run_judge_demo` | The judge sees the autonomous loop, the evil found, and rejected hypotheses in one report. |

## ROCBA disk snapshot

- 8 entity-merged findings.
- 5 single-source claims downgraded by independent enforcement.
- 3 multi-source cloud-sync entities structurally permitted as CONFIRMED.
- 4 pre-registered hypotheses checked; unsupported credential-theft and lateral-movement hypotheses are falsified by absence of killer evidence.
- One-command judge report writes `cases_outputs/judge_demo/report.md`.

## Safety boundary

- No case files are redistributed.
- Evidence artifacts are read as data and wrapped before model review.
- `CONFIRMED` requires two independent content-bearing sources in code.
- Missing or unsupported hypotheses are reported, not silently smoothed over.
