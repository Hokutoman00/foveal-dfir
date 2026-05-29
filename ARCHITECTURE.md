# Architecture

## Thesis

The hackathon names its own open problem: an autonomous agent that "just says find evil" hallucinates and needs a human to guide it. We take that at face value — **the failure mode is self-deception** — and answer it structurally.

Two observations drive the design.

**Observation 1 (the analyst).** A single observer cannot see its own blind spot. Confidence the same observer assigns to its own conclusions is structurally fakeable. Both points are old (Hofstadter; the Exclusion / Intrinsicality axioms of IIT 4.0) and they apply unchanged to an autonomous LLM analyst.

**Observation 2 (the adversary).** Per Anthropic's GTG-1002 report, modern intrusions increasingly come from autonomous LLM-driven attackers. An agent attacker has the same structural limit — it cannot see its own blind spot — and its action stream carries machine-paced signatures (near-constant cadence, no fatigue, no hesitation). This is a target the defender can exploit.

The architecture therefore:
- investigates with **two structurally independent observers**, blind to each other, and treats their **disagreement** as the primary discovery surface;
- enforces confidence **in code**, not in the model's report;
- actively **models the adversary as an agent** and hunts the signatures of agentic action.

## Module layout

```
foveal-dfir/
├── verifier/
│   ├── grader.py             # T1 ✓  independent blind grader (evidence only, no trace, no claim)
│   ├── staging.py            # T1 ✓  rule-based source-counting confidence ceiling
│   ├── quarantine.py         # T1 ✓  structural adversarial-evidence handling
│   ├── verify.py             # T1 ✓  orchestrates the three layers into one verdict
│   ├── divergence.py         # T1 ✓  emit AGREE_REAL / AGREE_FP / DISAGREE
│   ├── boundary_register.py  # T1 ✓  declared uninvestigated / low-confidence areas
│   ├── actor_cadence.py      # T2 ✓  agent-vs-human signature via inter-event timing
│   ├── falsifier.py          # T2 ✓  pre-registered killer evidence per hypothesis
│   └── responsibility_ledger.py  # T3 ✓  per-claim provenance + divergence + verdict-holder
├── prior_fit.py              # T3    "fits the defender's prior too well" anomaly
├── stereo_fusion.py          # T3    reconstruct higher-dim attack shape from two views
└── run_prototype.py          # entry point
```

Legend: **T1 ✓** = exists today, on toy samples. **T2** = mid-tier, needed for the demo's agent-vs-agent beat. **T3** = scaffolded; depth scales with demo weight and remaining time.

## How a finding flows through the system

1. **Investigator** (the host Protocol SIFT / Valhuntir agent) emits a finding: an observation, an interpretation, a set of evidence artifacts, a claimed confidence.
2. **`quarantine.scan_finding`** flags instruction-like spans inside artifact content; **`quarantine.wrap`** delimits artifact content as untrusted data so it can never reach the instruction channel.
3. **`staging.structural_ceiling`** derives the maximum confidence the evidence *structure* allows. `CONFIRMED` requires two or more independent content-bearing sources with full provenance, counted in code.
4. **`grader.grade`** runs a separate model against evidence-only + the claim. It does **not** see the investigator's reasoning trace, and it is **not** told the claimed confidence (no anchoring).
5. **`verify.verify`** returns the **most conservative** of (claimed, structural ceiling, grader), and caps to `INDICATED` if unresolved adversarial content was found.
6. **`divergence`** records `AGREE_REAL` / `AGREE_FP` / `DISAGREE` between investigator and grader; `DISAGREE` is the escalate set and the source of the demo's self-correction moment.
7. **`actor_cadence`** + **`falsifier`** run on the case timeline and the active hypothesis set: cadence flags machine-paced actors; falsifier hunts pre-declared killer evidence.
8. **`boundary_register`** records what the agent did **not** examine or could not resolve. Missed evidence is reported, never silently dropped.
9. **`responsibility_ledger`** carries provenance per claim across the whole pipeline.

## Safety boundary

- The grader is **read-only over the finding**. It cannot modify evidence, cannot call tools, cannot upgrade a verdict beyond what the evidence alone justifies.
- The quarantine layer separates the **data channel** (evidence) from the **instruction channel** (model prompt). Adversarial directives become signals, never instructions.
- All claims pass through code-enforced confidence rules; `CONFIRMED` is not a self-reported label.
- The boundary register makes "what we did not look at" an explicit output, never a silent gap.
- The investigator's claimed confidence can only be **downgraded** by this pipeline, never upgraded.

## On foveation — a falsification we accepted

Foveated / active-inference exploration was a design candidate. An independent experiment on real-data scale showed that a cheap salience pass **misses ~75% of real findings**: in this domain, "evil" is by definition not salient. We therefore use attention only to **order exploration and provide a natural stop on an active hypothesis** — **never to prune coverage**. The boundary register makes the consequence explicit: areas without high-confidence resolution are reported as uninspected, not silently skipped. This adjustment is load-bearing for the IR-Accuracy axis (missed evil is the worst failure).

## Why this scores

- **Autonomous Execution Quality (tiebreaker)**: the pipeline runs end-to-end without a human approval gate; the human enters only at the divergence escalate set and at the boundary register.
- **IR Accuracy (confirmed vs inferred, hallucination)**: structural confidence ceiling + independent grader + boundary register together replace self-grading with code-enforced honesty.
- **Constraint Implementation (architectural > prompt)**: every guardrail is in code, not in instructions to the model. The quarantine separates channels; staging is a pure function over the finding structure; the grader is structurally blind to the investigator's trace.
- **Audit Trail Quality**: the responsibility ledger records which observer produced each claim, where they diverged, and which entity carries each verdict.
- **Breadth & Depth**: stereo fusion reconstructs the kill-chain across multiple evidence types from independent vantages; foveation directs depth where the marginal hypothesis information is highest.
- **Usability & Docs**: the architecture is a single thesis — *structural answers to self-deception* — and every module serves it.
