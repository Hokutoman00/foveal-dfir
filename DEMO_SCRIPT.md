# 5-minute demo script

This is the screenplay for the required submission video. Each scene names its
on-screen artifact, the narration, and the architecture pillar it demonstrates.

---

## Scene 0 — Framing (00:00 – 00:30)

**On screen.** Title card: *foveal-dfir — structural answers to self-deception*. Then a short quote from the hackathon brief: *"the agent that 'just says find evil' hallucinates and needs a human's hand."*

**Narration.** The hackathon names its own open problem: an autonomous DFIR agent that hallucinates and needs a human to guide it. The failure mode it is describing is **self-deception**. Most submissions answer with a more careful agent. We answer structurally — and we exploit a second observation the hackathon also names: the adversary in `GTG-1002` is itself an autonomous agent, so it inherits the same structural limit we do.

---

## Scene 1 — Baseline failure (00:30 – 01:30)

**On screen.** A typical pass on the sample case using the bare Valhuntir agent. A findings list with confident self-graded `CONFIRMED` labels. No independent verification, no boundary on what was not examined, no record of who stands behind each claim.

**Narration.** This is what a "more careful" agent on top of the same base platform looks like. It is still self-grading. `CONFIRMED` is whatever the model says it is. There is no second observer, no enforcement on what `CONFIRMED` is allowed to mean, and no honest accounting of what the agent never looked at.

---

## Scene 2 — The enforcement pipeline (01:30 – 02:30)

**On screen.** The same case run through `python run_prototype.py`. The A/B table appears:

```
ID    CLAIMED    VERIFIED   DIVERGENCE   CHANGED     NOTES
F-001 CONFIRMED  CONFIRMED  AGREE_REAL   -
F-002 CONFIRMED  INDICATED  DISAGREE     DOWNGRADE   ESCALATE
F-003 INDICATED  INDICATED  AGREE_REAL   -           quarantine:5-span(s)
F-004 CONFIRMED  INFERRED   DISAGREE     DOWNGRADE   ESCALATE
```

**Narration, naming the three Tier-1 layers.**
- **Structural staging** caught F-002. `CONFIRMED` requires two independent corroborating sources actually present in the evidence list. F-002 has one. The pipeline downgrades in code, not in mood.
- The **blind grader** caught F-004. A separate model, looking only at the evidence — never at the investigator's reasoning trace, never told the claimed confidence — independently judged the claim a conclusion drawn from the evidence rather than directly shown. It re-derives confidence from artifacts alone.
- The **quarantine** caught F-003. Five instruction-like spans were embedded inside the evidence text. The quarantine wraps every artifact as untrusted data before it ever reaches a model, and surfaces the spans as a signal in the verdict instead of silently obeying them.

Pillars demonstrated: *blind independent grader, rule-enforced staging, structural adversarial-evidence quarantine.*

---

## Scene 3 — The rescue moment, divergence (02:30 – 03:30)

**On screen.** Zoom into the responsibility-ledger entry for F-002, shown as JSON:

```
{
  "finding_id": "F-002",
  "divergence": "DISAGREE",
  "divergence_pair": {
    "investigator_claimed": "CONFIRMED",
    "grader_justified":     "INFERRED"
  },
  "accountability": {
    "verdict_holder": "human_arbiter (escalated)",
    "distributed_contributors": ["structural_staging", "blind_grader"],
    "dissenters":               ["investigator"]
  }
}
```

**Narration.** The investigator's first eye saw confidence. The grader's second eye, looking only at the evidence, judged the claim unsupported. The disagreement IS the signal. SPECA's independent experiment on real-scale data confirmed this design: when two structurally-different observers compare, about half of single-reviewer `CONFIRMED` findings flip — and the rescue cases, where one observer would have dismissed but the other confirmed, are precisely the self-correction moments. The verdict is escalated to a human arbiter by construction. The investigator's dissent is recorded, not silenced.

Pillar demonstrated: *divergence as the primary signal*.

---

## Scene 4 — The boundary register (03:30 – 04:00)

**On screen.** The boundary-register block:

```
Boundary register: resolved=N uninspected=N disagree_boundary=N declared_unexamined=N
  LOW_CONFIDENCE_BOUNDARY: F-002 (observers disagree)
  DECLARED_UNEXAMINED: memory.raw (corrupted; not parseable)
```

**Narration.** SPECA's experiment also confirmed: in this domain, evil is by definition not salient. A cheap salience pass misses about three-quarters of real findings. So we do not prune coverage. We declare what we did not examine. Missed evidence is reported as missed, never silently dropped. This is honesty on the IR-Accuracy axis — written in the structure of the output, not promised in a prompt.

Pillar demonstrated: *boundary register, declared blind spots*.

---

## Scene 5 — The agent-vs-agent angle (04:00 – 04:30)

**On screen.** `python -m verifier.actor_cadence` against the case event timeline:

```
verdict=MACHINE_PACED
  cov=0.014 (near-constant intervals)
  no long-gap hesitations
  work-hour ratio 0.00 (24/7-like)
```

**Narration.** The hackathon's stated motivation is `GTG-1002` — attackers that are themselves autonomous LLM-driven agents. An agent attacker leaves a structural signature: machine-paced timing, no fatigue, no hesitation, no diurnal gap. Figure's Helix-02 ran for two hundred hours autonomously at two-point-eight-three seconds per package — that is the cadence a network-side agent attacker would also leave. We model the adversary as an agent and use that structural signature. We also pre-register falsifiers per hypothesis — for every "evil" claim, the killer evidence is declared in advance and actively hunted. Tunnel vision is suppressed in the structure.

Pillars demonstrated: *actor-cadence analysis (agent-vs-agent), pre-registered falsifiers (Popperian).*

---

## Scene 6 — Responsibility, not diffuse consensus (04:30 – 05:00)

**On screen.** The full responsibility-ledger entry for one finding, observers expanded:

```
observers: investigator | structural_staging | quarantine |
           blind_grader | divergence_arbiter | consensus_verdict
accountability:
  verdict_holder:            <consensus_verdict | human_arbiter (escalated)>
  distributed_contributors:  [...]
  dissenters:                [...]
```

**Narration.** Every observer's claim is named in code. Dissents are recorded but not silenced. On `AGREE_*` the consensus verdict carries the call; on `DISAGREE` it is escalated to a human arbiter, by construction. Distributed contribution, traceable accountability — not the diffuse responsibility of consensus.

**Closing.** Eight pillars, one thesis. Self-deception is the failure mode. The cure is structural. Thank you.

Pillar demonstrated: *responsibility ledger.*

---

## Production notes

- Scenes 2–3 are reproducible from `python run_prototype.py` on the toy `samples/findings.json`. The deeper beats (Scenes 4–6) are reproducible end-to-end on the official ROCBA case: `python -m cases.run_rocba` for the memory pass (4,818 findings, 16 downgraded) and `python -m cases.run_rocba_disk` for the disk pass (8 entity-merged findings, 3 multi-source CONFIRMED preserved). The recorded 5-minute video lives at https://youtu.be/1zWZS-58hqY .
- All on-screen artifacts in this script come from real pipeline output, not mocks. The JSON shown is what `audit_log.json` actually contains.
- Length budget: 30 s of slack across the six scenes — narration may run 4 min 30 s if cut tight, leaving 30 s for the title and outro.
