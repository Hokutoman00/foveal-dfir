"""Responsibility ledger: distributed contribution, traceable accountability.

The failure mode of consensus is diffuse responsibility -- everyone is at the
table, no one is accountable. The fix is not less consensus; it is making
every contributor's contribution traceable in code, so that no claim is
faceless and no observer can hide.

For each finding the ledger records, in order:

  observer            claim                              evidence
  --------            -----                              --------
  investigator        observation + interpretation       (the source artifacts)
                      + claimed_confidence
  structural_staging  ceiling label                      provenance reasons
  quarantine          n_adversarial_spans                quarantine flags
  blind_grader        justified_confidence               evidence-only reasoning
  divergence_arbiter  AGREE_REAL / AGREE_FP / DISAGREE   observer pair
  consensus_verdict   verified_confidence                most-conservative rule

The accountability section names the verdict_holder
("consensus_verdict" on AGREE_*, "human_arbiter (escalated)" on DISAGREE),
the distributed_contributors (observers whose direction aligns with the
verdict), and the dissenters (whose direction does not). Responsibility
is distributed across observers but never diffuse: each observer's
contribution is named in code, and the human arbiter holds final
accountability on the escalate set, by construction.

Aggregated per-finding records form the structured execution log required
by the hackathon submission deliverables.
"""

from __future__ import annotations
from typing import Iterable
from . import staging


def _real_or_not(label: str | None) -> bool | None:
    """True if INDICATED+, False if INFERRED/UNKNOWN, None if unknown label."""
    if label not in staging.LADDER:
        return None
    return staging._rank(label) >= staging.LADDER.index("INDICATED")


def attribute(verdict: dict) -> dict:
    """Build the responsibility-ledger entry for one verified finding.

    Input is the output of verify.verify() optionally annotated by
    divergence.annotate(). Output is JSON-serializable.
    """
    investigator = {
        "role": "investigator",
        "claim": {
            "claimed_confidence": verdict.get("claimed_confidence"),
            # observation / interpretation live in the source finding; we
            # name the contribution rather than copy the raw text here.
            "observation_source": "finding payload",
        },
    }
    structural = {
        "role": "structural_staging",
        "claim": {"ceiling": verdict.get("structural_ceiling")},
        "reasons": verdict.get("structural_reasons", []),
    }
    quarantine_entry = {
        "role": "quarantine",
        "claim": {
            "n_adversarial_spans": sum(
                len(a.get("suspicious_spans", []))
                for a in verdict.get("adversarial_flags", [])
            ),
            "any_flagged": bool(verdict.get("adversarial_flags")),
        },
        "flags": verdict.get("adversarial_flags", []),
    }
    grader_out = verdict.get("grader") or {}
    blind_grader = {
        "role": "blind_grader",
        "claim": {
            "justified_confidence": grader_out.get("justified_confidence"),
            "interpretation_is_inference": grader_out.get(
                "interpretation_is_inference"
            ),
            "adversarial_text_detected": grader_out.get(
                "adversarial_text_detected"
            ),
        },
        "reasoning": grader_out.get("reasoning"),
        "available": bool(grader_out) and not grader_out.get("_error"),
    }
    divergence_state = verdict.get("divergence", "GRADER_UNAVAILABLE")
    divergence_entry = {
        "role": "divergence_arbiter",
        "claim": {"state": divergence_state},
        "pair": verdict.get("divergence_pair", {}),
    }
    consensus = {
        "role": "consensus_verdict",
        "claim": {
            "verified_confidence": verdict.get("verified_confidence"),
            "downgraded_from_claimed": verdict.get("downgraded"),
        },
    }

    observers = [
        investigator,
        structural,
        quarantine_entry,
        blind_grader,
        divergence_entry,
        consensus,
    ]

    # Accountability: who holds the verdict, who agreed, who dissented.
    final_real = _real_or_not(verdict.get("verified_confidence"))
    if divergence_state == "DISAGREE":
        verdict_holder = "human_arbiter (escalated)"
    else:
        verdict_holder = "consensus_verdict"

    contributors: list[str] = []
    dissenters: list[str] = []

    def _classify(role: str, label: str | None) -> None:
        if final_real is None:
            return
        side = _real_or_not(label)
        if side is None:
            return
        (contributors if side == final_real else dissenters).append(role)

    _classify("investigator", verdict.get("claimed_confidence"))
    _classify("structural_staging", verdict.get("structural_ceiling"))
    _classify("blind_grader", grader_out.get("justified_confidence"))

    accountability = {
        "verdict_holder": verdict_holder,
        "distributed_contributors": contributors,
        "dissenters": dissenters,
    }

    return {
        "finding_id": verdict.get("id"),
        "observers": observers,
        "accountability": accountability,
        "note": (
            "Distributed contribution, traceable accountability. Every "
            "observer's claim is named in code. On DISAGREE the verdict is "
            "escalated to a human arbiter by construction; on consensus the "
            "verdict_holder is the agreed label and dissenters are recorded "
            "but not silenced."
        ),
    }


def audit_log(verdicts: Iterable[dict]) -> dict:
    """Aggregate per-finding attributions into the structured execution log."""
    entries = [attribute(v) for v in verdicts]
    n_escalated = sum(
        1
        for e in entries
        if e["accountability"]["verdict_holder"].startswith("human_arbiter")
    )
    n_downgraded = sum(
        1
        for e in entries
        if any(
            obs["role"] == "consensus_verdict"
            and obs["claim"].get("downgraded_from_claimed")
            for obs in e["observers"]
        )
    )
    return {
        "n_findings": len(entries),
        "n_downgraded_by_pipeline": n_downgraded,
        "n_escalated_to_human": n_escalated,
        "entries": entries,
    }


# --- Synthetic-data smoke test --------------------------------------------

if __name__ == "__main__":
    import json

    # A synthesized verify+divergence output: F-002 (only one source, the
    # investigator over-claims CONFIRMED, the grader independently judges
    # INFERRED -> DISAGREE -> escalate to human arbiter).
    sample = {
        "id": "F-002",
        "claimed_confidence": "CONFIRMED",
        "verified_confidence": "INDICATED",
        "structural_ceiling": "INDICATED",
        "structural_reasons": [
            "1 content-bearing source -> capped at INDICATED (CONFIRMED needs >=2 independent)"
        ],
        "adversarial_flags": [],
        "downgraded": True,
        "grader": {
            "justified_confidence": "INFERRED",
            "interpretation_is_inference": True,
            "adversarial_text_detected": False,
            "reasoning": "The observation is a conclusion drawn from a single source.",
        },
        "divergence": "DISAGREE",
        "divergence_pair": {
            "investigator_claimed": "CONFIRMED",
            "grader_justified": "INFERRED",
        },
    }
    log = audit_log([sample])
    print(json.dumps(log, indent=2))
