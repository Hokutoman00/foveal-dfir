"""Boundary register: an explicit list of what was NOT resolved.

Honest IR Accuracy depends on reporting missed evidence as missed, not
silently dropping it. SPECA's independent experiment on real-scale data
confirmed: in this domain, evil is by definition not salient -- a cheap
salience pass misses ~75% of real findings at a 20% budget. Therefore
coverage must be exhaustive OR explicitly declared. This module is the
explicit-declaration half.

Categories:
  RESOLVED                - examined and judged at INDICATED or above,
                             OR jointly judged FP by both observers
                             (AGREE_FP).
  UNINSPECTED             - examined but no verdict could be reached and
                             the observers do not disagree -- typically a
                             single content-bearing source, missing
                             provenance, or grader uncertain.
  LOW_CONFIDENCE_BOUNDARY - examined and the two observers DISAGREE; the
                             finding sits on the boundary between real and
                             FP, awaiting human arbitration.
  DECLARED_UNEXAMINED     - regions the agent KNEW about but explicitly
                             chose not to examine, with stated reason
                             (e.g. "memory.raw absent -> memory-only
                             artifacts not examined").

Items in any of these categories are reported. They are never silently
dropped from the accuracy report.
"""

from __future__ import annotations
from typing import Iterable, Optional
from . import staging


def _is_resolved(verdict: dict) -> bool:
    """A verdict is resolved if its verified confidence is INDICATED or
    above, or if both observers concur it is unsupported (AGREE_FP)."""
    verified = verdict.get("verified_confidence", "UNKNOWN")
    if staging._rank(verified) >= staging.LADDER.index("INDICATED"):
        return True
    if verdict.get("divergence") == "AGREE_FP":
        return True
    return False


def register(
    verdicts: Iterable[dict],
    declared_unexamined: Optional[list[dict]] = None,
) -> dict:
    """Build the boundary register from (divergence-annotated) verdicts.

    declared_unexamined: list of {"area": str, "reason": str} describing
    regions the agent chose not to examine, with explicit reason. These are
    always reported as such, never silently omitted.
    """
    resolved = 0
    uninspected = []
    low_conf_boundary = []

    for v in verdicts:
        if _is_resolved(v):
            resolved += 1
            continue
        entry = {
            "id": v.get("id"),
            "verified_confidence": v.get("verified_confidence"),
            "divergence": v.get("divergence"),
            "reasons": v.get("structural_reasons", []),
        }
        if v.get("divergence") == "DISAGREE":
            low_conf_boundary.append(entry)
        else:
            uninspected.append(entry)

    return {
        "resolved_count": resolved,
        "uninspected": uninspected,
        "low_confidence_boundary": low_conf_boundary,
        "declared_unexamined": declared_unexamined or [],
        "note": (
            "Items here were NOT silently dropped. UNINSPECTED = examined "
            "but no verdict possible (single-source / missing provenance / "
            "grader uncertain). LOW_CONFIDENCE_BOUNDARY = the two observers "
            "disagreed; the finding awaits human arbitration. "
            "DECLARED_UNEXAMINED = the agent explicitly chose not to "
            "examine these regions and states why."
        ),
    }


def summary_lines(reg: dict) -> list[str]:
    """Human-readable summary lines suitable for stdout."""
    lines = []
    n_un = len(reg["uninspected"])
    n_bd = len(reg["low_confidence_boundary"])
    n_de = len(reg["declared_unexamined"])
    lines.append(
        f"Boundary register: resolved={reg['resolved_count']} "
        f"uninspected={n_un} disagree_boundary={n_bd} "
        f"declared_unexamined={n_de}"
    )
    for e in reg["low_confidence_boundary"]:
        lines.append(
            f"  LOW_CONFIDENCE_BOUNDARY: {e['id']} "
            f"(verified={e['verified_confidence']}, observers disagree)"
        )
    for e in reg["uninspected"]:
        lines.append(
            f"  UNINSPECTED: {e['id']} "
            f"(verified={e['verified_confidence']})"
        )
    for e in reg["declared_unexamined"]:
        lines.append(
            f"  DECLARED_UNEXAMINED: {e.get('area', '?')} "
            f"({e.get('reason', 'no reason given')})"
        )
    return lines
