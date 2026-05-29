"""Inter-observer divergence: the two passes yield one of three explicit states.

The investigator (host SIFT agent) and the blind grader judge each finding
independently. We compare their verdicts and emit one of:

  AGREE_REAL  - both judge the finding real (INDICATED or above).
  AGREE_FP    - both judge it unsupported (INFERRED or below).
  DISAGREE    - one judges real, the other unsupported.

DISAGREE is the escalate set. SPECA's independent experiment on real-scale
data confirmed this design: about half of single-reviewer CONFIRMED findings
flip under an independent eye, and the rescue cases (one reviewer dismissed
-> the other confirmed) ARE the self-correction moments. We emit divergence
as a first-class signal, not as a silent gate.
"""

from __future__ import annotations
from . import staging

# "Real" threshold: INDICATED or above. INFERRED / UNKNOWN are treated as
# effectively false-positive for divergence purposes.
_REAL_FLOOR_RANK = staging.LADDER.index("INDICATED")


def _is_real(label: str | None) -> bool:
    if label is None:
        return False
    return staging._rank(label) >= _REAL_FLOOR_RANK


def divergence_state(verdict: dict) -> str:
    """Return AGREE_REAL / AGREE_FP / DISAGREE / GRADER_UNAVAILABLE.

    The investigator's label is taken from `claimed_confidence` (their first-
    pass self-grading). The grader's label is `grader.justified_confidence`
    (evidence-only, never anchored on the investigator's claim).
    """
    investigator_label = verdict.get("claimed_confidence")
    grader_out = verdict.get("grader") or {}
    grader_label = grader_out.get("justified_confidence")
    if grader_label not in staging.LADDER:
        return "GRADER_UNAVAILABLE"
    inv_real = _is_real(investigator_label)
    grd_real = _is_real(grader_label)
    if inv_real and grd_real:
        return "AGREE_REAL"
    if not inv_real and not grd_real:
        return "AGREE_FP"
    return "DISAGREE"


def annotate(verdict: dict) -> dict:
    """Return a verdict dict with divergence state and the observer pair attached."""
    state = divergence_state(verdict)
    grader_out = verdict.get("grader") or {}
    return {
        **verdict,
        "divergence": state,
        "divergence_pair": {
            "investigator_claimed": verdict.get("claimed_confidence"),
            "grader_justified": grader_out.get("justified_confidence"),
        },
    }


def is_escalate(verdict: dict) -> bool:
    """DISAGREE is the escalate set: the second eye reveals depth the first
    cannot see alone. These are the demo's self-correction moments."""
    return verdict.get("divergence") == "DISAGREE"
