"""Orchestration: combine the three enforcement layers into one verdict.

verified_confidence = most conservative of:
  - the investigator's claimed confidence (we only ever DOWNGRADE)
  - the structural ceiling (rule-based, unfakeable)
  - the independent grader's evidence-only justified_confidence
and is further capped to INDICATED if unresolved adversarial content is present.
"""

from __future__ import annotations

from . import staging
from . import quarantine
from . import grader as grader_mod


def verify(finding: dict, use_grader: bool = True) -> dict:
    claimed = finding.get("confidence", "UNKNOWN")

    ceiling, ceiling_reasons = staging.structural_ceiling(finding)
    adversarial = quarantine.scan_finding(finding)

    candidates = [ceiling]
    grader_out = None
    if use_grader:
        grader_out = grader_mod.grade(finding)
        g_label = grader_out.get("justified_confidence")
        if g_label in staging.LADDER:
            candidates.append(g_label)

    if claimed in staging.LADDER:
        candidates.append(claimed)
    final = staging.most_conservative(*candidates)

    # Adversarial content the agent's claim ignored -> cap and flag.
    if adversarial and staging._rank(final) > staging._rank("INDICATED"):
        final = "INDICATED"

    downgraded = (
        staging._rank(final) < staging._rank(claimed)
        if claimed in staging.LADDER else None
    )

    return {
        "id": finding.get("id"),
        "claimed_confidence": claimed,
        "verified_confidence": final,
        "downgraded": downgraded,
        "structural_ceiling": ceiling,
        "structural_reasons": ceiling_reasons,
        "adversarial_flags": adversarial,
        "grader": grader_out,
    }
