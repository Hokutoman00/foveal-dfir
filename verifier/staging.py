"""Rule-based structural staging: the confidence ceiling the evidence STRUCTURE
permits, independent of any agent's self-reported confidence.

The label is derived from observable facts (how many independent artifacts carry
content, whether each has full provenance), not from a number the generating
agent emits. That is what makes it unfakeable: a CONFIRMED label requires >=2
independent corroborating sources to actually be present in the finding.
"""

from __future__ import annotations

# Ordered confidence ladder (low -> high). CONTRADICTED/SPECULATIVE are handled
# conservatively (treated as the lowest rank) so they can never be upgraded.
LADDER = ["UNKNOWN", "INFERRED", "INDICATED", "CONFIRMED"]


def _rank(label: str) -> int:
    try:
        return LADDER.index(label)
    except ValueError:
        return 0


def most_conservative(*labels: str) -> str:
    return min(labels, key=_rank)


def independent_sources(finding: dict) -> list[str]:
    """Distinct artifact sources that actually carry content."""
    seen = set()
    for art in finding.get("artifacts", []):
        src = (art.get("source") or "").strip()
        content = (art.get("content") or "").strip()
        if src and content:
            seen.add(src)
    return sorted(seen)


def provenance_gaps(finding: dict) -> list[str]:
    gaps = []
    arts = finding.get("artifacts", [])
    if not arts:
        gaps.append("no artifacts attached")
    for i, art in enumerate(arts):
        for field in ("source", "extraction", "content"):
            if not (art.get(field) or "").strip():
                gaps.append(f"artifact[{i}] missing {field}")
    return gaps


def structural_ceiling(finding: dict) -> tuple[str, list[str]]:
    """Return (max label allowed by structure, reasons)."""
    reasons = []
    sources = independent_sources(finding)
    n = len(sources)
    gaps = provenance_gaps(finding)
    if gaps:
        reasons.append(f"provenance gaps: {gaps}")

    if n >= 2 and not gaps:
        ceiling = "CONFIRMED"
        reasons.append(f"{n} independent sources w/ full provenance -> CONFIRMED eligible")
    elif n >= 1:
        ceiling = "INDICATED"
        reasons.append(f"{n} content-bearing source -> capped at INDICATED (CONFIRMED needs >=2 independent)")
    else:
        ceiling = "INFERRED" if (finding.get("interpretation") or "").strip() else "UNKNOWN"
        reasons.append("no content-bearing artifact -> cannot exceed INFERRED")
    return ceiling, reasons
