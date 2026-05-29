"""FIND EVIL! enforcement-layer prototype runner.

Loads sample findings (as a self-grading agent would emit them) and runs
each through the verification pipeline:

  1. quarantine + structural staging + independent blind grader
     (verifier.verify) -> the most-conservative verdict.
  2. divergence annotation (verifier.divergence) -> AGREE_REAL / AGREE_FP /
     DISAGREE. DISAGREE is the escalate set.
  3. boundary-register aggregation (verifier.boundary_register) -> explicit
     list of what was NOT resolved (UNINSPECTED, LOW_CONFIDENCE_BOUNDARY,
     DECLARED_UNEXAMINED). Items here are never silently dropped.

Prints an A/B table per finding, then the boundary register.
"""

import json
import pathlib
import sys

from verifier.verify import verify
from verifier import divergence, boundary_register


def main() -> None:
    use_grader = "--no-grader" not in sys.argv
    path = pathlib.Path(__file__).parent / "samples" / "findings.json"
    samples = json.loads(path.read_text(encoding="utf-8"))

    print(f"\nIndependent enforcement (grader={'on' if use_grader else 'OFF'})\n")
    header = (
        f"{'ID':<7} {'CLAIMED':<10} {'VERIFIED':<10} {'DIVERGENCE':<18} "
        f"{'CHANGED':<10} NOTES"
    )
    print(header)
    print("-" * len(header))

    annotated = []
    changed = 0
    for f in samples:
        v = verify(f, use_grader=use_grader)
        v = divergence.annotate(v)
        annotated.append(v)

        notes = []
        if v["adversarial_flags"]:
            n = sum(len(a["suspicious_spans"]) for a in v["adversarial_flags"])
            notes.append(f"quarantine:{n}-span(s)")
        g = v.get("grader") or {}
        if g and not g.get("_error") and not g.get("_parse_error"):
            notes.append(f"grader->{g.get('justified_confidence', '?')}")
            if g.get("interpretation_is_inference"):
                notes.append("inference")
            if g.get("adversarial_text_detected"):
                notes.append("grader-caught-injection")
        elif g.get("_error"):
            notes.append(f"grader-error:{g['_error'][:40]}")
        elif g.get("_parse_error"):
            notes.append("grader-parse-error")

        if divergence.is_escalate(v):
            notes.append("ESCALATE")

        mark = "DOWNGRADE" if v["downgraded"] else ("-" if v["downgraded"] is False else "?")
        if v["downgraded"]:
            changed += 1
        print(
            f"{v['id']:<7} {v['claimed_confidence']:<10} {v['verified_confidence']:<10} "
            f"{v['divergence']:<18} {mark:<10} {'; '.join(notes)}"
        )

    print("-" * len(header))
    print(f"{changed}/{len(samples)} findings were downgraded by independent enforcement.")

    # Boundary register: explicit accounting of what was NOT resolved.
    # `declared_unexamined` is filled in by the host investigator describing
    # regions it knowingly skipped (e.g. memory.raw absent, network logs
    # not collected). On toy samples we have none.
    reg = boundary_register.register(annotated, declared_unexamined=[])
    print()
    for line in boundary_register.summary_lines(reg):
        print(line)

    print(
        "\nExpected on toy samples:\n"
        "  F-001 unchanged (legit, >=2 independent sources)        -> AGREE_REAL\n"
        "  F-002 downgraded (only one content-bearing source)      -> typically AGREE_FP or DISAGREE\n"
        "  F-003 quarantine-flagged (instruction span in evidence) -> DISAGREE or capped\n"
        "  F-004 over-claim caught by independent grader           -> DISAGREE (the rescue moment)\n"
    )


if __name__ == "__main__":
    main()
