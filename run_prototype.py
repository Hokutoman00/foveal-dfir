"""FIND EVIL! enforcement-layer prototype runner.

Loads sample findings (as a self-grading agent would emit them) and runs each
through the independent enforcement layer. Prints an A/B table:
  CLAIMED  = the confidence a self-grading agent recorded
  VERIFIED = the confidence after structural staging + quarantine + independent grader
"""

import json
import pathlib
import sys

from verifier.verify import verify


def main() -> None:
    use_grader = "--no-grader" not in sys.argv
    path = pathlib.Path(__file__).parent / "samples" / "findings.json"
    samples = json.loads(path.read_text(encoding="utf-8"))

    print(f"\nIndependent enforcement (grader={'on' if use_grader else 'OFF'})\n")
    print(f"{'ID':<7} {'CLAIMED':<10} {'VERIFIED':<10} {'CHANGED':<8} NOTES")
    print("-" * 100)

    changed = 0
    for f in samples:
        v = verify(f, use_grader=use_grader)
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

        mark = "DOWNGRADE" if v["downgraded"] else ("-" if v["downgraded"] is False else "?")
        if v["downgraded"]:
            changed += 1
        print(f"{v['id']:<7} {v['claimed_confidence']:<10} {v['verified_confidence']:<10} {mark:<8} {'; '.join(notes)}")

    print("-" * 100)
    print(f"{changed}/{len(samples)} findings were downgraded by independent enforcement.")
    print("\nExpected: F-001 unchanged (legit), F-002 downgraded (1 source),")
    print("          F-003 quarantine-flagged, F-004 downgraded (over-claim caught by grader).\n")


if __name__ == "__main__":
    main()
