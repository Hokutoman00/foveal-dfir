"""FIND EVIL! enforcement-layer prototype runner.

Loads sample findings (as a self-grading investigator would emit them) and
runs each through the verification pipeline:

  1. quarantine + structural staging + independent blind grader
     (verifier.verify) -> the most-conservative verdict.
  2. divergence annotation (verifier.divergence) -> AGREE_REAL /
     AGREE_FP / DISAGREE. DISAGREE is the escalate set.
  3. prior-fit anomaly scan (verifier.prior_fit) -> flags artifacts that
     fit the "normal" prior TOO well in a suspicious context — a signal
     that an autonomous AI attacker may have crafted the evidence.
  4. boundary-register aggregation (verifier.boundary_register) ->
     explicit list of what was NOT resolved (UNINSPECTED,
     LOW_CONFIDENCE_BOUNDARY, DECLARED_UNEXAMINED). Items here are never
     silently dropped.
  5. responsibility-ledger attribution (verifier.responsibility_ledger)
     -> per-finding audit record naming each observer's contribution and
     the verdict_holder. Distributed contribution, traceable
     accountability.
  6. stereo-fusion kill-chain (verifier.stereo_fusion) -> reconstruct
     the attack shape across MITRE stages from both observers' views.
     RESCUED entries are where the binocular depth effect surfaces real
     findings that one observer alone would have missed.

Prints the A/B table, then the boundary register, then the responsibility
ledger summary, then the kill-chain reconstruction. With --audit-json,
writes the full per-finding audit log to audit_log.json.
"""

import argparse
import json
import pathlib

from verifier.verify import verify
from verifier import divergence, boundary_register, responsibility_ledger
from verifier import prior_fit as prior_fit_mod
from verifier import stereo_fusion

# "Normal-looking" Windows artifact patterns. High fit in a suspicious
# context (off-hours, near-incident) is the crafted-normal signal.
_DFIR_NORMAL_PRIOR = [
    r"signed by Microsoft",
    r"(no|zero|0)\s+(suspicious|anomalous|malicious)",
    r"legitimate\s+(process|activity|traffic|connection)",
    r"known.*(clean|safe|trusted)",
    r"expected\s+(system|behaviour|behavior)",
]


def main() -> None:
    ap = argparse.ArgumentParser(description="Run foveal-dfir on a sample findings file.")
    ap.add_argument("--sample", default="samples/findings.json",
                    help="Path to a sample findings JSON file.")
    ap.add_argument("--no-grader", action="store_true",
                    help="Skip the blind grader.")
    ap.add_argument("--audit-json", action="store_true",
                    help="Write the full per-finding audit log to audit_log.json.")
    args = ap.parse_args()

    use_grader = not args.no_grader
    path = pathlib.Path(args.sample)
    if not path.is_absolute():
        path = pathlib.Path(__file__).parent / path
    samples = json.loads(path.read_text(encoding="utf-8"))

    print(f"\nIndependent enforcement (sample={path.name}, grader={'on' if use_grader else 'OFF'})\n")
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

        # Prior-fit scan: flag artifacts that look TOO normal in context.
        # Findings may carry a _prior_fit_context dict with timestamp /
        # near_incident / from_untrusted_host keys for richer assessment.
        pf_ctx = f.get("_prior_fit_context")
        pf_flags = []
        for art in f.get("artifacts", []):
            pf = prior_fit_mod.assess(art, _DFIR_NORMAL_PRIOR, suspicion_context=pf_ctx)
            if pf["verdict"] == "SUSPICIOUSLY_NORMAL":
                pf_flags.append(art.get("source", "?"))
        v["prior_fit_flags"] = pf_flags

        annotated.append(v)

        notes = []
        if v["adversarial_flags"]:
            n = sum(len(a["suspicious_spans"]) for a in v["adversarial_flags"])
            notes.append(f"quarantine:{n}-span(s)")
        if pf_flags:
            notes.append(f"prior-fit:SUSPICIOUS({len(pf_flags)})")
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
    # declared_unexamined would be filled in by the host investigator
    # describing regions it knowingly skipped (e.g. memory.raw absent).
    reg = boundary_register.register(annotated, declared_unexamined=[])
    print()
    for line in boundary_register.summary_lines(reg):
        print(line)

    # Responsibility ledger: distributed contribution, traceable accountability.
    ledger = responsibility_ledger.audit_log(annotated)
    print(
        f"\nResponsibility ledger: {ledger['n_findings']} findings; "
        f"{ledger['n_downgraded_by_pipeline']} downgraded by pipeline; "
        f"{ledger['n_escalated_to_human']} escalated to human arbiter."
    )
    if args.audit_json:
        out = pathlib.Path(__file__).parent / "audit_log.json"
        out.write_text(json.dumps(ledger, indent=2), encoding="utf-8")
        print(f"  Full per-finding audit log written to {out}.")

    # Stereo-fusion kill-chain: reconstruct attack shape from both observers.
    kc = stereo_fusion.fuse_kill_chain(annotated, findings=samples)
    print(f"\nStereo-fusion kill-chain ({kc['n_stages_present']} stage(s), {kc['n_findings']} finding(s)):")
    for stage_block in kc["kill_chain"]:
        print(f"  [{stage_block['stage']}]")
        for entry in stage_block["entries"]:
            status = entry["fusion_status"]
            conf = entry["verified_confidence"]
            rescued = " ← RESCUED" if status == "RESCUED" else ""
            print(f"    {entry['finding_id']} ({status}, {conf}){rescued}")
    if kc["unstaged"]:
        print(f"  [unstaged: {len(kc['unstaged'])} finding(s) - no MITRE stage keyword matched]")

    print(
        "\nExpected signal:\n"
        "  - single-source overclaims are downgraded by structural staging;\n"
        "  - instruction-like text inside evidence is surfaced by quarantine;\n"
        "  - prior-fit:SUSPICIOUS flags artifacts fitting the normal prior too well;\n"
        "  - two-source control findings can remain CONFIRMED when no gate objects;\n"
        "  - stereo-fusion RESCUED entries show the binocular depth effect.\n"
    )


if __name__ == "__main__":
    main()
