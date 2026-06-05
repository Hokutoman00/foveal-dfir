"""End-to-end driver: disk-side pass on the ROCBA case.

Loads pre-extracted Sleuth Kit `fls` listings from key locations on the
``rocba-cdrive.E01`` disk image (Google Drive sync folder, iCloud sync
folder, Downloads, Windows Prefetch) and runs the same enforcement
pipeline used for the memory pass:

  case_ingest counterpart -> verifier.disk_ingest.from_listings
  verify                  -> structural staging + quarantine + (optional)
                              blind grader
  divergence              -> AGREE_REAL / AGREE_FP / DISAGREE
  boundary register       -> declared blind spots
  responsibility ledger   -> per-claim provenance + accountability

The key contrast vs the memory pass: the disk ingest merges findings by
entity-id, so a single entity (e.g. ``cloud_sync.google_drive``)
accumulates artifacts from multiple independent sources (filesystem
folder + Prefetch). When the structural ceiling counts >= 2 distinct
sources, the ``CONFIRMED`` claim is allowed to survive. This demonstrates
the rule both ways: it downgrades single-source CONFIRMED (the memory
pass) and it preserves CONFIRMED when the structure justifies it (this
pass).

Usage:
  python -m cases.run_rocba_disk --findings-dir cases_data/rocba_disk \
      [--no-grader] [--out-dir cases_outputs/rocba_disk]
"""

from __future__ import annotations
import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from verifier import (
    disk_ingest,
    divergence,
    boundary_register,
    responsibility_ledger,
    falsifier,
)
from verifier.verify import verify


def _read(path: pathlib.Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="ROCBA disk-side enforcement pipeline (entity-merged ingest)."
    )
    ap.add_argument("--findings-dir", required=True,
                    help="Directory containing fls listing .txt files.")
    ap.add_argument("--out-dir", default="cases_outputs/rocba_disk",
                    help="Where to write audit_log.json and summary.")
    ap.add_argument("--no-grader", action="store_true",
                    help="Skip the blind grader.")
    ap.add_argument("--hypotheses", default=str(pathlib.Path(__file__).with_name("rocba_hypotheses.json")),
                    help="JSON file of pre-registered hypotheses and killer evidence.")
    args = ap.parse_args()

    findings_dir = pathlib.Path(args.findings_dir)
    out_dir = pathlib.Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    googledrive = _read(findings_dir / "googledrive_listing.txt")
    icloud = _read(findings_dir / "icloud_listing.txt")
    downloads = _read(findings_dir / "downloads_listing.txt")
    prefetch = _read(findings_dir / "prefetch_listing.txt")

    findings = disk_ingest.from_listings(
        googledrive_text=googledrive,
        icloud_text=icloud,
        downloads_text=downloads,
        prefetch_text=prefetch,
    )
    print(f"Loaded fls listings from {findings_dir}")
    print(f"Total entity-merged findings: {len(findings)}\n")

    use_grader = not args.no_grader
    print(f"Running enforcement pipeline (grader={'on' if use_grader else 'OFF'})...\n")

    annotated: list[dict] = []
    divergence_counts = {"AGREE_REAL": 0, "AGREE_FP": 0, "DISAGREE": 0,
                         "GRADER_UNAVAILABLE": 0}
    downgraded = 0

    print(f"{'ID':<48} {'#SRC':<5} {'CLAIMED':<10} {'VERIFIED':<10} {'CHANGED':<10} DIVERGENCE")
    print("-" * 110)
    for f in findings:
        v = verify(f, use_grader=use_grader)
        v = divergence.annotate(v)
        annotated.append(v)
        n_sources = len({a.get("source") for a in f.get("artifacts", [])})
        mark = "DOWNGRADE" if v["downgraded"] else ("-" if v["downgraded"] is False else "?")
        if v["downgraded"]:
            downgraded += 1
        divergence_counts[v.get("divergence", "GRADER_UNAVAILABLE")] += 1
        print(f"{f['id'][:48]:<48} {n_sources:<5} {v['claimed_confidence']:<10} "
              f"{v['verified_confidence']:<10} {mark:<10} {v['divergence']}")

    print("-" * 110)
    print(f"{downgraded}/{len(findings)} findings were downgraded by independent enforcement.")

    reg = boundary_register.register(annotated, declared_unexamined=[])
    print()
    for line in boundary_register.summary_lines(reg):
        print(line)

    ledger = responsibility_ledger.audit_log(annotated)
    print(
        f"\nResponsibility ledger: {ledger['n_findings']} findings; "
        f"{ledger['n_downgraded_by_pipeline']} downgraded by pipeline; "
        f"{ledger['n_escalated_to_human']} escalated to human arbiter."
    )

    hypothesis_report = {"n_hypotheses": 0, "n_falsified": 0, "results": []}
    hypotheses_path = pathlib.Path(args.hypotheses)
    if hypotheses_path.exists():
        hypotheses = json.loads(hypotheses_path.read_text(encoding="utf-8"))
        evidence = falsifier.evidence_from_findings(findings)
        hypothesis_report = falsifier.check_hypotheses(hypotheses, evidence)
        print(
            f"\nFalsifier: {hypothesis_report['n_hypotheses']} pre-registered "
            f"hypotheses checked; {hypothesis_report['n_falsified']} falsified."
        )
        for result in hypothesis_report["results"]:
            marker = "FALSIFIED" if result["falsified"] else "not falsified"
            hit_names = ", ".join(k["name"] for k in result["killers_hit"]) or "-"
            print(f"  {result['hypothesis']}: {marker}; killers_hit=[{hit_names}]")
    else:
        print(f"\nFalsifier: no hypotheses file found at {hypotheses_path}")

    # Write artifacts.
    (out_dir / "audit_log.json").write_text(
        json.dumps(ledger, indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "boundary_register.json").write_text(
        json.dumps(reg, indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "hypotheses.json").write_text(
        json.dumps(hypothesis_report, indent=2, ensure_ascii=False), encoding="utf-8")
    summary = {
        "case": "rocba-cdrive.E01 (NTFS partition image, Windows 10 build 19042)",
        "ingest": "disk_ingest (entity-merged: filesystem + Prefetch)",
        "n_findings_after_merge": len(findings),
        "n_downgraded_by_pipeline": downgraded,
        "divergence_counts": divergence_counts,
        "n_uninspected": len(reg["uninspected"]),
        "n_low_confidence_boundary": len(reg["low_confidence_boundary"]),
        "n_escalated_to_human": ledger["n_escalated_to_human"],
        "grader_used": use_grader,
        "hypotheses_checked": hypothesis_report["n_hypotheses"],
        "hypotheses_falsified": hypothesis_report["n_falsified"],
        "headline": (
            "Disk-side pass demonstrates the staging rule both ways: single-source "
            "claims are capped at INDICATED; multi-source claims (e.g. cloud_sync.* "
            "entities with artifacts from BOTH filesystem AND Prefetch) keep their "
            "CONFIRMED label because the structural floor (>= 2 independent sources) "
            "is met."
        ),
    }
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nWrote audit_log.json / boundary_register.json / hypotheses.json / summary.json to {out_dir}")


if __name__ == "__main__":
    main()
