"""End-to-end driver: run the foveal-dfir enforcement pipeline against the
ROCBA memory case.

Inputs:
  - Volatility3 plugin JSON outputs (one file per plugin) in a directory.

Pipeline:
  1. Load each plugin's JSON output.
  2. case_ingest.aggregate -> investigator findings.
  3. verify.verify on each finding (structural staging + quarantine +
     optional blind grader) -> verdict.
  4. divergence.annotate -> AGREE_REAL / AGREE_FP / DISAGREE.
  5. boundary_register.register -> explicit list of UNINSPECTED /
     LOW_CONFIDENCE_BOUNDARY / DECLARED_UNEXAMINED.
  6. responsibility_ledger.audit_log -> structured execution log.

Outputs:
  - audit_log.json: the structured execution log (one of the submission
    deliverables).
  - A short stdout summary table.

Usage:
  python -m cases.run_rocba \
    --findings-dir /var/findevil/cases/rocba/Rocba-Memory/findings \
    --source-file Rocba-Memory.raw \
    --out-dir cases_outputs/rocba

Use --no-grader to skip the blind grader (no Ollama needed). The
enforcement pipeline still applies structural staging and quarantine.
"""

from __future__ import annotations
import argparse
import json
import pathlib
import sys

# Make the verifier package importable when running from the repo root.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from verifier import case_ingest, divergence, boundary_register, responsibility_ledger
from verifier.verify import verify

# Plugins we ingest. Names match the file basenames the Volatility runner
# produces: pslist.json, cmdline.json, netscan.json, malfind.json.
DEFAULT_PLUGINS = ("pslist", "cmdline", "netscan", "malfind")


def load_plugin_outputs(findings_dir: pathlib.Path, plugins: tuple[str, ...]) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in plugins:
        f = findings_dir / f"{p}.json"
        if not f.exists():
            print(f"  (skip: {f.name} not present)", file=sys.stderr)
            continue
        out[p] = f.read_text(encoding="utf-8", errors="replace")
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="ROCBA end-to-end enforcement pipeline.")
    ap.add_argument("--findings-dir", required=True,
                    help="Directory of Volatility3 plugin JSON outputs.")
    ap.add_argument("--source-file", default="Rocba-Memory.raw",
                    help="Source memory image filename (for provenance).")
    ap.add_argument("--out-dir", default="cases_outputs/rocba",
                    help="Where to write audit_log.json and summary.")
    ap.add_argument("--no-grader", action="store_true",
                    help="Skip the blind grader (no Ollama call).")
    ap.add_argument("--plugins", nargs="+", default=list(DEFAULT_PLUGINS),
                    help="Plugin file basenames to ingest (without .json).")
    ap.add_argument("--limit", type=int, default=None,
                    help="Limit number of findings processed (useful for smoke tests).")
    args = ap.parse_args()

    findings_dir = pathlib.Path(args.findings_dir)
    out_dir = pathlib.Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    plugin_outputs = load_plugin_outputs(findings_dir, tuple(args.plugins))
    if not plugin_outputs:
        print("No plugin outputs found.", file=sys.stderr)
        sys.exit(2)

    print(f"\nLoaded {len(plugin_outputs)} plugin output(s) from {findings_dir}")
    findings = case_ingest.aggregate(plugin_outputs, source_file=args.source_file)
    print(f"Total candidate findings: {len(findings)}")
    if args.limit is not None:
        findings = findings[: args.limit]
        print(f"  (limit applied: processing first {len(findings)})")

    use_grader = not args.no_grader
    print(f"Running enforcement pipeline (grader={'on' if use_grader else 'OFF'})...\n")

    annotated: list[dict] = []
    divergence_counts = {"AGREE_REAL": 0, "AGREE_FP": 0, "DISAGREE": 0, "GRADER_UNAVAILABLE": 0}
    downgraded = 0
    quarantine_flagged = 0

    for i, f in enumerate(findings):
        v = verify(f, use_grader=use_grader)
        v = divergence.annotate(v)
        annotated.append(v)
        divergence_counts[v.get("divergence", "GRADER_UNAVAILABLE")] += 1
        if v.get("downgraded"):
            downgraded += 1
        if v.get("adversarial_flags"):
            quarantine_flagged += 1
        if (i + 1) % 50 == 0:
            print(f"  ... {i + 1}/{len(findings)} processed", file=sys.stderr)

    # Boundary register + responsibility ledger.
    reg = boundary_register.register(annotated, declared_unexamined=[])
    ledger = responsibility_ledger.audit_log(annotated)

    # Headline summary on stdout.
    print()
    print("=" * 60)
    print(f"Case: {args.source_file}")
    print(f"Findings ingested:           {len(findings)}")
    print(f"Downgraded by pipeline:      {downgraded}")
    print(f"Quarantine-flagged:          {quarantine_flagged}")
    print("Divergence:")
    for k, n in divergence_counts.items():
        if n:
            print(f"  {k:<22} {n}")
    for line in boundary_register.summary_lines(reg):
        print(line)
    print(
        f"Responsibility ledger: {ledger['n_findings']} findings; "
        f"{ledger['n_downgraded_by_pipeline']} downgraded; "
        f"{ledger['n_escalated_to_human']} escalated to human arbiter."
    )
    print("=" * 60)

    # Write structured execution log.
    audit_path = out_dir / "audit_log.json"
    audit_path.write_text(json.dumps(ledger, indent=2, ensure_ascii=False), encoding="utf-8")
    boundary_path = out_dir / "boundary_register.json"
    boundary_path.write_text(json.dumps(reg, indent=2, ensure_ascii=False), encoding="utf-8")
    summary_path = out_dir / "summary.json"
    summary_path.write_text(json.dumps({
        "case": args.source_file,
        "n_findings_ingested": len(findings),
        "n_downgraded_by_pipeline": downgraded,
        "n_quarantine_flagged": quarantine_flagged,
        "divergence_counts": divergence_counts,
        "n_uninspected": len(reg["uninspected"]),
        "n_low_confidence_boundary": len(reg["low_confidence_boundary"]),
        "n_escalated_to_human": ledger["n_escalated_to_human"],
        "grader_used": use_grader,
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nWrote:\n  {audit_path}\n  {boundary_path}\n  {summary_path}\n")


if __name__ == "__main__":
    main()
