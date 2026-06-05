"""One-command judge demo: autonomous ROCBA case loop.

This runner is intentionally small and judge-facing. It does not introduce
new forensic extraction; it composes the existing enforcement modules into a
single autonomous loop:

  1. declare the active case questions;
  2. ingest available ROCBA disk evidence;
  3. verify each finding with structural staging / quarantine / optional grader;
  4. check pre-registered falsifiers;
  5. emit the strongest supported "evil found" conclusion and the hypotheses
     that were rejected.

Usage:
  python -m cases.run_judge_demo --findings-dir cases_data/rocba_disk --no-grader
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Iterable

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from verifier import boundary_register
from verifier import disk_ingest
from verifier import divergence
from verifier import falsifier
from verifier import responsibility_ledger
from verifier.verify import verify


CASE_QUESTIONS = [
    "Did Fred Rocba's host show personal cloud-sync infrastructure?",
    "Were SRL-relevant files staged in a personal cloud-sync location?",
    "Does the available disk evidence support credential theft?",
    "Does the available disk evidence support lateral movement?",
    "Which claims are too weak to keep as CONFIRMED?",
]


def _read(path: pathlib.Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _load_disk_findings(findings_dir: pathlib.Path) -> list[dict]:
    return disk_ingest.from_listings(
        googledrive_text=_read(findings_dir / "googledrive_listing.txt"),
        icloud_text=_read(findings_dir / "icloud_listing.txt"),
        downloads_text=_read(findings_dir / "downloads_listing.txt"),
        prefetch_text=_read(findings_dir / "prefetch_listing.txt"),
    )


def _annotate(findings: Iterable[dict], use_grader: bool) -> list[dict]:
    annotated = []
    for finding in findings:
        verdict = verify(finding, use_grader=use_grader)
        annotated.append(divergence.annotate(verdict))
    return annotated


def _sources(finding: dict) -> set[str]:
    return {a.get("source", "?") for a in finding.get("artifacts", [])}


def _sensitive_files(findings: Iterable[dict]) -> list[str]:
    prefix = "sensitive_file.in_cloud."
    out = []
    for finding in findings:
        fid = finding.get("id", "")
        if fid.startswith(prefix):
            out.append(fid.removeprefix(prefix).replace("_", " "))
    return sorted(out)


def _finding_by_id(findings: Iterable[dict]) -> dict[str, dict]:
    return {f.get("id", ""): f for f in findings}


def _strongest_supported_evil(findings: list[dict], verdicts: list[dict]) -> dict:
    by_id = _finding_by_id(findings)
    verdict_by_id = {v.get("id"): v for v in verdicts}
    cloud_confirmed = []
    for fid in ("cloud_sync.google_drive", "cloud_sync.icloud", "cloud_sync.dropbox"):
        finding = by_id.get(fid)
        verdict = verdict_by_id.get(fid)
        if not finding or not verdict:
            continue
        if verdict.get("verified_confidence") == "CONFIRMED":
            cloud_confirmed.append({
                "id": fid,
                "verified_confidence": "CONFIRMED",
                "sources": sorted(_sources(finding)),
            })

    files = _sensitive_files(findings)
    if cloud_confirmed and files:
        return {
            "verdict": "CONFIRMED",
            "claim": (
                "Fred Rocba's workstation contains personal cloud-sync "
                "infrastructure, and SRL-relevant documents are present in a "
                "personal Google Drive folder. The strongest supported evil is "
                "IP staging or exfiltration risk through personal cloud sync."
            ),
            "confirmed_cloud_entities": cloud_confirmed,
            "sensitive_files": files,
            "confidence_reason": (
                "The cloud-sync entities that remain CONFIRMED have two "
                "independent artifact sources; the file-level SRL claims are "
                "kept at INDICATED because they are single-source."
            ),
        }
    return {
        "verdict": "INDICATED",
        "claim": (
            "The available evidence suggests cloud-sync risk, but the runner "
            "did not find enough structural support to make a CONFIRMED case "
            "conclusion."
        ),
        "confirmed_cloud_entities": cloud_confirmed,
        "sensitive_files": files,
        "confidence_reason": "Insufficient multi-source structure for a confirmed case conclusion.",
    }


def _hypothesis_summary(hypothesis_report: dict) -> dict:
    supported = []
    falsified = []
    for result in hypothesis_report.get("results", []):
        row = {
            "hypothesis": result.get("hypothesis"),
            "description": result.get("description", ""),
            "killers_hit": [k.get("name") for k in result.get("killers_hit", [])],
        }
        (falsified if result.get("falsified") else supported).append(row)
    return {"supported_or_not_falsified": supported, "falsified": falsified}


def _write_markdown(path: pathlib.Path, report: dict) -> None:
    evil = report["evil_found"]
    hyp = report["hypotheses"]
    lines = [
        "# foveal-dfir Judge Demo Report",
        "",
        "## Autonomous Case Loop",
        "",
    ]
    for i, step in enumerate(report["autonomous_steps"], start=1):
        lines.append(f"{i}. {step}")
    lines.extend([
        "",
        "## Evil Found",
        "",
        f"**Verdict:** {evil['verdict']}",
        "",
        evil["claim"],
        "",
        "**Why this confidence is bounded:**",
        "",
        evil["confidence_reason"],
        "",
        "**Confirmed cloud-sync entities:**",
        "",
    ])
    for entity in evil["confirmed_cloud_entities"]:
        lines.append(f"- `{entity['id']}` via {', '.join(entity['sources'])}")
    lines.extend(["", "**SRL-relevant files found in personal Google Drive:**", ""])
    for name in evil["sensitive_files"]:
        lines.append(f"- `{name}`")
    lines.extend(["", "## Hypotheses Rejected", ""])
    for row in hyp["falsified"]:
        lines.append(
            f"- `{row['hypothesis']}`: falsified by "
            f"{', '.join(row['killers_hit']) or 'registered killer evidence'}"
        )
    lines.extend(["", "## Hypotheses Not Falsified", ""])
    for row in hyp["supported_or_not_falsified"]:
        lines.append(f"- `{row['hypothesis']}`")
    lines.extend([
        "",
        "## Boundary And Accountability",
        "",
        f"- Findings examined: {report['counts']['findings']}",
        f"- Downgraded by pipeline: {report['counts']['downgraded']}",
        f"- Boundary unresolved: {report['counts']['uninspected']}",
        f"- Human escalations: {report['counts']['escalated_to_human']}",
        "",
        "The report is generated from evidence-derived findings. Case files are not redistributed.",
        "",
    ])
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the one-command foveal-dfir judge demo.")
    parser.add_argument(
        "--findings-dir",
        default="cases_data/rocba_disk",
        help="Directory containing ROCBA disk fls listings.",
    )
    parser.add_argument(
        "--hypotheses",
        default=str(pathlib.Path(__file__).with_name("rocba_hypotheses.json")),
        help="Pre-registered hypothesis JSON.",
    )
    parser.add_argument(
        "--out-dir",
        default="cases_outputs/judge_demo",
        help="Output directory for judge_demo.json and report.md.",
    )
    parser.add_argument("--no-grader", action="store_true", help="Skip the blind grader.")
    args = parser.parse_args()

    findings_dir = pathlib.Path(args.findings_dir)
    out_dir = pathlib.Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    findings = _load_disk_findings(findings_dir)
    verdicts = _annotate(findings, use_grader=not args.no_grader)
    reg = boundary_register.register(verdicts, declared_unexamined=[])
    ledger = responsibility_ledger.audit_log(verdicts)

    hypotheses_path = pathlib.Path(args.hypotheses)
    hypotheses = json.loads(hypotheses_path.read_text(encoding="utf-8"))
    evidence = falsifier.evidence_from_findings(findings)
    hypothesis_report = falsifier.check_hypotheses(hypotheses, evidence)

    report = {
        "case": "ROCBA / Fred Rocba",
        "grader_used": not args.no_grader,
        "autonomous_steps": [
            "Declare case questions before scoring the evidence.",
            "Ingest available ROCBA disk evidence from Sleuth Kit fls listings.",
            "Merge findings by entity so structural source count is over the same claim.",
            "Verify every claim with staging, quarantine, and optional blind grader.",
            "Check pre-registered falsifiers before writing the case conclusion.",
            "Emit both the evil found and the hypotheses rejected.",
        ],
        "case_questions": CASE_QUESTIONS,
        "evil_found": _strongest_supported_evil(findings, verdicts),
        "hypotheses": _hypothesis_summary(hypothesis_report),
        "counts": {
            "findings": len(findings),
            "downgraded": sum(1 for v in verdicts if v.get("downgraded")),
            "uninspected": len(reg["uninspected"]),
            "low_confidence_boundary": len(reg["low_confidence_boundary"]),
            "escalated_to_human": ledger["n_escalated_to_human"],
            "hypotheses_checked": hypothesis_report["n_hypotheses"],
            "hypotheses_falsified": hypothesis_report["n_falsified"],
        },
        "boundary_register": reg,
        "hypothesis_report": hypothesis_report,
    }

    json_path = out_dir / "judge_demo.json"
    md_path = out_dir / "report.md"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    _write_markdown(md_path, report)

    evil = report["evil_found"]
    print("foveal-dfir one-command judge demo")
    print("----------------------------------")
    print(f"Case: {report['case']}")
    print(f"Findings examined: {report['counts']['findings']}")
    print(f"Downgraded by pipeline: {report['counts']['downgraded']}")
    print(f"Hypotheses checked/falsified: {report['counts']['hypotheses_checked']}/{report['counts']['hypotheses_falsified']}")
    print(f"Evil found verdict: {evil['verdict']}")
    print(evil["claim"])
    print(f"Wrote {json_path} and {md_path}")


if __name__ == "__main__":
    main()
