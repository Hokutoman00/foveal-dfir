"""Stereo fusion: reconstruct the higher-dimensional attack shape from two views.

Binocular analogy: two projections of the same scene, slightly offset, let
the brain reconstruct a third dimension (depth) that neither projection
contains alone. Applied to forensics: the investigator's view and the
blind grader's view, taken together, can reconstruct the full attack
shape -- the kill-chain stages across evidence types, the rescued items,
the downgraded over-claims -- that neither view captures alone.

This module fuses a sequence of verified+divergence-annotated verdicts
into a kill-chain record:

  - Classify each finding into an attack stage from observation/
    interpretation keywords (initial_access, execution, persistence,
    privilege_escalation, defense_evasion, credential_access, discovery,
    lateral_movement, collection, exfiltration, impact).
  - Mark how the two observers related on that finding:
       SHARED            -- both observers agree (AGREE_REAL)
       SHARED_DISMISSED  -- both observers agree it's not real (AGREE_FP)
       RESCUED           -- investigator dismissed, grader confirmed
       DOWNGRADED        -- investigator over-claimed, grader caught it
       DISPUTED          -- DISAGREE with no clear direction
       UNCONTESTED       -- grader unavailable / no comparison possible
  - Order by canonical attack-stage so the chain shape is visible.

The fused kill-chain is what the agent surfaces in the demo's
"reconstructed attack story" beat: not a flat findings list, but the
attack's shape across both observers.
"""

from __future__ import annotations
import re
from typing import Iterable

from . import staging

# MITRE-ATT&CK-inspired stage order. Findings are placed into the first
# matching stage by keyword. This is heuristic; a real deployment would
# use proper MITRE technique mapping over the full case state.
_STAGE_KEYWORDS = [
    ("initial_access", [r"phish", r"spearphish", r"web shell", r"exploit public", r"\bvpn\b"]),
    ("execution", [r"powershell", r"cmd\.exe", r"wmiexec", r"\bscript\b", r"-enc base64"]),
    ("persistence", [r"scheduled task", r"\brun key\b", r"registry .* run", r"service install"]),
    ("privilege_escalation", [r"\btoken\b", r"\buac\b", r"elevat", r"\brunas\b"]),
    ("defense_evasion", [r"clear log", r"disable defender", r"obfuscat", r"timestomp"]),
    ("credential_access", [r"credential", r"\blsass\b", r"mimikatz", r"sam dump", r"\bntds\b"]),
    ("discovery", [r"net view", r"net group", r"ipconfig", r"systeminfo", r"reconnaiss"]),
    ("lateral_movement", [r"psexec", r"smbexec", r"\brdp\b", r"remote shell", r"wmi remote"]),
    ("collection", [r"\barchive\b", r"\bzip\b", r"\bstage\b", r"collect"]),
    ("exfiltration", [r"exfil", r"outbound .*?(MB|GB|TB)", r"upload", r"egress"]),
    ("impact", [r"ransom", r"\bwipe\b", r"encrypt", r"defacement"]),
]
_STAGE_ORDER = [s for s, _ in _STAGE_KEYWORDS]


def _classify_stage(text: str) -> str | None:
    if not text:
        return None
    for stage, patterns in _STAGE_KEYWORDS:
        for p in patterns:
            try:
                if re.search(p, text, re.IGNORECASE):
                    return stage
            except re.error:
                continue
    return None


def _label_is_real(label: str | None) -> bool | None:
    if label not in staging.LADDER:
        return None
    return staging._rank(label) >= staging.LADDER.index("INDICATED")


def fusion_status(verdict: dict) -> str:
    """How did the two observers relate on this finding?"""
    div = verdict.get("divergence")
    pair = verdict.get("divergence_pair", {}) or {}
    inv = pair.get("investigator_claimed")
    grd = pair.get("grader_justified")
    if div == "AGREE_REAL":
        return "SHARED"
    if div == "AGREE_FP":
        return "SHARED_DISMISSED"
    if div == "DISAGREE":
        inv_real = _label_is_real(inv)
        grd_real = _label_is_real(grd)
        if inv_real and not grd_real:
            return "DOWNGRADED"
        if grd_real and not inv_real:
            return "RESCUED"
        return "DISPUTED"
    return "UNCONTESTED"


def fuse_kill_chain(
    verdicts: Iterable[dict],
    findings: list[dict] | None = None,
) -> dict:
    """Fuse verdicts into a kill-chain record ordered by canonical stage.

    findings: optional, source findings used to read observation/
    interpretation text for stage classification. If not provided, stage
    classification falls back to whatever text lives on the verdict
    itself (usually nothing).
    """
    by_id = {f.get("id"): f for f in (findings or [])}
    chain: dict[str, list[dict]] = {}
    unstaged: list[dict] = []
    for v in verdicts:
        fid = v.get("id")
        src = by_id.get(fid, {})
        text = " ".join([
            str(src.get("observation", "")),
            str(src.get("interpretation", "")),
        ])
        stage = _classify_stage(text)
        entry = {
            "finding_id": fid,
            "stage": stage,
            "verified_confidence": v.get("verified_confidence"),
            "fusion_status": fusion_status(v),
        }
        if stage:
            chain.setdefault(stage, []).append(entry)
        else:
            unstaged.append(entry)

    ordered = [
        {"stage": s, "entries": chain[s]}
        for s in _STAGE_ORDER
        if s in chain
    ]

    return {
        "kill_chain": ordered,
        "unstaged": unstaged,
        "n_stages_present": len(ordered),
        "n_findings": sum(len(s["entries"]) for s in ordered) + len(unstaged),
        "note": (
            "Each entry's fusion_status names how the two observers related "
            "(SHARED, RESCUED, DOWNGRADED, DISPUTED, ...). The chain shows "
            "the attack across both views; stages are heuristic keyword-"
            "mapped and a production deployment would use proper MITRE "
            "ATT&CK technique mapping."
        ),
    }


# --- Synthetic-data smoke test --------------------------------------------

if __name__ == "__main__":
    findings = [
        {"id": "F-A", "observation": "powershell.exe -enc base64 spawned",
         "interpretation": "malicious execution"},
        {"id": "F-B", "observation": "lsass memory dump via mimikatz pattern",
         "interpretation": "credential access"},
        {"id": "F-C", "observation": "rdp connection to 10.0.5.7 using cached credentials",
         "interpretation": "lateral movement"},
        {"id": "F-D", "observation": "outbound 800 MB to TLS:443 unknown ASN",
         "interpretation": "data exfiltration"},
        {"id": "F-E", "observation": "scheduled task installed: \\Microsoft\\Update Sync",
         "interpretation": "persistence"},
    ]
    verdicts = [
        {"id": "F-A", "verified_confidence": "CONFIRMED", "divergence": "AGREE_REAL",
         "divergence_pair": {"investigator_claimed": "CONFIRMED",
                              "grader_justified": "CONFIRMED"}},
        {"id": "F-B", "verified_confidence": "INDICATED", "divergence": "DISAGREE",
         "divergence_pair": {"investigator_claimed": "CONFIRMED",
                              "grader_justified": "INFERRED"}},
        {"id": "F-C", "verified_confidence": "CONFIRMED", "divergence": "DISAGREE",
         "divergence_pair": {"investigator_claimed": "INFERRED",
                              "grader_justified": "CONFIRMED"}},
        {"id": "F-D", "verified_confidence": "CONFIRMED", "divergence": "AGREE_REAL",
         "divergence_pair": {"investigator_claimed": "CONFIRMED",
                              "grader_justified": "CONFIRMED"}},
        {"id": "F-E", "verified_confidence": "INDICATED", "divergence": "AGREE_REAL",
         "divergence_pair": {"investigator_claimed": "INDICATED",
                              "grader_justified": "INDICATED"}},
    ]
    chain = fuse_kill_chain(verdicts, findings=findings)
    print(
        f"Reconstructed kill-chain "
        f"({chain['n_stages_present']} stages, {chain['n_findings']} findings):"
    )
    for s in chain["kill_chain"]:
        print(f"  [{s['stage']}]")
        for e in s["entries"]:
            print(
                f"    {e['finding_id']} "
                f"({e['fusion_status']}, {e['verified_confidence']})"
            )
    if chain["unstaged"]:
        print("  [unstaged]")
        for e in chain["unstaged"]:
            print(f"    {e['finding_id']} ({e['fusion_status']}, {e['verified_confidence']})")
