"""Pre-registered falsifiers: each evil hypothesis declares its killers in advance.

Competitors do reactive self-correction. We do Popperian self-correction: for
every "evil" hypothesis the analyst declares, BEFORE inspection, the killer
evidence -- the specific finding pattern that, if observed (or conversely, if
not observed), refutes the hypothesis. The pipeline then actively hunts those
killers in the evidence. Tunnel vision is structurally suppressed: the
hypothesis is hunted alongside its falsifiers.

Killers come in two modes:
  found_falsifies   -- if the pattern hits in the evidence, the hypothesis is
                       falsified (e.g. hypothesis "process X was malicious";
                       killer "process X never executed").
  absent_falsifies  -- if the pattern does NOT hit, the hypothesis is
                       falsified (e.g. hypothesis "data was exfiltrated";
                       killer "outbound traffic > N MB during window Y").

A hypothesis is a JSON-serializable record:
  {
    "label": "data_exfiltration",
    "description": "...",
    "killers": [
       {"name": "no_outbound_traffic", "mode": "absent_falsifies",
        "pattern": "outbound .* (MB|GB)", "description": "..."},
       ...
    ]
  }
"""

from __future__ import annotations
import re
from typing import Iterable

MODE_FOUND = "found_falsifies"
MODE_ABSENT = "absent_falsifies"
VALID_MODES = {MODE_FOUND, MODE_ABSENT}


def _evidence_text(evidence: Iterable[dict]) -> str:
    """Concatenate all evidence content for pattern matching."""
    return "\n".join((art.get("content") or "") for art in evidence)


def check_hypothesis(hypothesis: dict, evidence: list[dict]) -> dict:
    """Check all registered killers against the evidence.

    Returns:
      {
        "hypothesis": <label>,
        "n_killers_registered": <int>,
        "falsified": <bool>,
        "killers_hit": [{name, description, mode}, ...],
        "killers_checked": [{name, mode, observed_pattern_hit}, ...]
      }
    """
    text = _evidence_text(evidence)
    killers_hit = []
    killers_checked = []
    for k in hypothesis.get("killers", []):
        mode = k.get("mode")
        if mode not in VALID_MODES:
            killers_checked.append({"name": k.get("name"), "mode": mode, "error": "invalid mode"})
            continue
        pattern = k.get("pattern", "")
        try:
            hits = bool(re.search(pattern, text, re.IGNORECASE | re.MULTILINE))
        except re.error as e:
            killers_checked.append({"name": k.get("name"), "mode": mode, "error": f"regex: {e}"})
            continue
        killers_checked.append({"name": k.get("name"), "mode": mode, "observed_pattern_hit": hits})
        kills = (mode == MODE_FOUND and hits) or (mode == MODE_ABSENT and not hits)
        if kills:
            killers_hit.append({
                "name": k.get("name"),
                "description": k.get("description", ""),
                "mode": mode,
            })
    return {
        "hypothesis": hypothesis.get("label"),
        "description": hypothesis.get("description", ""),
        "n_killers_registered": len(hypothesis.get("killers", [])),
        "falsified": bool(killers_hit),
        "killers_hit": killers_hit,
        "killers_checked": killers_checked,
    }


def evidence_from_findings(findings: Iterable[dict]) -> list[dict]:
    """Flatten finding observations, interpretations, and artifacts into evidence."""
    evidence: list[dict] = []
    for finding in findings:
        fid = finding.get("id", "?")
        text_parts = [
            str(finding.get("observation") or ""),
            str(finding.get("interpretation") or ""),
        ]
        if any(part.strip() for part in text_parts):
            evidence.append({
                "source": f"finding.{fid}.claim_text",
                "content": "\n".join(part for part in text_parts if part.strip()),
            })
        for art in finding.get("artifacts", []):
            evidence.append({
                "source": art.get("source") or f"finding.{fid}.artifact",
                "content": art.get("content") or "",
            })
    return evidence


def check_hypotheses(hypotheses: Iterable[dict], evidence: list[dict]) -> dict:
    """Check a list of pre-registered hypotheses against one evidence set."""
    results = [check_hypothesis(h, evidence) for h in hypotheses]
    return {
        "n_hypotheses": len(results),
        "n_falsified": sum(1 for r in results if r["falsified"]),
        "results": results,
    }


def register_hypothesis(label: str, description: str = "") -> dict:
    """Convenience builder for an empty hypothesis record."""
    return {"label": label, "description": description, "killers": []}


def add_killer(
    hypothesis: dict,
    name: str,
    pattern: str,
    mode: str = MODE_FOUND,
    description: str = "",
) -> dict:
    """Append a killer to an existing hypothesis dict (mutates and returns)."""
    if mode not in VALID_MODES:
        raise ValueError(f"mode must be one of {VALID_MODES}, got {mode}")
    hypothesis.setdefault("killers", []).append({
        "name": name,
        "pattern": pattern,
        "mode": mode,
        "description": description,
    })
    return hypothesis


# --- Synthetic-data smoke test --------------------------------------------

if __name__ == "__main__":
    # Hypothesis: data was exfiltrated
    h = register_hypothesis(
        "data_exfiltration",
        "Sensitive files were transferred to an external host.",
    )
    add_killer(
        h, "outbound_large_transfer",
        pattern=r"outbound .*?(\d{2,})\s*(MB|GB)",
        mode=MODE_ABSENT,
        description="If no large outbound transfer is recorded, the hypothesis fails.",
    )
    add_killer(
        h, "process_known_clean",
        pattern=r"process .*? signed by Microsoft and untouched",
        mode=MODE_FOUND,
        description="If the suspect process is explicitly attested clean, the hypothesis fails.",
    )

    # Evidence A: confirms exfiltration -> NOT falsified
    evidence_confirms = [
        {"source": "netflow", "content": "outbound 2024-01-12T03:14:09 dst=203.0.113.4 250 MB to TLS:443"},
        {"source": "process_audit", "content": "process powershell.exe spawned with -enc base64..."},
    ]
    # Evidence B: no outbound transfer matching the pattern -> falsified (absent_falsifies)
    evidence_no_outbound = [
        {"source": "netflow", "content": "only DNS lookups recorded; no large outbound."},
        {"source": "process_audit", "content": "process powershell.exe spawned with -enc base64..."},
    ]
    # Evidence C: explicit clean attestation -> falsified (found_falsifies)
    evidence_clean = [
        {"source": "netflow", "content": "outbound 250 MB to TLS:443 (legitimate backup)"},
        {"source": "process_audit", "content": "process backup.exe signed by Microsoft and untouched"},
    ]

    for label, ev in [("CONFIRMS", evidence_confirms), ("NO_OUTBOUND", evidence_no_outbound), ("CLEAN_ATTEST", evidence_clean)]:
        r = check_hypothesis(h, ev)
        marker = "FALSIFIED" if r["falsified"] else "not falsified"
        names = ", ".join(k["name"] for k in r["killers_hit"]) or "-"
        print(f"{label:<14} -> {marker:<14} killers_hit=[{names}]")
