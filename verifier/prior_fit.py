"""Prior-fit anomaly: 'fits the defender's prior too well' detector.

T-8 (controlled hallucination, Anil Seth): perception is shaped by the
prior. The defender's prior is "this is what normal activity looks like."
An autonomous-AI attacker that has read the same docs as the defender
can craft evidence to fit that prior exactly -- making the malicious
look not just normal but TOO normal. Crafted-normal artifacts score
suspiciously close to 1.0 on a prior-fit metric, while real-normal
artifacts show some natural variation.

This module scores each artifact against a list of "expected normal"
patterns and flags ones with anomalously perfect fit, especially when
the surrounding context (off-hours timestamp, near an incident, etc.)
suggests suspicion. Suspicious context alone is not enough; high fit
alone is not enough; the combination is.

API:
  fit_score(text, prior_patterns) -> {score, hits, n_patterns}
  assess(artifact, prior_patterns, suspicion_context=None) ->
    {verdict: SUSPICIOUSLY_NORMAL | NORMAL | NOT_NORMAL | INSUFFICIENT,
     score, hits, reasons}
"""

from __future__ import annotations
import re
from datetime import datetime
from typing import Iterable

DEFAULT_SUSPICIOUSLY_NORMAL_THRESHOLD = 0.95
DEFAULT_NORMAL_FLOOR = 0.5


def fit_score(text: str, prior_patterns: Iterable[str]) -> dict:
    """Fraction of prior_patterns that match in the text (case-insensitive,
    multiline). Bad regexes are silently skipped."""
    hits: list[str] = []
    patterns = list(prior_patterns)
    for p in patterns:
        try:
            if re.search(p, text or "", re.IGNORECASE | re.MULTILINE):
                hits.append(p)
        except re.error:
            continue
    score = len(hits) / len(patterns) if patterns else 0.0
    return {"score": score, "hits": hits, "n_patterns": len(patterns)}


def _suspicious_context(ctx: dict | None) -> tuple[bool, list[str]]:
    """Read a suspicion context dict and return (flag, reasons)."""
    if not ctx:
        return False, []
    reasons: list[str] = []
    flag = False
    ts = ctx.get("timestamp")
    if ts:
        try:
            dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            hour = dt.hour
            if hour < 6 or hour >= 22:
                flag = True
                reasons.append(f"timestamp at unusual hour {hour:02d}:00")
        except Exception:
            pass
    if ctx.get("near_incident"):
        flag = True
        reasons.append("artifact falls within a declared incident window")
    if ctx.get("from_untrusted_host"):
        flag = True
        reasons.append("artifact came from an untrusted host")
    return flag, reasons


def assess(
    artifact: dict,
    prior_patterns: Iterable[str],
    suspicion_context: dict | None = None,
    threshold: float = DEFAULT_SUSPICIOUSLY_NORMAL_THRESHOLD,
) -> dict:
    """Assess whether an artifact 'fits the prior too well'.

    Verdict is one of:
      SUSPICIOUSLY_NORMAL -- high fit AND suspicious context (crafted-normal)
      NORMAL              -- moderate-to-high fit, benign context
      NOT_NORMAL          -- low fit (anomalous)
      INSUFFICIENT        -- no prior patterns supplied
    """
    text = artifact.get("content", "")
    s = fit_score(text, prior_patterns)
    if s["n_patterns"] == 0:
        return {
            **s,
            "verdict": "INSUFFICIENT",
            "reasons": ["no prior patterns supplied"],
        }

    reasons = [
        f"prior-fit score {s['score']:.2f} "
        f"({len(s['hits'])}/{s['n_patterns']} patterns match)"
    ]
    ctx_flag, ctx_reasons = _suspicious_context(suspicion_context)
    reasons.extend(ctx_reasons)

    if s["score"] >= threshold and ctx_flag:
        verdict = "SUSPICIOUSLY_NORMAL"
        reasons.append(
            f"high fit (>= {threshold}) AND suspicious context "
            "-> crafted-normal candidate"
        )
    elif s["score"] >= threshold:
        verdict = "NORMAL"
        reasons.append(f"high fit, benign context -> ordinary normal")
    elif s["score"] >= DEFAULT_NORMAL_FLOOR:
        verdict = "NORMAL"
        reasons.append("moderate fit -> within normal variation")
    else:
        verdict = "NOT_NORMAL"
        reasons.append(f"low fit (< {DEFAULT_NORMAL_FLOOR}) -> anomalous")

    return {**s, "verdict": verdict, "reasons": reasons}


# --- Synthetic-data smoke test --------------------------------------------

if __name__ == "__main__":
    # A defender's prior for an ordinary process-creation log entry on a
    # Windows host. A crafted-normal artifact will match every pattern;
    # a real-normal one will match most but not all; an anomaly matches none.
    prior = [
        r"\b(explorer|svchost|searchhost)\.exe\b",
        r"parent=\\Device\\HarddiskVolume\d+\\Windows\\System32",
        r"signature=Microsoft Windows Publisher",
        r"integrity=System",
        r"session=0",
    ]

    crafted = {
        "content": (
            "svchost.exe parent=\\Device\\HarddiskVolume2\\Windows\\System32 "
            "signature=Microsoft Windows Publisher integrity=System session=0"
        ),
    }
    real_normal = {
        "content": (
            "explorer.exe parent=\\Device\\HarddiskVolume2\\Windows\\Explorer "
            "signature=Microsoft Windows Publisher session=1"
        ),
    }
    anomalous = {
        "content": "powershell.exe -enc base64 download to %TEMP%\\update.bin",
    }

    crafted_ctx = {"timestamp": "2026-05-30T03:14:00", "near_incident": True}
    benign_ctx = {"timestamp": "2026-05-30T14:30:00"}

    for label, art, ctx in [
        ("CRAFTED ", crafted, crafted_ctx),
        ("ORDINARY", real_normal, benign_ctx),
        ("ANOMALY ", anomalous, benign_ctx),
    ]:
        r = assess(art, prior, suspicion_context=ctx)
        print(f"{label}  verdict={r['verdict']:<22} score={r['score']:.2f}")
        for reason in r["reasons"]:
            print(f"            - {reason}")
