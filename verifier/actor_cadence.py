"""Actor cadence: agent-vs-human signature via inter-event timing.

The hackathon's stated motivation is Anthropic's GTG-1002 report:
autonomous LLM-driven attackers. We exploit a structural property of an
agent attacker -- machine-paced timing -- to distinguish autonomous-AI
activity from human-operated activity.

Human-operated activity tends to show:
  - high coefficient of variation in inter-event intervals (CoV > ~0.5);
  - work-hour clustering (no continuous 24h activity);
  - fatigue / hesitation (occasional long gaps mid-task).

Machine-paced (autonomous-agent) activity tends to show:
  - low CoV (intervals near constant);
  - 24/7 continuity (no diurnal gap);
  - no long-gap hesitations.

This module computes those signatures from an ordered list of event
timestamps and emits a verdict with explicit reasons. It is NOT a binary
classifier: when the signals conflict, the verdict is AMBIGUOUS and the
boundary register records the uncertainty rather than forcing a call.

Vivid reference: Figure Helix-02's 200-hour autonomous shift at 2.83s/
package -- machine-perfect cadence across a multi-day run. Such a log on
a network would show the same near-constant inter-action gaps.
"""

from __future__ import annotations
import statistics
from datetime import datetime
from typing import Iterable

# Decision thresholds. These are starting points to be tuned against
# labelled cases; exposed as parameters so a future calibration step can
# adjust them without code changes.
DEFAULT_COV_MAX_FOR_MACHINE = 0.35
DEFAULT_LONG_GAP_FACTOR = 10.0    # gap > 10x median interval => "hesitation"
DEFAULT_WORK_HOUR_RATIO_MAX = 0.85  # >85% events in 08-22 local => human-like
DEFAULT_MIN_EVENTS = 6              # below this, no verdict


def _to_seconds(ts: object) -> float:
    """Accept epoch seconds (int/float), datetime, or ISO-8601 strings."""
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, datetime):
        return ts.timestamp()
    return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()


def intervals(timestamps: Iterable[object]) -> list[float]:
    secs = sorted(_to_seconds(t) for t in timestamps)
    return [secs[i + 1] - secs[i] for i in range(len(secs) - 1)]


def stats(timestamps: Iterable[object]) -> dict:
    ivs = intervals(timestamps)
    if not ivs:
        return {"n_events": 0, "n_intervals": 0}
    mean = statistics.mean(ivs)
    stdev = statistics.stdev(ivs) if len(ivs) > 1 else 0.0
    median = statistics.median(ivs)
    cov = stdev / mean if mean > 0 else 0.0
    long_gaps = sum(
        1 for v in ivs if median > 0 and v > median * DEFAULT_LONG_GAP_FACTOR
    )
    return {
        "n_events": len(ivs) + 1,
        "n_intervals": len(ivs),
        "mean_interval_s": mean,
        "stdev_interval_s": stdev,
        "median_interval_s": median,
        "cov": cov,
        "long_gap_count": long_gaps,
    }


def _work_hour_ratio(timestamps: Iterable[object]) -> float:
    """Fraction of events whose local hour falls in 08-22 (typical human work)."""
    secs = sorted(_to_seconds(t) for t in timestamps)
    if not secs:
        return 0.0
    in_work = sum(1 for s in secs if 8 <= datetime.fromtimestamp(s).hour < 22)
    return in_work / len(secs)


def assess(
    timestamps: Iterable[object],
    cov_max: float = DEFAULT_COV_MAX_FOR_MACHINE,
    work_hour_ratio_max: float = DEFAULT_WORK_HOUR_RATIO_MAX,
) -> dict:
    """Assess whether the cadence is machine-paced, human, or ambiguous.

    Returns a dict with raw stats, the verdict, and explicit reasons. Verdict
    is one of:
      MACHINE_PACED  -- all signals point to a near-constant 24/7 cadence
      HUMAN_LIKELY   -- variability / work-hour clustering / long gaps
      AMBIGUOUS      -- mixed signals; no confident call
      INSUFFICIENT   -- too few events for any verdict
    """
    s = stats(timestamps)
    if s["n_events"] < DEFAULT_MIN_EVENTS:
        return {
            **s,
            "verdict": "INSUFFICIENT",
            "reasons": [f"only {s['n_events']} events (need >= {DEFAULT_MIN_EVENTS})"],
        }
    work_ratio = _work_hour_ratio(timestamps)
    reasons = []
    machine_signals = 0
    human_signals = 0

    if s["cov"] <= cov_max:
        machine_signals += 1
        reasons.append(f"cov={s['cov']:.3f} <= {cov_max} (near-constant intervals)")
    else:
        human_signals += 1
        reasons.append(f"cov={s['cov']:.3f} > {cov_max} (variable intervals)")

    if s["long_gap_count"] == 0:
        machine_signals += 1
        reasons.append("no long-gap hesitations")
    else:
        human_signals += 1
        reasons.append(f"{s['long_gap_count']} long-gap hesitation(s)")

    if work_ratio < work_hour_ratio_max:
        machine_signals += 1
        reasons.append(
            f"work-hour ratio {work_ratio:.2f} < {work_hour_ratio_max} (24/7-like)"
        )
    else:
        human_signals += 1
        reasons.append(
            f"work-hour ratio {work_ratio:.2f} >= {work_hour_ratio_max} (human work hours)"
        )

    if machine_signals >= 2 and human_signals == 0:
        verdict = "MACHINE_PACED"
    elif human_signals >= 2 and machine_signals == 0:
        verdict = "HUMAN_LIKELY"
    else:
        verdict = "AMBIGUOUS"
    return {**s, "work_hour_ratio": work_ratio, "verdict": verdict, "reasons": reasons}


# --- Synthetic-data smoke test --------------------------------------------
#
# Real case-log integration will arrive with the sample dataset. Until then
# this self-test exercises the assessor on three synthetic timelines: a
# machine-paced one (constant interval, 24/7), a human-like one (variable
# interval, work-hour clustered, occasional long gap), and an ambiguous one.

def _synthetic_machine(n: int = 50, interval_s: float = 2.85, jitter_s: float = 0.05) -> list[float]:
    """Constant 2.85s cadence with tiny jitter, starting at midnight UTC."""
    import random
    rng = random.Random(0)
    base = datetime(2026, 5, 30, 0, 0, 0).timestamp()
    return [base + i * interval_s + rng.uniform(-jitter_s, jitter_s) for i in range(n)]


def _synthetic_human(n: int = 50) -> list[float]:
    """Variable intervals, clustered in 09-18 local with one long lunch gap."""
    import random
    rng = random.Random(1)
    base = datetime(2026, 5, 30, 9, 0, 0).timestamp()
    out = []
    t = base
    for i in range(n):
        out.append(t)
        gap = rng.expovariate(1 / 60.0)  # mean 60s, high variance
        if i == n // 2:
            gap += 3600  # lunch break => long gap
        t += gap
    return out


def _synthetic_ambiguous(n: int = 30) -> list[float]:
    """Moderate variability, 24/7 continuity, no long gaps -> mixed signals."""
    import random
    rng = random.Random(2)
    base = datetime(2026, 5, 30, 0, 0, 0).timestamp()
    return [base + i * 5.0 + rng.uniform(-2.0, 2.0) for i in range(n)]


if __name__ == "__main__":
    cases = [
        ("MACHINE", _synthetic_machine()),
        ("HUMAN  ", _synthetic_human()),
        ("MIXED  ", _synthetic_ambiguous()),
    ]
    for label, ts in cases:
        a = assess(ts)
        print(f"{label}  verdict={a['verdict']:<14} cov={a.get('cov', 0):.3f}  "
              f"long_gaps={a.get('long_gap_count', 0)}  "
              f"work_hour_ratio={a.get('work_hour_ratio', 0):.2f}")
        for r in a["reasons"]:
            print(f"        - {r}")
