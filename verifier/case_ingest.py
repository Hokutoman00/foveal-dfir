"""Case ingest: convert Volatility3 plugin output into foveal-dfir findings.

Volatility plugins emit per-row records describing what they extracted from a
memory image: processes, network connections, command lines, injected code,
etc. We treat each row as a candidate finding the investigator emits. The
investigator's first-pass interpretation and confidence are heuristic-mapped
per-plugin (see PLUGIN_PROFILE below); the structural enforcement layer
(verifier.verify) then judges each finding from the raw evidence content,
independent of any heuristic claim, exactly as the architecture intends.

Usage:
  from verifier.case_ingest import from_vol_json, aggregate
  findings = aggregate({
      "pslist": pslist_json_text,
      "netscan": netscan_json_text,
      "malfind": malfind_json_text,
  }, source_file="Rocba-Memory.raw")

  # Then pipe through the enforcement layer:
  from verifier.verify import verify
  from verifier import divergence
  verdicts = [divergence.annotate(verify(f)) for f in findings]
"""

from __future__ import annotations
import json
from typing import Callable


def _fmt_row(template: Callable[[dict], str], row: dict) -> str:
    """Apply a row-formatting lambda safely, falling back to a JSON dump."""
    try:
        return template(row)
    except Exception:
        return json.dumps(row, ensure_ascii=False)


# Plugin-specific heuristics. These are the INVESTIGATOR'S first-pass labels.
# The blind grader, structural staging, and quarantine layers independently
# judge from the artifact content. None of the labels here is binding -- they
# are the input to our enforcement, not its output.
PLUGIN_PROFILE: dict[str, dict] = {
    "pslist": {
        "obs": lambda r: f"Process {r.get('ImageFileName','?')} "
                         f"(PID {r.get('PID','?')}, "
                         f"PPID {r.get('PPID','?')})",
        "interp": "Active process at memory-acquisition time",
        "claimed_confidence": "INDICATED",
    },
    "pstree": {
        "obs": lambda r: f"Process-tree node: {r.get('ImageFileName','?')} "
                         f"(PID {r.get('PID','?')}, parent {r.get('PPID','?')})",
        "interp": "Process hierarchy reconstructed from memory",
        "claimed_confidence": "INDICATED",
    },
    "cmdline": {
        "obs": lambda r: f"Command line for {r.get('Process','?')} "
                         f"(PID {r.get('PID','?')}): {r.get('Args','?')}",
        "interp": "Recovered command-line argument string",
        "claimed_confidence": "INDICATED",
    },
    "netscan": {
        "obs": lambda r: (
            f"Network connection: {r.get('Proto','?')} "
            f"{r.get('LocalAddr','?')}:{r.get('LocalPort','?')} -> "
            f"{r.get('ForeignAddr','?')}:{r.get('ForeignPort','?')} "
            f"(state {r.get('State','?')}, owner {r.get('Owner','?')})"
        ),
        "interp": "Active or recently-closed network connection",
        "claimed_confidence": "INDICATED",
    },
    "malfind": {
        "obs": lambda r: (
            f"Suspected code injection in {r.get('Process','?')} "
            f"(PID {r.get('PID','?')}) at VA {r.get('Start VPN','?')}"
        ),
        "interp": "Memory region with executable permissions and no "
                  "backing file -- candidate injected code",
        "claimed_confidence": "CONFIRMED",
    },
    "filescan": {
        "obs": lambda r: f"File object: {r.get('Name','?')} "
                         f"(offset {r.get('Offset','?')})",
        "interp": "_FILE_OBJECT recovered from kernel pool -- "
                  "open or recently-closed file handle",
        "claimed_confidence": "INDICATED",
    },
    "dlllist": {
        "obs": lambda r: f"DLL {r.get('Path','?')} loaded in "
                         f"{r.get('Process','?')} (PID {r.get('PID','?')})",
        "interp": "Module loaded into a process address space",
        "claimed_confidence": "INDICATED",
    },
    "handles": {
        "obs": lambda r: f"Handle {r.get('HandleValue','?')} "
                         f"({r.get('Type','?')}) in PID {r.get('PID','?')}: "
                         f"{r.get('Name','?')}",
        "interp": "Kernel handle table entry held by the process",
        "claimed_confidence": "INDICATED",
    },
    "registry.userassist": {
        "obs": lambda r: f"UserAssist entry: {r.get('Name','?')} "
                         f"(run count {r.get('Count','?')}, "
                         f"last {r.get('Last Modified','?')})",
        "interp": "Registry record of user-initiated program execution",
        "claimed_confidence": "INDICATED",
    },
    "registry.userassist_full": {
        "obs": lambda r: f"UserAssist (extended): {r.get('Name','?')}",
        "interp": "Registry user-execution record (extended)",
        "claimed_confidence": "INDICATED",
    },
    "envars": {
        "obs": lambda r: f"Env var in PID {r.get('PID','?')}: "
                         f"{r.get('Variable','?')}={r.get('Value','?')}",
        "interp": "Process environment variable",
        "claimed_confidence": "INDICATED",
    },
}


def from_vol_json(
    text: str,
    plugin: str,
    source_file: str | None = None,
) -> list[dict]:
    """Convert one Volatility3 JSON-renderer output blob to a list of findings.

    plugin: short plugin name (e.g. 'pslist', 'netscan', 'malfind').
            Looked up in PLUGIN_PROFILE for the per-row heuristic.
    text:   the JSON output from `vol -r json -f <image> windows.<plugin>`.
    source_file: optional, propagated into each artifact so the enforcement
                 layer knows which memory image the finding came from.
    """
    profile = PLUGIN_PROFILE.get(plugin)
    if not profile:
        return []
    try:
        rows = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(rows, list):
        return []
    findings: list[dict] = []
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        artifact = {
            "source": f"vol.windows.{plugin}",
            "extraction": f"Volatility3 plugin windows.{plugin}",
            "content": json.dumps(row, ensure_ascii=False),
        }
        if source_file:
            artifact["source_file"] = source_file
        findings.append({
            "id": f"{plugin}-{i + 1:04d}",
            "observation": _fmt_row(profile["obs"], row),
            "interpretation": profile["interp"],
            "confidence": profile["claimed_confidence"],
            "artifacts": [artifact],
        })
    return findings


def aggregate(
    plugin_outputs: dict[str, str],
    source_file: str | None = None,
) -> list[dict]:
    """Aggregate multiple Volatility plugin outputs into one findings list."""
    all_findings: list[dict] = []
    for plugin, text in plugin_outputs.items():
        all_findings.extend(from_vol_json(text, plugin, source_file))
    return all_findings


# --- Synthetic-data smoke test --------------------------------------------

if __name__ == "__main__":
    # A minimal synthetic Volatility-style JSON output for pslist + malfind.
    pslist_json = json.dumps([
        {"PID": 4, "PPID": 0, "ImageFileName": "System", "CreateTime": "2020-12-19T08:30:00"},
        {"PID": 632, "PPID": 4, "ImageFileName": "smss.exe", "CreateTime": "2020-12-19T08:30:01"},
        {"PID": 1804, "PPID": 632, "ImageFileName": "powershell.exe", "CreateTime": "2020-12-19T08:35:14"},
    ])
    malfind_json = json.dumps([
        {"Process": "powershell.exe", "PID": 1804, "Start VPN": "0x7ffe0000",
         "Hexdump": "4d 5a 90 00 03 00 00 00 ...", "Disasm": "dec ebp\\npop edx\\n..."},
    ])
    findings = aggregate(
        {"pslist": pslist_json, "malfind": malfind_json},
        source_file="Rocba-Memory.raw",
    )
    print(f"Total findings: {len(findings)}")
    for f in findings:
        print(f"  {f['id']:<14} ({f['confidence']:<10}) {f['observation']}")
