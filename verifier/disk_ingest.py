"""Disk-side ingest: convert Sleuth Kit `fls` listings into foveal-dfir findings.

This module is the disk-image counterpart of `case_ingest.py` (memory). It
takes raw `fls -f ntfs` listings from key locations on a Windows host disk
and emits findings keyed by **entity** (e.g. ``cloud_sync.google_drive``,
``sensitive_file.in_cloud.SRL-Offer.pdf``).

The point of the entity key is that the SAME entity can be supported by
evidence from MULTIPLE independent sources:

  - the filesystem (the file or folder exists at a particular path),
  - Windows Prefetch (the corresponding executable ran),
  - Windows registry / AmCache (the program was installed, etc.).

`merge_by_id()` combines findings that share an id into one finding with
the union of their artifacts (deduplicated by ``source``). After the merge,
``verifier.staging.structural_ceiling`` independently counts the unique
artifact ``source`` values and decides whether ``CONFIRMED`` is structurally
permitted. If the merge produced two or more distinct sources for the
SAME claim, the rule allows ``CONFIRMED`` to survive -- this is the
counterpart of the memory-side run where every ``CONFIRMED`` got
downgraded to ``INDICATED`` because each finding only carried one source.
"""

from __future__ import annotations
import re
from typing import Iterable

from . import staging

# fls -f ntfs lines look like:
#   r/r 177765-128-5:	SRL-Offer.pdf
#   d/d 168221-144-13:	Google Drive
# Two type letters, an inode triple, then the name.
_FLS_LINE = re.compile(
    r"^\s*([dr])/([dr])\s+(\d+)-(\d+)-(\d+)\s*:\s*(.+?)\s*$"
)


def parse_fls(text: str) -> list[dict]:
    """Parse Sleuth Kit `fls -f ntfs` output into ``{type, inode, name}`` records."""
    out: list[dict] = []
    for line in text.splitlines():
        m = _FLS_LINE.match(line)
        if not m:
            continue
        out.append({
            "type": m.group(1),
            "inode": int(m.group(3)),
            "name": m.group(6).strip(),
        })
    return out


# Cloud-sync tool family -> (Prefetch keyword set, profile-folder name set).
CLOUD_SYNC_TOOLS: dict[str, dict] = {
    "google_drive": {
        "label": "Google Drive personal cloud sync",
        "prefetch_keys": ("GOOGLEDRIVEFS", "GOOGLEDRIVE"),
        "profile_folder_keys": ("Google Drive",),
    },
    "dropbox": {
        "label": "Dropbox personal cloud sync",
        "prefetch_keys": ("DROPBOX",),
        "profile_folder_keys": ("Dropbox",),
        "downloads_keys": ("DROPBOXINSTALLER", "DROPBOX"),
    },
    "onedrive": {
        "label": "OneDrive cloud sync",
        "prefetch_keys": ("ONEDRIVE",),
        "profile_folder_keys": ("OneDrive",),
    },
    "icloud": {
        "label": "Apple iCloud sync",
        "prefetch_keys": ("ICLOUD",),
        "profile_folder_keys": ("iCloudDrive", "iCloudPhotos"),
    },
}

# Filename substrings that look like SRL intellectual property on the host.
SENSITIVE_FILE_PATTERNS = (
    "SRL", "VIBRANIUM", "BusinessPlan", "Offer", "Confidential", "Internal",
    "Firedam", "HighFive",
)


def _entity_id_for_filename(name: str) -> str:
    """Stable id slug for a single filename so it can be merged."""
    return f"sensitive_file.in_cloud.{name.replace(' ', '_').replace('/', '_')}"


def from_googledrive_listing(text: str) -> list[dict]:
    """Findings from the contents of ``Users/fredr/Google Drive/``."""
    entries = parse_fls(text)
    if not entries:
        return []
    findings: list[dict] = []

    # Source artifact: the folder itself exists and has these entries.
    top = [e["name"] for e in entries if not e["name"].startswith(".")][:15]
    findings.append({
        "id": "cloud_sync.google_drive",
        "observation": "Google Drive sync folder present in Fred Rocba's user profile",
        "interpretation": (
            "Personal cloud-sync infrastructure on a corporate host -- a "
            "documented IP-exfiltration channel."
        ),
        "confidence": "CONFIRMED",
        "artifacts": [{
            "source": "ntfs.fls.user_profile_googledrive_folder",
            "extraction": "Sleuth Kit `fls -f ntfs` on rocba.E01 path Users/fredr/Google Drive/",
            "content": (
                "Top-level entries in C:\\Users\\fredr\\Google Drive\\: "
                + ", ".join(top)
            ),
        }],
    })

    # For each SRL-relevant filename, emit a finding keyed by the filename.
    for e in entries:
        nm = e["name"]
        if any(pat.lower() in nm.lower() for pat in SENSITIVE_FILE_PATTERNS):
            findings.append({
                "id": _entity_id_for_filename(nm),
                "observation": (
                    f"SRL-relevant document '{nm}' located in personal "
                    "Google Drive sync folder"
                ),
                "interpretation": (
                    "Stark Research Labs document staged on a personal "
                    "cloud-sync channel."
                ),
                "confidence": "CONFIRMED",
                "artifacts": [{
                    "source": "ntfs.fls.googledrive_folder_contents",
                    "extraction": "Sleuth Kit `fls -f ntfs` path Users/fredr/Google Drive/",
                    "content": f"File present in Google Drive folder: {nm} (NTFS inode {e['inode']})",
                }],
            })
    return findings


def from_icloud_listing(text: str) -> list[dict]:
    """Findings from ``Users/fredr/iCloudDrive/``."""
    entries = parse_fls(text)
    if not entries:
        return []
    top = [e["name"] for e in entries if not e["name"].startswith(".")][:10]
    return [{
        "id": "cloud_sync.icloud",
        "observation": "Apple iCloud Drive sync folder present in Fred Rocba's user profile",
        "interpretation": "Additional personal cloud-sync infrastructure -- a parallel exfiltration channel.",
        "confidence": "CONFIRMED",
        "artifacts": [{
            "source": "ntfs.fls.user_profile_iclouddrive_folder",
            "extraction": "Sleuth Kit `fls -f ntfs` path Users/fredr/iCloudDrive/",
            "content": "Top-level entries: " + ", ".join(top),
        }],
    }]


def from_downloads_listing(text: str) -> list[dict]:
    """Findings from ``Users/fredr/Downloads/``."""
    entries = parse_fls(text)
    findings: list[dict] = []
    for cloud_id, profile in CLOUD_SYNC_TOOLS.items():
        keys = profile.get("downloads_keys") or ()
        if not keys:
            continue
        matches = [e["name"] for e in entries
                   if any(k in e["name"].upper() for k in keys)
                   and "ZONE.IDENTIFIER" not in e["name"].upper()
                   and "SMARTSCREEN" not in e["name"].upper()]
        if matches:
            findings.append({
                "id": f"cloud_sync.{cloud_id}",
                "observation": f"Installer for {profile['label']} present in Downloads",
                "interpretation": "User downloaded the installer for an additional personal cloud-sync client.",
                "confidence": "CONFIRMED",
                "artifacts": [{
                    "source": "ntfs.fls.user_profile_downloads",
                    "extraction": "Sleuth Kit `fls -f ntfs` path Users/fredr/Downloads/",
                    "content": "Installer file: " + ", ".join(matches),
                }],
            })
    return findings


def from_prefetch_listing(text: str) -> list[dict]:
    """Findings from ``Windows/Prefetch/`` (program execution records)."""
    entries = parse_fls(text)
    pf_names = [e["name"] for e in entries if e["name"].upper().endswith(".PF")]
    findings: list[dict] = []
    for cloud_id, profile in CLOUD_SYNC_TOOLS.items():
        matching = [pf for pf in pf_names
                    if any(k in pf.upper() for k in profile["prefetch_keys"])]
        if matching:
            findings.append({
                "id": f"cloud_sync.{cloud_id}",
                "observation": (
                    f"{profile['label']} client was executed on this host "
                    f"({len(matching)} Prefetch record"
                    f"{'s' if len(matching) != 1 else ''})"
                ),
                "interpretation": (
                    "Cloud-sync client actively ran on this host -- "
                    "consistent with sync activity to personal cloud."
                ),
                "confidence": "CONFIRMED",
                "artifacts": [{
                    "source": "windows.prefetch",
                    "extraction": "Sleuth Kit `fls -f ntfs` on C:\\Windows\\Prefetch\\",
                    "content": "Prefetch entries: " + ", ".join(matching[:6]),
                }],
            })
    return findings


def merge_by_id(findings: Iterable[dict]) -> list[dict]:
    """Combine findings sharing an id; union the artifact list (dedup by source).

    The structural-staging layer counts distinct ``source`` values across the
    artifact list; the merge therefore directly determines whether a finding
    has the structural support to keep its ``CONFIRMED`` claim.
    """
    merged: dict[str, dict] = {}
    for f in findings:
        fid = f.get("id")
        if not fid:
            continue
        if fid not in merged:
            merged[fid] = {
                "id": fid,
                "observation": f.get("observation", ""),
                "interpretation": f.get("interpretation", ""),
                "confidence": f.get("confidence", "INDICATED"),
                "artifacts": list(f.get("artifacts", [])),
            }
            continue
        # Union artifacts (dedup by source); concatenate content.
        existing_sources = {a.get("source") for a in merged[fid]["artifacts"]}
        for art in f.get("artifacts", []):
            if art.get("source") not in existing_sources:
                merged[fid]["artifacts"].append(art)
                existing_sources.add(art.get("source"))
        # Take the highest claimed confidence across contributors.
        cur = merged[fid]["confidence"]
        nxt = f.get("confidence")
        try:
            if staging._rank(nxt) > staging._rank(cur):
                merged[fid]["confidence"] = nxt
        except (TypeError, AttributeError):
            pass
        # Also union the interpretation if the new one is longer.
        if len(f.get("interpretation", "")) > len(merged[fid]["interpretation"]):
            merged[fid]["interpretation"] = f["interpretation"]
    return list(merged.values())


def from_listings(
    googledrive_text: str = "",
    icloud_text: str = "",
    downloads_text: str = "",
    prefetch_text: str = "",
) -> list[dict]:
    """Run all per-plugin ingesters, then merge findings sharing an id.

    Returns a list of findings ready for ``verifier.verify.verify`` with the
    structural-source merge already applied.
    """
    all_findings: list[dict] = []
    all_findings.extend(from_googledrive_listing(googledrive_text))
    all_findings.extend(from_icloud_listing(icloud_text))
    all_findings.extend(from_downloads_listing(downloads_text))
    all_findings.extend(from_prefetch_listing(prefetch_text))
    return merge_by_id(all_findings)
