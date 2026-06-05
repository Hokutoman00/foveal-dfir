# Dataset documentation — ROCBA / "The Fred Rocba Case"

This document describes the case data used by the worked example in [EXAMPLE_ACCURACY_REPORT_ROCBA.md](EXAMPLE_ACCURACY_REPORT_ROCBA.md) and is included as the per-case dataset-documentation submission deliverable.

## Provenance

- **Source**: SANS FIND EVIL! hackathon 2026 sample data share, folder *HACKATHON-2026 / Standard Forensic Case*.
- **Shared by**: Rob Lee (SANS Institute), via the Egnyte share linked from the hackathon resources page.
- **Available period**: through 2026-06-17 (per Egnyte share notice).
- **Acquired**: 2026-05-30 by direct download (no modification).

## Scenario

The hackathon brief (`ROCBA-BACKGROUND.pptx`, 7 slides) frames the case as:

- **Subject**: Fred Rocba, employed by **Stark Research Labs (SRL)**.
- **Incident**: Break-in and **intellectual-property (IP) theft** affecting Fred and SRL.
- **Context**: Fred was on vacation at the time of the incident; pictures had synced to his home system. SRL is the IP-bearing party of interest.
- **Investigator question**: *"The Game is Afoot! Key Questions to Answer."*

The case is presented as a **human-operated IP-theft** scenario rather than an autonomous-agent intrusion. This is honestly relevant to our pillar #6 (`actor_cadence`): on this case we expect the cadence verdict to be `HUMAN_LIKELY`, which is a correct result, not a failure. The architecture does not force `MACHINE_PACED`; it surfaces the signature it actually observes.

## Files

| File                       | Size    | SHA-256 hash | Used in the worked example | Notes                                   |
|----------------------------|---------|--------------|----------------------------|-----------------------------------------|
| `ROCBA-BACKGROUND.pptx`    | 38.3 MB | *(see below)*| yes (case context)         | 7 slides; case narrative.               |
| `rocba-cdrive.e01`         | 22.1 GB | *(see below)*| disk-side pillars (next)   | EnCase disk image of Fred's host.       |
| `Rocba-Memory.zip`         |  5.3 GB | *(see below)*| memory-side pillars (yes)  | Container: holds `Rocba-Memory/Rocba-Memory.7z`. |
| └─ `Rocba-Memory/Rocba-Memory.7z` |  5.3 GB | *(see below)* | --                       | 7z, LZMA2:24, single block.             |
| └─ `Rocba-Memory.raw`      | 17.7 GB | *(see below)*| **yes**                    | Raw memory dump, 19,050,528,768 bytes.  |

> Hashes are recorded at the time of integration. The worked example now uses both the memory image and a disk-side entity-merged pass over selected Sleuth Kit `fls` listings from the E01.

## Host identification (Volatility3 `windows.info`)

| Field                | Value                                                       |
|----------------------|-------------------------------------------------------------|
| Product              | `NtProductWinNt`                                            |
| Major/Minor          | `15.19041` (NT 10.0 build 19041)                            |
| NtMajorVersion       | 10                                                          |
| NtMinorVersion       | 0                                                           |
| Architecture         | x64 (`Is64Bit=True`, `IsPAE=False`)                         |
| Kernel base          | `0xf8025d600000`                                            |
| KdVersionBlock       | `0xf8025e20f340`                                            |
| DTB                  | `0x1ad000`                                                  |
| Processors           | 4                                                           |
| Memory layer         | `WindowsIntel32e` over a single `FileLayer`                 |
| `NtSystemRoot`       | `C:\WINDOWS`                                                |
| Symbol PDB           | `ntkrnlmp.pdb / 15B12C74F0E177581B6B27DD4C5022C2-1.json.xz` |
| **System time at acquisition** | **`2020-11-16 02:32:38 UTC`**                     |
| PE TimeDateStamp     | `2023-08-27 22:21:11`                                       |

The host is **Windows 10 x64, May 2020 Update (build 19041)**; the memory image was acquired on **2020-11-16 at 02:32 UTC** with the system running.

## Extraction layout (local layout used by the worked example)

The runner expects the memory image to live in a directory readable by Volatility3. The layout we used:

```
/var/findevil/cases/rocba/
└── Rocba-Memory/
    ├── Rocba-Memory.7z        # extracted from Rocba-Memory.zip
    ├── Rocba-Memory.raw       # extracted from the .7z; this is the dump
    └── findings/
        ├── pslist.json        # Volatility3 windows.pslist  (715 KB)
        ├── cmdline.json       # Volatility3 windows.cmdline (228 KB)
        ├── netscan.json       # Volatility3 windows.netscan (127 KB)
        ├── malfind.json       # Volatility3 windows.malfind ( 12 KB)
        └── vol.log            # Volatility runner stderr / progress
```

## Reproduction

```bash
# Unpack (after downloading Rocba-Memory.zip):
mkdir -p /var/findevil/cases/rocba
unzip Rocba-Memory.zip -d /var/findevil/cases/rocba
cd /var/findevil/cases/rocba/Rocba-Memory
7z x Rocba-Memory.7z                      # produces Rocba-Memory.raw

# Identify (Volatility3):
vol -f Rocba-Memory.raw windows.info

# Extract per-plugin JSON:
mkdir -p findings
vol -r json -f Rocba-Memory.raw windows.pslist  > findings/pslist.json
vol -r json -f Rocba-Memory.raw windows.cmdline > findings/cmdline.json
vol -r json -f Rocba-Memory.raw windows.netscan > findings/netscan.json
vol -r json -f Rocba-Memory.raw windows.malfind > findings/malfind.json

# Run the enforcement pipeline:
python -m cases.run_rocba \
  --findings-dir /var/findevil/cases/rocba/Rocba-Memory/findings \
  --source-file Rocba-Memory.raw \
  --no-grader \
  --out-dir cases_outputs/rocba

# Inspect:
cat cases_outputs/rocba/summary.json
```

## Plugins used in the worked example

| Plugin           | Findings produced | Notes                                                   |
|------------------|-------------------|---------------------------------------------------------|
| `windows.pslist` | many              | Active processes at acquisition time.                   |
| `windows.cmdline`| many              | Process command lines (look for exfil tools, archives). |
| `windows.netscan`| many              | Active and recently-closed network connections.         |
| `windows.malfind`| 16                | Memory regions with executable permissions and no backing file. |

Total candidate findings ingested: **4,818**. See [EXAMPLE_ACCURACY_REPORT_ROCBA.md](EXAMPLE_ACCURACY_REPORT_ROCBA.md) for the per-pillar results.

## What this dataset documentation does NOT cover

- **Disk side**. The disk pass is integrated via `verifier/disk_ingest.py` (parses Sleuth Kit `fls -f ntfs` listings from the user's Google Drive folder, iCloud folder, Downloads, and Windows Prefetch) and `cases/run_rocba_disk.py`. The entity-merged ingest unions findings sharing an id across sources, so the structural rule sees >=2 distinct artifact sources for the multi-source entities (e.g. `cloud_sync.google_drive`, `cloud_sync.icloud`). Run with `python -m cases.run_rocba_disk --findings-dir cases_data/rocba_disk [--no-grader]`; the worked example is in [EXAMPLE_ACCURACY_REPORT_ROCBA.md](EXAMPLE_ACCURACY_REPORT_ROCBA.md).
- **Ground truth**. The hackathon brief is the only narrative we have; no ground-truth labels accompany the share at this writing. The accuracy report's false-positive matrix is therefore left blank in the baseline run; it will be populated when ground truth is available (or against a community-derived consensus).
- **Cross-case generalization**. Numbers above describe the ROCBA case only; the `Compromised APT Attack Scenarios` folder (`SRL-2015`, `SRL-2018`) is out of scope for this run.

## Privacy and IP-theft sensitivity

The case is fictional but mirrors real IP-theft scenarios. The case file path names (e.g., `\\Rocba\\`), the `Stark Research Labs` employer, and the surrounding narrative are pre-distributed by SANS as a teaching scenario. We do not redistribute the case files in this repository; users obtain them from the SANS Egnyte share.
