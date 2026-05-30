"""Produce the 5-minute submission demo video for foveal-dfir.

No live screen capture. Every scene is a still PNG frame (terminal /
JSON / title styling) plus a TTS narration MP3, combined into an MP4
clip. The clips are then concatenated into a single deliverable.

Requires (already installed on this host):
  - ffmpeg.exe (in PATH or at the WinGet-Links shim path)
  - Node + msedge-tts (.claude/video pipeline)
  - Python + Pillow

Usage:
  python demo/produce_demo.py

Outputs:
  demo/build/scene_NN.png
  demo/build/scene_NN.mp3
  demo/build/scene_NN.mp4
  demo/build/foveal-dfir-demo.mp4   <-- final submission video
"""

from __future__ import annotations
import json
import os
import pathlib
import shutil
import subprocess
import sys
import textwrap
from PIL import Image, ImageDraw, ImageFont

# --- Layout constants ----------------------------------------------------

WIDTH, HEIGHT = 1920, 1080
BG = (16, 18, 22)           # near-black
FG = (220, 225, 232)         # near-white
ACCENT = (96, 165, 250)      # blue accent
ACCENT_2 = (250, 200, 96)    # amber accent (for "CONFIRMED")
DIM = (140, 145, 155)        # subtitles / footers

TITLE_FONT_SIZE = 96
SUB_FONT_SIZE = 44
BODY_FONT_SIZE = 28
SECTION_FONT_SIZE = 36

# --- Font discovery ------------------------------------------------------

FONT_CANDIDATES_MONO = [
    "C:/Windows/Fonts/consola.ttf",
    "C:/Windows/Fonts/cour.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
]
FONT_CANDIDATES_SANS = [
    "C:/Windows/Fonts/segoeui.ttf",
    "C:/Windows/Fonts/arial.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
]


def _font(size: int, mono: bool = True) -> ImageFont.FreeTypeFont:
    candidates = FONT_CANDIDATES_MONO if mono else FONT_CANDIDATES_SANS
    for p in candidates:
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()


# --- Frame renderers -----------------------------------------------------

def _draw_footer(draw: ImageDraw.ImageDraw) -> None:
    f = _font(20, mono=False)
    draw.text((40, HEIGHT - 50), "foveal-dfir   ·   SANS FIND EVIL! 2026",
              font=f, fill=DIM)


def render_title(path: pathlib.Path, title: str, subtitle: str) -> None:
    img = Image.new("RGB", (WIDTH, HEIGHT), BG)
    d = ImageDraw.Draw(img)
    title_font = _font(TITLE_FONT_SIZE, mono=True)
    sub_font = _font(SUB_FONT_SIZE, mono=False)
    t_bbox = d.textbbox((0, 0), title, font=title_font)
    tw, th = t_bbox[2] - t_bbox[0], t_bbox[3] - t_bbox[1]
    d.text(((WIDTH - tw) / 2, (HEIGHT - th) / 2 - 100),
           title, font=title_font, fill=ACCENT)
    # Subtitle: multi-line
    y = HEIGHT / 2 + 80
    for line in subtitle.splitlines():
        b = d.textbbox((0, 0), line, font=sub_font)
        w = b[2] - b[0]
        d.text(((WIDTH - w) / 2, y), line, font=sub_font, fill=FG)
        y += SUB_FONT_SIZE + 16
    _draw_footer(d)
    img.save(path)


def render_text(path: pathlib.Path, title: str, body: str) -> None:
    img = Image.new("RGB", (WIDTH, HEIGHT), BG)
    d = ImageDraw.Draw(img)
    title_font = _font(SECTION_FONT_SIZE + 12, mono=False)
    body_font = _font(BODY_FONT_SIZE + 10, mono=False)
    d.text((100, 130), title, font=title_font, fill=ACCENT)
    y = 270
    for line in body.splitlines():
        d.text((100, y), line, font=body_font, fill=FG)
        y += BODY_FONT_SIZE + 24
    _draw_footer(d)
    img.save(path)


def render_terminal(path: pathlib.Path, title: str, body: str) -> None:
    img = Image.new("RGB", (WIDTH, HEIGHT), BG)
    d = ImageDraw.Draw(img)
    title_font = _font(SECTION_FONT_SIZE, mono=False)
    body_font = _font(BODY_FONT_SIZE, mono=True)
    d.text((80, 80), title, font=title_font, fill=ACCENT)
    # Terminal pane
    pane_left, pane_top = 80, 180
    pane_right, pane_bot = WIDTH - 80, HEIGHT - 120
    d.rectangle([pane_left, pane_top, pane_right, pane_bot],
                outline=DIM, width=2, fill=(8, 10, 14))
    # Header bar
    d.rectangle([pane_left, pane_top, pane_right, pane_top + 36],
                fill=(28, 32, 38))
    d.text((pane_left + 16, pane_top + 6), "~/foveal-dfir $ python -m cases.run_rocba",
           font=_font(20, mono=True), fill=DIM)
    # Body lines
    y = pane_top + 60
    for line in body.splitlines():
        color = FG
        if "CONFIRMED" in line and "INDICATED" not in line:
            color = ACCENT_2
        if "DOWNGRADE" in line:
            color = (250, 130, 130)
        d.text((pane_left + 24, y), line, font=body_font, fill=color)
        y += BODY_FONT_SIZE + 8
    _draw_footer(d)
    img.save(path)


def render_json(path: pathlib.Path, title: str, body: str) -> None:
    img = Image.new("RGB", (WIDTH, HEIGHT), BG)
    d = ImageDraw.Draw(img)
    title_font = _font(SECTION_FONT_SIZE, mono=False)
    body_font = _font(BODY_FONT_SIZE, mono=True)
    d.text((80, 80), title, font=title_font, fill=ACCENT)
    pane_left, pane_top = 80, 180
    pane_right, pane_bot = WIDTH - 80, HEIGHT - 120
    d.rectangle([pane_left, pane_top, pane_right, pane_bot],
                outline=DIM, width=2, fill=(10, 14, 20))
    y = pane_top + 24
    for line in body.splitlines():
        color = FG
        if '"CONFIRMED"' in line:
            color = ACCENT_2
        if '"INDICATED"' in line or '"DISAGREE"' in line:
            color = (250, 130, 130)
        if line.strip().endswith("{") or line.strip().startswith("}"):
            color = ACCENT
        d.text((pane_left + 24, y), line, font=body_font, fill=color)
        y += BODY_FONT_SIZE + 6
    _draw_footer(d)
    img.save(path)


def render_table(path: pathlib.Path, title: str, body: str) -> None:
    # Same monospace layout, color rule slightly different.
    render_terminal(path, title, body)


RENDERERS = {
    "title": render_title,
    "text": render_text,
    "terminal": render_terminal,
    "json": render_json,
    "table": render_table,
}


# --- Scene table ---------------------------------------------------------

SCENES = [
    {
        "name": "00_title",
        "type": "title",
        "title": "foveal-dfir",
        "subtitle": "structural answers to self-deception\nSANS FIND EVIL! 2026",
        "narration": (
            "foveal-dfir. Structural answers to self-deception in "
            "autonomous digital forensics."
        ),
    },
    {
        "name": "01_thesis",
        "type": "text",
        "title": "The failure mode is self-deception.",
        "body": (
            "Most submissions: build a more careful agent.\n"
            "\n"
            "We answer structurally.\n"
            "\n"
            "(The adversary in GTG-1002 is itself an autonomous agent,\n"
            "so it inherits the same structural limit we do.)"
        ),
        "narration": (
            "The hackathon names its own open problem: an autonomous DFIR "
            "agent that just says find evil hallucinates and needs a "
            "human to guide it. The failure mode is self-deception. Most "
            "submissions answer with a more careful agent. We answer "
            "structurally."
        ),
    },
    {
        "name": "02_memory_pass",
        "type": "terminal",
        "title": "Memory pass on real evidence: 4,818 findings, 16 over-claims caught",
        "body": (
            "$ python -m cases.run_rocba --no-grader\n"
            "Loaded 4 plugin output(s) from cases_data/rocba\n"
            "Total candidate findings: 4818\n"
            "\n"
            "ID         CLAIMED    VERIFIED   DIVERGENCE\n"
            "pslist-*   INDICATED  INDICATED  AGREE_REAL\n"
            "cmdline-*  INDICATED  INDICATED  AGREE_REAL\n"
            "netscan-*  INDICATED  INDICATED  AGREE_REAL\n"
            "malfind-*  CONFIRMED  INDICATED  AGREE_REAL  DOWNGRADE\n"
            "\n"
            "16/4818 findings were downgraded by independent enforcement.\n"
            "All 16 downgrades are malfind CONFIRMED -> INDICATED.\n"
            "\n"
            "Reason: each finding carries 1 independent source.\n"
            "CONFIRMED requires >= 2 independent sources, counted in code."
        ),
        "narration": (
            "The pipeline runs end-to-end on a real eighteen-gigabyte "
            "memory image. Four thousand eight hundred and eighteen "
            "candidate findings come from Volatility plugins. Sixteen "
            "of those claim CONFIRMED. The structural staging layer — "
            "in code — caps all sixteen at INDICATED. The rule CONFIRMED "
            "requires two independent sources, written in every "
            "competitor's README, is not actually enforced in code by "
            "any of them. We enforce it."
        ),
    },
    {
        "name": "03_grader",
        "type": "json",
        "title": "Independent blind grader: AGREE on the claim, the structural rule still binds",
        "body": (
            "{\n"
            "  \"finding_id\": \"malfind-0001\",\n"
            "  \"investigator\":      \"CONFIRMED\",\n"
            "  \"blind_grader\":      \"CONFIRMED\",\n"
            "  \"divergence\":        \"AGREE_REAL\",\n"
            "  \"structural_ceiling\": \"INDICATED\",\n"
            "  \"verified_confidence\": \"INDICATED\",\n"
            "  \"grader_reasoning\": \"The memory region has executable\n"
            "    permissions and no file backing, directly supporting\n"
            "    the claim of code injection.\"\n"
            "}\n"
            "\n"
            "Both observers say CONFIRMED.\n"
            "The pipeline still binds at INDICATED.\n"
            "The rule holds over the consensus of the observers themselves."
        ),
        "narration": (
            "An independent grader, a separate model running locally — "
            "qwen2.5 7B — re-judges every finding from the evidence only. "
            "It never sees the investigator's reasoning trace, and is "
            "never told the claimed confidence. On the sixteen malfind "
            "findings, the grader independently judged CONFIRMED. The "
            "investigator and the grader agreed. And the consensus "
            "verdict was still INDICATED, because the structural rule "
            "held the line over the consensus of the observers themselves."
        ),
    },
    {
        "name": "04_disk_both_ways",
        "type": "terminal",
        "title": "Disk pass: the rule works the OTHER way too",
        "body": (
            "$ python -m cases.run_rocba_disk\n"
            "Total entity-merged findings: 8\n"
            "\n"
            "ID                                SRC  VERIFIED   GRADER\n"
            "cloud_sync.icloud                  2   CONFIRMED  CONFIRMED\n"
            "cloud_sync.google_drive            2   INDICATED  pushed back\n"
            "cloud_sync.dropbox                 2   INDICATED  pushed back\n"
            "cloud_sync.onedrive                1   INDICATED  staging cap\n"
            "sensitive_file.SRL-Offer.pdf       1   INDICATED  staging cap\n"
            "sensitive_file.VIBRANIUM.docx      1   INDICATED  staging cap\n"
            "sensitive_file.HighFiveBP.docx     1   INDICATED  staging cap\n"
            "sensitive_file.Firedam.xls         1   INDICATED  staging cap\n"
            "\n"
            "3 layers must agree for CONFIRMED to stand:\n"
            "  investigator + structural staging + blind grader.\n"
            "The rule is fair: single -> cap, multi-source -> permitted."
        ),
        "narration": (
            "The disk pass shows the rule in the OTHER direction. Same "
            "pipeline, against Fred Rocba's disk image. Eight entity-merged "
            "findings. The three personal cloud sync clients — Google "
            "Drive, Dropbox, iCloud — each carry artifacts from two "
            "distinct sources: the filesystem AND the prefetch. The "
            "structural staging layer permits CONFIRMED. The blind grader "
            "pushes back on two and lets iCloud through. Only when all "
            "three layers agree does CONFIRMED stand. The rule is fair: "
            "it caps single-source and it permits multi-source."
        ),
    },
    {
        "name": "05_responsibility",
        "type": "json",
        "title": "Responsibility ledger: per-claim attribution, dissents recorded",
        "body": (
            "{\n"
            "  \"finding_id\": \"cloud_sync.google_drive\",\n"
            "  \"observers\": [\n"
            "    {\"role\": \"investigator\",        \"claim\": \"CONFIRMED\"},\n"
            "    {\"role\": \"structural_staging\", \"claim\": \"CONFIRMED\"},\n"
            "    {\"role\": \"blind_grader\",       \"claim\": \"INDICATED\"},\n"
            "    {\"role\": \"divergence_arbiter\", \"claim\": \"AGREE_REAL\"},\n"
            "    {\"role\": \"consensus_verdict\",  \"claim\": \"INDICATED\"}\n"
            "  ],\n"
            "  \"accountability\": {\n"
            "    \"verdict_holder\":           \"consensus_verdict\",\n"
            "    \"distributed_contributors\": [\"investigator\",\n"
            "                                  \"structural_staging\"],\n"
            "    \"dissenters\":               [\"blind_grader\"]\n"
            "  }\n"
            "}"
        ),
        "narration": (
            "Every observer is named in code. Dissents are recorded, "
            "not silenced. Each claim records which observer produced it, "
            "where the observers diverged, and which entity carries each "
            "verdict. Distributed contribution, traceable accountability — "
            "not the diffuse responsibility of consensus."
        ),
    },
    {
        "name": "06_close",
        "type": "title",
        "title": "foveal-dfir",
        "subtitle": (
            "github.com/Hokutoman00/foveal-dfir\n\n"
            "Eight pillars. One thesis.\n"
            "Self-deception is the failure mode.\n"
            "The cure is structural."
        ),
        "narration": (
            "foveal-dfir. Eight pillars, one thesis. Self-deception is "
            "the failure mode. The cure is structural. Thank you."
        ),
    },
]


# --- Pipeline glue -------------------------------------------------------

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
VIDEO_PIPELINE = pathlib.Path(r"C:\Users\hokut\Desktop\マルチ開発\.claude\video")
BUILD_DIR = REPO_ROOT / "demo" / "build"

# ffmpeg executable: prefer Windows-side ffmpeg.exe.
FFMPEG_CANDIDATES = [
    "C:\\Users\\hokut\\AppData\\Local\\Microsoft\\WinGet\\Links\\ffmpeg.exe",
    "ffmpeg.exe",
    "ffmpeg",
]


def _ffmpeg() -> str:
    for c in FFMPEG_CANDIDATES:
        if pathlib.Path(c).exists() or shutil.which(c):
            return c
    raise RuntimeError("ffmpeg not found")


def run(cmd: list[str]) -> None:
    print("  $", " ".join(repr(c) if " " in c else c for c in cmd))
    subprocess.run(cmd, check=True)


def render_scene_png(scene: dict, path: pathlib.Path) -> None:
    rt = RENDERERS[scene["type"]]
    if scene["type"] == "title":
        rt(path, scene["title"], scene["subtitle"])
    else:
        rt(path, scene["title"], scene["body"])


def make_tts(text: str, out_mp3: pathlib.Path) -> None:
    """Call the existing node tts-to-file.mjs to produce an mp3."""
    script = VIDEO_PIPELINE / "scripts" / "tts-to-file.mjs"
    cmd = [
        "node",
        str(script),
        str(out_mp3),
        "en-US-AriaNeural",
        text,
    ]
    print("  $ (tts)", out_mp3.name, "len=", len(text))
    subprocess.run(cmd, check=True, cwd=str(VIDEO_PIPELINE))


def make_scene_mp4(png: pathlib.Path, mp3: pathlib.Path, out_mp4: pathlib.Path) -> None:
    """Loop the PNG for the duration of the mp3, encode as a single mp4."""
    ffmpeg = _ffmpeg()
    cmd = [
        ffmpeg, "-y", "-loop", "1", "-i", str(png),
        "-i", str(mp3),
        "-c:v", "libx264", "-tune", "stillimage",
        "-pix_fmt", "yuv420p",
        "-c:a", "aac", "-b:a", "192k",
        "-shortest",
        "-r", "30",
        str(out_mp4),
    ]
    subprocess.run(cmd, check=True, capture_output=True)


def concat_mp4s(mp4_paths: list[pathlib.Path], final_out: pathlib.Path) -> None:
    """Concat via ffmpeg's concat demuxer."""
    ffmpeg = _ffmpeg()
    listfile = final_out.parent / "concat_list.txt"
    with listfile.open("w", encoding="utf-8") as f:
        for p in mp4_paths:
            # Use forward slashes; absolute paths.
            f.write(f"file '{p.as_posix()}'\n")
    cmd = [
        ffmpeg, "-y", "-f", "concat", "-safe", "0",
        "-i", str(listfile),
        "-c", "copy",
        str(final_out),
    ]
    subprocess.run(cmd, check=True, capture_output=True)


def main() -> None:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    scene_mp4s: list[pathlib.Path] = []
    for s in SCENES:
        print(f"\n=== {s['name']} ({s['type']}) ===")
        png = BUILD_DIR / f"{s['name']}.png"
        mp3 = BUILD_DIR / f"{s['name']}.mp3"
        mp4 = BUILD_DIR / f"{s['name']}.mp4"
        render_scene_png(s, png)
        make_tts(s["narration"], mp3)
        make_scene_mp4(png, mp3, mp4)
        scene_mp4s.append(mp4)
        print(f"  -> {mp4}  ({mp4.stat().st_size // 1024} KB)")

    final = BUILD_DIR / "foveal-dfir-demo.mp4"
    print(f"\n=== concatenating {len(scene_mp4s)} scenes -> {final} ===")
    concat_mp4s(scene_mp4s, final)
    print(f"\nDONE. {final}  ({final.stat().st_size // 1024 // 1024} MB)")


if __name__ == "__main__":
    main()
