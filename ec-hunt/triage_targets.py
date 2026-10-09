#!/usr/bin/env python3
"""Extracted Telegram target triage for the CF1B EC-engine hunt.

The fetch workflow runs relay/fetch_files.py first (including its archive
extraction pass), then this script inspects the three MTProto target folders.
It records classification and static GENERATE-marker localization only; the
Cortex-M mailbox driver in ec_generate_emu.py is not wired yet.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

from ec_classify import classify_bytes  # noqa: E402
from ec_generate_emu import locate_generate_engine  # noqa: E402

TARGETS = {
    "tg_7470AIO_MCU": "30339 — OptiPlex 7470 AIO MCU",
    "tg_EDW40_MEC1515NB": "24189 — EDW40 MEC1515-NB EC reads",
    "tg_3310_19717": "30462 — Latitude 3310 8MB/16MB dump",
}
RAW_ROOT = ROOT / "bios-analysis" / "collected" / "raw"
OUT = HERE / "target-triage.json"
IGNORED_NAMES = {".cookies", "manifest.json", "page.html", "tg_diag.txt"}
TEXT_SUFFIXES = {".html", ".htm", ".json", ".txt", ".xml", ".md", ".log"}
IMAGE_SUFFIXES = {".jpg", ".jpeg", ".png", ".gif", ".webp"}
ARCHIVE_MAGICS = (
    b"PK\x03\x04",
    b"Rar!",
    b"7z\xbc\xaf\x27\x1c",
    b"\x1f\x8b",
    b"MSCF",
)
ARCHIVE_SUFFIXES = {".zip", ".rar", ".7z", ".gz", ".cab"}


def inspect_targets() -> dict:
    entries = []
    payload_count = 0
    archive_count = 0

    for folder, description in TARGETS.items():
        target_dir = RAW_ROOT / folder
        if not target_dir.is_dir():
            entries.append({"target": folder, "description": description,
                            "state": "not-downloaded", "files": []})
            continue

        files = []
        for path in sorted(target_dir.rglob("*")):
            if not path.is_file() or path.name in IGNORED_NAMES:
                continue
            if path.suffix.lower() in TEXT_SUFFIXES | IMAGE_SUFFIXES:
                continue
            try:
                size = path.stat().st_size
                if size < 256:
                    continue
                data = path.read_bytes()
            except OSError as exc:
                files.append({"path": str(path.relative_to(ROOT)),
                              "state": "read-error", "error": str(exc)})
                continue

            rel = str(path.relative_to(ROOT))
            digest = hashlib.sha256(data).hexdigest()
            if path.suffix.lower() in ARCHIVE_SUFFIXES or any(
                    data.startswith(magic) for magic in ARCHIVE_MAGICS):
                archive_count += 1
                files.append({"path": rel, "size": size, "sha256": digest,
                              "state": "archive-awaiting-extraction"})
                continue

            result = classify_bytes(data, rel)
            locator = locate_generate_engine(data)
            payload_count += 1
            files.append({
                "path": rel,
                "size": size,
                "sha256": digest,
                "state": "classified",
                "classification": result,
                "generate_locator": locator,
            })

        entries.append({
            "target": folder,
            "description": description,
            "state": "payloads-found" if files else "no-firmware-payload",
            "files": files,
        })

    hits = [f for target in entries for f in target["files"]
            if f.get("classification", {}).get("hit")]
    return {
        "targets": entries,
        "payload_count": payload_count,
        "archive_count": archive_count,
        "hit_count": len(hits),
        "emulator_status": (
            "static locator only; mailbox-driver wiring remains pending a real HIT image"
        ),
    }


def main() -> int:
    report = inspect_targets()
    OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    for target in report["targets"]:
        print(f"{target['target']}: {target['state']} ({len(target['files'])} candidate file(s))")
        for file in target["files"]:
            classification = file.get("classification", {})
            print(f"  {file['state']}: {file['path']} — "
                  f"{classification.get('class', 'archive')} hit={classification.get('hit', False)}")
    print(f"payloads={report['payload_count']} archives={report['archive_count']} "
          f"GENERATE_hits={report['hit_count']}")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
