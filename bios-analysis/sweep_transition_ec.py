#!/usr/bin/env python3
"""
sweep_transition_ec.py — Exhaustive 2018–2020 E7A8 -> 8FC8/CF1B Transition-Boundary
& Dell ChromeOS Wilco EC Firmware Hunter.

Tests the exact hardware/firmware boundary between:
  - Unsealed MEC5107 PHCM (`hdr[6] == 0x00`, e.g. Latitude 5X90)
  - OTP-sealed MEC5105/5107/1515 PHCM (`hdr[6] == 0x80/0x84`, 8FC8/CF1B/1B58 era)
  - 2018–2020 ODM ITE / Nuvoton / SMSC EC platforms (Latitude 3300/3301/3310/3400/3500,
    Inspiron/Vostro 3490/5490, XPS 9370/9380/7390/9570/7590, Precision 3430/3530/5530/7X30/7X40,
    OptiPlex 3060/5060/7060/7070 Ultra, Wyse 5070, Edge Gateway 5200)
  - Dell ChromeOS Enterprise Wilco EC (`sarien` = Latitude 5400 Chromebook,
    `arcada` = Latitude 5300 2-in-1 Chromebook) via HTTP Range on FLREG8 (`0x000000..0x100FFF`).

If ANY target contains BOTH `cmd 0x21 sub 3 type 6` (`8FC8`/`CF1B`/`1B58`) AND an
unsealed/plaintext EC payload (or any novel unsealed EC with password logic), the raw
binary is saved under `bios-analysis/transition_hits/` for immediate Unicorn emulation.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import gc
import json
import os
import re
import shutil
import struct
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import collect_latest_dell_ec as clde  # noqa: E402
import ec_keygen_solver as eks  # noqa: E402

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) DellTransitionAuditor/1.0"

TRANSITION_PATTERNS = [
    r"\blatitude 7x90\b",
    r"\blatitude 5x91\b",
    r"\blatitude 7390 2-in-1\b",
    r"\blatitude 3390 2-in-1\b",
    r"\blatitude 7x00\b",
    r"\blatitude 5x00\b",
    r"\blatitude 3300\b",
    r"\batitude 3301\b",
    r"\blatitude 3310\b",
    r"\blatitude 3310 2in1\b",
    r"\blatitude 3500, latitude 3400\b",
    r"\bprecision 7x30\b",
    r"\bprecision 7x40\b",
    r"\bxps 15 9570/precision 5530\b",
    r"^precision 5530$",
    r"\bxps 15 7590/precision 5540\b",
    r"^precision 5540$",
    r"\bxps 13 9370\b",
    r"\bxps 13 9380\b",
    r"\bxps 13 7390\b",
    r"^optiplex 3060$",
    r"^optiplex 5060$",
    r"^optiplex 7060$",
    r"^optiplex 3070$",
    r"^optiplex 5070$",
    r"^optiplex 7070 ultra$",
    r"^precision tower 3430$",
    r"^precision 3630 tower$",
    r"^precision 3930 rack$",
    r"\bwyse 5070 thin client\b",
    r"\bedge gateway 5000/5100\b",
    r"^egw5200$",
    r"\binspiron 3490\b",
    r"\bvostro 5490\b",
    r"\bg3 3500, g5 5500\b",
    r"\bg5 5000\b",
    r"\binspiron 14 7000 gaming\b",
]


def http_get(url: str, timeout: int = 90, byte_range: str | None = None) -> bytes | None:
    headers = {"User-Agent": USER_AGENT}
    if byte_range:
        headers["Range"] = f"bytes={byte_range}"
    req = urllib.request.Request(url, headers=headers)
    for attempt in range(2):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except Exception as e:
            if attempt == 1:
                print(f"[warn] GET failed {url}: {e}", flush=True)
            time.sleep(1.5)
    return None


def select_lvfs_transition_targets(index_path: Path) -> list[dict]:
    comps = json.loads(index_path.read_text())
    rx = re.compile("|".join(f"(?:{p})" for p in TRANSITION_PATTERNS), re.I)
    targets = []
    seen_urls = set()
    seen_model_slot = set()

    for c in comps:
        name = c["name"].strip()
        low = name.lower()
        if any(w in low for w in ["nvme", "ssd", "thunderbolt", "dock", "wd19", "sd25", "camera", "monitor", "tpm", "retimer", "china hdd"]):
            continue
        if not rx.search(name):
            continue

        # Pick oldest available release FIRST (closest to 2018-2019 launch!),
        # and also latest if version differs significantly on key 7X90/7X00/5X00/9380/3400 boards.
        candidates = [("oldest", c["oldest"])]
        if c["latest"]["url"] != c["oldest"]["url"] and any(
            k in low for k in ["7x90", "5x91", "7390", "7x00", "5x00", "3400", "3300", "9380", "7060", "5530", "7x30"]
        ):
            candidates.append(("latest", c["latest"]))

        norm_model = re.sub(r"[^a-z0-9]+", "_", low).strip("_")[:28]
        for slot, rel in candidates:
            u = rel["url"]
            # Keep early 1.7.2 / 1.19.0 / 1.9.1 single-release components distinct
            key = (norm_model, slot, rel["version"][:3] if slot == "oldest" else "latest")
            if u in seen_urls or key in seen_model_slot:
                continue
            seen_urls.add(u)
            seen_model_slot.add(key)
            slug = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{name}_{rel['version']}_{slot}").strip("_")[:64]
            targets.append({
                "slug": slug,
                "name": name,
                "version": rel["version"],
                "slot": slot,
                "url": u,
                "source": "lvfs",
            })
    return targets


def discover_wayback_birth_releases() -> list[dict]:
    """Query Wayback CDX for early 2019 1.0.x / 1.1.x / 1.2.0 capsules of Latitude 7400/7X00/5X00/5300."""
    queries = [
        "downloads.dell.com/FOLDER*/*7400_1.0*.exe",
        "downloads.dell.com/FOLDER*/*7400_1.1*.exe",
        "downloads.dell.com/FOLDER*/*7400_1.2*.exe",
        "downloads.dell.com/FOLDER*/*7X00_1.0*.exe",
        "downloads.dell.com/FOLDER*/*7X00_1.1*.exe",
        "downloads.dell.com/FOLDER*/*7X00_1.2*.exe",
        "downloads.dell.com/FOLDER*/*5300_1.0*.exe",
        "downloads.dell.com/FOLDER*/*5X00*1.0*.exe",
        "downloads.dell.com/FOLDER*/*G5_5590*.exe",
    ]
    found = []
    seen = set()
    for q in queries:
        cdx = (
            "https://web.archive.org/cdx/search/cdx?url="
            + urllib.parse.quote(q)
            + "&output=json&fl=timestamp,original,statuscode&filter=statuscode:200&limit=5"
        )
        raw = http_get(cdx, timeout=20)
        if not raw:
            continue
        try:
            rows = json.loads(raw.decode("utf-8", "ignore"))
        except Exception:
            continue
        for row in rows[1:]:
            ts, orig, _st = row
            fn = orig.rsplit("/", 1)[-1]
            if fn.lower() in seen:
                continue
            seen.add(fn.lower())
            found.append({
                "slug": re.sub(r"[^A-Za-z0-9._-]+", "_", f"wb_{fn[:-4]}")[:64],
                "name": fn,
                "version": fn,
                "slot": "wayback",
                "url": orig if orig.startswith("http") else f"https://{orig}",
                "wayback_url": f"https://web.archive.org/web/{ts}id_/{orig}",
                "source": "dell_wayback",
            })
    return found


def check_wilco_chromebooks() -> list[dict]:
    """Fetch FLREG8 (0x000000..0x100FFF = first 1,052,672 bytes) of Sarien & Arcada MrChromebox ROMs."""
    # Check sources.sh on GitHub first for exact current release version & date
    sources_raw = http_get("https://raw.githubusercontent.com/MrChromebox/scripts/main/sources.sh", timeout=20)
    ver, dt = "2609.2", "20261015"
    if sources_raw:
        txt = sources_raw.decode("utf-8", "ignore")
        mv = re.search(r'release_current_version="([^"]+)"', txt)
        md = re.search(r'release_current_date="([^"]+)"', txt)
        if mv:
            ver = mv.group(1)
        if md:
            dt = md.group(1)

    results = []
    for board, model in [
        ("sarien", "Dell Latitude 5400 Chromebook Enterprise (2019 Wilco EC)"),
        ("arcada", "Dell Latitude 5300 2-in-1 Chromebook Enterprise (2019 Wilco EC)"),
        ("drallion", "Dell Latitude 7410 Chromebook Enterprise (2020 Wilco EC)"),
    ]:
        urls = [
            f"https://www.mrchromebox.tech/files/firmware/full_rom/MrChromebox-{ver}/coreboot_edk2-{board}-mrchromebox_{dt}.rom",
            f"https://www.mrchromebox.tech/files/firmware/full_rom/coreboot_edk2-{board}-mrchromebox_{dt}.rom",
        ]
        head_1mb = None
        used_url = ""
        for u in urls:
            head_1mb = http_get(u, timeout=45, byte_range="0-1052671")
            if head_1mb and len(head_1mb) >= 0x82000:
                used_url = u
                break
        if not head_1mb:
            results.append({
                "slug": f"wilco_{board}",
                "name": model,
                "version": f"MrChromebox-{ver}",
                "status": "not_on_cdn",
                "pw_mode": "chromeos_vboot",
                "ecs": [],
            })
            continue

        ec_region = head_1mb[0x1000:0x101000]
        ecs_info = []
        for slot_off, slot_lbl in [(0x0, "TAG0_primary"), (0x80000, "TAG1_backup")]:
            blob = ec_region[slot_off : slot_off + 0x40000]
            if blob[:4] == b"PHCM":
                hdr_flag = blob[6]
                ver_hex = blob[4:8].hex()
                act_h = round(clde.active_entropy(blob[0x40:0x24000]), 4)
                ecs_info.append({
                    "kind": f"WILCO_PHCM_{slot_lbl}",
                    "size": len(blob),
                    "phcm_hdr_hex": blob[:24].hex(),
                    "phcm_flag_byte6": f"0x{hdr_flag:02x}",
                    "plaintext": (hdr_flag == 0 and act_h < 7.5),
                    "active_entropy": act_h,
                })
        results.append({
            "slug": f"wilco_{board}",
            "name": model,
            "version": f"MrChromebox-{ver}_{dt}",
            "url": used_url,
            "status": "ok",
            "ifd_tag0_tag1": head_1mb[:16].hex(),
            "pw_mode": "chromeos_wilco_ec",
            "ecs": ecs_info,
        })
    return results


def classify_pw_mode(pw_bytes: bytes) -> dict:
    """Detect whether a UEFI password module uses cmd 0x21 sub 3 type 6 (8FC8/CF1B/1B58) vs <=E7A8."""
    has_alph0 = b"0Q2drGk99WLJ1EGnqR5y3DGr" in pw_bytes
    has_salt = bytes.fromhex("257bfc8d") in pw_bytes
    has_smm_ec_guid = bytes.fromhex("8ee21073ea966043946e5adc6be8f531") in pw_bytes
    # Check for EC suffix family table (at least 2 of 8FC8, CF1B, 9ABE, 3FE2, 1B58 within 24 bytes)
    fams = []
    for code, name in [(0x8FC8, "8FC8"), (0xCF1B, "CF1B"), (0x1B58, "1B58"), (0x3FE2, "3FE2"), (0x9ABE, "9ABE"), (0xE7A8, "E7A8")]:
        le = struct.pack("<H", code)
        if le in pw_bytes:
            fams.append(name)
    # Tight proximity check for genuine suffix table vs random code bytes
    ec_fams_clustered = False
    for anchor in (b"\xc8\x8f", b"\x1b\xcf"):
        pos = 0
        while True:
            idx = pw_bytes.find(anchor, pos)
            if idx < 0:
                break
            win = pw_bytes[max(0, idx - 32) : idx + 32]
            cnt = sum(1 for c in (0x8FC8, 0xCF1B, 0x1B58, 0x3FE2, 0x9ABE, 0xE7A8) if struct.pack("<H", c) in win)
            if cnt >= 2:
                ec_fams_clustered = True
                break
            pos = idx + 1
    # Check for cmd 0x21, sub 3, type 6 call pattern in x86-64 (mov dl/ecx/r8/stack = 0x21, 0x03, 0x06)
    has_cmd21 = bool(re.search(rb"\xb2\x21.{0,24}\x03.{0,24}\x06|\x21\x00\x03\x06", pw_bytes, re.S))
    return {
        "has_alphabet0": has_alph0,
        "has_salt_8dfc7b25": has_salt,
        "has_smm_ec_guid": has_smm_ec_guid,
        "ec_suffix_table": ec_fams_clustered,
        "has_cmd21_pattern": has_cmd21,
        "raw_suffix_hits": fams,
    }


def analyze_one_target(t: dict, hits_dir: Path) -> dict:
    t0 = time.time()
    pkg = http_get(t["url"], timeout=120)
    if not pkg and t.get("wayback_url"):
        pkg = http_get(t["wayback_url"], timeout=120)
    if not pkg:
        return {**t, "status": "download_failed", "elapsed": round(time.time() - t0, 1)}
    pkg_mb = round(len(pkg) / (1024 * 1024), 2)

    with tempfile.TemporaryDirectory() as td:
        inner_blobs = []
        if pkg[:4] == b"MSCF" or (pkg[:2] == b"MZ" and len(pkg) >= 512 * 1024):
            cab_p = os.path.join(td, "pkg.bin")
            Path(cab_p).write_bytes(pkg)
            ext_d = os.path.join(td, "ext")
            import subprocess
            if shutil.which("7z"):
                subprocess.run(["7z", "x", "-y", f"-o{ext_d}", cab_p], capture_output=True, timeout=240)
            for root, _dirs, files in os.walk(ext_d):
                for fn in sorted(files):
                    if fn in (".text", ".rdata", ".data", ".pdata", ".reloc", ".rsrc", "CERTIFICATE"):
                        continue
                    fp = os.path.join(root, fn)
                    if os.path.isfile(fp) and os.path.getsize(fp) >= 4096 and not fn.lower().endswith(
                        (".xml", ".asc", ".p7b", ".cat", ".inf", ".txt", ".dll", ".mui")
                    ):
                        inner_blobs.append((f"cab:{fn}", Path(fp).read_bytes()))
            if pkg[:2] == b"MZ":
                inner_blobs.append(("raw", pkg))
        else:
            inner_blobs.append(("raw", pkg))

        all_streams = []
        for ilbl, ibytes in inner_blobs:
            st, _pm = clde.unpack_deep(ibytes, ilbl)
            all_streams.extend(st)

        ecs, pws = clde.extract_ec_and_pw_from_streams(all_streams)
        all_streams.clear()
        inner_blobs.clear()
        del pkg
        gc.collect()

        pw_summaries = []
        has_ec_8fc8 = False
        for p in pws:
            pb = p.pop("bytes")
            pm = classify_pw_mode(pb)
            if pm["ec_suffix_table"] and (pm["has_smm_ec_guid"] or pm["has_cmd21_pattern"]):
                has_ec_8fc8 = True
            pw_summaries.append({
                "size": p["size"],
                "sha256_16": p["sha256"][:16],
                **pm,
            })

        ec_summaries = []
        any_unsealed_ec = False
        tmp_ec_path = Path(td) / "cand_ec.bin"
        for idx, e in enumerate(ecs, 1):
            eb = e.pop("bytes")
            tmp_ec_path.write_bytes(eb)
            insp = eks.inspect_ec_dump(tmp_ec_path)
            phcm_b6 = f"0x{eb[6]:02x}" if eb[:4] == b"PHCM" and len(eb) > 8 else None
            is_unsealed = (eb[:4] == b"PHCM" and len(eb) > 8 and eb[6] in (0x00, 0x01) and (e.get("active_entropy") or 8.0) < 7.5)
            if is_unsealed:
                any_unsealed_ec = True
            saved_hit = None
            # Save binary ONLY if an unsealed PHCM EC actually embeds ALPHABET0 (true 8FC8/CF1B EC generator)
            if is_unsealed and e["kind"] == "PHCM" and insp.get("has_alphabet0"):
                hits_dir.mkdir(parents=True, exist_ok=True)
                out_fn = f"{t['slug']}__ec{idx}_{e['kind']}_{len(eb)}.bin"
                (hits_dir / out_fn).write_bytes(eb)
                saved_hit = f"transition_hits/{out_fn}"

            ec_summaries.append({
                "kind": e["kind"],
                "size": e["size"],
                "phcm_byte6": phcm_b6,
                "active_entropy": e.get("active_entropy"),
                "unsealed": is_unsealed,
                "has_ec_alph72": insp.get("has_ec_alph72", False),
                "has_alphabet0": insp.get("has_alphabet0", False),
                "family_dispatch": insp.get("family_dispatch_candidates", []),
                "saved_hit": saved_hit,
            })

        golden_overlap = has_ec_8fc8 and any_unsealed_ec
        print(
            f"[done] {t['slug']}: ec={len(ec_summaries)} unsealed={any_unsealed_ec} "
            f"ec_8fc8={has_ec_8fc8} GOLDEN={golden_overlap} ({time.time()-t0:.1f}s)",
            flush=True,
        )
        return {
            **t,
            "status": "ok",
            "pkg_mb": pkg_mb,
            "elapsed": round(time.time() - t0, 1),
            "has_ec_8fc8_protocol": has_ec_8fc8,
            "has_unsealed_ec": any_unsealed_ec,
            "golden_unsealed_8fc8_overlap": golden_overlap,
            "ecs": ec_summaries,
            "pws": pw_summaries,
        }


def write_report(results: list[dict], wilco: list[dict], out_md: Path, out_json: Path) -> None:
    payload = {
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_capsules_tested": len(results),
        "wilco_chromebooks_tested": len(wilco),
        "golden_overlaps": [r["slug"] for r in results if r.get("golden_unsealed_8fc8_overlap")],
        "wilco_results": wilco,
        "capsule_results": results,
    }
    out_json.write_text(json.dumps(payload, indent=2))

    lines = [
        "# 2018–2020 Dell `E7A8 -> 8FC8/CF1B` Transition Boundary & ChromeOS Wilco EC Audit",
        "",
        f"- **Capsules unpacked & audited**: `{len(results)}`",
        f"- **Dell ChromeOS Wilco EC boards audited (`FLREG8`)**: `{len(wilco)}`",
        f"- **Golden Overlaps (`unsealed EC` + `cmd 0x21 / 8FC8` in same platform)**: `{len(payload['golden_overlaps'])}`",
        "",
        "## 1. Dell ChromeOS Enterprise Wilco EC (`FLREG8` `0x001000..0x100FFF`)",
        "",
        "| Board | Model | Version | Status | EC Slots (`PHCM` byte 6 & active H) |",
        "|---|---|---|---|---|",
    ]
    for w in wilco:
        slots = "; ".join(
            f"{e['kind']} byte6={e['phcm_flag_byte6']} H={e['active_entropy']} plain={e['plaintext']}"
            for e in w.get("ecs", [])
        ) or "-"
        lines.append(f"| `{w['slug']}` | {w['name']} | `{w['version']}` | `{w['status']}` | {slots} |")

    lines += [
        "",
        "## 2. 2018–2020 Transition Capsule Matrix (`LVFS` + `Dell Wayback`)",
        "",
        "| Model | Version (`slot`) | `8FC8/CF1B` EC Proto? | Unsealed EC? | GOLDEN? | EC Payloads (`kind`, `PHCM[6]`, `H`, `EC_ALPH72`) |",
        "|---|---|:---:|:---:|:---:|---|",
    ]
    for r in results:
        if r.get("status") != "ok":
            lines.append(f"| {r['name']} | `{r['version']}` ({r['slot']}) | - | - | - | `{r.get('status')}` |")
            continue
        ec_str = "; ".join(
            f"{e['kind']}({e['size']//1024}K, b6={e['phcm_byte6']}, H={e['active_entropy']}, "
            f"unsealed={e['unsealed']}, alph72={e['has_ec_alph72']})"
            for e in r["ecs"]
        ) or "none"
        lines.append(
            f"| {r['name'][:38]} | `{r['version']}` ({r['slot']}) | "
            f"{'YES' if r['has_ec_8fc8_protocol'] else 'no'} | "
            f"{'**YES**' if r['has_unsealed_ec'] else 'no'} | "
            f"{'**HIT!**' if r['golden_unsealed_8fc8_overlap'] else 'no'} | {ec_str[:140]} |"
        )
    out_md.write_text("\n".join(lines) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", default=str(HERE / "collected_latest_ec" / "lvfs_dell_2026_index.json"))
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--max-targets", type=int, default=48)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    targets = select_lvfs_transition_targets(Path(args.index))
    if args.dry_run:
        print(f"Selected {len(targets)} LVFS transition targets:")
        for t in targets:
            print(f"  {t['slug']:50s} -> {t['url']}")
        return 0

    wb = discover_wayback_birth_releases()
    print(f"[init] LVFS transition targets={len(targets)}, Wayback birth targets={len(wb)}", flush=True)
    all_targets = (wb + targets)[: args.max_targets]

    wilco = check_wilco_chromebooks()
    hits_dir = HERE / "transition_hits"
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(analyze_one_target, t, hits_dir): t for t in all_targets}
        for fut in concurrent.futures.as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as e:
                t = futs[fut]
                results.append({**t, "status": f"error:{e}"})
            gc.collect()
            if len(results) % 5 == 0:
                write_report(
                    sorted(results, key=lambda r: r["slug"]),
                    wilco,
                    HERE / "TRANSITION_EC_SWEEP_REPORT.md",
                    HERE / "transition_ec_sweep.json",
                )

    results.sort(key=lambda r: (not r.get("golden_unsealed_8fc8_overlap", False), not r.get("has_unsealed_ec", False), r["slug"]))
    write_report(
        results,
        wilco,
        HERE / "TRANSITION_EC_SWEEP_REPORT.md",
        HERE / "transition_ec_sweep.json",
    )
    print(f"[complete] Report written to bios-analysis/TRANSITION_EC_SWEEP_REPORT.md", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
