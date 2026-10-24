#!/usr/bin/env python3
"""
telegram_rea_agent.py — Online Latest Security Telegram Agent Fetch + REA
(morluto/rea v6.7.0) Evidence & Security Table Collector.

Stages:
  1A. Telegram MTProto Agent Fetch (when TG_API_ID / TG_API_HASH / TG_SESSION are set):
      - Fetches targeted Dell EC/BIOS archives from @biosarchive (#30339, #24189, #30462,
        plus keyword searches for MEC1515, MEC5200, PC14250, 1B58, CF1B, 8FC8) and
        inspects @aditya11ttt_broadcast/#1862 (SVOD4_ver0.0.7.6.zip) in /tmp.
  1B. Public Telegram Web & Screenshot OCR Agent Fetch (zero-secret HTTP + Tesseract):
      - Scrapes full history of https://t.me/s/Bios_Password, recent + queried pages of
        https://t.me/s/biosarchive, and https://t.me/s/aditya11ttt_broadcast.
      - Extracts CSS background-image URLs (cdn4.telesco.pe), downloads photos, runs
        2-pass Tesseract OCR (raw + 2x autocontrast), matches Dell XXXXXXX-YYYY tags
        and 16-char unlock strings, and retains top Dell screenshots in
        bios-analysis/telegram_captures/ (< 1.2 MB total).
  2.  Latest Online Security Firmware & Bin-file Archive Unpack:
      - Unpacks serversupdep-ai/Bin-file (ARCHES_15...16MB_&_32MB_BIOS_TESTED.rar +
        BIOS_IMG.rcv.part1..2) in /tmp, scanning SPI dumps for SIVB / DVAR / Service Tag /
        PHCM EC blocks / UEFI security modules.
      - Downloads & unpacks 6 latest 2026 Dell security capsules from CDN/LVFS:
          * Pro 14 PC14250 / Pro 16 PC16250 (RPL 1.18.0 & ARL 1.18.0)
          * OptiPlex Tower/Micro/SFF 7020 (1.29.0 DVT)
          * Latitude 5440 / Precision 3480 (1.34.0 DVT)
          * Latitude 5450 / Precision 3490 (1.26.0 QS)
          * Latitude 7450 / 7650 (1.26.0 DVT_QS)
      - Saves unique extracted DellSecurityVaultSmm / PasswordSmm PE32+ modules into
        tracked bios-analysis/rea_corpus/ (< 1.5 MB total).
  3.  REA (morluto/rea / rea-agents) Automated Binary Evidence & Parameter Extraction:
      - Runs `rea inspect-artifact`, `rea inspect-pe-resources`,
        `rea inspect-with-objdump`, and `rea execute-rizin-command` (if rizin present)
        plus x86-64 Capstone dispatch verification across bios-analysis/rea_corpus/,
        writing bios-analysis/rea_security_data.json and bios-analysis/TELEGRAM_REA_REPORT.md.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import collect_latest_dell_ec as collector  # noqa: E402

try:
    import pefile
except ImportError:
    pefile = None

try:
    from capstone import CS_ARCH_X86, CS_MODE_64, Cs
except ImportError:
    Cs = None

try:
    from PIL import Image, ImageOps
except ImportError:
    Image = None
    ImageOps = None

UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
)

DELL_TAG_SUFFIX_RE = re.compile(
    r"\b([A-Z0-9]{7})\s*[-–—~_]\s*(8FC8|CF1B|1B58|3FE2|9ABE|A6E0|E7A8|6FF1|BF97|1F66|1D3B|2A7B|0001|D35B|595B)\b",
    re.IGNORECASE,
)
DELL_SUFFIX_ONLY_RE = re.compile(
    r"\b(8FC8|CF1B|1B58|3FE2|9ABE|A6E0|E7A8|6FF1|BF97|1F66|1D3B|2A7B)\b",
    re.IGNORECASE,
)
PW16_CAND_RE = re.compile(r"\b([A-Za-z0-9\[\]]{16})\b")

LATEST_2026_SECURITY_CAPSULES = [
    {
        "slug": "pc14250_rpl_1_18_0",
        "name": "Dell Pro 14 PC14250 / Pro 16 PC16250 (RPL 1.18.0)",
        "url": "https://cdn.fwupd.org/downloads/c37df5361070555a60111ea93ad7632fa15e030c0b3d4c05429da3f90238a4d3-Dell_Pro_14_PC14250_16_PC16250_RPL_1.17.0_firmware.lvfs.cab",
    },
    {
        "slug": "pc14250_arl_1_18_0",
        "name": "Dell Pro 14 PC14250 / Pro 16 PC16250 (JadeArl 1.18.0)",
        "url": "https://cdn.fwupd.org/downloads/2edf7490ad39e84a41f2c0db2490f498a2860f89575a93dcd318c8311eec3ea2-JadeArl_1.17.0_firmware.lvfs.cab",
    },
    {
        "slug": "optiplex_7020_1_29_0_dvt",
        "name": "OptiPlex Tower/Micro/SFF 7020 (1.29.0 DVT)",
        "url": "https://cdn.fwupd.org/downloads/184a81bc3bdc20bbbff67aaff3b83ec6af70743239790bc396baa804dafd1e11-OptiLowMlkRpl_16.1.42.2872_DVT_firmware.lvfs.cab",
    },
    {
        "slug": "latitude_5440_1_34_0_dvt",
        "name": "Latitude 5440 / Precision 3480 (Arches14Rpl 1.34.0 DVT)",
        "url": "https://cdn.fwupd.org/downloads/4abc15fd360801722e19df8ea2c6e0495048fa5dfdbcdde368fb2f5d8d690405-Arches14Rpl_16.1.42.2872_DVT_firmware.lvfs.cab",
    },
    {
        "slug": "latitude_5450_1_26_0_qs",
        "name": "Latitude 5450 / Precision 3490 (Arches14Mtl 1.26.0 QS)",
        "url": "https://cdn.fwupd.org/downloads/1068c43c72f3c34ded6770ae654f2e02a0d0a87985d2d690ea65365a1ce455de-Arches14Mtl_QS_firmware.lvfs.cab",
    },
    {
        "slug": "latitude_7450_1_26_0_dvt_qs",
        "name": "Latitude 7450 / 7650 (Oasis1416Mtl 1.26.0 DVT_QS)",
        "url": "https://cdn.fwupd.org/downloads/6d8959b616a42fbc56ef5d96ccd120c5b6cebe2fdac4750b9790bd541066fd11-Oasis1416Mtl_DVT_QS_firmware.lvfs.cab",
    },
]

ALPHABET0 = b"0Q2drGk99WLJ1EGnqR5y3DGrX6373456798234567890123z567890123456789012345678"[:24]


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def http_get(url: str, timeout: int = 30, max_bytes: int = 120 * 1024 * 1024) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read(max_bytes)


def parse_tme_posts(raw_html: str, channel: str) -> list[dict]:
    posts = []
    # Split on message containers
    chunks = raw_html.split('class="tgme_widget_message_wrap')
    for ch in chunks[1:]:
        m_id = re.search(rf'data-post="{re.escape(channel)}/(\d+)"', ch)
        post_id = int(m_id.group(1)) if m_id else None
        m_txt = re.search(
            r'class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>', ch, re.DOTALL
        )
        txt = ""
        if m_txt:
            txt = re.sub(r"<br\s*/?>", "\n", m_txt.group(1))
            txt = re.sub(r"<[^>]+>", "", txt)
            txt = html.unescape(txt).strip()
        photos = re.findall(
            r"background-image:url\('(https://cdn\d*\.telesco\.pe/file/[^']+)'\)", ch
        )
        m_doc = re.search(
            r'class="tgme_widget_message_document_title"[^>]*>(.*?)</div>', ch, re.DOTALL
        )
        doc_title = html.unescape(re.sub(r"<[^>]+>", "", m_doc.group(1)).strip()) if m_doc else None
        m_extra = re.search(
            r'class="tgme_widget_message_document_extra"[^>]*>(.*?)</div>', ch, re.DOTALL
        )
        doc_extra = html.unescape(re.sub(r"<[^>]+>", "", m_extra.group(1)).strip()) if m_extra else None
        m_time = re.search(r'datetime="([^"]+)"', ch)
        dt = m_time.group(1) if m_time else None
        if post_id is not None:
            posts.append(
                {
                    "channel": channel,
                    "post_id": post_id,
                    "datetime": dt,
                    "text": txt,
                    "doc_title": doc_title,
                    "doc_extra": doc_extra,
                    "photo_urls": photos,
                }
            )
    return posts


def ocr_image_bytes(img_bytes: bytes, tmp_dir: Path, stem: str) -> str:
    raw_p = tmp_dir / f"{stem}_raw.jpg"
    raw_p.write_bytes(img_bytes)
    texts = []
    if shutil.which("tesseract"):
        for psm in ("6", "11"):
            r = subprocess.run(
                ["tesseract", str(raw_p), "stdout", "--psm", psm],
                capture_output=True,
                text=True,
                timeout=20,
            )
            if r.stdout.strip():
                texts.append(r.stdout.strip())
        if Image is not None and ImageOps is not None:
            try:
                im = Image.open(raw_p).convert("L")
                im = ImageOps.autocontrast(im)
                w, h = im.size
                im2 = im.resize((w * 2, h * 2))
                enh_p = tmp_dir / f"{stem}_enh.png"
                im2.save(enh_p)
                r2 = subprocess.run(
                    ["tesseract", str(enh_p), "stdout", "--psm", "6"],
                    capture_output=True,
                    text=True,
                    timeout=25,
                )
                if r2.stdout.strip():
                    texts.append(r2.stdout.strip())
                im_inv = ImageOps.invert(im2)
                inv_p = tmp_dir / f"{stem}_inv.png"
                im_inv.save(inv_p)
                r3 = subprocess.run(
                    ["tesseract", str(inv_p), "stdout", "--psm", "6"],
                    capture_output=True,
                    text=True,
                    timeout=25,
                )
                if r3.stdout.strip():
                    texts.append(r3.stdout.strip())
            except Exception:
                pass
    return "\n---\n".join(texts)


def run_telegram_mtproto(work_dir: Path) -> dict:
    api_id = os.environ.get("TG_API_ID", "").strip()
    api_hash = os.environ.get("TG_API_HASH", "").strip()
    session_str = os.environ.get("TG_SESSION", "").strip()
    res = {
        "configured": bool(api_id and api_hash and session_str),
        "downloaded": [],
        "search_hits": [],
        "svod4_summary": None,
        "errors": [],
    }
    if not res["configured"]:
        return res

    try:
        import asyncio
        from pyrogram import Client

        dl_dir = work_dir / "mtproto"
        dl_dir.mkdir(parents=True, exist_ok=True)

        async def _go():
            async with Client(
                "tg_rea_agent",
                api_id=int(api_id),
                api_hash=api_hash,
                session_string=session_str,
                in_memory=True,
                no_updates=True,
            ) as app:
                targets = [
                    ("biosarchive", 30339),
                    ("biosarchive", 24189),
                    ("biosarchive", 30462),
                    ("aditya11ttt_broadcast", 1862),
                ]
                for chat, mid in targets:
                    try:
                        msg = await app.get_messages(chat, mid)
                        if msg and msg.media:
                            f_name = getattr(msg.document, "file_name", None) or f"{chat}_{mid}.bin"
                            f_size = getattr(msg.document, "file_size", 0) or 0
                            if f_size <= 45 * 1024 * 1024:
                                out_f = dl_dir / f"{chat}_{mid}_{Path(f_name).name}"
                                await app.download_media(msg, file_name=str(out_f))
                                res["downloaded"].append(
                                    {
                                        "chat": chat,
                                        "msg_id": mid,
                                        "file_name": f_name,
                                        "bytes": out_f.stat().st_size if out_f.exists() else 0,
                                        "local_tmp": str(out_f),
                                    }
                                )
                    except Exception as e:
                        res["errors"].append(f"{chat}/{mid}: {e}")

                for kw in ("MEC1515", "MEC5200", "PC14250", "1B58", "CF1B", "Dell Pro"):
                    try:
                        count = 0
                        async for m in app.search_messages("biosarchive", query=kw, limit=8):
                            fn = getattr(getattr(m, "document", None), "file_name", None)
                            sz = getattr(getattr(m, "document", None), "file_size", 0) or 0
                            res["search_hits"].append(
                                {
                                    "query": kw,
                                    "msg_id": m.id,
                                    "date": str(m.date),
                                    "file_name": fn,
                                    "file_size": sz,
                                    "caption": (m.caption or m.text or "")[:200],
                                }
                            )
                            if fn and 0 < sz <= 35 * 1024 * 1024 and count < 2:
                                out_f = dl_dir / f"biosarchive_{m.id}_{Path(fn).name}"
                                if not out_f.exists():
                                    await app.download_media(m, file_name=str(out_f))
                                    res["downloaded"].append(
                                        {
                                            "chat": "biosarchive",
                                            "msg_id": m.id,
                                            "file_name": fn,
                                            "bytes": out_f.stat().st_size if out_f.exists() else 0,
                                            "local_tmp": str(out_f),
                                        }
                                    )
                                    count += 1
                    except Exception as e:
                        res["errors"].append(f"search({kw}): {e}")

        asyncio.run(_go())
    except Exception as e:
        res["errors"].append(f"mtproto_init: {e}")
    return res


def run_public_telegram_sweep(work_dir: Path, captures_dir: Path) -> dict:
    captures_dir.mkdir(parents=True, exist_ok=True)
    tmp_img_dir = work_dir / "tg_imgs"
    tmp_img_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "channels_scraped": {},
        "dell_posts": [],
        "ocr_findings": [],
        "saved_captures": [],
    }

    # 1. Full history of Bios_Password
    bp_posts = {}
    before = None
    for _ in range(12):
        url = "https://t.me/s/Bios_Password" + (f"?before={before}" if before else "")
        try:
            raw = http_get(url, timeout=20).decode("utf-8", errors="ignore")
            batch = parse_tme_posts(raw, "Bios_Password")
            if not batch:
                break
            for p in batch:
                bp_posts[p["post_id"]] = p
            min_id = min(p["post_id"] for p in batch)
            if before is not None and min_id >= before:
                break
            before = min_id
            if min_id <= 1:
                break
        except Exception as e:
            summary["channels_scraped"]["Bios_Password_error"] = str(e)
            break

    summary["channels_scraped"]["Bios_Password_posts"] = len(bp_posts)

    # 2. biosarchive latest + targeted queries
    ba_posts = {}
    ba_urls = [
        "https://t.me/s/biosarchive",
        "https://t.me/s/biosarchive?q=PC14250",
        "https://t.me/s/biosarchive?q=MEC1515",
        "https://t.me/s/biosarchive?q=MEC5200",
        "https://t.me/s/biosarchive?q=Latitude+5450",
        "https://t.me/s/biosarchive?q=OptiPlex+7020",
        "https://t.me/s/biosarchive?q=UNPASS+DELL",
    ]
    for url in ba_urls:
        try:
            raw = http_get(url, timeout=20).decode("utf-8", errors="ignore")
            for p in parse_tme_posts(raw, "biosarchive"):
                ba_posts[p["post_id"]] = p
        except Exception:
            pass
    summary["channels_scraped"]["biosarchive_posts"] = len(ba_posts)

    # 3. aditya11ttt_broadcast latest
    ad_posts = {}
    try:
        raw = http_get("https://t.me/s/aditya11ttt_broadcast", timeout=20).decode(
            "utf-8", errors="ignore"
        )
        for p in parse_tme_posts(raw, "aditya11ttt_broadcast"):
            ad_posts[p["post_id"]] = p
    except Exception:
        pass
    summary["channels_scraped"]["aditya11ttt_broadcast_posts"] = len(ad_posts)

    # Filter Dell-related posts & run OCR on Bios_Password photos
    seen_photo_sha = set()
    scored_photos = []

    for pid in sorted(bp_posts):
        p = bp_posts[pid]
        txt_low = (p["text"] or "").lower()
        is_dell_text = any(
            k in txt_low
            for k in (
                "dell",
                "latitude",
                "inspiron",
                "vostro",
                "precision",
                "optiplex",
                "xps",
                "alienware",
                "8fc8",
                "cf1b",
                "1b58",
                "3fe2",
                "9abe",
                "a6e0",
                "e7a8",
                "service tag",
                "master code",
            )
        )
        if is_dell_text:
            summary["dell_posts"].append(
                {
                    "channel": "Bios_Password",
                    "post_id": pid,
                    "datetime": p["datetime"],
                    "text": p["text"][:400],
                    "photo_count": len(p["photo_urls"]),
                }
            )
        # OCR photos from Dell posts OR any post if total < 75
        if is_dell_text or len(bp_posts) <= 85:
            for idx, purl in enumerate(p["photo_urls"][:3]):
                try:
                    ib = http_get(purl, timeout=15, max_bytes=3 * 1024 * 1024)
                    ih = sha256_bytes(ib)[:16]
                    if ih in seen_photo_sha:
                        continue
                    seen_photo_sha.add(ih)
                    ocr_txt = ocr_image_bytes(ib, tmp_img_dir, f"bp_{pid}_{idx}")
                    combined = f"{p['text']}\n{ocr_txt}"
                    tag_matches = [
                        f"{m.group(1).upper()}-{m.group(2).upper()}"
                        for m in DELL_TAG_SUFFIX_RE.finditer(combined)
                    ]
                    sfx_matches = sorted(
                        {m.group(1).upper() for m in DELL_SUFFIX_ONLY_RE.finditer(combined)}
                    )
                    pw16 = sorted(
                        {
                            m.group(1)
                            for m in PW16_CAND_RE.finditer(ocr_txt)
                            if any(c.isdigit() for c in m.group(1))
                            and any(c.isalpha() for c in m.group(1))
                        }
                    )
                    ocr_low = ocr_txt.lower()
                    dell_screen = any(
                        w in ocr_low
                        for w in (
                            "system number",
                            "service tag",
                            "unlock key",
                            "admin password",
                            "system password",
                            "dell",
                            "latitude",
                            "8fc8",
                            "cf1b",
                            "1b58",
                            "3fe2",
                            "9abe",
                        )
                    )
                    if tag_matches or sfx_matches or dell_screen or is_dell_text:
                        score = (
                            len(tag_matches) * 50
                            + len(sfx_matches) * 15
                            + (20 if dell_screen else 0)
                            + (10 if is_dell_text else 0)
                        )
                        rec = {
                            "post_id": pid,
                            "photo_idx": idx,
                            "datetime": p["datetime"],
                            "post_text": p["text"][:260],
                            "tag_matches": sorted(set(tag_matches)),
                            "suffix_matches": sfx_matches,
                            "pw16_candidates": pw16[:10],
                            "ocr_excerpt": ocr_txt[:700],
                            "score": score,
                        }
                        summary["ocr_findings"].append(rec)
                        if score >= 20 and len(ib) <= 180 * 1024:
                            scored_photos.append((score, pid, idx, ib, rec))
                except Exception:
                    pass

    scored_photos.sort(key=lambda x: (x[0], x[1]), reverse=True)
    total_saved_bytes = 0
    for score, pid, idx, ib, rec in scored_photos[:12]:
        if total_saved_bytes + len(ib) > 1200 * 1024:
            break
        fn = f"bios_password_{pid}_{idx}.jpg"
        (captures_dir / fn).write_bytes(ib)
        total_saved_bytes += len(ib)
        summary["saved_captures"].append(
            {
                "file": f"bios-analysis/telegram_captures/{fn}",
                "post_id": pid,
                "bytes": len(ib),
                "score": score,
                "tag_matches": rec["tag_matches"],
                "suffix_matches": rec["suffix_matches"],
            }
        )

    for pid in sorted(ba_posts, reverse=True)[:40]:
        p = ba_posts[pid]
        if any(
            w in (f"{p['text']} {p['doc_title'] or ''}").lower()
            for w in ("dell", "latitude", "optiplex", "precision", "inspiron", "vostro", "xps", "mec")
        ):
            summary["dell_posts"].append(
                {
                    "channel": "biosarchive",
                    "post_id": pid,
                    "datetime": p["datetime"],
                    "doc_title": p["doc_title"],
                    "doc_extra": p["doc_extra"],
                    "text": p["text"][:260],
                }
            )
    return summary


def inspect_spi_dump_bytes(name: str, data: bytes) -> dict:
    info = {
        "name": name,
        "bytes": len(data),
        "sha256": sha256_bytes(data),
        "sivb_offsets": [],
        "dvar_offsets": [],
        "phcm_blocks": [],
        "service_tag_hits": [],
    }
    # Scan SIVB
    pos = 0
    while True:
        i = data.find(b"SIVB", pos)
        if i == -1:
            break
        hdr = data[i : i + 64]
        info["sivb_offsets"].append(
            {"offset": hex(i), "head_hex": hdr[:32].hex(), "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in hdr[:48])}
        )
        pos = i + 4
        if len(info["sivb_offsets"]) >= 16:
            break

    # Scan DVAR
    pos = 0
    while True:
        i = data.find(b"DVAR", pos)
        if i == -1:
            break
        info["dvar_offsets"].append(hex(i))
        pos = i + 4
        if len(info["dvar_offsets"]) >= 16:
            break

    # Scan PHCM EC headers
    pos = 0
    while True:
        i = data.find(b"PHCM", pos)
        if i == -1:
            break
        if i + 64 <= len(data):
            b6 = data[i + 6]
            load_addr = struct.unpack_from("<I", data, i + 0x10)[0]
            info["phcm_blocks"].append(
                {
                    "offset": hex(i),
                    "b6_flag": hex(b6),
                    "sealed": b6 == 0x80,
                    "u32_at_0x10": hex(load_addr),
                    "head32": data[i : i + 32].hex(),
                }
            )
        pos = i + 4
        if len(info["phcm_blocks"]) >= 16:
            break

    # Look for H6C9P or 7-char Service Tag around $JA / SIVB
    for needle in (b"H6C9P", b"$JA", b"AdminPw", b"SysPw", b"DellSecurityVault"):
        idx = data.find(needle)
        if idx != -1:
            ctx = data[max(0, idx - 16) : min(len(data), idx + 48)]
            info["service_tag_hits"].append(
                {
                    "needle": needle.decode("latin1"),
                    "offset": hex(idx),
                    "context_hex": ctx.hex(),
                    "context_ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in ctx),
                }
            )
    return info


def unpack_archive_and_scan(
    archive_path: Path, tag_prefix: str, work_dir: Path, corpus_dir: Path
) -> dict:
    ext_dir = work_dir / f"unpack_{tag_prefix}"
    ext_dir.mkdir(parents=True, exist_ok=True)
    if archive_path.suffix.lower() == ".rar" and shutil.which("unrar"):
        subprocess.run(
            ["unrar", "x", "-o+", str(archive_path), str(ext_dir) + "/"],
            capture_output=True,
            timeout=180,
        )
    else:
        subprocess.run(
            ["7z", "x", "-y", f"-o{ext_dir}", str(archive_path)],
            capture_output=True,
            timeout=180,
        )

    out = {"archive": archive_path.name, "files": [], "spi_scans": [], "pkg_results": []}
    pw_dedup = work_dir / "pw_dedup"
    pw_dedup.mkdir(parents=True, exist_ok=True)
    out_models = work_dir / "pkg_out"
    out_models.mkdir(parents=True, exist_ok=True)
    budget = [0]

    for root, _dirs, files in os.walk(ext_dir):
        for fn in sorted(files):
            fp = Path(root) / fn
            sz = fp.stat().st_size
            out["files"].append({"path": str(fp.relative_to(ext_dir)), "bytes": sz})
            if sz >= 128 * 1024 and fp.suffix.lower() in (".bin", ".rom", ".rcv", ".fd", ".cap", ""):
                blob = fp.read_bytes()
                out["spi_scans"].append(inspect_spi_dump_bytes(fn, blob))
                try:
                    pkg_res = collector.process_one_package(
                        blob,
                        f"{tag_prefix}_{fp.stem[:24]}",
                        {"name": fn, "source": archive_path.name},
                        str(out_models),
                        str(pw_dedup),
                        budget,
                    )
                    out["pkg_results"].append(
                        {
                            "file": fn,
                            "ec_count": len(pkg_res.get("ec_candidates", [])),
                            "pw_count": len(pkg_res.get("pw_modules", [])),
                            "pw_modules": pkg_res.get("pw_modules", []),
                            "ec_candidates": pkg_res.get("ec_candidates", []),
                        }
                    )
                except Exception as e:
                    out["pkg_results"].append({"file": fn, "error": str(e)})

    # Copy any extracted unique PW modules < 100 KB into tracked corpus_dir
    for efi in sorted(pw_dedup.glob("*.efi")):
        if efi.stat().st_size <= 100 * 1024:
            dst = corpus_dir / efi.name
            if not dst.exists():
                shutil.copy2(efi, dst)
    return out


def run_binfile_and_lvfs2026(work_dir: Path, corpus_dir: Path) -> dict:
    corpus_dir.mkdir(parents=True, exist_ok=True)
    result = {"bin_file_repo": {}, "lvfs_2026_capsules": []}

    # Seed corpus_dir with canonical existing local binaries if present
    local_seeds = [
        HERE / "collected_latest_ec" / "pb14255_smm" / "DellSecurityVaultSmm_53248.efi",
        HERE / "collected_latest_ec" / "unique_pw" / "pw_x86_64_77e719e0dece9039_11776.efi",
        HERE / "collected_latest_ec" / "unique_pw" / "pw_x86_64_308bb92b6fa0b5c7_38912.efi",
        HERE / "collected_latest_ec" / "unique_pw" / "pw_x86_64_e7ae0202e1df4127_39424.efi",
        HERE / "collected_latest_ec" / "unique_pw" / "pw_x86_64_9ba12406f7c1161a_42496.efi",
        HERE / "collected_latest_ec" / "unique_pw" / "pw_x86_64_25af06756e91ade2_43008.efi",
        HERE / "collected_latest_ec" / "unique_pw" / "pw_x86_64_8f7db0c4f5e8345b_51712.efi",
    ]
    for s in local_seeds:
        if s.exists() and s.stat().st_size <= 100 * 1024:
            dst = corpus_dir / s.name
            if not dst.exists():
                shutil.copy2(s, dst)

    # 1. Clone and unpack serversupdep-ai/Bin-file
    bf_dir = work_dir / "binfile_repo"
    r = subprocess.run(
        [
            "git",
            "clone",
            "--depth",
            "1",
            "--branch",
            "arena/01a0a0ac-bin-file",
            "https://github.com/serversupdep-ai/Bin-file.git",
            str(bf_dir),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if r.returncode != 0:
        subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "https://github.com/serversupdep-ai/Bin-file.git",
                str(bf_dir),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

    if bf_dir.exists():
        rar_files = list(bf_dir.rglob("*.rar"))
        result["bin_file_repo"]["rar_archives"] = []
        for rf in rar_files:
            result["bin_file_repo"]["rar_archives"].append(
                unpack_archive_and_scan(rf, rf.stem[:20], work_dir, corpus_dir)
            )
        p1 = bf_dir / "BIOS_IMG.rcv.part1"
        p2 = bf_dir / "BIOS_IMG.rcv.part2"
        if p1.exists() and p2.exists():
            rcv_bytes = p1.read_bytes() + p2.read_bytes()
            rcv_tmp = work_dir / "BIOS_IMG.rcv"
            rcv_tmp.write_bytes(rcv_bytes)
            pw_dedup = work_dir / "pw_dedup_rcv"
            pw_dedup.mkdir(parents=True, exist_ok=True)
            pkg_res = collector.process_one_package(
                rcv_bytes,
                "binfile_bios_img_rcv",
                {"name": "BIOS_IMG.rcv", "source": "Bin-file"},
                str(work_dir / "rcv_out"),
                str(pw_dedup),
                [0],
            )
            for efi in sorted(pw_dedup.glob("*.efi")):
                if efi.stat().st_size <= 100 * 1024 and not (corpus_dir / efi.name).exists():
                    shutil.copy2(efi, corpus_dir / efi.name)
            result["bin_file_repo"]["bios_img_rcv"] = {
                "bytes": len(rcv_bytes),
                "sha256": sha256_bytes(rcv_bytes),
                "spi_scan": inspect_spi_dump_bytes("BIOS_IMG.rcv", rcv_bytes),
                "ec_count": len(pkg_res.get("ec_candidates", [])),
                "pw_modules": pkg_res.get("pw_modules", []),
            }

    # 2. Fetch & unpack 6 latest 2026 Dell LVFS capsules
    pw_dedup_lvfs = work_dir / "pw_dedup_lvfs"
    pw_dedup_lvfs.mkdir(parents=True, exist_ok=True)
    lvfs_out = work_dir / "lvfs_out"
    lvfs_out.mkdir(parents=True, exist_ok=True)
    budget = [0]

    for cap in LATEST_2026_SECURITY_CAPSULES:
        t0 = time.time()
        try:
            cab_bytes = http_get(cap["url"], timeout=90, max_bytes=120 * 1024 * 1024)
            pkg_res = collector.process_one_package(
                cab_bytes,
                cap["slug"],
                {"name": cap["name"], "url": cap["url"]},
                str(lvfs_out),
                str(pw_dedup_lvfs),
                budget,
            )
            result["lvfs_2026_capsules"].append(
                {
                    "slug": cap["slug"],
                    "name": cap["name"],
                    "cab_bytes": len(cab_bytes),
                    "elapsed_s": round(time.time() - t0, 2),
                    "ec_candidates": pkg_res.get("ec_candidates", []),
                    "pw_modules": pkg_res.get("pw_modules", []),
                }
            )
        except Exception as e:
            result["lvfs_2026_capsules"].append(
                {"slug": cap["slug"], "name": cap["name"], "error": str(e)}
            )

    # Copy newly discovered unique PW modules (< 100 KB, total corpus cap 1.4 MB)
    cur_bytes = sum(p.stat().st_size for p in corpus_dir.glob("*.efi"))
    for efi in sorted(pw_dedup_lvfs.glob("*.efi")):
        sz = efi.stat().st_size
        if sz <= 100 * 1024 and not (corpus_dir / efi.name).exists():
            if cur_bytes + sz <= 1400 * 1024:
                shutil.copy2(efi, corpus_dir / efi.name)
                cur_bytes += sz

    return result


def extract_pe_security_tables(efi_path: Path) -> dict:
    raw = efi_path.read_bytes()
    out = {
        "file": efi_path.name,
        "bytes": len(raw),
        "sha256": sha256_bytes(raw),
        "embedded_pe_count": 0,
        "embedded_ui_names": [],
        "alphabets_found": [],
        "ec_vault_suffixes": [],
        "offline_suffix_registry": [],
        "cmp_0xff_sentinel_verified": False,
        "cmp_0xffff_reject_verified": False,
        "has_ec_cmd_0x21": False,
        "has_legacy_salt_8dfc7b25": bytes.fromhex("257bfc8d") in raw,
    }
    # Check UTF-16 UI section names (e.g. PwByPassSmm)
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){5,24}\x00\x00", raw):
        s = m.group(0)[:-2].decode("utf-16le", errors="ignore")
        if any(w in s for w in ("Smm", "Dxe", "Pei", "Pass", "Vault", "Dell", "Ec", "Sec")):
            out["embedded_ui_names"].append(s)
    out["embedded_ui_names"] = sorted(set(out["embedded_ui_names"]))

    # Find 72-byte Dell password alphabets
    idx = 0
    while True:
        p = raw.find(b"0Q2drGk99", idx)
        if p == -1:
            break
        cand = raw[p : p + 72]
        if len(cand) == 72 and all(32 <= b < 127 for b in cand):
            out["alphabets_found"].append({"offset": hex(p), "alphabet": cand.decode("ascii")})
        idx = p + 9

    # Scan for EC suffix array {1B58, 9ABE, 3FE2, CF1B[, 8FC8]}
    ec_pat4 = struct.pack("<HHHH", 0x1B58, 0x9ABE, 0x3FE2, 0xCF1B)
    p4 = raw.find(ec_pat4)
    if p4 != -1:
        sufs = [0x1B58, 0x9ABE, 0x3FE2, 0xCF1B]
        if p4 + 10 <= len(raw) and struct.unpack_from("<H", raw, p4 + 8)[0] == 0x8FC8:
            sufs.append(0x8FC8)
        out["ec_vault_suffixes"] = [f"{x:04X}" for x in sufs]
    elif bytes.fromhex("c88f") in raw and b"0Q2drGk99" in raw:
        out["ec_vault_suffixes"] = ["8FC8"]

    # Scan offline 16-byte or 24-byte suffix registry entries starting with 0x8FC8 / 0xE7A8 / 0x6FF1
    for suf in (0x8FC8, 0xE7A8, 0xBF97, 0x6FF1, 0x1F66, 0x1D3B, 0x2A7B, 0xD35B, 0x595B, 0xA95B):
        pat = struct.pack("<H", suf)
        if pat in raw:
            out["offline_suffix_registry"].append(f"{suf:04X}")

    # Verify x86-64 instructions via pefile + Capstone
    if pefile is not None:
        pos = 0
        while True:
            mz = raw.find(b"MZ", pos)
            if mz == -1:
                break
            try:
                pe = pefile.PE(data=raw[mz:], fast_load=True)
                if pe.DOS_HEADER.e_lfanew <= 0x400:
                    out["embedded_pe_count"] += 1
                    if mz == 0 and Cs is not None:
                        mem = pe.get_memory_mapped_image()
                        md = Cs(CS_ARCH_X86, CS_MODE_64)
                        for sec in pe.sections:
                            if sec.Characteristics & 0x20000000:
                                code = mem[
                                    sec.VirtualAddress : sec.VirtualAddress + sec.Misc_VirtualSize
                                ]
                                for ins in md.disasm(code, sec.VirtualAddress):
                                    if ins.mnemonic == "cmp" and ins.op_str == "rax, 0xff":
                                        out["cmp_0xff_sentinel_verified"] = True
                                    elif ins.mnemonic == "cmp" and ins.op_str == "rax, 0xffff":
                                        out["cmp_0xffff_reject_verified"] = True
                                    elif ins.mnemonic == "mov" and ", 0x21" in ins.op_str:
                                        out["has_ec_cmd_0x21"] = True
            except Exception:
                pass
            pos = mz + 2
    return out


def run_rea_collection(rea_bin: str, corpus_dir: Path) -> dict:
    rea_out = {
        "rea_cli": rea_bin,
        "rea_version": None,
        "modules": [],
    }
    try:
        vr = subprocess.run([rea_bin, "--version"], capture_output=True, text=True, timeout=15)
        rea_out["rea_version"] = (vr.stdout or vr.stderr).strip()
    except Exception as e:
        rea_out["rea_version"] = f"error: {e}"

    has_rizin = shutil.which("rizin") is not None

    for efi in sorted(corpus_dir.glob("*.efi")):
        rec = extract_pe_security_tables(efi)
        rec["rea_evidence"] = {}

        # 1. rea inspect-artifact
        try:
            r1 = subprocess.run(
                [rea_bin, "inspect-artifact", str(efi), "--format", "json"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            j1 = json.loads(r1.stdout)
            rec["rea_evidence"]["inspect_artifact"] = {
                "evidence_id": j1.get("evidence_id"),
                "provider": j1.get("provider"),
                "root_format": j1.get("normalized_result", {}).get("subject", {}).get("root_format"),
                "substeps": [
                    {"operation": s.get("operation"), "status": s.get("status")}
                    for s in j1.get("normalized_result", {}).get("substeps", [])
                ],
            }
        except Exception as e:
            rec["rea_evidence"]["inspect_artifact_error"] = str(e)

        # 2. rea inspect-pe-resources
        try:
            r2 = subprocess.run(
                [rea_bin, "inspect-pe-resources", str(efi), "--format", "json"],
                capture_output=True,
                text=True,
                timeout=20,
            )
            j2 = json.loads(r2.stdout)
            rec["rea_evidence"]["inspect_pe_resources"] = {
                "evidence_id": j2.get("evidence_id"),
                "format": j2.get("normalized_result", {}).get("format"),
                "machine": j2.get("normalized_result", {}).get("machine"),
                "resources_count": j2.get("normalized_result", {})
                .get("coverage", {})
                .get("resources"),
            }
        except Exception as e:
            rec["rea_evidence"]["inspect_pe_resources_error"] = str(e)

        # 3. rea inspect-with-objdump section_headers
        try:
            r3 = subprocess.run(
                [rea_bin, "inspect-with-objdump", str(efi), "section_headers", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=20,
            )
            j3 = json.loads(r3.stdout)
            rec["rea_evidence"]["objdump_sections"] = {
                "evidence_id": j3.get("evidence_id"),
                "stdout_excerpt": (j3.get("raw_result", {}) or {}).get("stdout", "")[:700],
            }
        except Exception as e:
            rec["rea_evidence"]["objdump_sections_error"] = str(e)

        # 4. rea execute-rizin-command (when rizin is installed)
        if has_rizin:
            try:
                r4 = subprocess.run(
                    [rea_bin, "execute-rizin-command", str(efi), "iI; iz~0Q2drGk", "--format", "json"],
                    capture_output=True,
                    text=True,
                    timeout=25,
                )
                if r4.stdout.strip().startswith("{"):
                    j4 = json.loads(r4.stdout)
                    rec["rea_evidence"]["rizin_info"] = {
                        "evidence_id": j4.get("evidence_id"),
                        "stdout_excerpt": str(j4.get("raw_result") or j4.get("normalized_result"))[:500],
                    }
            except Exception as e:
                rec["rea_evidence"]["rizin_error"] = str(e)

        rea_out["modules"].append(rec)

    return rea_out


def write_markdown_report(
    report_path: Path, mtproto_res: dict, pub_tg_res: dict, fw_res: dict, rea_res: dict
) -> None:
    lines = [
        "# Online Latest Security (Telegram Agent Fetch) + REA Collection Report",
        "",
        f"- Generated: `{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}`",
        f"- REA CLI Version: `{rea_res.get('rea_version')}`",
        "",
        "## 1. Telegram Agent Fetch Summary",
        f"- MTProto credentials configured in runner secrets: `{mtproto_res.get('configured')}`",
        f"- MTProto files downloaded: `{len(mtproto_res.get('downloaded', []))}`",
        f"- Public `@Bios_Password` posts scraped: `{pub_tg_res.get('channels_scraped', {}).get('Bios_Password_posts', 0)}`",
        f"- Public `@biosarchive` posts scraped: `{pub_tg_res.get('channels_scraped', {}).get('biosarchive_posts', 0)}`",
        f"- Public `@aditya11ttt_broadcast` posts scraped: `{pub_tg_res.get('channels_scraped', {}).get('aditya11ttt_broadcast_posts', 0)}`",
        f"- OCR-matched Dell posts/screenshots: `{len(pub_tg_res.get('ocr_findings', []))}`",
        f"- High-signal screenshots saved to `bios-analysis/telegram_captures/`: `{len(pub_tg_res.get('saved_captures', []))}`",
        "",
        "### Top Telegram OCR Findings",
    ]
    for f in sorted(pub_tg_res.get("ocr_findings", []), key=lambda x: x["score"], reverse=True)[:15]:
        lines.append(
            f"- Post `#{f['post_id']}` (`{f.get('datetime')}`): tags=`{f['tag_matches']}` "
            f"suffixes=`{f['suffix_matches']}` pw16_cands=`{f['pw16_candidates'][:4]}`"
        )

    lines += [
        "",
        "## 2. `Bin-file` Archive & Latest 2026 LVFS Security Capsules",
    ]
    for rar in fw_res.get("bin_file_repo", {}).get("rar_archives", []):
        lines.append(f"- Unpacked RAR `{rar['archive']}`: `{len(rar['files'])}` files")
        for s in rar.get("spi_scans", []):
            lines.append(
                f"  - `{s['name']}` (`{s['bytes']:,}` B, sha256 `{s['sha256'][:16]}...`): "
                f"SIVB=`{len(s['sivb_offsets'])}`, DVAR=`{len(s['dvar_offsets'])}`, "
                f"PHCM=`{s['phcm_blocks']}`, tag_hits=`{[h['needle'] for h in s['service_tag_hits']]}`"
            )
    rcv = fw_res.get("bin_file_repo", {}).get("bios_img_rcv")
    if rcv:
        lines.append(
            f"- Unpacked `BIOS_IMG.rcv` (`{rcv['bytes']:,}` B): EC=`{rcv['ec_count']}`, PW=`{len(rcv['pw_modules'])}`"
        )

    lines.append("")
    lines.append("### Latest 2026 Dell LVFS Security Capsules")
    for c in fw_res.get("lvfs_2026_capsules", []):
        if "error" in c:
            lines.append(f"- `{c['name']}`: ERROR `{c['error']}`")
        else:
            pws = [m.get("saved_name") or m.get("sha256", "")[:12] for m in c.get("pw_modules", [])]
            ecs = [
                f"{e.get('kind')}(sealed={e.get('sealed_or_encrypted')})"
                for e in c.get("ec_candidates", [])
            ]
            lines.append(
                f"- `{c['name']}` (`{c['cab_bytes']:,}` B in `{c['elapsed_s']}s`): "
                f"PW modules=`{pws}`, ECs=`{ecs}`"
            )

    lines += [
        "",
        "## 3. REA (`rea-agents`) Security Module Evidence Inventory",
        "",
        "| Module | Size | SHA-256 | EC Suffixes | Offline Suffixes | `cmp 0xFF` (`0001`) | `cmp 0xFFFF` Reject | REA Artifact Evidence |",
        "|---|---:|---|---|---|---|---|---|",
    ]
    for m in rea_res.get("modules", []):
        ev = (
            m.get("rea_evidence", {}).get("inspect_artifact", {}).get("evidence_id", "n/a") or "n/a"
        )[:19]
        lines.append(
            f"| `{m['file']}` | {m['bytes']:,} | `{m['sha256'][:12]}` | "
            f"`{','.join(m['ec_vault_suffixes']) or '-'}` | "
            f"`{','.join(m['offline_suffix_registry']) or '-'}` | "
            f"`{m['cmp_0xff_sentinel_verified']}` | "
            f"`{m['cmp_0xffff_reject_verified']}` | `{ev}...` |"
        )
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rea-bin", default="rea", help="Path to REA CLI executable")
    ap.add_argument(
        "--rea-only",
        action="store_true",
        help="Run only Stage 3 (REA binary collection) on local corpus",
    )
    ap.add_argument(
        "--corpus-dir",
        default=str(HERE / "rea_corpus"),
        help="Directory for tracked Dell security PE32+ modules",
    )
    ap.add_argument(
        "--captures-dir",
        default=str(HERE / "telegram_captures"),
        help="Directory for top Dell BIOS screenshots from Telegram",
    )
    ap.add_argument(
        "--out-json",
        default=str(HERE / "rea_security_data.json"),
        help="Output JSON path",
    )
    ap.add_argument(
        "--out-report",
        default=str(HERE / "TELEGRAM_REA_REPORT.md"),
        help="Output Markdown report path",
    )
    args = ap.parse_args()

    corpus_dir = Path(args.corpus_dir)
    captures_dir = Path(args.captures_dir)
    corpus_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="tg_rea_") as td:
        work_dir = Path(td)
        if args.rea_only:
            # Seed local corpus
            for s in [
                HERE / "collected_latest_ec" / "pb14255_smm" / "DellSecurityVaultSmm_53248.efi",
                HERE / "collected_latest_ec" / "unique_pw" / "pw_x86_64_77e719e0dece9039_11776.efi",
                HERE / "collected_latest_ec" / "unique_pw" / "pw_x86_64_308bb92b6fa0b5c7_38912.efi",
                HERE / "collected_latest_ec" / "unique_pw" / "pw_x86_64_e7ae0202e1df4127_39424.efi",
                HERE / "collected_latest_ec" / "unique_pw" / "pw_x86_64_9ba12406f7c1161a_42496.efi",
                HERE / "collected_latest_ec" / "unique_pw" / "pw_x86_64_25af06756e91ade2_43008.efi",
                HERE / "collected_latest_ec" / "unique_pw" / "pw_x86_64_8f7db0c4f5e8345b_51712.efi",
            ]:
                if s.exists() and not (corpus_dir / s.name).exists():
                    shutil.copy2(s, corpus_dir / s.name)
            mtproto_res = {"configured": False, "skipped": True}
            pub_tg_res = {"channels_scraped": {}, "ocr_findings": [], "saved_captures": []}
            fw_res = {"bin_file_repo": {}, "lvfs_2026_capsules": []}
        else:
            print("[1/4] Running Telegram MTProto fetch (if secrets present)...", flush=True)
            mtproto_res = run_telegram_mtproto(work_dir)
            # Unpack any MTProto downloaded archives
            mtproto_res["unpacked"] = []
            for dl in mtproto_res.get("downloaded", []):
                lp = Path(dl["local_tmp"])
                if lp.exists():
                    if "SVOD4" in lp.name.upper():
                        ext_s = work_dir / "svod4"
                        subprocess.run(
                            ["7z", "l", str(lp)], capture_output=True, text=True, timeout=60
                        )
                        r_l = subprocess.run(
                            ["7z", "l", str(lp)], capture_output=True, text=True, timeout=60
                        )
                        mtproto_res["svod4_summary"] = r_l.stdout[-2500:]
                    else:
                        mtproto_res["unpacked"].append(
                            unpack_archive_and_scan(lp, f"tg_{dl['msg_id']}", work_dir, corpus_dir)
                        )

            print("[2/4] Running Public Telegram Web & OCR sweep...", flush=True)
            pub_tg_res = run_public_telegram_sweep(work_dir, captures_dir)

            print("[3/4] Unpacking Bin-file RAR/RCV + 2026 LVFS Security Capsules...", flush=True)
            fw_res = run_binfile_and_lvfs2026(work_dir, corpus_dir)

        print("[4/4] Running REA (rea-agents) binary evidence collection...", flush=True)
        rea_res = run_rea_collection(args.rea_bin, corpus_dir)

        payload = {
            "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "telegram_mtproto": {
                k: v for k, v in mtproto_res.items() if k != "downloaded"
            },
            "telegram_mtproto_downloaded": [
                {k: v for k, v in d.items() if k != "local_tmp"}
                for d in mtproto_res.get("downloaded", [])
            ],
            "telegram_public_ocr": pub_tg_res,
            "firmware_unpacks": fw_res,
            "rea_collection": rea_res,
        }
        Path(args.out_json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        write_markdown_report(Path(args.out_report), mtproto_res, pub_tg_res, fw_res, rea_res)
        print(f"Done -> {args.out_json} & {args.out_report}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
