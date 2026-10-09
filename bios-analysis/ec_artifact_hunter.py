#!/usr/bin/env python3
"""ec_artifact_hunter.py — automated EC-artifact hunter (relay fetchlist
generator). NEW agent tool (cycle 15).

The single missing keygen input is an EC-INTERNAL flash dump ("EC程序",
~192-480 KB, Cortex-M vector table at offset 0) of any 2020-21 8FC8-family
Dell (OptiPlex 3080/3090/5080/7080 — one shared EC; Latitude 3410/5410;
Inspiron/Vostro 5401/5501). This agent sweeps venues for it and emits
relay-ready `PAGE|`/`FILE|` lines for relay/fetchlist.txt.

Venues (registry below, extend freely):
  * Telegram public channels (t.me/s/<slug>?q=<term>) — incl. NEW channels
    discovered 2026-10-05: ITHINKHS BIOS & SCHEMATIC, AFS BIOS FREE
  * badcaps file_search (1.1M-file archive)
  * archive.org full-text search (JSON API)
  * vinafix/dr-bios/elvikom search pages (mostly gated, but cheap to poll)

Usage:
  python3 ec_artifact_hunter.py                 # print fetchlist lines
  python3 ec_artifact_hunter.py --append        # append to relay/fetchlist.txt
  python3 ec_artifact_hunter.py --terms a,b     # override search terms
"""
import os
import sys
import urllib.parse

# ---- search terms: fleet boards + EC part numbers + wild names -----------
DEFAULT_TERMS = [
    "EC", "EC程序", "MEC1515", "MEC1618", "MEC1521",
    "3090", "3080", "5080", "7080", "3410", "5410", "5401",
    "IPCML", "QUAKEL14", "MOCKINGBIRD", "CYBORG",
]

# ---- venue registry --------------------------------------------------------
TELEGRAM_CHANNELS = [
    "biosarchive",           # 128K subs, 25.7K files (swept: 5410/3090 only)
    "schematicslaptop",      # sister channel, NOT yet swept
    "ithinkhsbios",          # "ITHINKHS BIOS & SCHEMATIC" (new 2026-10-05)
    "afsbiosfree",           # "AFS BIOS FREE" (new 2026-10-05)
]

BADCAPS_SEARCH = "https://www.badcaps.net/file_search?search={q}"
ARCHIVE_SEARCH = ("https://archive.org/advancedsearch.php?q="
                  "{q}&fl%5B%5D=identifier&fl%5B%5D=title&rows=50&output=json")


def emit_lines(terms):
    lines = []
    seen = set()

    def add(line):
        if line not in seen:
            seen.add(line)
            lines.append(line)

    for ch in TELEGRAM_CHANNELS:
        for t in terms:
            q = urllib.parse.quote(t)
            add(f"PAGE|https://t.me/s/{ch}?q={q}|tg_{ch}_{t.replace(' ', '')}")
    for t in terms:
        q = urllib.parse.quote(t)
        add(f"PAGE|{BADCAPS_SEARCH.format(q=q)}|badcaps_fs_{t.replace(' ', '')}")
    q = urllib.parse.quote(
        '("EC程序" OR "EC dump" OR MEC1515 OR MEC1618) dell')
    add(f"PAGE|{ARCHIVE_SEARCH.format(q=q)}|archive_ec_dell")
    return lines


def main():
    argv = sys.argv[1:]
    terms = DEFAULT_TERMS
    if "--terms" in argv:
        terms = [t.strip() for t in
                 argv[argv.index("--terms") + 1].split(",") if t.strip()]
    lines = emit_lines(terms)
    if "--append" in argv:
        path = os.path.join(os.path.dirname(__file__), "..", "relay",
                            "fetchlist.txt")
        with open(path, "a") as f:
            f.write("\n# === §15 ec_artifact_hunter sweep (auto) ===\n")
            f.write("\n".join(lines) + "\n")
        print(f"appended {len(lines)} lines to relay/fetchlist.txt")
    else:
        print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
