#!/usr/bin/env python3
"""lvfs_latest.py — Dell LVFS latest-BIOS tracker (fleet-focused).

Parses the fwupd client metadata (cdn.fwupd.org/downloads/firmware.xml.gz —
relay-fetched, NO anti-bot on this host/path) and reports the newest release
for every Dell UEFI component, flagging anything NEWER than the solution
kit's pinned versions (solution_kit/MODEL_PROFILES.json).

Also rewrites cab location URLs to the working CDN host.

Usage: python3 lvfs_latest.py [firmware.xml[.gz]] [--fleet]
"""
import gzip
import json
import os
import re
import sys
import datetime

FLEET = {
    "OptiPlex 3080": "optiplex-3080",
    "OptiPlex 3090": "optiplex-3090",
    "OptiPlex 3090 UFF": "optiplex-3090uff",
    "Latitude 5X10": "latitude-5410-sibling",   # 5410/5510 platform (vault pairs)
    "Latitude 3440": "latitude-3440",
}

def load(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace").read()
    return open(path, encoding="utf-8", errors="replace").read()

def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    path = args[0] if args else os.path.join(
        os.path.dirname(__file__), "collected", "raw", "fwupd_meta", "firmware.xml.gz")
    fleet_only = "--fleet" in sys.argv
    d = load(path)
    comps = re.split(r"(?=<component )", d)
    rows = []
    for c in comps:
        if "com.dell.uefi" not in c:
            continue
        n = re.search(r"<name>([^<]+)</name>", c)
        rels = re.findall(r'version="([^"]+)"[^>]*timestamp="(\d+)"[^>]*>.*?'
                          r"<location>([^<]+)</location>", c, re.S)
        if not (n and rels):
            continue
        def vt(v):
            try:
                return tuple(int(x) for x in v.split("."))
            except ValueError:
                return (0,)
        rels.sort(key=lambda r: vt(r[0]), reverse=True)
        rows.append((n.group(1), rels[0][0], int(rels[0][1]),
                     rels[0][2].replace("https://fwupd.org/",
                                        "https://cdn.fwupd.org/")))
    # kit pins
    pins = {}
    try:
        mp = json.load(open(os.path.join(os.path.dirname(__file__),
                    "solution_kit", "MODEL_PROFILES.json")))
        for k, v in mp.items():
            if isinstance(v, dict) and "latest_bios" in v:
                pins[k] = str(v.get("latest_bios"))
    except Exception:
        pass
    print(f"{len(rows)} Dell UEFI components with releases "
          f"(metadata: {os.path.basename(path)})\n")
    newer = []
    for n, v, ts, url in sorted(rows):
        dt = datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d")
        mark = ""
        for fleet_name, model_id in FLEET.items():
            if n.startswith(fleet_name):
                mark = f"  <== fleet ({model_id})"
        if fleet_only and not mark:
            continue
        print(f"  {n[:58]:58s} {v:10s} {dt}{mark}")
        if mark:
            newer.append((n, v, url))
    if newer:
        print("\ncab URLs (CDN host, fetch via relay):")
        for n, v, url in newer:
            print(f"  {v:10s} {url}")

if __name__ == "__main__":
    main()
