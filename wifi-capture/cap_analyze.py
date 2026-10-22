#!/usr/bin/env python3
"""cap_analyze.py — offline parser for 802.11 monitor-mode captures (.cap/.pcap).

Pure stdlib: no scapy, no tshark, no aircrack-ng required. Uses only the
structure of libpcap + IEEE 802.11 to answer the questions that actually
matter for a WPA2-PSK capture:

  * what network is this, on what channel, with what security?
  * is it WPA2-PSK / CCMP, is PMF (802.11w) required?
  * is WPS enabled on the AP? (and which WPS stack is it)
  * did we capture a usable 4-way handshake, and for which station?
  * handshake -> hashcat mode 22000 line (WPA*02*...)
  * handshake -> hashcat mode 22001 (PMK) line, when a PMKID is present

Usage:
    python3 cap_analyze.py CAP [--outdir out] [--json] [--hashcat]

Outputs (with --hashcat):
    out/handshake.json    machine-readable handshake(s)
    out/hs_22000.txt      hashcat -m 22000 input
    out/hs_22001.txt      hashcat -m 22001 input (only if PMKID found)

Exit codes: 0 ok; 2 no usable handshake found; 1 parse error.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import json
import os
import struct
import sys

# ---------------------------------------------------------------------------
# libpcap
# ---------------------------------------------------------------------------

PCAP_MAGICS = {
    0xA1B2C3D4: ("<", "us"),   # big-endian file written on LE? handled below
    0xD4C3B2A1: ("<", "us"),
    0xA1B23C4D: ("<", "ns"),
    0x4D3CB2A1: ("<", "ns"),
}

LINKTYPE_IEEE802_11 = 105
LINKTYPE_IEEE802_11_RADIOTAP = 127


def read_pcap(path: str):
    """Yield (ts_float, bytes) for every record. Handles both endiannesses."""
    raw = open(path, "rb").read()
    if len(raw) < 24:
        raise ValueError("file shorter than a pcap header")
    magic = struct.unpack("<I", raw[:4])[0]
    if magic in (0xD4C3B2A1, 0xA1B2C3D4) or magic in (0x4D3CB2A1, 0xA1B23C4D):
        pass
    # Detect by trying little-endian first: the common case on x86 capture rigs.
    endian = "<"
    vmaj, vmin, _tz, _sig, snap, link = struct.unpack(endian + "HHiIII", raw[4:24])
    if not (1 <= vmaj <= 5) or link > 300 or snap == 0:
        endian = ">"
        vmaj, vmin, _tz, _sig, snap, link = struct.unpack(endian + "HHiIII", raw[4:24])
    if link not in (LINKTYPE_IEEE802_11, LINKTYPE_IEEE802_11_RADIOTAP):
        raise ValueError(f"unsupported linktype {link} (need 105 or 127)")

    recs = []
    off = 24
    n = len(raw)
    while off + 16 <= n:
        ts, tu, incl, _orig = struct.unpack(endian + "IIII", raw[off:off + 16])
        off += 16
        if incl > n - off:          # truncated last record
            break
        body = raw[off:off + incl]
        off += incl
        if link == LINKTYPE_IEEE802_11_RADIOTAP:
            body = strip_radiotap(body)
        recs.append((ts + tu / 1_000_000.0, body))
    return recs, (vmaj, vmin, snap, link)


def strip_radiotap(b: bytes) -> bytes:
    if len(b) < 4:
        return b""
    hlen = struct.unpack("<H", b[2:4])[0]
    return b[hlen:]


# ---------------------------------------------------------------------------
# 802.11 dissection
# ---------------------------------------------------------------------------

MAC = lambda b: ":".join("%02x" % x for x in b) if len(b) == 6 else "?"
T_MGMT, T_CTRL, T_DATA, T_EXT = 0, 1, 2, 3

MGMT = {0: "assoc-req", 1: "assoc-resp", 2: "reassoc-req", 3: "reassoc-resp",
        4: "probe-req", 5: "probe-resp", 8: "beacon", 9: "atim",
        10: "disassoc", 11: "auth", 12: "deauth", 13: "action", 14: "action-noack"}
CTRL = {4: "ps-poll", 7: "cfa", 8: "bar", 9: "ba", 10: "ps-poll", 11: "rts",
        12: "cts", 13: "ack", 14: "cf-end", 15: "cf-end-ack"}
DATA = {0: "data", 1: "data-cfack", 2: "data-cfpoll", 4: "null", 8: "qos-data",
        9: "qos-null", 12: "qos-cfackpoll", 14: "qos-null2"}

IE = {0: "SSID", 1: "SupportedRates", 3: "DS-Parameter", 5: "TIM", 7: "Country",
      45: "HT-Capabilities", 48: "RSN", 50: "ExtRates", 61: "HT-Information",
      74: "RM-Enabled", 127: "ExtCapabilities", 191: "VHT-Capabilities",
      221: "Vendor"}

WPS_ATTR = {0x104A: "Version", 0x1044: "WPS State", 0x1045: "AP Setup Locked",
            0x1008: "Config Methods", 0x1021: "Manufacturer", 0x1023: "Model Name",
            0x1024: "Model Number", 0x1042: "Serial Number", 0x1054: "Primary Device Type",
            0x103B: "Response Type", 0x1047: "UUID-E", 0x1011: "Device Name"}

AKM = {1: "802.1X", 2: "PSK", 3: "FT-802.1X", 4: "FT-PSK", 5: "802.1X-SHA256",
       6: "PSK-SHA256", 8: "SAE", 9: "FT-SAE", 18: "OWE"}
CIPHER = {1: "WEP-40", 2: "TKIP", 4: "CCMP", 5: "WEP-104", 8: "GCMP", 9: "GCMP-256"}


def frame_class(b: bytes):
    if len(b) < 2:
        return None, None, None
    fc = struct.unpack("<H", b[:2])[0]
    typ = (fc >> 2) & 3
    sub = (fc >> 4) & 0xF
    flags = fc >> 8
    name = {T_MGMT: MGMT, T_CTRL: CTRL, T_DATA: DATA}.get(typ, {}).get(sub, str(sub))
    return typ, sub, (name, flags)


def addrs(b: bytes, typ: int, sub: int):
    """Return (a1, a2, a3) as byte strings."""
    if len(b) < 22:
        return b"", b"", b""
    tods, fromds = (struct.unpack("<H", b[:2])[0] >> 8) & 1, (struct.unpack("<H", b[:2])[0] >> 9) & 1
    if typ == T_DATA and tods and fromds:      # WDS
        return b[4:10], b[10:16], b[16:22]
    return b[4:10], b[10:16], b[16:22]


def parse_ies(p: bytes):
    out = []
    i = 0
    while i + 2 <= len(p):
        eid, ln = p[i], p[i + 1]
        if i + 2 + ln > len(p):
            break
        out.append((eid, p[i + 2:i + 2 + ln]))
        i += 2 + ln
    return out


def parse_rsn(v: bytes):
    """Minimal RSN/WPA2 IE decoder."""
    info = {"group": None, "pairwise": [], "akm": [], "mfpc": None, "mfpr": None,
            "pmkid": [], "version": None}
    if len(v) < 2:
        return info
    info["version"] = struct.unpack("<H", v[:2])[0]
    i = 2
    if i + 4 <= len(v):
        info["group"] = CIPHER.get(v[i + 3], "oui:%s" % v[i:i + 4].hex())
        i += 4
    if i + 2 <= len(v):
        n = struct.unpack("<H", v[i:i + 2])[0]
        i += 2
        for _ in range(n):
            if i + 4 > len(v):
                break
            info["pairwise"].append(CIPHER.get(v[i + 3], v[i:i + 4].hex()))
            i += 4
    if i + 2 <= len(v):
        n = struct.unpack("<H", v[i:i + 2])[0]
        i += 2
        for _ in range(n):
            if i + 4 > len(v):
                break
            info["akm"].append(AKM.get(v[i + 3], v[i:i + 4].hex()))
            i += 4
    if i + 2 <= len(v):
        caps = struct.unpack("<H", v[i:i + 2])[0]
        info["mfpc"] = bool(caps & 0x80)
        info["mfpr"] = bool(caps & 0x40)
        i += 2
    while i + 4 <= len(v):                     # PMKID count + list
        cnt = struct.unpack("<H", v[i:i + 2])[0]
        i += 2
        for _ in range(cnt):
            info["pmkid"].append(v[i:i + 16].hex())
            i += 16
        break
    return info


def parse_wps(v: bytes):
    if len(v) < 4:
        return None
    out = {}
    i = 0
    while i + 4 <= len(v):
        aid, aln = struct.unpack("!HH", v[i:i + 4])
        val = v[i + 4:i + 4 + aln]
        name = WPS_ATTR.get(aid, "0x%04x" % aid)
        try:
            s = val.decode("ascii")
            out[name] = s if all(32 <= ord(c) < 127 for c in s) else val.hex()
        except Exception:
            out[name] = val.hex()
        i += 4 + aln
    return out


# ---------------------------------------------------------------------------
# EAPOL / 4-way handshake
# ---------------------------------------------------------------------------

def eapol_of(b: bytes, typ: int, sub: int, bssids=()):
    """Return (eapol_frame, ap_mac, sta_mac) if this data frame carries EAPOL.

    Address roles are resolved against the known BSSID set when available,
    because several cheap 4G CPEs (this Realtek-based Inwi unit included)
    emit EAPOL with both ToDS and FromDS cleared, which makes the textbook
    addr1/addr2/addr3 rules lie about who is the AP.
    """
    if typ != T_DATA or len(b) < 26:
        return None
    hdr = 24 + (2 if (sub & 8) else 0)          # QoS control
    if hdr >= len(b):
        return None
    llc = b[hdr:hdr + 8]
    if len(llc) < 8 or llc[:6] != b"\xaa\xaa\x03\x00\x00\x00":
        return None
    et = struct.unpack("!H", llc[6:8])[0]
    if et != 0x888E:
        return None
    eap = b[hdr + 8:]
    if len(eap) < 4:
        return None
    fc = struct.unpack("<H", b[:2])[0]
    tods, fromds = (fc >> 8) & 1, (fc >> 9) & 1
    a1, a2, a3 = b[4:10], b[10:16], b[16:22]
    if tods and not fromds:      # STA -> AP : addr1=BSSID(AP), addr2=STA
        ap, sta = a1, a2
    elif fromds and not tods:    # AP -> STA : addr1=STA, addr2=BSSID(AP)
        ap, sta = a2, a1
    elif bssids:
        if MAC(a2) in bssids:
            ap, sta = a2, a1
        elif MAC(a1) in bssids:
            ap, sta = a1, a3
        elif MAC(a3) in bssids:
            ap, sta = a3, (a2 if MAC(a1) == MAC(a3) else a1)
        else:
            ap, sta = a3, a2
    else:
        ap, sta = a3, a2
    return eap, ap, sta


def eapol_parse(eap: bytes):
    if len(eap) < 99:
        return None
    ver, etype, elen = struct.unpack("!BBH", eap[:4])
    if etype != 3:                              # EAPOL-Key
        return None
    ki = struct.unpack("!H", eap[5:7])[0]
    keylen = struct.unpack("!H", eap[7:9])[0]
    replay = struct.unpack("!Q", eap[9:17])[0]
    nonce = eap[17:49]
    mic = eap[81:97]
    kdlen = struct.unpack("!H", eap[97:99])[0]
    kde = eap[99:99 + kdlen]
    ack, micb, inst, sec = bool(ki & 0x80), bool(ki & 0x100), bool(ki & 0x40), bool(ki & 0x200)
    enc = bool(ki & 0x1000)
    if ack and not micb:
        msg = 1
    elif micb and not ack and not sec:
        msg = 2
    elif ack and micb and inst:
        msg = 3
    elif micb and not ack and sec:
        msg = 4
    else:
        msg = 0
    pmkid = None
    if msg == 1:
        i = 0
        while i + 4 <= len(kde):
            typ, ln = kde[i], kde[i + 1]
            if typ == 0xDD and ln >= 20 and kde[i + 2:i + 5] == b"\x00\x0f\xac\x04":
                pmkid = kde[i + 6:i + 22].hex()
                break
            i += 2 + ln
    return {"msg": msg, "keyinfo": ki, "replay": replay, "keylen": keylen,
            "nonce": nonce.hex(), "mic": mic.hex(), "eapol": eap.hex(),
            "pmkid": pmkid, "ver": ver, "encrypted_kde": enc}


def find_handshakes(recs, bssids=()):
    """Collect M1/M2/M3/M4 per (AP,STA) and emit usable handshake dicts."""
    per = collections.defaultdict(dict)
    for ts, b in recs:
        typ, sub, _ = frame_class(b)
        got = eapol_of(b, typ, sub, bssids)
        if not got:
            continue
        eap, ap, sta = got
        k = eapol_parse(eap)
        if not k:
            continue
        key = (MAC(ap), MAC(sta))
        per[key].setdefault(k["msg"], []).append((ts, k))

    hss = []
    for (ap, sta), msgs in per.items():
        if 2 not in msgs:
            continue
        # A capture can contain a stale M1 from an older session (the ANonce in
        # M3 is authoritative for the session whose M2 we hold). Emit one
        # candidate per distinct ANonce: M1 first, then M3.
        anonces = []
        for src in (1, 3):
            for t, m in msgs.get(src, []):
                if m["nonce"] != "00" * 32 and m["nonce"] not in [a[0] for a in anonces]:
                    anonces.append((m["nonce"], src, t, m["replay"]))
        for anonce, src, t1, replay1 in anonces:
            # M2 echoes the ANonce frame's replay counter (M1) or is exactly one
            # behind it (M3), so pair on the counter, not on wall-clock order:
            # a stale M1 can precede the M2 while the real ANonce is in M3.
            cand = [(t2, m2) for t2, m2 in msgs[2] if m2["replay"] <= replay1]
            if not cand:
                continue
            t2, m2 = max(cand, key=lambda x: x[0])
            if not m2["mic"].strip("0"):
                continue
            m3 = next(((t, m) for t, m in msgs.get(3, []) if t >= t2), None)
            m4 = next(((t, m) for t, m in msgs.get(4, []) if t >= t2), None)
            hss.append({
                "ap": ap, "sta": sta, "m1_ts": t1, "m2_ts": t2,
                "anonce": anonce, "anonce_source": "M%d" % src,
                "snonce": m2["nonce"],
                "mic": m2["mic"], "eapol": m2["eapol"],
                "replay_m1": replay1, "replay_m2": m2["replay"],
                "pmkid": next((m["pmkid"] for _, m in msgs.get(1, []) if m["pmkid"]), None),
                "m3_mic": m3[1]["mic"] if m3 else None,
                "m4_mic": m4[1]["mic"] if m4 else None,
                "complete_4way": bool(m3 and m4),
                "keyver": m2["keyinfo"] & 7,
            })
    return hss


def hashcat_22000(hs, ssid_hex):
    # trailing field = hcxtools message pair: 00 = M1+M2, 02 = M3(ANonce)+M2
    mp = "02" if hs.get("anonce_source") == "M3" else "00"
    return "WPA*02*%s*%s*%s*%s*%s*%s*%s*" % (
        hs["mic"], hs["ap"].replace(":", ""), hs["sta"].replace(":", ""),
        ssid_hex, hs["anonce"], hs["snonce"], hs["eapol"]) + mp


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def analyze(path: str, outdir: str, do_hashcat: bool):
    recs, hdr = read_pcap(path)
    if not recs:
        print("no packets", file=sys.stderr)
        return 1

    classes = collections.Counter()
    ssids = collections.Counter()
    bssids = collections.Counter()
    stations = collections.Counter()
    deauth = collections.Counter()
    deauth_reasons = collections.Counter()
    assoc = []
    eapol_n = 0
    clear_llc = collections.Counter()
    beacon_info = {}
    first, last = recs[0][0], recs[-1][0]

    for ts, b in recs:
        typ, sub, fc = frame_class(b)
        if typ is None:
            classes["tiny"] += 1
            continue
        classes[fc[0]] += 1
        if typ == T_MGMT and sub in (8, 5, 4) and len(b) >= 36:
            ies = dict(parse_ies(b[36:] if sub != 4 else b[24:]))
            bssid = MAC(b[16:22])
            bssids[bssid] += 1
            if 0 in ies:
                ssids[ies[0].decode("utf-8", "replace")] += 1
            if sub in (8, 5) and bssid not in beacon_info:
                rsn = parse_rsn(ies[48]) if 48 in ies else None
                wps = None
                for eid, v in parse_ies(b[36:]):
                    if eid == 221 and v[:3] == b"\x00\x50\xf2" and len(v) > 4 and v[3] == 0x04:
                        wps = parse_wps(v[4:])
                        break
                beacon_info[bssid] = {
                    "ssid": ies.get(0, b"").decode("utf-8", "replace"),
                    "channel": ies[3][0] if 3 in ies and ies[3] else None,
                    "country": ies[7][:2].decode("ascii", "replace") if 7 in ies and len(ies[7]) >= 2 else None,
                    "rsn": rsn, "wps": wps,
                    "privacy": bool(struct.unpack("<H", b[34:36])[0] & 0x10),
                }
        elif typ == T_MGMT and sub in (11, 0, 1) and len(b) >= 22:
            stations[MAC(b[10:16])] += 1
            if sub in (0, 1):
                assoc.append((ts, MGMT[sub], MAC(b[10:16]), MAC(b[16:22])))
        elif typ == T_MGMT and sub == 12 and len(b) >= 26:
            deauth[(MAC(b[10:16]), MAC(b[16:22]))] += 1
            deauth_reasons[struct.unpack("<H", b[24:26])[0]] += 1
        elif typ == T_DATA:
            got = eapol_of(b, typ, sub)
            if got:
                eapol_n += 1
            else:
                hdr_len = 24 + (2 if (sub & 8) else 0)
                pl = b[hdr_len:hdr_len + 8]
                if len(pl) == 8 and pl[:6] == b"\xaa\xaa\x03\x00\x00\x00":
                    clear_llc["0x%04x" % struct.unpack("!H", pl[6:8])[0]] += 1

    hss = find_handshakes(recs, set(bssids))
    primary = max(hss, key=lambda h: h["complete_4way"]) if hss else None

    def ts(x):
        return dt.datetime.utcfromtimestamp(x).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"

    print("=" * 74)
    print("CAPTURE  %s" % os.path.basename(path))
    print("=" * 74)
    print("linktype      : %d (IEEE802.11%s)   pcap v%d.%d  snaplen %d"
          % (hdr[3], " radiotap" if hdr[3] == 127 else "", hdr[0], hdr[1], hdr[2]))
    print("packets       : %d" % len(recs))
    print("window        : %s  ->  %s  (%.1f s)" % (ts(first), ts(last), last - first))
    print("frame mix     : " + "  ".join("%s=%d" % kv for kv in classes.most_common(8)))

    print("\n--- NETWORK ---")
    for bssid, info in beacon_info.items():
        print("BSSID         : %s" % bssid)
        print("SSID          : %s" % info["ssid"])
        print("channel       : %s   country: %s" % (info["channel"], info["country"]))
        print("beacons/probes: %d" % bssids[bssid])
        r = info["rsn"]
        if r:
            sec = "WPA2" if "PSK" in r["akm"] else ",".join(r["akm"])
            print("security      : %s  group=%s pairwise=%s akm=%s"
                  % (sec, r["group"], "/".join(r["pairwise"]), "+".join(r["akm"])))
            print("PMF (802.11w) : MFPC=%s MFPR=%s  -> deauth protection %s"
                  % (r["mfpc"], r["mfpr"], "ON" if r["mfpr"] else "OFF (deauth-able)"))
        w = info["wps"]
        print("WPS           : %s" % ("ENABLED  " + json.dumps(w) if w else "not advertised"))
        print()

    print("--- CLIENTS ---")
    for m, c in stations.most_common(10):
        print("  %s  mgmt frames=%d%s" % (m, c, "  (locally-administered/random)" if int(m[:2], 16) & 2 else ""))
    for t, kind, src, dst in assoc[:8]:
        print("  %s  %-12s %s -> %s" % (ts(t), kind, src, dst))

    print("\n--- DEAUTH / DISASSOC ---")
    for (s, d), c in deauth.most_common(6):
        print("  deauth %s -> %s   x%d" % (s, d, c))
    print("  reason codes: " + ", ".join(
        "%d(%s)=%d" % (r, {1: "unspecified", 6: "class2-nonauth", 7: "class3-nonassoc"}.get(r, "?"), c)
        for r, c in deauth_reasons.most_common()))

    print("\n--- EAPOL / HANDSHAKE ---")
    print("  EAPOL frames captured: %d" % eapol_n)
    print("  plaintext LLC above 802.11: %s" % (dict(clear_llc) or "none"))
    if not hss:
        print("  NO COMPLETE M1+M2 PAIR FOUND")
        return 2
    for i, h in enumerate(hss, 1):
        print("  [%d] AP %s  STA %s" % (i, h["ap"], h["sta"]))
        print("      ANonce(%s) %s  replay=%d  %s"
              % (h["anonce_source"], ts(h["m1_ts"]), h["replay_m1"], h["anonce"]))
        print("      M2 %s  replay=%d  SNonce=%s" % (ts(h["m2_ts"]), h["replay_m2"], h["snonce"]))
        print("      MIC=%s  keyver=%d  M3=%s M4=%s"
              % (h["mic"], h["keyver"], "yes" if h["m3_mic"] else "no",
                 "yes" if h["m4_mic"] else "no"))
        print("      PMKID=%s" % (h["pmkid"] or "none"))

    if do_hashcat:
        os.makedirs(outdir, exist_ok=True)
        ssid = beacon_info.get(primary["ap"], {}).get("ssid", "")
        ssid_hex = ssid.encode().hex()
        with open(os.path.join(outdir, "handshake.json"), "w") as f:
            json.dump({"ssid": ssid, "ssid_hex": ssid_hex,
                       "network": beacon_info.get(primary["ap"], {}),
                       "handshakes": hss}, f, indent=2)
        lines = [hashcat_22000(h, ssid_hex) for h in hss]
        with open(os.path.join(outdir, "hs_22000.txt"), "w") as f:
            f.write("\n".join(lines) + "\n")
        print("\n  wrote %s/handshake.json  (%d handshake(s))" % (outdir, len(hss)))
        print("  wrote %s/hs_22000.txt" % outdir)
        print("  hashcat command:  hashcat -m 22000 -a 0 %s/hs_22000.txt <wordlist> "
              "-r rules/best64.rule" % outdir)
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cap")
    ap.add_argument("--outdir", default="out")
    ap.add_argument("--hashcat", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    return analyze(a.cap, a.outdir, a.hashcat)


if __name__ == "__main__":
    sys.exit(main())
