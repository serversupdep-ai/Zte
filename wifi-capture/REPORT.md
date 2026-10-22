# Capture report — `HS_inwi_Home_4G_6A6EDE10_20_31.cap`

Analyzed 2026-10-22 with `cap_analyze.py` / `wpa_crack.py` (pure stdlib).
Source file: `serversupdep-ai/Bin-file` @ `main`, 1,167,948 bytes,
SHA-256 `72cc6be55e7db3b1b967af6f57e97aba420059e9fcfd101e2d82b0fc7c09ac87`.

---

## 1. File facts

| Property | Value |
|---|---|
| Container | libpcap, v2.4, snaplen 65535, **linktype 105** (raw IEEE 802.11) |
| Records | 18,247 (one trailing record is truncated, 1 byte short of a full record header) |
| Window | 2026-10-12 20:29:21.765 Z → 20:31:11.892 Z (110.1 s) |
| Payload captured | 876 KB across 18,247 frames; max frame 1,330 B |
| Entropy | 7.01 bit/byte (802.11 headers + counters, not compressed data) |

The file is a raw monitor-mode capture — no radiotap header, so **no per-frame signal
strength, no channel metadata beyond the DS Parameter IE, and no FCS**. Timestamps are
microsecond-resolution and monotonic throughout.

Frame mix:

```
cts        8029      ← block-ack / aggregation burst padding
ba         3032      ← block acks (11n A-MPDU traffic)
ack        2324
deauth     1813      ← see §5
cf-end     1444
bar         938
qos-data    493
probe-resp   94
auth/assoc    8
beacon        1
```

## 2. Network identity

| | |
|---|---|
| SSID | `inwi Home 4G 6A6EDE` |
| BSSID | `54:1f:8d:6a:6e:de` |
| Channel | 11 (2.437 GHz) |
| Country IE | `MA` (Morocco), first channel 1, max power 30 dBm |
| Rates | 1–54 Mb/s legacy + HT (802.11n, 20 MHz, 1 SS) |
| Beacons / probe responses | 1 / 94 (the capture starts mid-session) |

`54:1f:8d` is a globally-administered OUI; the **WPS device descriptor identifies the radio
stack**, not a Dell/ZTE stack:

```
Manufacturer : Realtek Semiconductor Corp.
Model Name   : RTL8xxx
Model Number : EV-2010-09-20      ← Realtek reference/default firmware strings
Device Name  : RTK_AP
Serial       : 123456789012347    ← placeholder, never provisioned
UUID-E       : 63041253101920061228541f8d6a6ede
```

So this is an ISP-branded 4G CPE built on a Realtek RTL8xxx reference design running the
default Realtek WPS/AP firmware identity. The SSID suffix `6A6EDE` is the last three octets
of the BSSID, i.e. the unit is labelled by MAC tail, not by a serial.

## 3. Security configuration

RSN IE: `01 00 00 0f ac 04 01 00 00 0f ac 04 01 00 00 0f ac 02 00 00`

| Field | Value | Meaning |
|---|---|---|
| Group cipher | CCMP | AES-CCMP only, no TKIP fallback |
| Pairwise | CCMP | |
| AKM | PSK (00-0f-ac:02) | WPA2-Personal, no 802.1X |
| RSN capabilities | `0x0000` | **MFPC = 0, MFPR = 0** |

Consequences:

* **No PMF (802.11w)** → management frames are unprotected; deauthentication/disassociation
  injection works and forces reconnection (§5). This is the enabler for the handshake that was
  captured.
* No WPA3/SAE transition mode, no OWE. Pure WPA2-PSK.
* No TKIP → the captured handshake is a clean AES-CCMP handshake, key descriptor version 2.

**WPS is enabled** (`00-50-f2:04` vendor IE, version 1.0, `WPS State = 0x02` = *configured*):

| Attribute | Value |
|---|---|
| Version | 1.0 (`0x10`) |
| WPS State | `0x02` configured |
| AP Setup Locked | **absent → not locked** |
| Config Methods | `0x2008` (Display / Virtual Display — no physical push button) |
| Response Type | `0x03` (AP) |

An unlocked, PIN-capable WPS implementation on a Realtek RTL8xxx stack is the single most
practical weakness of this network (§7).

## 4. Stations

Two client MACs appear, both **locally administered (randomised)** — typical of modern
Android/iOS MAC randomisation:

| MAC | Role | First seen |
|---|---|---|
| `e6:5d:da:66:07:3d` | associate at 20:30:22.307, re-associate 20:30:23.237 | 20:30:22 |
| `92:5d:ce:2b:e2:27` | associate at 20:31:11.796 (0.8 s after the last deauth) | 20:31:11 |

The first station's 4-way handshake is **not** in the capture: only M4s survive
(`00…00` nonce, MIC set), M1/M2 were missed. The second station delivers a complete
handshake.

## 5. The deauth storm (attack fingerprint)

1,813 deauthentication frames in a 51.2 s window (20:30:19.97 → 20:31:11.14):

| Source → Destination | Count |
|---|---|
| `54:1f:8d:6a:6e:de` → `54:1f:8d:6a:6e:de` (spoofed, src = BSSID) | 913 |
| `e6:5d:da:66:07:3d` → `54:1f:8d:6a:6e:de` | 484 |
| `92:5d:ce:2b:e2:27` → `54:1f:8d:6a:6e:de` | 416 |

Reason codes: `7` (class-3 frame from non-associated station) × 1,804, `6` × 8, `1` × 1.

An AP does not spontaneously emit 913 deauths addressed *to its own BSSID*; the signature
(spoofed source, reason 7 flood, ending with a client re-association 0.8 s later) is the
standard "deauthenticate → force reconnect → grab the 4-way handshake" capture technique.
Practical reading: **this network was actively attacked (or a capture rig was doing the
attacking) while the file was recorded**. It also demonstrates live that the missing PMF
protection is exploitable.

## 6. Captured key material

EAPOL-Key frames: 6 total, one complete 4-way handshake:

```
AP  54:1f:8d:6a:6e:de
STA 92:5d:ce:2b:e2:27

M1  20:31:11.823  replay=1  ANonce = 243701e748c138ad4d3fc50bdabefbd68
                                       7b69a463e0fd930fbc6f8ebb89360be
M2  20:31:11.845  replay=1  SNonce = 02bdf5092bd8af61427af61527aa9eaa
                                       7aab2aa1aa85abd750a07af8ebe3a0e7
                            MIC    = 78c9befeb5f54ad9a3355f1e0a3c860b
M3  20:31:11.871  replay=2  MIC    = 613be303a9c75b5a2c60341099b4a145
                            key data 56 B (encrypted GTK)
M4  20:31:11.874  replay=2  MIC    = d4d7f359f5ecdf8486b41464fc7253db
```

* Key descriptor version **2** (HMAC-SHA1-128 with AES-CCMP) — the MIC is
  `HMAC-SHA1(KCK, EAPOL)[:16]`, KCK = PTK[0:16].
* **No PMKID.** M1 carries key-data length 0, so there is no `WPA*01*` hash — PMKID cracking
  is not possible from this file (a PMKID would have to be solicited with `hcxdumptool`
  against an associating client).
* Plaintext traffic above 802.11: **none**. Of 553 data frames, 487 are protected; the 66
  unprotected ones are 60 null/QoS-null keep-alives plus the 6 EAPOL-Key frames. The only
  cleartext ethertype is `0x888e` (EAPOL itself). There is no HTTP/DNS/DHCP leakage.

Hashcat-ready (`out/hs_22000.txt`, mode 22000):

```
WPA*02*78c9befeb5f54ad9a3355f1e0a3c860b*541f8d6a6ede*925dce2be227*\
696e776920486f6d6520344720364136454445*243701e7…360be*02bdf509…3a0e7*0103007502…*00
```

## 7. PSK recovery status

The passphrase was **not recovered**. 186,048 candidates were tested in-process
(~450 PMK/s/core → 6 min 47 s), covering:

* every SSID token (`inwi`, `Home 4G`, `6A6EDE`, `6a6ede10`, `RTK_AP`, `realtek`, `maroc`, …)
  × 43 suffix patterns (`1234`, `2024`…`2026`, `@123`, `!`, …) × 5 case/spacing variants;
* the ISP/brand family (`inwi2024…2026`, `inwi@1234`, `inwi4G…`, `Home4G…`);
* MAC-tail and SSID-tail hex/digit forms, plus a ±2,000 numeric sweep around each 8-digit tail;
* a curated common-password seed list with light mangling.

Conclusion: the PSK is **not** derived from the SSID, the BSSID, the model string or the ISP
name — consistent with an ISP-provisioned random key. For this device class the key is a
label-printed 8–12 character random string; the effective search space (~62⁸ and up) is out
of reach of wordlists.

Realistic routes, cheapest first:

1. **Read the label.** `inwi Home 4G` CPEs ship with the Wi-Fi key (and WPS PIN) printed on
   the bottom sticker; the web UI is normally `192.168.1.1` with the same label credentials.
2. **GPU wordlist.** The 22000 file is ready: `hashcat -m 22000 -a 0 out/hs_22000.txt
   rockyou.txt -r rules/best64.rule` (~14 M × 64 rules at 1–2 MH/s on one modern GPU ≈
   10–20 min). Worth one run; low prior given the finding above.
3. **WPS PIN / Pixie-Dust.** Best fit for this device: WPS 1.0 enabled, not locked, Realtek
   RTL8xxx reference stack (a well-known Pixie-Dust target because of its weak nonce/E-S1/E-S2
   generation). Requires an active radio next to the AP — `reaver`/`pixiewps`, or
   `hcxdumptool` + `hcxtools` if only a PMKID capture is wanted.
4. **Reset the CPE** if physical access exists — restores the label key (and re-provisions the
   ISP settings, so check with the ISP first).

If the goal is instead *hardening* the network (the more useful outcome of this capture):
turn WPS off, and enable WPA2/WPA3 with PMF (802.11w) "required" — that alone defeats the
deauth + handshake technique demonstrated in §5.

## 8. Reproducing

```bash
cd wifi-capture
python3 wpa_crack.py --selftest                                   # toolchain proof
python3 cap_analyze.py HS_inwi_Home_4G_6A6EDE10_20_31.cap --hashcat
python3 gen_candidates.py --ssid "inwi Home 4G 6A6EDE" --bssid 54:1f:8d:6a:6e:de
python3 wpa_crack.py out/handshake.json --wordlist wordlists/candidates.txt --rules
```

The analyzer is a from-scratch libpcap + 802.11 + EAPOL dissector; `wpa_crack.py` implements
PBKDF2-4096, the 802.11i PRF-512, KCK derivation and the EAPOL-Key MIC check. Both are
validated against three independent published vectors (`--selftest`), including a full crack
of aircrack-ng's `testm1m2m3.pcap` → `12345678`.

> Scope note: this analysis is passive and offline. Attacking a network you do not own or
> administer is illegal in most jurisdictions — including Morocco (loi 07-03 / 24-96).
