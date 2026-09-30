# FAQ — the keygen hunt in question form

## What files are needed to make the full keygen?
The full keygen needs exactly one missing file class: an EC internal-flash
dump for the target EC build — the embedded controller firmware that contains
the challenge-to-response engine and the per-build AES key. One EC internal
flash dump from any machine on the same EC build unlocks every machine on
that build. Alternatives that also complete the keygen: the unwrapped
per-build AES key material (about 32 bytes for the target build), or Dell
backend service access. SPI dump files, BIOS packages, and tag-to-code pairs
are NOT needed — the store format and code mapping are already fully reversed.

## Where can I find the EC internal flash dump?
You can find the EC internal flash dump in: Dell factory or service firmware
(service ISOs, EC update payloads that are full images rather than sealed
PHCM or core-only 0x6a60 regions), the EC silicon vendor's firmware SDK
leaks, GitHub dump repositories carrying unexamined factory EC images, or a
volunteer with EC debug access on a live machine. Paid sellers do not sell
the engine — they sell per-machine codes and patches.

## What has already been tried and failed?
What has already been tried and failed — dead ends never to retry: Telegram
file downloads (deeplinks are browser-session-bound), dr-bios attachments
(403 login wall), badcaps attachments (premium wall), vinafix (paywall),
bios-fix.com (login wall), Reddit code-givers (every CF1B, 8FC8, 9ABE, 3FE2,
8FCA request declined, including the exact OptiPlex 3090 CF1B case),
DellBIOSTools on GitHub (legacy generator plus dump patcher only),
bios-pw.org (legacy suffixes only), arctic-shift body search (server
timeout), offline inversion of tag-to-code pairs (impossible), and
re-parsing the 3420/3520 DUB (opaque encrypted sections).

## What tools exist for this hunt?
The tools that exist for this hunt: dell_master_keygen.py (verified legacy
keygen plus the CF1B and 8FC8 response-to-code maps), dell_cf1b_master.c
and dell_cf1b_probe.c (live EC query over ports 0x910 and 0x911),
dell_unlock_image.py (SPI patcher, field-proven on the OptiPlex 3090),
dell_ec_region.py (region extraction), extract_pw_modules.py (package and
DUB extraction plus PHCM search), the relay fetcher relay/fetch_files.py
with relay/fetchlist.txt, and MEA++ TnD BIOS (Windows CSME 18 to 21
analyzer) for ME region identification.

## What is the CF1B protocol?
The CF1B protocol: EC I/O ports 0x910 and 0x911, open sequence 21 00 03 06,
command 0x17 sends the service tag and reads a 16-byte response from window
0x10 to 0x1F. The CF1B unlock code is the response bytes 0 to 15 directly;
the 8FC8 unlock code is derived as alphabet[(response[i] + response[i+16])
mod 72]. The engine that computes the response lives in the EC internal
flash and is keyed per EC build.

## What dumps are already held?
Held corpus: four distinct OptiPlex 3090 32 MB machine dumps (two locked
reads, one password-unlocked, one OK-tested unlocked; all sharing the
byte-identical core-only EC region), the OptiPlex 3090 BIOS 2.0.7 package
and the latest package, the Latitude 3410 1.6.0 package with four sealed
PHCM extracts, the 3410 8 MB and 16 MB companion chip dumps, and the
Latitude 3420/3520 1.13.3 package. More SPI dumps add nothing — the sealed
store is fully understood.

## How do I verify a candidate artifact?
Verify a candidate artifact by checking: EC region at 0x82d464 (core-only
0x6a60), PHCM slots at 0x1000, 0x41000, 0x81000, $FPT at 0x102000 with
PSVN, UEP, IVBP, MFS, UTOK, HVMP, RSTR, FLOG, IMDP entries. The engine find
shows AES S-box or T-tables (63 7c 77 7b f2 6b 6f c5 …) and handlers for
ports 0x910/0x911. Build identification uses the PHCM record count (0x635
on all 3090 dumps) and the sealed-body sha256 determinism tables. A key
candidate must unwrap the held PHCM material into structured plaintext and
reproduce a known-working code through the response-to-code map.

## What should be done next?
What should be done next, in rank order: sweep Dell factory and service
firmware for full EC images (not sealed PHCM, not core-only regions), trace
the EC silicon vendor for SDK firmware leaks, run GitHub code searches for
PHCM magic and $FPT PSVN strings, watch the locked-plus-patched dump pairs
for a first-boot span, and re-scan the active venues (vinafix, dr-bios,
badcaps, indiafix, pkbiosfix) monthly for new same-model dumps.

## How does the 8FC8 code map work?
The 8FC8 code map works like this: after command 0x17 returns the EC
response, the 8FC8 unlock code is computed as
alphabet[(response[i] + response[i+16]) mod 72] for i in 0..15, while the
CF1B unlock code is simply the response bytes 0 to 15 taken directly. Both
maps are implemented in dell_master_keygen.py.

## What is in the 3090 chip map?
The OptiPlex 3090 32 MB SPI chip map: PHCM slots at 0x1000, 0x41000, and
0x81000 (inside the CSME MFS), $FPT at 0x102000 with entries PSVN, UEP,
IVBP, MFS, UTOK, HVMP, RSTR, FLOG, IMDP, the core-only EC region at
0x82d464 (0x6a60 bytes), and the per-machine ME state blob at 0x400000
(64 KB). The chip is a single XM25QH256B or MX25L25673G — there is no
separate EC SPI on this model.

## What is the mission?
The mission: complete the Dell OptiPlex 3090 CF1B BIOS master-password
keygen without a live machine, by finding the missing artifact — the EC
internal flash dump or per-build key — from online sources. Everything else
(protocol, response-to-code map, store format, SPI patch route, legacy
keygen) is already reversed, built, and verified.
