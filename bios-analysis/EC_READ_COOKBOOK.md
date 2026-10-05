# EC-READ COOKBOOK — how to get the one missing file for the new-suffix keygen

The offline keygen for the EC-era suffixes (8FC8/CF1B/9ABE/3FE2/1B58) needs
ONE artifact: a dump of an EC's INTERNAL flash from any machine of the
2020-21 8FC8 generation (OptiPlex 3080/3090/5080/7080 — one shared EC
firmware; Latitude 3410/5410; Inspiron/Vostro 5401/5501).

That dump contains, in PLAINTEXT:
  * the type-6 GENERATE engine (tag + family byte -> 32-byte master material)
  * the per-build key material
  * on a locked machine's own dump: the EC NVRAM record store, where
    record 0x15 IS the enrolled master password string

Feed any dump to: `python3 solution_kit/src/dell_ec_keygen.py --triage <file>`

## What the EC is (fleet)

| Model | EC | Evidence |
|---|---|---|
| Latitude 3410/3510 (some) | Microchip MEC1515H / Nuvoton NPCE285PA0DX | board photos, ELVIKOM/badcaps |
| OptiPlex 3090 (+5080/7080) | MEC15xx-class (Cortex-M) | EC-region vector table byte-identical to the 3410's; Cortex-M table (SP=0x20016F84) |
| Latitude 5410 | Nuvoton NPCE-class | LA-J371P era |

MEC152x family facts (public datasheet DS00003427F):
  * 32-bit ARM Cortex-M4, 480 KB internal code+data flash
  * boots from the shared SPI flash (the "EC region" we see in dumps is the
    staging area); the secure bootloader **decrypts the staged image with
    AES-256 + ECDSA, keys in lockable OTP** — this is why update packages
    are sealed and why ONLY an internal-flash read yields the engine
  * debug: **2-pin SWD** (CPU debug) + 4-wire JTAG (boundary scan)

## Route A — SWD (Cortex-M ECs: MEC15xx — the OptiPlex fleet + 3410)

1. Board schematic/boardview: find the EC's SWD/SWDIO/SWCLK test pads
   (3410: MOCKINGBIRD-L schematic held in-repo, JTAG1/KBC connector noted).
2. Probe: any J-Link clone / FT2232H / Raspberry-Pi GPIO running OpenOCD
   (~$0-20). J-Link officially supports MEC15xx (SEGGER device list).
3. OpenOCD:
     halt
     dump_image ec_internal.bin 0x0 0x78000     # 480 KB
4. Unknown until tried on hardware: whether Dell fuses off the debug port
   (secure boot can lock it). If SWD answers, the dump is complete.

## Route B — JTAG flash-controller method (MEC16xx/MEC50xx ARC ECs)

Complete public recipe (piernov, Aug 2023 — "Dell Factory Mode through
SMSC MECxxxx JTAG", snapshotted via Wayback; four0four gist + dossalab's
tool in-repo):
  * OpenOCD arc-2021.09 (+ piernov's build-fix fork), USB-Blaster/FT2232
  * JTAG IDs: MEC5075=0x200024b1, MEC5055=0x1000024b1
  * `dump_image mec_backup.bin 0x0 0x48000` (288 KB, ~5 min)
  * flash controller registers per the MEC1618 datasheet (public)
  * tool: collected/github_src/mec16xx-simple-flash/ (dossalab, Python)
  * Glasgow Interface Explorer applet `program/mec16xx` (same interface)
Tested by piernov on Dell boards (Compal LA-9832P MEC5075, Inventec Krug).

## Route C — RT809H programmer (repair shops; the "$20 patch seller" method)

RT809H changelog (official docs): supports SMSC MEC1609/1618/1619/1633/
1650/1653, MEC5035/5045/5055/5075/5085, NPCE288/388 (adapter board), and
MEC16xx online via flying leads. MEC16xx read range = first 192 KB (code,
plaintext) — the last 64 KB parameter area (serial + password) is stored
encrypted but is writable. NOTE: repair forums report MEC1515 (3410) as
"no public programming solution" — use Route A (SWD) there instead.

## Route D — buy it (zero-tech)

Ask any of these for "an EC-internal dump (EC程序), 192KB+, read from the
EC chip directly" of an OptiPlex 3080/3090/5080/7080 (or Latitude 3410/5410,
Inspiron 5401/5501):
  * the code seller: wa.me/923280493988 (~$10-30; ask for the dump file
    instead of a single code — one dump = unlimited codes for that build)
  * the BIOS ARCHIVE Telegram vault (t.me/MAHMOODJAVAN, 180GB paid archive,
    "BIOS/EC programmers" clientele)
  * any laptop repair shop with an RT809H + EC/LPC adapter or a JTAG/SWD
    probe (the procedure above is 15 minutes; shops do exactly this to
    make the $20 unlock patches)

## On landing a dump

    python3 solution_kit/src/dell_ec_keygen.py --triage  dump.bin
    # -> NVRAM records (id 0x15 = master) + engine markers
    python3 solution_kit/src/dell_ec_keygen.py --locate dump.bin
    # -> mailbox-literal functions (dispatcher/GENERATE wiring)
    python3 solution_kit/src/dell_ec_keygen.py --keygen dump.bin \
        --tag XXXXXXX --suffix CF1B [--handler 0xADDR]
    # -> master code for ANY service tag of that EC build

References in-repo: collected/github_src/mec16xx-simple-flash/ (dossalab
tool), relay-saved piernov article + Glasgow applet + SVOD MEC5075 paper +
MEC1618/MEC152x datasheets (collected/raw/ec_tools/).
