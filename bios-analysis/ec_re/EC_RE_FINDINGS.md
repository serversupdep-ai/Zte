# EC firmware reverse-engineering — cycle 16 findings (2026-10-05)

Never-used sources this cycle: **morluto/REA** (user-directed; PE/artifact
lanes used, Ghidra lane CDN-blocked — see REA_USAGE.md), **capstone + unicorn
via PyPI** (new toolchain), and the **first-ever disassembly of Dell's
plaintext EC firmware** (Latitude 5X90 1.41.0 PHCM bodies, in-repo since
cycle ~6 but never readable before — no disassembler existed in the sandbox).

New tool: **`dell_ec_engine_re.py`** (this directory) — PHCM parser, mailbox
xref, dispatcher extractor, family-table scanner, annotated Thumb disassembler,
and a unicorn emulation harness with the decoded segment map. Emulation-verified
end-to-end (below).

## 1. PHCM container format (decoded)

```
dword[0]      'PHCM'
dword[1]      version/flags — byte at offset 6, bit 7 (0x80) = body AES-SEALED
              5X90 ec_1: 0x03000100 -> PLAINTEXT
              2019+ (3090/3410/3420/5X10/5X00/3240/...): 0x038x0101 -> sealed
dword[4]      'bt' boot entry (image-relative, Thumb, bit0 set)
dword[5]      header size (0x80)
```

5X90 ec_1 layout (166784 B — confirmed by content match, see §4):

| file range        | loads at   | contents |
|-------------------|------------|----------|
| `[0x00000:0x00080)` | —        | main PHCM header |
| `[0x00080:0x20000)` | `0x00110000` | CODE (ARM Cortex-M4F Thumb-2) |
| `[0x20000:0x20080)` | —        | 2nd segment header |
| `[0x20080:0x28B80)` | `0x000F0000` | DATA (tables, strings, alphabets) |

Runtime↔file: `CODE: file = rt - 0x00110000 + 0x80`;
`DATA: file = rt - 0x000F0000 + 0x20080`.
Verification: the 72-char table literal `0x000F17A9` (xrefs at file
0xD09C/0xD1D0/0xD64C) == file `0x21829` EXACTLY, and the DATA segment
contains the battery/eSPI tables + strings (`Dell`, `08 Cell`,
`ESpiRead Flash busy!…`) that the 0x53A8-cluster parsers expect.

**Fleet-wide verdict (45 PHCM candidates scanned):** ONLY the 5X90 pair
(ec_1/ec_2, E7A8-era 2018) is plaintext. Every 2019+ EC update payload
(5X00, 5X10, 3080, 3090, 3090UFF, 3410, 3420, 3240, 3280, 5000, 5070-5090,
5480-5490, 7000/XE4, 3580/3581, 5440/3480 …) is AES-sealed (entropy 8.00,
zero mailbox literals). Dell sealed EC bodies from the 5X00 generation on.

## 2. EC host window protocol (MEC mailbox) — decoded + emulated

| address      | role |
|--------------|------|
| `0x400F0110` | command byte (dispatchers at file 0xD868 / 0x914 / 0xE9C8) |
| `0x400F0111` | sub-command / status byte |
| `0x400F0112` | chunk-ready flag |
| `0x400F0113` | chunk length (≤ 8) |
| `0x400F0114` | data chunk (8 B) |

- `0x17` written on `0x400F0110`/`0x400F0111` = **xfer handshake value**
  (fn file 0x1C85C waits on it) — this is the §11.22.3 "cmd 0x17 xfer".
- Transport primitives: file `0x1C8B8(buf, len)` = window→buf reader,
  file `0x1C8F0(buf, len)` = buf→window writer (≤8-byte chunks).
- **Response traffic is XOR-0x85 obfuscated**: cmd `0x5A` handler (file
  0xCD80) emits `buffer[1..32] ^ 0x85` sequentially into
  `0x400F0112..0x400F0131`. Same XOR on cmd `0x51`/`0x5F` short senders.

### Password-session command set (dispatcher, file 0xD868)

```
0x21 reset session      0x22/0x23 state       0x24/0x25 mode set
0x26 PASSWORD SESSION   (sub 0..8 via TBB @file 0xD7BC; verify/enroll paths,
                         sub-handlers file 0xD6A0/0xD70C/0xD654/0xD754)
0x4D ack                0x4E send 8B of enrolled block
0x4F recv -> 0x0011899C {len,data..}          0x50 recv->staging + compare
0x51 send 2B            0x52 flag read        0x5A SEND 32B, XOR 0x85
0xB4 mode-verify
record-store ops via session subs 4 / 5 / 0x15 (handlers file 0xCF60/0xCF84/
0xCF48; 0x15 = enrolled-master record, cf. dell_ec_keygen --triage)
```

Other dispatchers: file `0x914` = hardware/telemetry cmds (0x08,0x43,0x61,
0x70,0x9B,0xAB,0xB8,0xC1,0xC2,0xF5-F7); file `0xE9C8` = cmd `0xCA` battery/
adapter sub-protocol; NEW this cycle via `--dispatch`: file `0x1E790`
(cmds 0x4B,0x4C,0x53,0x64,0x90,0xB1) and file `0x1F4A8` (0x01,0x02,0x78,
0x80) — eSPI/peripheral command sets, not password paths.

### Buffers (runtime addresses)

```
0x0011899C  rx buffer {len, data…}        (0x20 memset each session)
0x001189C0  staging (32 B, typed/derived candidate)
0x00119420  enrolled block (33 B: len + 32) — cmd 0x4E leaks its first 8B
0x00118952  {len, 16 B} verify input
0x00118978  status flags (bit0 = "response pending")
```

### 16-char verifier (file 0xD5E8)

`for i in 0..15: table72[input[i] % 72] == staged[i]` — table72 at runtime
`0x000F17A9` (file 0x21829):

```
012345679abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0
```

(72 chars, '8' skipped in the first decade); charset bitmap at
`0x000F17F1` (file 0x21871). Same %72 shape as the BIOS-side 8FC8 render
(`alphabet0[(a[i]+a[i+16]) % 72]`) and the E7A8 finish
(`ALPHABET[(d[i]+d[i+16]) % 65]`) — one render-family across generations.

## 3. EMULATION PROOF (unicorn harness validated)

```
python3 ec_re/dell_ec_engine_re.py --emul collected/Latitude_5X90_1.41.0/ec_1_166784.bin \
    --fn 0xCD8E --preload 0x0011899C=000102...21 --preload 0x20008000=0000000000001000
```

Ran the cmd-0x5A emitter (skipping its delay prologue): **32 mailbox writes,
exactly `buffer[1..32] ^ 0x85` into `0x400F0112..0x400F0131`** — bit-for-bit
as decoded. This validates the segment map, runtime addressing, buffer
placement and the harness itself. **The moment any new-era EC dump lands,
the same harness decodes its GENERATE engine** (`--xref` → dispatcher →
`--disasm` → `--emul` the handler → feed `resp32` to the verified RENDER).

## 4. GENERATE engine timeline (important negative result)

The 5X90 EC (2018, E7A8-era) implements password **verify/enroll** (cmd 0x26
session + record 0x15 store + table72 verifier) but **NOT the tag→response
GENERATE**: no `C065AEAB` GUID anywhere (even 3-byte prefixes), no
new-suffix family-byte table `{C8,1B,BE,E2,58}`, no 32-byte derivation
path. GENERATE entered the EC line with the sealed generation (2019+).
Therefore the offline keygen (Step 6) still requires a real new-era
EC-internal dump — doors unchanged: telegram 24189 (free, user-click),
badcaps premium (thread 95293 EC.rar / hoaca388 DM), seller, or a live
`dell_master_keygen --oracle local` run on any bootable machine (already
implemented: /dev/port mailbox I/O).

## 5. GUID discovery

`C065AEAB-1CDD-494D-BD33-4578E106C700` — the §11.22.3 "T6 {C065AEAB…}"
marker is actually a **full UEFI protocol GUID**, found in a GUID table
inside the BIOS-side vault modules (pw_2 @file 0x4F10 on 5X90; same GUID in
the 3090 pw_4). Searched GitHub code (gh api) and the web: **zero public
occurrences** — Dell-internal. The GUID identifies the EC password/GENERATE
protocol interface invoked from SMM/UEFI.

## 6. Tool usage

```
python3 ec_re/dell_ec_engine_re.py --info <bins…>          # PHCM/seal/engine verdict
python3 ec_re/dell_ec_engine_re.py --scan-plaintext <dirs> # hunt readable engines
python3 ec_re/dell_ec_engine_re.py --xref <bin>            # mailbox cross-refs
python3 ec_re/dell_ec_engine_re.py --dispatch <bin>        # command dispatchers
python3 ec_re/dell_ec_engine_re.py --family <bin>          # new-suffix family table
python3 ec_re/dell_ec_engine_re.py --disasm <bin> --start 0xD868 --end 0xD9D0
python3 ec_re/dell_ec_engine_re.py --emul <bin> --fn 0xFILE --preload ADDR=HEX
```

Optional deps: capstone, unicorn (venv at /home/user/venv has both:
`/home/user/venv/bin/python`). Rebuild after a sandbox reset:
`python3 -m venv /home/user/venv && /home/user/venv/bin/pip install capstone unicorn pefile`.
