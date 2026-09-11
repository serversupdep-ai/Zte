# 5X90 EC password engine — complete reversal (execution-validated)

Source: `Latitude_5X90_1.41.0_ec_2_172864.bin` (PHCM body, Thumb-2, mapped at
0xD0000). Everything below was confirmed by **emulation** (`ec_pw_driver.py`,
unicorn), not just static reading, unless noted. The 2017 build
(`..._ec_1_...bin`, 00.00.19) carries the same engine at different addresses
(alphabet @0xF17A9, pools @0xDD01C/0xDD150/0xDD5CC) — the design is stable
across EC generations (2017→2023), which strongly suggests the 3090-class EC
(2020-21, AES-sealed) shares it.

## 1. Storage layer — EC NVRAM

* Flash reads go through a cache window at **0x6D0000** (`[0x1183A8]` staging
  pointer, set by 0xDDB10). Read helpers: 0xDDA86 (byte), 0xDDAD4 (block);
  entry points 0xD1CFC/0xD1DD4 program the eSPI flash controller.
* NVRAM = **two 0x1000-byte pages at cache+0x46000 / +0x47000**
  (flat 0x716000 / 0x717000). Page validity: `[page+0xFFE]==0xFF` and
  `[page+0xFFF]==0x55` (0xDDB90); A/B mount logic in 0xDDBD0.
* Record format (4-byte aligned, stride = align4(len+3)):
  `{len_byte, payload[len-3], id_byte, 0xAA}` — scanner 0xDDE78(id), reader
  0xDE05C(id) (payload → encBlock 0x118F44), writer **0xDDFCE(id, len)**
  (encBlock → flash, via 0xDDA80/0xDDA60).

### Known record ids
| id | content | written by |
|----|---------|-----------|
| 0x0B | 11 bytes: service tag (7) + family (4), e.g. `H2FS5S38FC8` | factory / tag write (0xDE154→0xDDFCE(2,6) sync path) |
| 4 | **admin (setup) password string**, 32 B | sub=0 enroll (0xEBC1C→0xEBBD4(4)) |
| 5 | **system (boot) password string**, 32 B | sub=1 enroll (0xEBC64→0xEBBD4(5)) |
| 0x15 | **master password string**, 32 B | sub=8 enroll (0xEBCF0→0xEBBD4(0x15)) |
| 3 | 33-byte challenge/response value (len+32) | 0xEB634 (from received 0x11942C buffer); served back on success by 0xEB694→0xDE028(0x21) |
| 0x21 | 33 B (compare/lock state, 0xEB634 vs 0x119408 bit2) | — |
| 0x2A, 0x31, 0x40 | flags/small data | various |

**Passwords are stored as plaintext strings** (NUL-padded to 32 bytes) in the
EC's internal flash. They are NOT in the host SPI image (the EC flash cache
region is not host-dumpable), and not hashed.

## 2. Session protocol (BIOS pw module ⇄ EC)

Window/regfile mapping (matches the 2.0.7 SMM provider packets exactly):
`win[2]/[0x400F0112]` = sub/ready, `win[3]/[0x400F0113]` = count,
`win[4..11]/[0x400F0114..0x400F011B]` = 8-byte payload; doorbell 0x17 = data
packet, 0x21 = command session (0xDEAA4 copies doorbell → [0x400F0110],
engine 0xEFEBC dispatches). Receive loop: 0xDEB04 (poll) / 0xDEB2C
(memcpy ≤8 per packet). Send loop: 0xDEB64 (packets out via [0x400F0114..]).

Sub-command map ([0x400F0112] role byte during cmd-0x21, TBB @0xEBD50):

| sub | handler | meaning |
|-----|---------|---------|
| 0 | 0xEBC1C | enroll/clear **admin** pw (record 4) |
| 1 | 0xEBC64 | enroll **system** pw (record 5); cold-flags path = **wipe records 4,5,3** |
| 2 | 0xEBCD4 | receive 32-byte X → 0x1193E2 (the SHA256-derived value) |
| 3–7 | — | nack (seq 0xF1) |
| 8 | 0xEBCF0 | enroll/clear **master** pw (record 0x15); locked-state → seq 0xF3 |

Success marker: seq tag [0x400F0111] = **0xFA**; nack = **0xF1** (locked/other
= 0xF3). String enroll 0xEBBD4(id): receive 32 B → if byte0==0 → clear record
(0xEB91C/0xEB974/0xEB904 zero-write chains) else write record.

## 3. Verify cascade (0xEC05C / 0xEC0C8)

Reference = the currently-typed password at **0x119450** (received from the
BIOS byte-by-byte via [0x400F0112], handler 0xEBED0; confirmation flow against
0x11942C). Checks in order:

1. **record 4** (0xEBE10(4): read NVRAM → encBlock, NUL-terminated cmp ≤32)
2. **record 5** — only if `[0x119403]` bit1 (0xEBE5C → 0xEBE10(5))
3. **render(X)** — only if bit3 and X non-empty (0xEBFA4):
   `ascii72[X[i] % 72] == pw[i]` for i in 0..15, ascii72 @0xF456C (72 chars)
4. **record 0x15** — only if bit5 (0xEC010 → 0xEBE40 → 0xEBE10(0x15))

PASS on any match → bit0 of [0x1193E1], optional 0xEB974 chain, memset
encBlock, return 1. All four arms **fail-closed** (the 0xEBFA4 “skip” paths
jump past `movs r0,#1` but r0 was pre-zeroed by `and r0,r3,#0xff` — subtle!).

Execution validation (ec_pw_driver.py): record-4/5/0x15 matches PASS with
their gate bits set, FAIL without; render(X) PASS with bit3 and X set; wrong
password FAILs all arms. Enrolls proven: sub=0/8 write the received 32-byte
string to records 4/0x15 and set bits 0/5 of [0x119403].

## 4. Challenge/suffix response (0xEBA7C)

```
memset(encBlock, 0, 0x40)
if ([0x400F0112] == 0):                    # role 0: from NVRAM
    read record 0x0B (11 B: tag+family) → encBlock
    encBlock[0] &= 0x7F
    calculateSuffix(type=1) over encBlock[0..4]   # the 5 tag bytes
else:                                      # role != 0: host-supplied
    memcpy(encBlock ← [0x400F0113], 11)
    calculateSuffix(type=0) over encBlock[0..1]   # 2 bytes only
copy 8 rendered chars → [0x400F0113..0x400F011A]  # the response
memset(encBlock)
```

`calculateSuffix` @0xEB990 is **byte-identical to the pw-module 0x7d84 /
public keygen construction** (0xAA-XOR bit select over the reversed input
bytes, mod 72, render via ascii72 @0xF456C). Validated by emulation:
`calculateSuffix(1, "H2FS5")` → `10l6leru` == `dell_keygen.calculateSuffix_fw("H2FS5", ascii72, 72)`;
role=1 with host payload `8FC8CF1B…` → `2b4rrrbb`.

Service-tag block: read 0xDE174 / write 0xDE18C (logs "read_service_tag()"),
tag copy 0xDE150 (0x118F44 → 0x118E35, 6 B) + 0xDDFCE(2,6); seq-tag MMIO
0x400F0111 via 0xEB986.

## 5. The 0xA4–0xAE console protocol (svc-0x18 subscriber 0xDF2F4)

Window tag byte 0xA0–0xAF (high nibble dispatch @0xDF308) → 0xDF24C(cmd, byte):
0xA4 status (seq 0xFA/0xF1), 0xA5 collect ≤32-char NUL-terminated string into
0x119409 (first byte is a swallowed preamble), 0xA6 completion check (sets
bit7 of 0x1193E1 via 0xEB80C), 0xAA send 0x55, 0xAB send 0, 0xAD/0xAE flag
0x10 @0x118F96. Responses go out via 0xDED28 → SMBus master 0x400F0400
(slave byte 0xA2/0x82).

## 6. What the EC does NOT do

* No hash computation at all (no MD5/SHA constants anywhere in the image).
* No master-password **derivation** — it stores, compares, and round-trips.
  The only arithmetic on the tag is the public calculateSuffix.
* Therefore the master for a given machine = the factory-written record 0x15
  (and/or owner-set records 4/5), not an EC-side computation.

## 7. Implication for the 3090 / CF1B target (H2FS5S3-CF1B)

The ≤2.0.7-era 3090 BIOS accepts `keygenDell(tag, "BF97")` **locally** — i.e.
Dell's master generation for the CF1B family IS the BF97 construction
(`shzNyjGRzRN2LLzL` for H2FS5S3). On 2.27.0+ the check moved into the EC, but
the EC only compares strings — the factory-enrolled record 0x15 must equal
what Dell's own generator (support flow) produces, which is the same
family-wide master. The previously-assumed “EC-computed master” does not
exist. Remaining validation routes (unchanged): dell_cf1b_probe oracle,
`dell_keygen.py --family CF1B --password <P>`, rex98_patcher.py --patch.

The owner password's sealed value (record 3 / X_enrolled) stays EC-internal —
offline recovery of an owner-set (non-master) password remains closed, as
before.

## 8. Key address index (ec_2, 1.41.0)

```
0xDDE78 record scan      0xDE05C record read→encBlock   0xDDFCE record write
0xDDBD0 page mount       0xDDB90 page validity (FF/55)  0xDDA86/0xDDAD4 flash rd
0xDEB04/0xDEB2C packet recv   0xDEB64 packet send       0xDEAC4/0xDEAA4 doorbell
0xEFEBC eSPI engine      0xDED28 SMBus send             0xDF2F4 svc18 subscriber
0xDF24C 0xA4-0xAE dispatcher
0xEBA7C suffix response  0xEBA5C role0 helper           0xEB990 calculateSuffix
0xEBC1C sub0 (admin)     0xEBC64 sub1 (system/wipe)     0xEBCD4 sub2 (X recv)
0xEBCF0 sub8 (master)    0xEBBD4 string enroll          0xEB5D0 recv→buf
0xEC05C/0xEC0C8 verify cascades   0xEBE10(id) read+cmp  0xEBFA4 render(X) cmp
0xEB634 challenge sync (rec 3)    0xEB694 success send  0xEBED0 pw byte recv
RAM: 0x118F44 encBlock(64B)  0x118E44 record staging   0x1193E2 X(32B)
     0x119409 console string 0x11942C challenge(len+32) 0x119450 typed pw(32B)
     flags: 0x1193E0/E1, 0x119403 (bit0=4-enrolled,1=5,3=X,5=0x15), 0x119408
tables: ascii72 @0xF456C, upper36 @0xF458F
```
