# CF1B architecture (reversed from firmware)

## Suffix families (FAMILY LSB byte)

| Suffix | FAMILY_LSB |
| --- | --- |
| CF1B | 0x1B |
| 8FC8 | 0xC8 |
| 9ABE | 0xBE |
| 3FE2 | 0xE2 |
| 1B58 | 0x58 |

Legacy suffixes (E7A8, BF97, 1F66, …) use the old serial-scramble + MD5
construction — fully implemented in dell_master_keygen.py.

## EC challenge→response protocol (EC-era Dell, TGL generation)

- EC I/O ports **0x910 / 0x911**
- open sequence: **21 00 03 06**
- command **0x17** (service tag → response)
- response window **0x10–0x1F** (16 bytes)
- CF1B unlock code = response bytes [0:16] directly
- 8FC8 unlock code = alphabet[(resp[i] + resp[i+16]) % 72] for i in 0..15

## PHCM container (sealed password store, staged in CSME MFS)

- magic **"PHCM\x01\x01\x80\x03"**
- header 192 B: record count n @+0x10, header size @+0x14 = 0xc0
- key material @+0x40..0xBF:
  - +0x40..0x5F (first 32 B): deterministic per build-size class
    (n9f4 class: cdb03925…; n9fc class: fbd98f4c…)
  - +0x60..0x9F: per-image
  - 0xA0..0xBF: FF-erased
- body: n × 64-B flat ciphertext chunks, no in-band structure
- identical EC build ⇒ byte-identical material AND body (proven on 3410 and 3090)

## Chip maps

**OptiPlex 3090, 32 MB SPI (single chip: XM25QH256B / MX25L25673G):**
- PHCM slots @ **0x1000 / 0x41000 / 0x81000** (inside CSME MFS)
- $FPT @ 0x102000 — entries: PSVN, UEP, IVBP, MFS, UTOK, HVMP, RSTR, FLOG, IMDP
- EC region @ **0x82d464** (core-only, 0x6a60 bytes; byte-identical across all
  four machine dumps and the 2.0.7 package region)
- per-machine ME state blob @ 0x400000 (64 KB)

**Latitude 3410, 8 MB companion SPI:**
- slots A @0x0, B @0x40000, C @0x80000; PHCM @ slot+0x1000

## Per-build determinism tables (sha256 prefixes of sealed bodies)

3410 class:
- X = 71cd0ff7… (n9f4, running)
- Y = 3ec6de4e… (n9f4, staged = slot B on both machines + package)
- Z = 48d817a8… (n9fc, running)
- W = 53fd65dc… (n9fc, package-only)

3090 class:
- three machines byte-identical: slot A 077c070c…, slot B b298ec57…
  (record count n = 0x635)
- fourth machine (newer EC build): slot A b0c5bf15…, slot B/C 628f0b43…

⇒ The key is **per-BUILD, not per-machine**: one EC-build leak unlocks every
machine on that build.
