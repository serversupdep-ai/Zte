# CF1B — its own implementation, exclusively (no legacy construction used)

Per directive: CF1B is analyzed exactly like 8FC8 was — every conclusion below
comes from CF1B-referencing code in the OptiPlex 3090 firmware itself
(pw_4 modules, 2.0.7 / 2.27.0 / 2.30.0, official Dell packages), at
instruction level. The legacy BF97 path is *not* used as a solution anywhere
in this document (it is only referenced as historical context in §6).

All addresses are RVAs in `collected/OptiPlex_3090_2.27.0/pw_4_43008.efi`
(PDB 876e788c…; 2.30.0's pw_4 is byte-identical in the relevant regions)
unless stated otherwise.

## 1. What routes CF1B — the delegation gate (NEW in 2.27.0)

```
0x9580  is_ec_routed_family(u16 family):
            walk list @0xA3C8 until 0xFFFF; true on match
0xA3C8  list = [0x1B58, 0x9ABE, 0x3FE2, 0xCF1B, 0x8FC8, 0xFFFF]
```

The identical list also ships in 2.27.0 pw_2 (@0x6158) and pw_3 (@0x70E8).
**2.0.7's pw_4 has NO such list** (byte-pattern absent) — CF1B was not
EC-routed in that era. Callers of the gate: 0x202B (verify entry), 0x211F
(change entry), 0x8D36 and 0x8E3B (value builders). A second gate is the
runtime flag @0xAEBC ("provider installed", set when the SMM mailbox
provider is found).

## 2. CF1B verify — fn 0x3314 (the session, instruction-confirmed)

```
verify(candidate):
    type = provider_type() (fn 0x30E8 = SMM-provider GUID matcher); need 3
    X = SHA256(candidate[0..16] || salt)          ; fn 0x1BB4, salt @0xA658
    session: cmd 0x21, sub 1, type 3              ; [ctx]=0x21 [ctx+2]=1 [ctx+3]=3
    SUBMIT  (provider vtbl +0x38)
    WRITE(X, 32)                                  ; vtbl +0x40
    WRITE(family u16 = 0xCF1B, 2)                 ; from global @0xA788
    R = READ(32)                                  ; vtbl +0x48
    Y = SHA256(X || salt)                         ; second 0x1BB4 call
    PASS iff memcmp(R, Y, 32) == 0                ; fn 0x4490
```

* `0x1BB4(in, len, out, &outlen)`: zeroize(out,32); SHA-256 init
  (**0x3C34**, H0 `6a09e667 bb67ae85 3c6ef372 …` inline at 0x3C51);
  update (0x3D0C) with `in[len]`; update with **salt = 4 raw bytes
  `8D FC 7B 25` @0xA658**; final (0x3E14) → out; outlen = 0x20.
* Salt occurrences: 3090 pw_4 in 2.0.7/2.27.0/2.30.0, 3090-UFF pw_3
  1.42/1.44, Latitude 5X90 pw_5 — one shared salt for this platform class
  (the "salt universe" is closed at 5 corpus-wide; see dell_salts_db.py).
* **Acceptance criterion (CF1B's own):**
  `R == SHA256(SHA256(pw[0..16] ‖ 8DFC7B25) ‖ 8DFC7B25)`

## 3. CF1B change/enroll — fn 0x37AC (sub 3)

```
change(struct{…, len@[+8], byte@[+0x10]}, …):
    type = provider_type(); must be 4, 5 or 6
    session: cmd 0x21, sub 3, type
    WRITE(len, data)
    type 4: if capability flag: WRITE(16, STATIC @0xA577 =
            4c bf e4 4d 7f 01 3f f2 5a 2a 37 b1 67 de 7a 47)
            READ(byte from [rsi], r12); READ 1 byte via vtbl+0; fn 0x31B4(…)
    type 6: WRITE(len, rbp); READ(32 → rsp+0x28);
            0x8E18(dst=r12, len, rsp+0x28, family=[rbp] u16)
```

## 4. CF1B value handling (contrast with table families)

| fn | table families (8FC8/E7A8) | CF1B (not in dispatch table) |
|----|------------------------------|------------------------------|
| 0x8E17 render | `out[i] = alphabet[(src[i] + src[i+16]) % 72]` (0x8DA4) | `bzero(out); memcpy(out ← src, 16)` — **raw 16 bytes, no mapping** |
| 0x8D0C build | sanitize only | sanitize (`0x21..0x7E` else `'*'`, 0x95B4); move to 23-B block; **output = block[9..20] (11 bytes)**, len := 11 — the tag(7)+family(4) composite for the EC's tag record |

The 23-byte block at `block[9..20]` = tag+family matches the EC engine's
record 0x0B (11-byte tag+family, FINDINGS_5X90_EC.md §1) — i.e. the BIOS
sends the EC exactly the identity string the EC engine stores.

## 5. Consequence — there is NO machine-side CF1B master derivation

* 2.27.0+/2.30.0: generation for CF1B is unreachable (the 0xFFFF sentinel
  gate, REPORT §9.6); verification is a pure SHA-256 challenge against the
  EC's enrolled store. The EC engine (execution-reversed on the 5X90) stores
  and compares — it derives nothing.
* Therefore a "CF1B keygen" cannot exist on the machine side in the current
  era, by construction. The accepted password is fixed at enrollment
  (factory or owner).

## 6. CF1B-exclusive recovery routes (no legacy algorithm involved)

1. **R-read + double-SHA256 grind** (`dell_cf1b_r.py`): the verify session
   returns R *before* the PASS/FAIL compare — `dell_cf1b_probe.c` reads it
   from the OS on the live (authorized) machine. Given R, the password is
   any `pw` with `SHA256(SHA256(pw16‖salt)‖salt) == R`. Preimage is hopeless
   for long passwords but tractable for short ones (≤6–7 chars over a
   constrained charset). This is CF1B's own arithmetic, validated
   firmware-side (selftest emulates the real 0x1BB4 under unicorn).
2. **EC flash dump** (hardware step): the enrolled values live in the EC's
   internal NVRAM (records 4/5/0x15 = plaintext password strings on the
   5X90-class engine). The 3090's EC firmware is AES-sealed in transit, but
   a direct EC-flash read on the bench exposes the records themselves.
3. Dell support transfer-of-ownership (the sanctioned channel).

Historical note only (not used as the solution): on ≤2.0.7 the module's
CF1B branch embeds a legacy-construction fallback — proven by execution in
REPORT.md §9.6 — which is why that era accepts the legacy password locally.
That path is dead on 2.27.0+ (sentinel gate), and per the standing directive
it is NOT the basis of the CF1B answer.

## 7. Address index (2.27.0 pw_4)

```
0x30E8 provider-type (GUID match)   0x3314 verify session (sub 1)
0x37AC change session (sub 3)       0x1BB4 SHA256(in‖salt)
0x3C34/0x3D0C/0x3E14 SHA-256 init/update/final
0x4490 memcmp                       0x95B4 sanitize 0x21-0x7E else '*'
0x9580 is_ec_routed_family          0xA3C8 family list (CF1B member)
0x8D0C tag+family builder           0x8E17/0x8DA4 value render
0xA577 16-B type-4 constant         0xA658 salt 8D FC 7B 25
globals: 0xA788 family, 0xAEBC provider-installed flag
```
