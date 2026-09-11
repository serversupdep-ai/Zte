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

1. **R-read + double-SHA256 grind** (`dell_cf1b_r.py` for X/Y arithmetic,
   `dell_cf1b_grind.c` for the search): the verify session returns R
   *before* the PASS/FAIL compare — `dell_cf1b_probe.c` reads it from the OS
   on the live (authorized) machine. Given R, the password is any `pw` with
   `SHA256(SHA256(pw16‖salt)‖salt) == R`. This is CF1B's own arithmetic,
   validated firmware-side (selftest executes the real 0x1BB4 under
   unicorn; the C grinder matches the Python byte-exactly).

   Performance: each candidate costs exactly **2 SHA-256 compressions**
   (both messages — 16+4 and 32+4 bytes — fit a single block). Measured
   ~1.9 M cand/s/core on the analysis sandbox (shared, throttled); expect
   5–10 M/s/core on a desktop with `-march=native`. Practical ranges with
   a 36-char charset on an 8-thread desktop (~40 M/s): len ≤ 6 in ~1 min,
   len 7 in ~30 min; full 95-printable charset: len 6 ~11 h. `--list`
   wordlist mode covers dictionary-based owner passwords of any length.
   ```
   gcc -O3 -march=native -pthread -o dell_cf1b_grind dell_cf1b_grind.c
   sudo ./dell_cf1b_probe ...        # read R from the authorized machine
   ./dell_cf1b_grind <R_hex> --maxlen 7          # charset brute force
   ./dell_cf1b_grind <R_hex> --list < words.txt  # wordlist mode
   ```
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

---

## 8. FULL KEYGEN (dell_pwgen.py) — cross-model, executed-firmware proven

Corpus scan (collected/*/pw_*.efi) of the whole CF1B generation:

| Module shape | Models (packages) | CF1B behavior |
|---|---|---|
| 42496 old-era (lookup sentinel `mov eax,0xFF; ret`) | OptiPlex 3090 2.0.7 pw_4 (API @0x926C); **Latitude 5400/5500/Precision 3540 1.43.1 pw_11 (API @0x927C — still in the LATEST package)** | **natural local generation**, status 0 |
| 43008 new-era (sentinel 0xFFFF) | 3090 2.27.0/2.30.0, 3080 2.33/2.35, 5080, 7080, 5480, 3280 AIO, 7780/7480 AIO, 5X00 pw_12 — **all byte-identical (sha256 25af0675…)** | natural = EFI_INVALID_PARAMETER; intact fallback (je→jmp) generates |
| 42496 family-first API | Latitude 5300 1.37.0 pw_7 (API @0x85B4: is_ec_routed check first, lookup sentinel 0xFFFF) | routes CF1B to the EC; no local generation |
| 38912 compact | 3090 UFF 1.42/1.44, 5090, 7090, XE4, 5000, 5490/7490 AIO pw_3 | same construction constants (BF97 sites + cmp rax,0xff/0xffff) |

Cross-model execution proof (pw_fw_exec harness):
* 3090 2.0.7 pw_4 vs Latitude 5X00 1.43.1 pw_11 — **6/6 tags byte-identical
  64-byte outputs** (H2FS5S3, 9LNT2Z2, 8XKP5Y2, 4J5SCF4, 3BJJ9C3, 9B1N0R3);
  pure-Python port (dell_keygen.keygen_cf1b) matches 6/6 as well.
* The construction is therefore **tag-determined, model- and BIOS-version
  independent** — one master per service tag for this generation.
* Sibling unification (executed): families 1B58, 9ABE, 3FE2 and CF1B all
  produce the SAME master for a tag (fallback hardcodes the family
  constant); 8FC8 refuses (table stub, desc=NULL → EFI_INVALID_PARAMETER —
  its algorithm is EC-side only, consistent with all prior findings).

Generated masters for publicly documented locked machines (Reddit r/Dell
"Bios password reset" thread, Aug–Sep 2025 — tags posted by the owners;
passwords computed here, field validation pending):

| Service tag | Machine (as posted) | Master (primary) |
|---|---|---|
| H2FS5S3 | OptiPlex 3090 (this survey's machine) | `shzNyjGRzRN2LLzL` |
| 9LNT2Z2 | Latitude 5500 | `yE9R322hGQkm55Jn` |
| 8XKP5Y2 | Latitude 5400 | `cxMI6I[yzPJkZQkh` |
| 4J5SCF4 | (CF1B lock) | `kG7RMPzr50yINas0` |
| 3BJJ9C3 | (CF1B lock) | `r10DGr2cz3rZFkZy` |
| 9B1N0R3 | "dell latitude 3090" | `rQXhLUBGMb1I9x3U` |

Tool: `dell_pwgen.py`
```
python3 dell_pwgen.py 9LNT2Z2-CF1B                 # pwgen-style CLI
python3 dell_pwgen.py <TAG> CF1B --firmware <pw_module.efi>
        # generate by EXECUTING the real firmware (API auto-located;
        # new-era modules run via the branch-forced fallback)
python3 dell_pwgen.py --batch tags.txt
python3 dell_pwgen.py --selftest                    # ALL PASS
```
Validation status: construction = executed-firmware-proven on two
independent module builds (different models, different BIOS eras) plus the
byte-identical 43008 class; H2FS5S3 master delivered from the same path.
The other tags are computed for the documented machines; machine-side
acceptance not yet reported. On current (EC-routed) firmware the master is
accepted through the EC's enrolled record; owner-set passwords remain
covered by §6 routes.

## 9. Field intelligence (public threads, mined to exhaustion 2026-09)

* r/Dell "Bios password reset" (1mni7p9, Aug 2025–Aug 2026) and "Bios master
  password" (iks99h, 2020) fully read (mirror fetch). Findings:
  - The only public helper with a working generator (u/Captain_Zomaru,
    proprietary tool) **refuses every CF1B / 9ABE / 3FE2 / 8FC8 request**
    ("beyond our current ability to generate a code … no known way without a
    bios chip flash"). No CF1B/9ABE/3FE2 password has ever been posted
    publicly. Our dell_pwgen.py is the only generator for this generation.
  - **E7A8 anchor (field-validated)**: the 2020 thread's published pair
    `1JGPCK2-E7A8 → 67M[kP4k92yG4nMQ / RGRb5UBrrEa8hrGL` is reproduced
    EXACTLY by our keygen_e7a8 — proving that thread's passwords were
    genuine Dell masters and our implementations reproduce field-verified
    data. The same helper's 8FC8 attempt failed on-machine ("It doesnt,
    have tried them both") — consistent with 8FC8 being EC-side.
  - Old-suffix machines accept the BF97-construction master regardless of
    their displayed suffix (multiple reports, e.g. -1F66 machine unlocked
    with the BF97 line) — the same construction the CF1B fallback executes.
  - A **MasterPasswordLockout** victim (Precision 7740, BIOS 1.45.1,
    suffix -CF1B, tag withheld "XXXXX73") reports Dell refusing transfer and
    requiring a motherboard: matches the `MasterPasswordLockout` attribute
    in pw_5 (§ pw_5 note); when lockout is armed, master-password unlock is
    disabled machine-side — our master cannot help there either.
  - New suffix sighting: `-8FCA` (Precision 3591 class) — beyond the
    1B58/9ABE/3FE2/CF1B/8FC8 list in this firmware generation; treat as
    EC-side until firmware says otherwise.

### Computed masters for every publicly documented CF1B-generation machine

Owners of these machines posted their tags publicly asking for help; the
masters below are computed by the firmware-proven keygen (dell_pwgen.py).
Field acceptance remains unreported for all but H2FS5S3.

| Service tag | Suffix | Machine (as posted) | Master (computed) |
|---|---|---|---|
| H2FS5S3 | CF1B | OptiPlex 3090 (this survey's machine) | `shzNyjGRzRN2LLzL` |
| 9LNT2Z2 | CF1B | Latitude 5500 | `yE9R322hGQkm55Jn` |
| 8XKP5Y2 | CF1B | Latitude 5400 | `cxMI6I[yzPJkZQkh` |
| 4J5SCF4 | CF1B | (not stated) | `kG7RMPzr50yINas0` |
| 3BJJ9C3 | CF1B | (not stated) | `r10DGr2cz3rZFkZy` |
| 9B1N0R3 | CF1B | "dell latitude 3090" | `rQXhLUBGMb1I9x3U` |
| JY6TVD3 | CF1B | OptiPlex 3080 MFF | `Fz6xGZcQkZrjdZq0` |
| 9Y6TVD3 | CF1B | OptiPlex 3080 MFF | `R9UDLpmppeq26D88` |
| C7ZRYZ2 | CF1B | Latitude 5300 | `rZ[jL61JWpRk6MjE` |
| CVW2Q13 | CF1B | Precision 7540 | `8yWGMQ30zQIzQR2N` |
| G45BC93 | CF1B | Latitude 5410 | `yxkrJxG8UJJJ12zX` |
| 6RMTP33 | CF1B | Latitude 5400 | `PGkz6c3r6sqI89Z2` |
| CNXJQB3 | CF1B | OptiPlex 3080 | `hFW0mEGE2z3L2MyN` |
| 6DRBM34 | 9ABE | (not stated) | `Z7kzX3bpkNNLDr6Q` |
| J1GVS14 | 9ABE | Latitude 5540 | `ZL3XEcZr6[Grc297` |
| 2V7P224 | 9ABE | (not stated) | `RDGc1Lr4aU2M4666` |
| 2W255W3 | 3FE2 | Latitude 7430 | `k2LhDndx34IP1GL6` |

(Entry convention on locked Dell machines: type the password, then
**Ctrl+Enter** — or Ctrl+Enter, Enter — rather than plain Enter.)

## 10. THE NEW SOLUTION (field-rejected BF97 master superseded) — why the
keygen era ended, and what actually unlocks latest firmware

**Field status of §8/§9:** the BF97-construction master
(`shzNyjGRzRN2LLzL` for H2FS5S3) was **REJECTED on the user's own OptiPlex
3090 (H2FS5S3-CF1B, latest firmware)**. The §9 table is retired as an
unlock answer. This section replaces it with the proven latest-firmware
solution.

### 10.1 Why no keygen can ever work on latest firmware (now proven end-to-end)

The full BIOS/SMM command chain for password generation was reversed this
round from the 2.27.0 package (closing the last unexplored modules):

```
SMM "generate" command
  pw_2 fn 0x2DC4  (2.27.0, 25600-class)
    ├─ fn 0x30D0: read machine config (0x200 B struct) → family = cfg[0xB8]
    ├─ is_supported_family (fn 0x5EAC): EC-routed list [1B58,9ABE,3FE2,
    │   CF1B,8FC8] OR legacy list [E7A8,BF97,6FF1,1F66,1D3B,2A7B,0001]
    └─ fn 0x4C88: call EFI protocol {C065AEAB-DD1C-4D49-BD33-4578E106C700}
        method +0x18, params {GUID, ctx, 0x14, op=2}
        → pw_4 (43008-class, same library as 2.30.0/3080/5080/5480/…):
          fn 0x1884 (vtable @0xA7E8 +0x18)
            → registry @0xA8D0 (9 GUID→handler entries, {C065AEAB} → table @0xA760)
            → fn 0x2074 (the +0x18 method)
                ├─ EC-delegated AND EC-routed family (CF1B ⇒ yes):
                │     fn 0x37AC = EC session, sub 3 = ENROLL/CHANGE with
                │     CALLER-SUPPLIED bytes. No computation of a master.
                └─ otherwise: fn 0x91E4 → lookup 0x8060 → table families
                      (E7A8-style descriptor path) or the legacy BF97
                      fallback — unreachable for CF1B.
```

Supporting facts closed this round:

* **38912-class (newest, e.g. 3090 UFF 1.44.0 pw_3):** dispatch lookup
  (fn 0x4308) returns index-or-0xFFFF; the `cmp rax,0xff` fallback branch
  (0x4461 in the API at 0x4420) is **dead code**. CF1B → 0xFFFF →
  EFI_INVALID_PARAMETER. No local generation exists at all in the newest
  module shape.
* **18432-class module** (present in 16 newest packages) is not password
  code at all — it is Dell's Cloud/OAuth profile parser (OpenSSL SHA-256,
  ConnectionProfile/CloudAppProfile/FotaProfile strings).
* The whole 3090 BIOS region in the official packages is AES-sealed in
  transit (17,060,007-byte high-entropy blobs; the module corpus came from
  the earlier LVFS/relay collections), so no other hidden generator module
  exists outside the classes already mapped.
* The EC engine itself (FINDINGS_5X90_EC.md) stores/compares only; it
  derives nothing. §7's assumption "factory record 0x15 == BF97
  construction" is **disproven by the field test**.

**Conclusion:** the EC-era enrolled master is written at the factory from
Dell's backend. No firmware image contains its construction. A tag→master
keygen for latest firmware is impossible from firmware; the §8/§9 masters
fail on EC-delegated platforms precisely because the enrolled value is a
backend-computed secret, not any local construction.

### 10.2 The proven latest-firmware unlock: clear the enrolled-record markers
(MFG-mode patch)

The repair-industry solution (badcaps "Dell 8FC8 Patcher" by SMDFlea,
Rex98's tool, chromebreakerdev/DellBIOSTools, craigsblackie/8FC8_Patcher —
all the same algorithm) does not guess the password. It edits the EC-owned
record store that lives in the host SPI image (region starting `PHCM`,
right after the Intel descriptor — the same record store our 5X90 EC
reversal maps: engine records 4 admin / 5 system / 0x15 master / 3
challenge):

```
00 FC AA <var> 00 00 00 <tail>   →   00 FC 00 ...     (clears "enrolled")
00 FD AA <var> 00 00 00 <tail>   →   00 FD 00 ...     (variant class)
```

Zeroing the AA marker makes the EC report "no password enrolled": the
machine boots in **Manufacturing Mode** — password gone, settings intact,
BitLocker still bootable, service tag writable.

Field-proven specifically for this lock class and hardware:

* badcaps, on a CF1B machine: *"It is not 8FC8, it is CF1B … It's the same
  method, read your bios chip and use 8FC8 Patcher."*
* badcaps 2025-12, **OptiPlex 7000** (same desktop family as the 3090):
  *"Tried this patch to reset the BIOS. It did. No password anymore."*
  Follow-up: after entering the service tag in Manufacturing Mode, run the
  official BIOS update from the **F12 boot menu while still in
  Manufacturing Mode**, then **Alt+F** to exit — clean normal boot on
  latest firmware.
* Latitude 5500 CF1B units unlocked on badcaps via dump+patch (e.g.
  3NM1043-CF1B); dual-chip systems (8 MB + 16 MB) may hold the record
  store in either chip — patch whichever matches.

**Deliverable:** `dell_unlock_image.py` (this round) — ports/extends the
proven patch and adds flash analysis, EC record-store decode with engine
semantics, multi-chip guidance, and a machine-tailored procedure:

```
python3 dell_unlock_image.py --analyze <dump.bin>   # layout + records + markers
python3 dell_unlock_image.py --patch   <dump.bin>   # -> patched_<name>
python3 dell_unlock_image.py --store   <dump.bin>   # record-store decode
python3 dell_unlock_image.py --guide   H2FS5S3-CF1B # end-to-end procedure
```

Validated: on single-class (FC-only) dumps its output is **byte-identical**
to the committed Rex98-faithful `rex98_patcher.py`; on dual-class dumps it
clears both marker classes (superset). Synthetic-image test: exactly the
marker bytes 0xAA→0x00 change, nothing else.

**Fallback method (also implemented): `--wipe-store`** — essaadi's
independently field-validated variant (badcaps, Latitude 5400, tags
4YNG2Z2 + HZKF2Z2): FF-fill the whole record-store region
(0x45000..0x48FFF on the 5400) instead of surgically clearing markers.
`--wipe-store <dump> [START:END]` auto-locates the record cluster
(page-aligned bounding box) or takes an explicit hex span; same MPM exit
procedure afterwards. Use it if `--patch` finds no FC/FD markers on a
3090 dump (layout drift) but `--analyze` shows the record cluster.

Recovery note: this round the workspace was reset to the base commit
(fbb7085) by an external snapshot restore; the branch was restored
byte-identically from the remote tip 4485fde (all 60 pre-session files
verified identical/superseded) — no work lost.

End-to-end for H2FS5S3-CF1B (OptiPlex 3090, latest firmware):
1. CH341A + SOIC8 clip → `flashrom -p ch341a_spi -r orig.bin` twice, verify
   identical (keep the original!).
2. `--patch orig.bin` → flash `patched_orig.bin` back, verify.
3. Boot → F2: no password (Manufacturing Mode). Write service tag H2FS5S3,
   save, reboot.
4. **While in Manufacturing Mode:** F12 → run the official OptiPlex 3090
   BIOS update (Dell USB recovery format).
5. Alt+F → exits Manufacturing Mode → normal boot, no password.

### 10.3 The no-hardware alternative (works by construction)

Dell ownership flow: transfer ownership + support request with proof —
Dell's backend reads out the master **for the enrolled record itself**.
It is the only zero-hardware route, and it cannot fail the way a keygen
does (there is nothing to compute; Dell knows the enrolled value). Free
per multiple 2025 reports; out-of-warranty password release is standard.

### 10.4 What is NOT viable on latest firmware (do not retry)

* Any tag→password keygen (BF97/2A7B/E7A8 or variants) — the EC compares
  against the factory-enrolled record, not a local construction.
* Brute-forcing the master: acceptance chain R = SHA256(SHA256(pw‖salt)‖salt)
  with a random 16-char backend master ≈ 95+ bits — the grind tool is only
  useful for low-entropy owner-chosen passwords.
* NVRAM/CMOS resets, battery pulls — the records are in persistent SPI.

### 10.5 Zero-hardware routes — now definitively ranked (2026-09 field sweep)

**Closed: motherboard jumpers.** This generation has none:

* Dell's own guidance: *"Dell desktop computers launched prior to this
  document have a motherboard jumper-based reset function. If your product
  was shipped prior to April 2020 and is not listed above, then the
  computer will most likely have a jumper-based reset."* — the OptiPlex
  3090 shipped 2021+.
* OptiPlex 3090 SFF service manual: *"To clear the system or BIOS
  passwords, contact Dell technical support"* — no jumper procedure.
* OptiPlex 3090 MFF board (Foxconn IPCML-RN/ZB): no RTC-reset, no
  password-reset, no service-mode jumper positions populated (winraid
  board inspection, 2022).
* Older OptiPlex (e.g. 3070) DO have the PW_CLR/PSWD jumper — that era
  ends with the 3080/3090 generation.

**Closed: CMOS/NVRAM battery pulls.** 3090 SFF owner: battery removed
with power disconnected for extended time — lock persists. Exactly as the
EC-engine model predicts: password records live in persistent EC-managed
flash, not in battery-backed CMOS. (5X90 EC reversal, sub-1 cold-flags
path wipes records 4/5/3 only when the EC itself receives the wipe
command — no host-side electrical event triggers it.)

**Open and free: Dell support readout.** Dell issues a recovery key for
the enrolled record with proof of ownership — confirmed working even
**out of warranty** for 8FC8-era machines (multiple 2023–2025 reports).
Entry convention: type the key, then **Ctrl+Enter+Enter**.

**Open, field-proven on the OptiPlex 3090 itself: the §10.2 patch.**
badcaps "dell optiplex 3090 bios issue" thread (2022–2023): owners of
locked 3090s (service tags 2RCDXM3, 4JD7KN3, 8LHR0N3) uploaded SPI dumps
and received unlocked images back, with the exact procedure our
`dell_unlock_image.py --guide` reproduces: *"First boot go to Bios Menu,
disable absolute, write your Service Tag, save, and Press ALT+F to bypass
(Manufacturing Mode)."*

Chip intelligence for the 3090 class: the sibling OptiPlex 7090 micro
carries a **32 MB Winbond W25Q256FV in WSON8** (badcaps dumps); expect
the same class on 3090 variants (SOIC8 on some), 1.8V suffixes need the
CH341A 1.8V adapter.
