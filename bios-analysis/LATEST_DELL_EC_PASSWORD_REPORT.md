# Latest Dell EC Firmware Collection & BIOS Master Password Algorithm Analysis (2024–2026)

## Executive Summary

To capture the complete Dell EC + UEFI BIOS master-password pipeline across Dell's latest shipping hardware (2024–2026), we harvested **894 official Dell LVFS firmware entries** (`bios-analysis/collected_latest_ec/lvfs_dell_2026_index.json`), deeply unpacked **52 latest Dell BIOS/EC firmware capsules** across XPS, Dell Pro / Pro Max / Pro Precision (`xx250` / `xx255` / `xx260` / `xx261`), Latitude, Precision, Inspiron, Vostro, OptiPlex, G-Series, and Alienware lines, and extracted **40 deduplicated UEFI password modules** (`unique_pw/*.efi`) plus **4 SMM EC/Vault modules** (`pb14255_smm/*.efi`) alongside every EC firmware image.

Instruction-level reverse engineering across **four hardware/firmware generations** establishes the complete architecture and evolution of Dell's EC-backed BIOS password algorithms:

1. **Generation 1 — Microchip `MEC50x5` (`MEC5085`, ARCompact ISA, Plaintext EC Firmware)**:
   - Captured in `XPS_13_9350_1.13.0_33773727/ec_1_RAW_PFS_SUBCOMPONENT_262144.bin` (`Embedded Controller vA.15.bin`, 256 KB plaintext, `H = 6.814`).
   - Disassembled using our custom ARCompact decoder (`bios-analysis/ec_re/analyze_latest_dell_ec.py`):
     - **Host Mailbox (`0x00FF0110..0x00FF0200`)** mapped over LPC I/O BARs `0x910/0x911` (`0x09108001`) and `0x930..0x934` (`0x09308304`) at `0x1d6b2..0x1d718`, dispatched via event `0x1E` (`0x065d4 -> 0x082e4 -> 0x257f8 -> 0x24d4c`).
     - **`cmd 0x21` (`0x24dec -> 0x08ef0 -> 0x1d3c4`)** is **`ClearPasswordFlags`** (clears 4 lockout/status bits in `[gp-196]`/`[gp-197]`), proving `MEC5085` predates `cmd 0x21, sub 3, type 6` (`8FC8`).
     - **`cmd 0x4E` (`0x1b760 -> 0x1abfc..0x1ad2c`) — In-EC 8-Char Master Password Generator (`595B` / `2A7B`)**: reverses a 5-byte packed Service Tag record (`0x80043c[0..4]`), extracts eight 5-bit selectors, seeds `acc = 0xAA`, XORs `rev[b]` for each set bit `b in 0..4`, and indexes the 72-byte EC alphabet at `0x246b4` (`acc % 72`).
     - **`cmd 0x50` (`0x1b974 -> 0x1d828..0x1d89e`) & `cmd 0x51`/`0x5A` (`0x1b86c`/`0x1b82c`) — In-EC 16-Char Verifier**: compares `user_pw[i] == alph72[ec_sram[0x8005f8 + i] % 72]` (`i = 0..15`) and exports bytes XORed with `0x85`.

2. **Generation 2 — Microchip `MEC5107` (ARM Cortex-M4, Plaintext `PHCM` EC Firmware)**:
   - Captured in `collected/Latitude_5X90/ec_1_ec_region_229376.bin` (`PHCM` v2, unsealed `byte[6] = 0x00`).
   - Introduces `cmd 0x21` (`sub 0..3`, types `0..5`) for NVRAM password storage and double-salted SHA-256 verification (`SHA256(SHA256(pw || 8DFC7B25) || 8DFC7B25)`), while moving legacy `cmd 0x24` to `cmd 0x26`. Rejects `type 6` (`sub r3, #4; cmp r3, #1; bhi error`), confirming `8FC8` master-password derivation was introduced only when Dell enabled hardware OTP encryption (`iFuse`).

3. **Generation 3 — `DEC1515 / MEC5200(iFuse)` & `NPCX993D(iFuse)` + Monolithic `DellSecurityVaultSmm` (`8FC8`, 2020–2025)**:
   - Dell's official internal EC family table (extracted from `dell_Latitude_3450_3550_1.3.1/ec_152_RAW_PFS_SUBCOMPONENT_79876.bin`) enumerates:
     - `MEC50x5`, `MSP430`, `MIPS32`, `MEC5107`, **`DEC1515 or MEC5200(iFuse)`**, **`MEC5200(iFuse)`**, and **`NPCX993D(iFuse)`**.
   - Every shipping `8FC8`-capable EC in the 2024–2026 harvest is hardware-OTP-encrypted (`iFuse`):
     - Microchip `DEC1515` / `MEC5200(iFuse)` (`PHCM` magic `5048434d`, `byte[6] = 0x80`, `hdr[0x40:0x60] = SHA256(hdr[0:0x40])`, payload `H = 7.999` — even on `"nonFused"` BootGuard SKU sections such as `G15_5511` `ec_7`).
     - Nuvoton `NPCX993D(iFuse)` (`5e4d3b2a` header, `LoadAddr = 0x10074000` / `0x10080000`, payload `H = 7.998–7.999`).
   - **Complete UEFI <-> EC `8FC8` Pipeline** (`pw_9ba1` `42,496 B` through `pw_308b` `38,912 B` and `PB14255 DellSecurityVaultSmm_53248.efi` + `DellEcIoMm_36864.efi`):
     - **Capability Gate**: `DellSecurityVaultSmm` (`0x1cb6..0x1ceb`) enables EC master-password RPC (`[0xaec8] = 1`) **only** when protocol `BD6B3090-6936-4DF0-BC73-68B06FB4E791` (`word[0] >= 1`, `byte[2] != 0`, `byte[3] != 0`) and `CA793777-2AE8-4073-8BC5-43376A61BFD5` (`byte[0] != 0`) are present, then binds `DellEcIoMm` (`7310E28E-96EA-4360-946E-5ADC6BE8F531`).
     - **Stage 1 (`EC_GENERATE`, inside OTP-sealed EC)**: SMM (`0x367c..0x3882`) sends mailbox header `{0x21, ?, 0x03, 0x06}` via `[7310E28E +0x38]` (`ports 0x900+ / 0x910,0x911 -> 0x400F0110`), streams the 7-byte Service Tag and 1-byte suffix low byte (`0xC8` for `8FC8`) via `[+0x40]` (`cmd 0x17`), and reads 32-byte `resp32` via `[+0x48]`.
     - **Stage 2 (`RENDER`, inside UEFI SMM `0x8bc8..0x8ca2`)**: unchanged from 2020 through 2026 on `8FC8` platforms:
       ```python
       ALPHABET0 = "0Q2drGk99WLJ1EGnqR5y3DGr16hN4seZPRM2zz2pzcU7JaBXIjbkGZrkQFMxN[Z638myIL2r"
       master_pw = "".join(ALPHABET0[(resp32[i] + resp32[i + 16]) % 72] for i in range(16))
       ```

4. **Generation 4 (NEW 2026 DISCOVERY) — Dell Panther Lake `xx260/xx261` Pure-EC Vault (`XPS 14 DA14260 1.8.2`, `Dell Pro 3 14/16 P314260/P316260 2.4.3`, `Dell Pro Precision 5 14/16 PW514261 1.7.0`)**:
   - On Dell's newest 2026 `xx260/xx261` platforms, Dell **retired `0x8FC8` and deleted `ALPHABET0` (`0Q2drGk9...`) from UEFI firmware altogether**, shrinking `DellSecurityVaultSmm` by 70% from `38,912 B` (`pw_308b`) to **`11,776 B` (`pw_x86_64_77e719e0dece9039_11776.efi`)**:
     - Both System/Vault DXE (`pw_5815` / `pw_3156`, `24,064 B`, handling `F2` setup key `0xF2` and `DellDataWipeDummyPwd$1`) and SMM (`pw_77e7`, `11,776 B`) drop `0x8FC8` from the suffix table, leaving **only `[0x1B58, 0x9ABE, 0x3FE2, 0xCF1B, 0xFFFF]`** (`raw 0x51c0` in `pw_5815`, `raw 0x2428` in `pw_77e7`).
     - **Verification (`0x2304`, `cmd 0x21, sub 1, type 3`)**: computes `X = SHA256(pw || 8DFC7B25)` (`0x1848`), sends `{0x21, ?, 0x01, 0x03}` + `X` (32 B) + `family_u16` (2 B), reads 32-byte `R` from EC, computes `Y = SHA256(X || 8DFC7B25)`, and accepts iff `memcmp(R, Y, 32) == 0`.
     - **Master Password RPC (`0x1f60 -> 0x2874`, `cmd 0x21, sub 3, type 6`)**: sanitizes input into an 11-byte identity (`0x1d54`), checks `family in {0x1B58, 0x9ABE, 0x3FE2, 0xCF1B}`, sends `{0x21, ?, 0x03, 0x06}` + identity + suffix via `7310E28E`, reads 32-byte `resp32`, and executes **`CopyMem(out, resp32, 16)` (`0x2aa8..0x2ab5`) with zero BIOS-side alphabet mapping**.

---

## 1. 2024–2026 Dell EC Hardware & Firmware Taxonomy (52 Unpacked Capsules)

Disassembling `dell_Latitude_3450_3550_1.3.1/ec_152_RAW_PFS_SUBCOMPONENT_79876.bin` (`DellEcSmm`) revealed Dell's own internal EC chip-family table:

| Dell Internal EC String | Architecture | Firmware Packaging in Capsule | Encryption Status | Password Architecture | Representative Models in `collected_latest_ec/` |
|---|---|---|---|---|---|
| `MEC50x5` (`MEC5085`) | Synopsys ARCompact (32/16-bit mixed) | Raw 256 KB (`Embedded Controller vA.15.bin`) | **Plaintext** (`H = 6.814`) | Legacy in-EC `cmd 0x4E`/`0x50` + UEFI `E7A8`/`BF97` (`90306BBD` absent -> `8FC8` disabled) | `XPS_13_9350_1.13.0` (`ec_1`) |
| `MEC5107` | ARM Cortex-M4 (Thumb-2) | `PHCM` v2 (`5048434d`, `byte[6] = 0x00`) | **Plaintext** (`H = 6.08`) | In-EC `cmd 0x21` (`sub 0..3`, types `0..5` SHA-256 store); `type 6` rejected | `collected/Latitude_5X90` (`ec_1`) |
| `DEC1515 or MEC5200(iFuse)` / `MEC5200(iFuse)` | ARM Cortex-M4F (Microchip MEC1515/1521/5200) | `PHCM` (`5048434d`, `byte[6] = 0x80`, 205–327 KB) | **Hardware OTP AES (`iFuse`, `H = 7.999`)** | `cmd 0x21, sub 3, type 6` (`8FC8` on 2020–2025; `{1B58..CF1B}` pure-EC on 2026 `xx260/xx261`) | `Latitude_3450_1.23.0`, `G15_5530_1.35.0`, `PB14255_1.16.0`, `XPS_14_DA14260_1.8.2`, `Pro_3_P314260_2.4.3` |
| `NPCX993D(iFuse)` | Nuvoton Cortex-M4 (`NPCX993D`) | `5e4d3b2a` header (`LoadAddr = 0x10074000` / `0x10080000`, 320 KB) | **Hardware OTP (`iFuse`, `H = 7.998`)** | Same `7310E28E` `cmd 0x21, sub 3` protocol as `MEC5200(iFuse)` (`8FC8` / `CF1B`) | `dell_Latitude_3450_3550_1.3.1`, `Inspiron_16_5640_1.19.0`, `15_D15260_1.2.0` |
| Compal Desktop MEC (Zephyr RTOS) | ARM Cortex-M4 (`CompalA31SWD1402`) | 518,970 B capsule (`ec_1`) | **Plaintext** (`H = 6.787`) | Desktop thermal/PD controller only — no Dell `cmd 0x21` password vault | `Pro_Max_Desktop_with_GB10_FCM1253` |
| ODM Insyde Dual ITE + ENE (`"ene\x00"`) | 8051 (`ITE` + `ENE` dual KBC images) | `$_IFLASH_EC_IMG_` (256 KB / 1 MB) | **Plaintext** (`H = 5.47–6.19`) | Insyde H2O BIOS password storage — no Dell `ALPHABET0` or `7310E28E` | `D14261_1.2.0`, `D14265_1.3.0`, `PV14265_1.3.0`, `Pro_PV15265_1.7.0`, `Inspiron_15_3525_1.36.0` |

### Key Negative Proofs on Sealed EC Payloads & False Positives
- **`"nonFused"` PFS Sections Are Still EC-OTP Encrypted**: Capsules such as `G15_5511` (`ec_7_PHCM_205328.bin`) and `Inspiron_15_3520` (`ec_10`) ship separate `"Fused"` and `"nonFused"` EC sections. `"nonFused"` refers to Intel PCH / BootGuard FPF manufacturing state, **not** the EC OTP key: `hdr[6]` remains `0x80` (`sealed = True`, `H = 7.999`), and zero-key `AES-{128,256}-{CBC,CTR}` tests yield random output (`H = 7.52..7.63`).
- **AMD CRB / PD `PHCM` Blobs**: `PHCM_1701_BIRMAN` (`PB14255`) is AMD's Birman CRB PSP EC stub (`0xAA` padding), and `5048434d00070002/03` 320 KB blobs (`D14265`, `PV14265`) are `Flash-PD` / `SVI3` power-delivery images, not Dell KBC firmware.
- **HII IFR `\xc8\x8f` False Positives**: The 9 `unique_pw/*.efi` modules with `ALPHABET0 = True` and `7310E28E = False` (`0bb9`, `27b9`, `281f`, `4708`, `72df`, `8f7d`, `a2eb`, `e8e8`, `fc83`) are `E7A8`/`BF97` modules where `\xc8\x8f` matched EFI HII IFR header bytes `59 00 00 00 c8 8f ff ff`, not suffix `0x8FC8`.

---

## 2. Plaintext `MEC5085` (ARCompact) Reverse Engineering (`XPS_13_9350_1.13.0/ec_1`)

File: `bios-analysis/collected_latest_ec/models/XPS_13_9350_1.13.0_33773727/ec_1_RAW_PFS_SUBCOMPONENT_262144.bin` (`262,144 B`, ARCompact little-endian / middle-endian 32-bit words, Flash base `0x00000000`, SRAM `0x00800000`, `gp = 0x00800218`).

### 2.1 LPC Host Mailbox & Command Dispatch
- **LPC BAR Initialization (`0x1d6b2..0x1d718`)**:
  - Programs Microchip EC LPC BARs for I/O ports `0x910/0x911` (`0x09108001` -> `[0xFF3474]`) and `0x930..0x934` (`0x09308304` -> `[0xFF3468]`), backing the shared Host Mailbox window at **`0x00FF0110..0x00FF0200`**.
- **Event `0x1E` Command Table (`0x065d4 -> 0x082e4 -> 0x257f8 -> 0x24d4c`)**:
  - `0x065d4` reads `[0x00FF0110]` and invokes `0x082e4(r0 = 0x1E, r1 = cmd_byte)`, which walks `(handler_ptr, (cmd_byte << 16) | flags)` entries starting at `0x24d4c`:

| Entry Offset | `(handler, meta)` | Host `cmd` | Decoded Behavior |
|---|---|---|---|
| `0x24dec` | `(0x00008ef0, 0x00210002)` | **`0x21`** | Branches at `0x08fb8` to **`bl 0x1d3c4` (`ClearPasswordFlags`)**: clears bits `0, 5, 1` of `[gp-196]` and bit `6` of `[gp-197]`, writes status `0`. Proves `MEC5085` predates `cmd 0x21, sub 3` Vault RPC. |
| `0x24df4` | `(0x00008ef0, 0x00240002)` | **`0x24`** | Branches at `0x08fca` to **`bl 0x1d310`**: legacy EC password session (`sub 0 = 0x1d388`, `sub 1 = 0x1d230`, `sub 2 = 0x1d288` streaming 32-byte digest via `cmd 0x17` helper `0x19698` into `0x8005f8..0x800617`, `sub 8 = 0x1d2c0`). |
| `0x24ee4` | `(0x0000944c, 0x00c20002)` | **`0xC2`** | Host state/notification handler (`0x0944c`), invoked by `DellSecurityVaultSmm` `EndOfDxe` callback (`0x1ae4` in `pw_77e7`). |
| `0x1b760` | Secondary KBC/SMM table | **`0x4E`** | Calls **`0x1abfc`** (in-EC 8-character `595B`/`2A7B` master-password generator). |
| `0x1b974` | Secondary KBC/SMM table | **`0x50`** | Calls **`0x1d828`** (in-EC 16-character password verifier against `0x8005f8`). |
| `0x1b86c` / `0x1b82c` | Secondary KBC/SMM table | **`0x51` / `0x5A`** | Exports `0x8005f8` bytes into `0xFF0112..0xFF0131` obfuscated with **`XOR 0x85`** (`xor r2, r2, 133`). |

### 2.2 Exact Decoded In-EC Algorithms (`MEC5085`)
1. **`cmd 0x4E` (`0x1abfc..0x1ad2c`) — 8-Char Master Password Generator**:
   ```python
   EC_ALPH72 = "012345679abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0"  # @ 0x246b4

   def mec5085_cmd4e_generate_8char(tag5: bytes) -> str:
       rev = tag5[::-1]  # 0x80043c[0..4] reversed into sp[8..12]
       groups = [
           rev[0] & 0x1F,
           ((rev[0] >> 5) & 0x07) | ((rev[1] & 0x03) << 3),
           (rev[1] >> 2) & 0x1F,
           ((rev[1] >> 7) & 0x01) | ((rev[2] & 0x0F) << 1),
           ((rev[2] >> 4) & 0x0F) | ((rev[3] & 0x01) << 4),
           (rev[3] >> 1) & 0x1F,
           ((rev[3] >> 6) & 0x03) | ((rev[4] & 0x07) << 2),
           (rev[4] >> 3) & 0x1F,
       ]
       out = []
       for g in groups:
           acc = 0xAA
           for bit in range(5):
               if g & (1 << bit):
                   acc ^= rev[bit]
           out.append(EC_ALPH72[acc % 72])
       return "".join(out)
   ```
2. **`cmd 0x50` (`0x1d828..0x1d89e`) — 16-Char Verifier**:
   ```python
   def mec5085_cmd50_verify_16char(user_pw16: str, ec_sram_8005f8: bytes) -> bool:
       expected = "".join(EC_ALPH72[ec_sram_8005f8[i] % 72] for i in range(16))
       return user_pw16 == expected
   ```

---

## 3. Monolithic `8FC8` Pipeline (`2020–2025` `DellSecurityVaultSmm` + `DellEcIoMm`)

Files analyzed:
- `unique_pw/pw_x86_64_9ba12406f7c1161a_42496.efi` (`XPS 13 9350 1.13.0`)
- `unique_pw/pw_x86_64_e7ae8e2dab7bc924_39424.efi` (`Latitude 3450 1.3.1`)
- `unique_pw/pw_x86_64_25af06756e91ade2_43008.efi` (`OptiPlex 3090 2.27.0+`)
- `unique_pw/pw_x86_64_308bfefc72690c51_38912.efi` (`Latitude 3450 1.23.0` / `G15 5530 1.35.0`)
- `pb14255_smm/DellSecurityVaultSmm_53248.efi` & `pb14255_smm/DellEcIoMm_36864.efi` (`Dell Pro Max 14 PB14255 1.11.0`)

### 3.1 Protocol Handshake & Capability Gate
1. **`DellEcIoMm` (`7310E28E-96EA-4360-946E-5ADC6BE8F531`)**:
   - Exposes vtable methods `+0x00` (read 1 status byte), `+0x20` (single command), `+0x38` (submit 4-byte command header `[rax+0x60]` to EC mailbox `0x400F0110` over LPC I/O ports `0x900+` / `0x910,0x911`, status port `0x934`), `+0x40` (`cmd 0x17` chunked data write), and `+0x48` (`cmd 0x17` chunked data read).
2. **`EC_VAULT_CAP_90306BBD` (`BD6B3090-6936-4DF0-BC73-68B06FB4E791`)**:
   - Checked in `pw_9ba1` (`0x1cb6..0x1ceb`), `pw_77e7` (`0x1a31..0x1a91`), and `Latitude_3450_1.23.0/ec_165` (`0x28fa..0x2974`):
     - `WORD [cap + 0x00]`: Vault protocol version (`>= 1` enables `DellSecurityVaultSmm` `[0xaec8] = 1`; `>= 2` / `>= 3` enables PKI/CertAuth EC storage in `ec_165` / `ec_119`).
     - `BYTE [cap + 0x02]`, `BYTE [cap + 0x03]`: non-zero capability flags required before `7310E28E` is bound.
   - Because `XPS_13_9350_1.13.0` (`MEC5085`) has **no producer** for `90306BBD`, `[0xaec8]` remains `0` even though `pw_9ba1` ships in the BIOS.

### 3.2 Complete `8FC8` Master-Password Pipeline
1. **Stage 1 — `EC_GENERATE` (Hardware-OTP-Encrypted `DEC1515/MEC5200(iFuse)` or `NPCX993D(iFuse)` EC)**:
   - `DellSecurityVaultSmm` (`0x367c..0x3882` in `pw_9ba1`) sends:
     - Header `{0x21, ?, 0x03, 0x06}` via `7310E28E->+0x38`
     - `ServiceTag[0..7]` via `7310E28E->+0x40`
     - `SuffixLowByte` (`0xC8` for `0x8FC8`) via `7310E28E->+0x40`
   - Reads 32-byte `resp32` via `7310E28E->+0x48`.
2. **Stage 2 — `RENDER` (`0x8bc8..0x8ca2` in `pw_9ba1`, identical across 2020–2026 `8FC8` modules)**:
   - Looks up `{0x8FC8, rot_table = NULL, alphabet = ALPHABET0}` in the 24-byte suffix table (`{0x8FC8, NULL, ALPHABET0}`, `{0xE7A8, rot_table, ALPHABET1}`, `{0xFFFF, NULL, NULL}`) and computes:
     $$\text{master}[i] = \text{ALPHABET0}\big[(\text{resp32}[i] + \text{resp32}[i + 16]) \bmod 72\big], \quad i \in \{0,\dots,15\}$$
     where `ALPHABET0 = "0Q2drGk99WLJ1EGnqR5y3DGr16hN4seZPRM2zz2pzcU7JaBXIjbkGZrkQFMxN[Z638myIL2r"`.

---

## 4. 2026 Panther Lake `xx260/xx261` Architectural Shift: Retirement of `8FC8` & `ALPHABET0`

Across Dell's newest 2026 `xx260/xx261` laptops (`XPS_14_DA14260_1.8.2`, `Pro_3_14_P314260_Pro_3_16_P316260_2.4.3`, `Pro_Precision_5_14_PW514261_1.7.0`), Dell replaced the 2024–2025 module triad with a stripped pure-EC Vault triad:

| Role | 2024–2025 (`Latitude 3450 1.23.0` / `G15 5530 1.35.0`) | 2026 `xx260/xx261` (`XPS 14 DA14260 1.8.2` / `Pro 3 P314260 2.4.3`) | Architectural Change |
|---|---|---|---|
| SMM Security Vault | `pw_308b` (`38,912 B`) | **`pw_77e7` (`11,776 B`)** | **70% smaller**: `0x8FC8`, `0xE7A8`, `ALPHABET0`, `ALPHABET1`, and all BIOS-side password derivation/rendering deleted. |
| System / Setup DXE | `pw_3c46` (`22,528 B`) | **`pw_5815` / `pw_3156` (`24,064 B`)** | Suffix list at `raw 0x51c0` changed from `[1B58, 9ABE, 3FE2, CF1B, 8FC8, FFFF]` to **`[1B58, 9ABE, 3FE2, CF1B, FFFF]`**. |
| HDD / NVMe DXE | `pw_6d2c` (`26,624 B`) | **`pw_701c` (`30,720 B`)** | Formats `#***********-CF1B` (`1B58`/`9ABE`/`3FE2`/`CF1B`) prompt (`0x2253..0x2412`). |

### Instruction-Confirmed `pw_77e7` (`11,776 B`) Operations
- **Salted SHA-256 Helper (`0x1848..0x195c`)**: calls `MmCryptLib` SHA-256 (`Init +0x220`, `Update +0x230`, `Final +0x238`) to compute `SHA256(input || 8DFC7B25)` (`8DFC7B25` at `raw 0x2418`).
- **Verify (`0x2304..0x253d`, `cmd 0x21, sub 1, type 3`)**:
  1. `X = SHA256(candidate[0..len] || 8DFC7B25)` (`0x23a7`).
  2. Sends `{0x21, ?, 0x01, 0x03}` (`0x23c7..0x23f5`), writes `X` (32 B, `0x2412`) and `family_u16` (2 B `@0x31a8`, `0x2436`), reads 32-byte `R` (`0x2452`).
  3. `Y = SHA256(X || 8DFC7B25)` (`0x2470`); authentication succeeds iff `CompareMem(R, Y, 32) == 0` (`0x2492`).
- **Master Password RPC (`0x1f60..0x209f -> 0x2874..0x2af8`, `cmd 0x21, sub 3, type 6`)**:
  1. Sanitizes input into 11-byte identity (`0x1d54`) and checks `family_u16 in {0x1B58, 0x9ABE, 0x3FE2, 0xCF1B}` (`0x2027..0x204b`).
  2. Sends `{0x21, ?, 0x03, 0x06}` (`0x2913..0x2942`), writes identity (`0x296a`) and suffix (`0x2a6a`), reads 32-byte `resp32` (`0x2a83`), and copies `resp32[0..15]` directly into the caller's output buffer (`mov r8d, 0x10; call CopyMem` at `0x2aa8..0x2ab5`).

---

## 5. Verification & Reproducibility

Run the standalone analyzer and self-test suite against the collected binaries:

```bash
.venv/bin/python3 bios-analysis/ec_re/analyze_latest_dell_ec.py --selftest
.venv/bin/python3 bios-analysis/ec_re/analyze_latest_dell_ec.py --disasm-mec5085 0x1abfc 0x1ad30
```

### Workspace Artifacts
- `bios-analysis/LATEST_DELL_EC_PASSWORD_REPORT.md` — This technical report.
- `bios-analysis/ec_re/analyze_latest_dell_ec.py` — ARCompact disassembler (`MEC50x5`) + verified implementations of `MEC5085` `cmd 0x4E`/`0x50`, `8FC8` `ALPHABET0` `RENDER`, and `2026` `CF1B` SHA-256 / identity routines.
- `bios-analysis/collect_latest_dell_ec.py` & `.github/workflows/collect-latest-dell-ec.yml` — Automated LVFS + `dl.dell.com`/Wayback Dell EC & UEFI Vault harvester.
- `bios-analysis/collected_latest_ec/` — Curated 16 MB dataset (52 model manifests, representative plaintext & `iFuse`-encrypted EC images, all 40 unique UEFI password modules in `unique_pw/`, and `pb14255_smm/`).
