# Forum real-machine dump analysis (CF1B generation)

## dumps / ifix_02__BACKUP.BIN

- size 33,554,432 B, sha256 `024c88c79d57c7ad...`
- flash descriptor: yes — {'bios': [16777216, 33554431], 'me': [1052672, 16777215]}
- record/store GUID hits: 0
- EC payloads: 2
  - 100,384 B `0f744e7c2553` -> NO PACKAGE MATCH (new EC image!)
  - 98,704 B `cc99360ae24b` -> NO PACKAGE MATCH (new EC image!)
- pw modules: 5
  - 87,040 B `6fc389b459e4` -> NO PACKAGE MATCH (new module!)
  - 42,496 B `b450d1397574` -> collected/OptiPlex_3090_2.0.7/pw_4_42496.efi
  - 31,744 B `bf35c4a2805f` -> collected/OptiPlex_3090_2.0.7/pw_3_31744.efi
  - 23,552 B `f9cdf1278185` -> collected/OptiPlex_3090_2.30.0/pw_1_23552.efi
  - 24,576 B `4cba53c8ace9` -> collected/OptiPlex_3090_2.0.7/pw_2_24576.efi

## dumps / ifix_02__Clean me.bin

- size 33,554,432 B, sha256 `9632bf2af78080d8...`
- flash descriptor: yes — {'bios': [16777216, 33554431], 'me': [1052672, 16777215]}
- record/store GUID hits: 0
- EC payloads: 2
  - 100,384 B `0f744e7c2553` -> NO PACKAGE MATCH (new EC image!)
  - 98,704 B `cc99360ae24b` -> NO PACKAGE MATCH (new EC image!)
- pw modules: 5
  - 87,040 B `6fc389b459e4` -> NO PACKAGE MATCH (new module!)
  - 42,496 B `b450d1397574` -> collected/OptiPlex_3090_2.0.7/pw_4_42496.efi
  - 31,744 B `bf35c4a2805f` -> collected/OptiPlex_3090_2.0.7/pw_3_31744.efi
  - 23,552 B `f9cdf1278185` -> collected/OptiPlex_3090_2.30.0/pw_1_23552.efi
  - 24,576 B `4cba53c8ace9` -> collected/OptiPlex_3090_2.0.7/pw_2_24576.efi

## dumps / ifix_06__3090 Bios Password Unlocked.bin

- size 33,554,432 B, sha256 `aab0ff9364809a97...`
- flash descriptor: yes — {'bios': [16777216, 33554431], 'me': [1060864, 16777215], 'gbe': [1052672, 1060863]}
- record/store GUID hits: 0
- EC payloads: 2
  - 102,048 B `e96f2c0a2726` -> collected/OptiPlex_3090_2.0.7/ec_3_102080.bin (machine image = package image prefix, pkg 102,080 B)
  - 102,096 B `a31359167e03` -> collected/OptiPlex_3090_2.0.7/ec_4_102096.bin
- pw modules: 5
  - 87,040 B `b65a35c0f776` -> collected/OptiPlex_3090_2.0.7/pw_5_87040.efi
  - 42,496 B `b450d1397574` -> collected/OptiPlex_3090_2.0.7/pw_4_42496.efi
  - 31,744 B `bf35c4a2805f` -> collected/OptiPlex_3090_2.0.7/pw_3_31744.efi
  - 23,552 B `f9cdf1278185` -> collected/OptiPlex_3090_2.30.0/pw_1_23552.efi
  - 24,576 B `4cba53c8ace9` -> collected/OptiPlex_3090_2.0.7/pw_2_24576.efi

## dumps / ifix_07__W25Q512NW@WSON8 8X6_20260423_181304 OFF.bin

- size 67,108,864 B, sha256 `db2cbcbb6c835688...`
- flash descriptor: no
- record/store GUID hits: 0
- EC payloads: 2
  - 261,888 B `db81defd3b79` -> NO PACKAGE MATCH (new EC image!)
  - 217,248 B `1c9f096c4154` -> NO PACKAGE MATCH (new EC image!)

## dumps / ifix_09__OptiPlex 7480 All-In-One ipcml-gz uma 1.10.0.bin

- size 33,554,432 B, sha256 `191042391daa774b...`
- flash descriptor: yes — {'bios': [16777216, 33554431], 'me': [1060864, 16777215], 'gbe': [1052672, 1060863]}
- record/store GUID hits: 0
- EC payloads: 2
  - 89,312 B `fe2c1160dd7b` -> NO PACKAGE MATCH (new EC image!)
  - 88,848 B `290329d9336c` -> NO PACKAGE MATCH (new EC image!)
- pw modules: 5
  - 85,504 B `d53d4e274f27` -> NO PACKAGE MATCH (new module!)
  - 43,008 B `a9eb964a8a08` -> NO PACKAGE MATCH (new module!)
  - 31,744 B `bf35c4a2805f` -> collected/OptiPlex_3090_2.0.7/pw_3_31744.efi
  - 23,552 B `f9cdf1278185` -> collected/OptiPlex_3090_2.30.0/pw_1_23552.efi
  - 24,576 B `4cba53c8ace9` -> collected/OptiPlex_3090_2.0.7/pw_2_24576.efi

## dumps / ifix_12__Clean cseme.bin

- size 33,554,432 B, sha256 `3528349a4915d051...`
- flash descriptor: yes — {'bios': [16777216, 33554431], 'me': [1060864, 16777215], 'gbe': [1052672, 1060863]}
- record/store GUID hits: 0
- EC payloads: 2
  - 102,048 B `e96f2c0a2726` -> collected/OptiPlex_3090_2.0.7/ec_3_102080.bin (machine image = package image prefix, pkg 102,080 B)
  - 102,096 B `a31359167e03` -> collected/OptiPlex_3090_2.0.7/ec_4_102096.bin
- pw modules: 5
  - 87,040 B `b65a35c0f776` -> collected/OptiPlex_3090_2.0.7/pw_5_87040.efi
  - 42,496 B `b450d1397574` -> collected/OptiPlex_3090_2.0.7/pw_4_42496.efi
  - 31,744 B `bf35c4a2805f` -> collected/OptiPlex_3090_2.0.7/pw_3_31744.efi
  - 23,552 B `f9cdf1278185` -> collected/OptiPlex_3090_2.30.0/pw_1_23552.efi
  - 24,576 B `4cba53c8ace9` -> collected/OptiPlex_3090_2.0.7/pw_2_24576.efi

## dumps / ifix_13__Alienware Aurora R12 .bin

- size 33,554,432 B, sha256 `a4286118dfa8fa6f...`
- flash descriptor: yes — {'bios': [20971520, 33554431], 'me': [4096, 16781311]}
- record/store GUID hits: 0

## ifix_03 / 2 TroyAdl_16.1.27.2176_EVT_64 v1.17.0 -- 1 System BIOS with BiosGuard v1.17.0.bin

- size 33,554,432 B, sha256 `05dfe72baa0dddda...`
- flash descriptor: no
- record/store GUID hits: 0
- pw modules: 8
  - 52,736 B `3660c5cf065c` -> NO PACKAGE MATCH (new module!)
  - 18,432 B `db8defcd6bdf` -> NO PACKAGE MATCH (new module!)
  - 23,040 B `4d40d53b986a` -> NO PACKAGE MATCH (new module!)
  - 28,672 B `36d9ceea7688` -> NO PACKAGE MATCH (new module!)
  - 20,992 B `b706ecc3cf8f` -> NO PACKAGE MATCH (new module!)
  - 45,568 B `1678be77f0e6` -> NO PACKAGE MATCH (new module!)
  - 17,408 B `1cb7f92bd63b` -> NO PACKAGE MATCH (new module!)
  - 39,424 B `66d4b9d4c38c` -> NO PACKAGE MATCH (new module!)

## ifix_14 / OptiPlex 3090 main_ok try First IF not Power On Try Another.bin

- size 33,554,432 B, sha256 `ce6cfe3722a2a929...`
- flash descriptor: yes — {'bios': [16777216, 33554431], 'me': [1060864, 16777215], 'gbe': [1052672, 1060863]}
- record/store GUID hits: 0
- EC payloads: 2
  - 102,560 B `21b0467a303b` -> NO PACKAGE MATCH (new EC image!)
  - 102,096 B `e4f7ba6b9692` -> NO PACKAGE MATCH (new EC image!)
- pw modules: 5
  - 87,040 B `9355de901c85` -> collected/OptiPlex_3090_2.30.0/pw_5_87040.efi
  - 42,496 B `b450d1397574` -> collected/OptiPlex_3090_2.0.7/pw_4_42496.efi
  - 31,744 B `bf35c4a2805f` -> collected/OptiPlex_3090_2.0.7/pw_3_31744.efi
  - 23,552 B `f9cdf1278185` -> collected/OptiPlex_3090_2.30.0/pw_1_23552.efi
  - 24,576 B `4cba53c8ace9` -> collected/OptiPlex_3090_2.0.7/pw_2_24576.efi

## ifix_14 / OptiPlex 3090 main_New ok.bin

- size 33,554,432 B, sha256 `244ba6c663e5fd2b...`
- flash descriptor: yes — {'bios': [16777216, 33554431], 'me': [1060864, 16777215], 'gbe': [1052672, 1060863]}
- record/store GUID hits: 0
- EC payloads: 2
  - 102,560 B `21b0467a303b` -> NO PACKAGE MATCH (new EC image!)
  - 102,096 B `e4f7ba6b9692` -> NO PACKAGE MATCH (new EC image!)
- pw modules: 5
  - 87,040 B `b65a35c0f776` -> collected/OptiPlex_3090_2.0.7/pw_5_87040.efi
  - 42,496 B `b450d1397574` -> collected/OptiPlex_3090_2.0.7/pw_4_42496.efi
  - 31,744 B `bf35c4a2805f` -> collected/OptiPlex_3090_2.0.7/pw_3_31744.efi
  - 23,552 B `f9cdf1278185` -> collected/OptiPlex_3090_2.30.0/pw_1_23552.efi
  - 24,576 B `4cba53c8ace9` -> collected/OptiPlex_3090_2.0.7/pw_2_24576.efi

## ifix_17 / Optiplex 7000 micro UNLOCKED.bin

- size 16,777,216 B, sha256 `d981b34dc806041e...`
- flash descriptor: yes — {'me': [1060864, 10948607], 'gbe': [1052672, 1060863]}
- record/store GUID hits: 0
- EC payloads: 2
  - 205,280 B `480332b0e244` -> NO PACKAGE MATCH (new EC image!)
  - 205,328 B `fc6fb13d0455` -> NO PACKAGE MATCH (new EC image!)

## ifix_17 / OK BACKUP.BIN

- size 16,777,216 B, sha256 `5d158745b4c5b986...`
- flash descriptor: yes — {'me': [1060864, 10948607], 'gbe': [1052672, 1060863]}
- record/store GUID hits: 0
- EC payloads: 2
  - 205,280 B `fdeeed49380c` -> NO PACKAGE MATCH (new EC image!)
  - 205,328 B `fc6fb13d0455` -> NO PACKAGE MATCH (new EC image!)

## ifix_17 / OK BACKUP 32MB.BIN

- size 33,554,432 B, sha256 `2b26e9a89b6b0824...`
- flash descriptor: no
- record/store GUID hits: 0
- pw modules: 8
  - 37,888 B `d34e4bf74d51` -> NO PACKAGE MATCH (new module!)
  - 18,432 B `6ab0e65f176d` -> NO PACKAGE MATCH (new module!)
  - 23,040 B `fa100de56dc7` -> NO PACKAGE MATCH (new module!)
  - 28,672 B `51d0f56a73ff` -> NO PACKAGE MATCH (new module!)
  - 20,992 B `5e2e52826e2f` -> NO PACKAGE MATCH (new module!)
  - 45,056 B `06a8cb22de60` -> NO PACKAGE MATCH (new module!)
  - 17,408 B `63f303085344` -> NO PACKAGE MATCH (new module!)
  - 39,424 B `fe3b77c1474c` -> NO PACKAGE MATCH (new module!)

## ifix_19 / Precision 3640 Tower TRY FIRST IF NOT WORK TRY _1.bin

- size 33,554,432 B, sha256 `ce337d491a6850e3...`
- flash descriptor: yes — {'bios': [16777216, 33554431], 'me': [1060864, 16777215], 'gbe': [1052672, 1060863]}
- record/store GUID hits: 0
- EC payloads: 2
  - 88,928 B `bb02aabd7cd9` -> NO PACKAGE MATCH (new EC image!)
  - 83,216 B `30cf3250e6b3` -> NO PACKAGE MATCH (new EC image!)
- pw modules: 5
  - 87,040 B `9355de901c85` -> collected/OptiPlex_3090_2.30.0/pw_5_87040.efi
  - 43,008 B `a9eb964a8a08` -> NO PACKAGE MATCH (new module!)
  - 31,744 B `bf35c4a2805f` -> collected/OptiPlex_3090_2.0.7/pw_3_31744.efi
  - 23,552 B `a6dbab710bd3` -> NO PACKAGE MATCH (new module!)
  - 24,576 B `4cba53c8ace9` -> collected/OptiPlex_3090_2.0.7/pw_2_24576.efi

## ifix_19 / Precision 3640 Tower_1.bin

- size 33,554,432 B, sha256 `9008024447fed7eb...`
- flash descriptor: yes — {'bios': [16777216, 33554431], 'me': [1060864, 16777215], 'gbe': [1052672, 1060863]}
- record/store GUID hits: 0
- EC payloads: 2
  - 88,928 B `bb02aabd7cd9` -> NO PACKAGE MATCH (new EC image!)
  - 83,216 B `30cf3250e6b3` -> NO PACKAGE MATCH (new EC image!)
- pw modules: 5
  - 87,040 B `9355de901c85` -> collected/OptiPlex_3090_2.30.0/pw_5_87040.efi
  - 43,008 B `a9eb964a8a08` -> NO PACKAGE MATCH (new module!)
  - 31,744 B `bf35c4a2805f` -> collected/OptiPlex_3090_2.0.7/pw_3_31744.efi
  - 23,552 B `a6dbab710bd3` -> NO PACKAGE MATCH (new module!)
  - 24,576 B `4cba53c8ace9` -> collected/OptiPlex_3090_2.0.7/pw_2_24576.efi

## ifix_21 / Alienware Aurora R110  IPCML-SH REV A00.bin

- size 33,554,432 B, sha256 `b0e98a7b56a55166...`
- flash descriptor: yes — {'bios': [22020096, 33554431], 'me': [4096, 16781311]}
- record/store GUID hits: 0

## ifix_22 / Dell Pro 14 Plus Dell_Pro_Plus_PB13255_PB14255_PB16255_1.11.0 AMD.bin

- size 67,108,864 B, sha256 `b536fbb6aae4e023...`
- flash descriptor: no
- record/store GUID hits: 0
- EC payloads: 2
  - 261,888 B `3f72c70a3070` -> NO PACKAGE MATCH (new EC image!)
  - 211,104 B `fc00540316ac` -> NO PACKAGE MATCH (new EC image!)

## ifix_23 / 32MB.BIN

- size 33,554,432 B, sha256 `390c0bef44c33ee7...`
- flash descriptor: yes — {'bios': [16777216, 33554431], 'me': [1060864, 16777215], 'gbe': [1052672, 1060863]}
- record/store GUID hits: 0
- EC payloads: 2
  - 102,048 B `67bd6123d86e` -> NO PACKAGE MATCH (new EC image!)
  - 102,096 B `e4f7ba6b9692` -> NO PACKAGE MATCH (new EC image!)
- pw modules: 5
  - 87,040 B `9355de901c85` -> collected/OptiPlex_3090_2.30.0/pw_5_87040.efi
  - 42,496 B `b450d1397574` -> collected/OptiPlex_3090_2.0.7/pw_4_42496.efi
  - 31,744 B `bf35c4a2805f` -> collected/OptiPlex_3090_2.0.7/pw_3_31744.efi
  - 23,552 B `f9cdf1278185` -> collected/OptiPlex_3090_2.30.0/pw_1_23552.efi
  - 24,576 B `4cba53c8ace9` -> collected/OptiPlex_3090_2.0.7/pw_2_24576.efi

## ifix_25 / optiplex_3090.bin

- size 33,554,432 B, sha256 `27b7054bf14d2e96...`
- flash descriptor: yes — {'bios': [16777216, 33554431], 'me': [1060864, 16777215], 'gbe': [1052672, 1060863]}
- record/store GUID hits: 0
- EC payloads: 2
  - 102,048 B `e96f2c0a2726` -> collected/OptiPlex_3090_2.0.7/ec_3_102080.bin (machine image = package image prefix, pkg 102,080 B)
  - 102,096 B `a31359167e03` -> collected/OptiPlex_3090_2.0.7/ec_4_102096.bin
- pw modules: 5
  - 87,040 B `9355de901c85` -> collected/OptiPlex_3090_2.30.0/pw_5_87040.efi
  - 42,496 B `b450d1397574` -> collected/OptiPlex_3090_2.0.7/pw_4_42496.efi
  - 31,744 B `bf35c4a2805f` -> collected/OptiPlex_3090_2.0.7/pw_3_31744.efi
  - 23,552 B `f9cdf1278185` -> collected/OptiPlex_3090_2.30.0/pw_1_23552.efi
  - 24,576 B `4cba53c8ace9` -> collected/OptiPlex_3090_2.0.7/pw_2_24576.efi

## ifix_28 / Dell XPS 13 9350 AAZ80 LA-C881P DINO2 MB 1.0 A00 Clear me.bin

- size 16,777,216 B, sha256 `8adfcf83cdd80315...`
- flash descriptor: yes — {'bios': [7340032, 16777215], 'me': [4096, 7340031]}
- record/store GUID hits: 0

## ifix_30 / ok  E6520 LA-6562p.BIN

- size 8,388,608 B, sha256 `0a4c7be9d06aec30...`
- flash descriptor: yes — {'bios': [6291456, 8388607], 'me': [20480, 6291455], 'gbe': [4096, 20479]}
- record/store GUID hits: 0

## ifix_30 / ok EC E6520 LA-6562p.BIN

- size 2,097,152 B, sha256 `96371485dc66b047...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_34 / 11.0.0.1205_CON_LP_C_NPDM_PRD_RGN_outimage.bin

- size 16,777,216 B, sha256 `de4aafd707cde686...`
- flash descriptor: yes — {'bios': [7340032, 16777215], 'me': [4096, 7340031]}
- record/store GUID hits: 0

## ifix_36 / W25Q32_20161217_50656.BIN

- size 4,194,304 B, sha256 `52e56f5d98c35404...`
- flash descriptor: no
- record/store GUID hits: 0
- pw modules: 1
  - 63,168 B `ea17b214bb40` -> NO PACKAGE MATCH (new module!)

## ifix_37 / 8MB.bin

- size 8,388,608 B, sha256 `94dc5a7c904607c3...`
- flash descriptor: yes — {'bios': [6291456, 8388607], 'me': [20480, 6291455], 'gbe': [4096, 20479]}
- record/store GUID hits: 2
  - X_enrolled candidate @0x6013D9+0x10: `fddf63699cab04a214632236591ef90b2537c6c961945d06ffc065a214632236`
  - X_enrolled candidate @0x6013D9+0x11: `df63699cab04a214632236591ef90b2537c6c961945d06ffc065a21463223659`
  - X_enrolled candidate @0x6013D9+0x12: `63699cab04a214632236591ef90b2537c6c961945d06ffc065a214632236591e`
  - X_enrolled candidate @0x6013D9+0x13: `699cab04a214632236591ef90b2537c6c961945d06ffc065a214632236591efa`
  - X_enrolled candidate @0x6013D9+0x14: `9cab04a214632236591ef90b2537c6c961945d06ffc065a214632236591efafe`
  - X_enrolled candidate @0x6013D9+0x15: `ab04a214632236591ef90b2537c6c961945d06ffc065a214632236591efafeff`
  - X_enrolled candidate @0x6013D9+0x16: `04a214632236591ef90b2537c6c961945d06ffc065a214632236591efafefff8`
  - X_enrolled candidate @0x6013D9+0x17: `a214632236591ef90b2537c6c961945d06ffc065a214632236591efafefff8f8`
  - X_enrolled candidate @0x6013D9+0x18: `14632236591ef90b2537c6c961945d06ffc065a214632236591efafefff8f8f9`
  - X_enrolled candidate @0x6013D9+0x19: `632236591ef90b2537c6c961945d06ffc065a214632236591efafefff8f8f943`
  - X_enrolled candidate @0x6013D9+0x1A: `2236591ef90b2537c6c961945d06ffc065a214632236591efafefff8f8f9436f`
  - X_enrolled candidate @0x6013D9+0x1B: `36591ef90b2537c6c961945d06ffc065a214632236591efafefff8f8f9436f6e`
  - X_enrolled candidate @0x6013D9+0x1C: `591ef90b2537c6c961945d06ffc065a214632236591efafefff8f8f9436f6e4f`
  - X_enrolled candidate @0x6013D9+0x1D: `1ef90b2537c6c961945d06ffc065a214632236591efafefff8f8f9436f6e4f75`
  - X_enrolled candidate @0x6013D9+0x1E: `f90b2537c6c961945d06ffc065a214632236591efafefff8f8f9436f6e4f7574`
  - X_enrolled candidate @0x6013D9+0x1F: `0b2537c6c961945d06ffc065a214632236591efafefff8f8f9436f6e4f7574db`
  - X_enrolled candidate @0x6013D9+0x20: `2537c6c961945d06ffc065a214632236591efafefff8f8f9436f6e4f7574db02`
  - X_enrolled candidate @0x6013D9+0x21: `37c6c961945d06ffc065a214632236591efafefff8f8f9436f6e4f7574db0201`
  - X_enrolled candidate @0x6013D9+0x22: `c6c961945d06ffc065a214632236591efafefff8f8f9436f6e4f7574db02010c`
  - X_enrolled candidate @0x6013D9+0x23: `c961945d06ffc065a214632236591efafefff8f8f9436f6e4f7574db02010c00`
  - X_enrolled candidate @0x6013D9+0x24: `61945d06ffc065a214632236591efafefff8f8f9436f6e4f7574db02010c00d0`
  - X_enrolled candidate @0x6013D9+0x25: `945d06ffc065a214632236591efafefff8f8f9436f6e4f7574db02010c00d041`
  - X_enrolled candidate @0x6013D9+0x26: `5d06ffc065a214632236591efafefff8f8f9436f6e4f7574db02010c00d04103`
  - X_enrolled candidate @0x6013D9+0x27: `06ffc065a214632236591efafefff8f8f9436f6e4f7574db02010c00d041030a`
  - X_enrolled candidate @0x6013D9+0x28: `ffc065a214632236591efafefff8f8f9436f6e4f7574db02010c00d041030a00`
  - X_enrolled candidate @0x6013D9+0x29: `c065a214632236591efafefff8f8f9436f6e4f7574db02010c00d041030a0000`
  - X_enrolled candidate @0x6013D9+0x2A: `65a214632236591efafefff8f8f9436f6e4f7574db02010c00d041030a000000`
  - X_enrolled candidate @0x6013D9+0x2B: `a214632236591efafefff8f8f9436f6e4f7574db02010c00d041030a00000000`
  - X_enrolled candidate @0x6013D9+0x2C: `14632236591efafefff8f8f9436f6e4f7574db02010c00d041030a0000000001`
  - X_enrolled candidate @0x6013D9+0x2D: `632236591efafefff8f8f9436f6e4f7574db02010c00d041030a000000000101`
  - X_enrolled candidate @0x6013D9+0x2E: `2236591efafefff8f8f9436f6e4f7574db02010c00d041030a00000000010106`
  - X_enrolled candidate @0x6013D9+0x2F: `36591efafefff8f8f9436f6e4f7574db02010c00d041030a0000000001010600`
  - X_enrolled candidate @0x6013D9+0x30: `591efafefff8f8f9436f6e4f7574db02010c00d041030a000000000101060000`
  - X_enrolled candidate @0x6013D9+0x31: `1efafefff8f8f9436f6e4f7574db02010c00d041030a00000000010106000001`
  - X_enrolled candidate @0x6013D9+0x32: `fafefff8f8f9436f6e4f7574db02010c00d041030a0000000001010600000101`
  - X_enrolled candidate @0x6013D9+0x33: `fefff8f8f9436f6e4f7574db02010c00d041030a000000000101060000010101`
  - X_enrolled candidate @0x6013D9+0x34: `fff8f8f9436f6e4f7574db02010c00d041030a00000000010106000001010106`
  - X_enrolled candidate @0x6013D9+0x35: `f8f8f9436f6e4f7574db02010c00d041030a0000000001010600000101010600`
  - X_enrolled candidate @0x6013D9+0x36: `f8f9436f6e4f7574db02010c00d041030a000000000101060000010101060000`
  - X_enrolled candidate @0x6013D9+0x37: `f9436f6e4f7574db02010c00d041030a00000000010106000001010106000000`
  - X_enrolled candidate @0x6013D9+0x38: `436f6e4f7574db02010c00d041030a0000000001010600000101010600000002`
  - X_enrolled candidate @0x6013D9+0x39: `6f6e4f7574db02010c00d041030a000000000101060000010101060000000203`
  - X_enrolled candidate @0x6013D9+0x3A: `6e4f7574db02010c00d041030a00000000010106000001010106000000020308`
  - X_enrolled candidate @0x6013D9+0x3B: `4f7574db02010c00d041030a0000000001010600000101010600000002030800`
  - X_enrolled candidate @0x6013D9+0x3C: `7574db02010c00d041030a000000000101060000010101060000000203080000`
  - X_enrolled candidate @0x6013D9+0x3D: `74db02010c00d041030a00000000010106000001010106000000020308000001`
  - X_enrolled candidate @0x6013D9+0x3E: `db02010c00d041030a0000000001010600000101010600000002030800000101`
  - X_enrolled candidate @0x6013D9+0x3F: `02010c00d041030a000000000101060000010101060000000203080000010180`
  - X_enrolled candidate @0x6013D9+0x40: `010c00d041030a0000000001010600000101010600000002030800000101807f`
  - X_enrolled candidate @0x6113AF+0x10: `fddf63699cab04a214632236591ef90b2537c6c961945d06ffc065a214632236`
  - X_enrolled candidate @0x6113AF+0x11: `df63699cab04a214632236591ef90b2537c6c961945d06ffc065a21463223659`
  - X_enrolled candidate @0x6113AF+0x12: `63699cab04a214632236591ef90b2537c6c961945d06ffc065a214632236591e`
  - X_enrolled candidate @0x6113AF+0x13: `699cab04a214632236591ef90b2537c6c961945d06ffc065a214632236591efa`
  - X_enrolled candidate @0x6113AF+0x14: `9cab04a214632236591ef90b2537c6c961945d06ffc065a214632236591efafe`
  - X_enrolled candidate @0x6113AF+0x15: `ab04a214632236591ef90b2537c6c961945d06ffc065a214632236591efafeff`
  - X_enrolled candidate @0x6113AF+0x16: `04a214632236591ef90b2537c6c961945d06ffc065a214632236591efafefff8`
  - X_enrolled candidate @0x6113AF+0x17: `a214632236591ef90b2537c6c961945d06ffc065a214632236591efafefff8f8`
  - X_enrolled candidate @0x6113AF+0x18: `14632236591ef90b2537c6c961945d06ffc065a214632236591efafefff8f8f9`
  - X_enrolled candidate @0x6113AF+0x19: `632236591ef90b2537c6c961945d06ffc065a214632236591efafefff8f8f943`
  - X_enrolled candidate @0x6113AF+0x1A: `2236591ef90b2537c6c961945d06ffc065a214632236591efafefff8f8f9436f`
  - X_enrolled candidate @0x6113AF+0x1B: `36591ef90b2537c6c961945d06ffc065a214632236591efafefff8f8f9436f6e`
  - X_enrolled candidate @0x6113AF+0x1C: `591ef90b2537c6c961945d06ffc065a214632236591efafefff8f8f9436f6e4f`
  - X_enrolled candidate @0x6113AF+0x1D: `1ef90b2537c6c961945d06ffc065a214632236591efafefff8f8f9436f6e4f75`
  - X_enrolled candidate @0x6113AF+0x1E: `f90b2537c6c961945d06ffc065a214632236591efafefff8f8f9436f6e4f7574`
  - X_enrolled candidate @0x6113AF+0x1F: `0b2537c6c961945d06ffc065a214632236591efafefff8f8f9436f6e4f7574db`
  - X_enrolled candidate @0x6113AF+0x20: `2537c6c961945d06ffc065a214632236591efafefff8f8f9436f6e4f7574db02`
  - X_enrolled candidate @0x6113AF+0x21: `37c6c961945d06ffc065a214632236591efafefff8f8f9436f6e4f7574db0201`
  - X_enrolled candidate @0x6113AF+0x22: `c6c961945d06ffc065a214632236591efafefff8f8f9436f6e4f7574db02010c`
  - X_enrolled candidate @0x6113AF+0x23: `c961945d06ffc065a214632236591efafefff8f8f9436f6e4f7574db02010c00`
  - X_enrolled candidate @0x6113AF+0x24: `61945d06ffc065a214632236591efafefff8f8f9436f6e4f7574db02010c00d0`
  - X_enrolled candidate @0x6113AF+0x25: `945d06ffc065a214632236591efafefff8f8f9436f6e4f7574db02010c00d041`
  - X_enrolled candidate @0x6113AF+0x26: `5d06ffc065a214632236591efafefff8f8f9436f6e4f7574db02010c00d04103`
  - X_enrolled candidate @0x6113AF+0x27: `06ffc065a214632236591efafefff8f8f9436f6e4f7574db02010c00d041030a`
  - X_enrolled candidate @0x6113AF+0x28: `ffc065a214632236591efafefff8f8f9436f6e4f7574db02010c00d041030a00`
  - X_enrolled candidate @0x6113AF+0x29: `c065a214632236591efafefff8f8f9436f6e4f7574db02010c00d041030a0000`
  - X_enrolled candidate @0x6113AF+0x2A: `65a214632236591efafefff8f8f9436f6e4f7574db02010c00d041030a000000`
  - X_enrolled candidate @0x6113AF+0x2B: `a214632236591efafefff8f8f9436f6e4f7574db02010c00d041030a00000000`
  - X_enrolled candidate @0x6113AF+0x2C: `14632236591efafefff8f8f9436f6e4f7574db02010c00d041030a0000000001`
  - X_enrolled candidate @0x6113AF+0x2D: `632236591efafefff8f8f9436f6e4f7574db02010c00d041030a000000000101`
  - X_enrolled candidate @0x6113AF+0x2E: `2236591efafefff8f8f9436f6e4f7574db02010c00d041030a00000000010106`
  - X_enrolled candidate @0x6113AF+0x2F: `36591efafefff8f8f9436f6e4f7574db02010c00d041030a0000000001010600`
  - X_enrolled candidate @0x6113AF+0x30: `591efafefff8f8f9436f6e4f7574db02010c00d041030a000000000101060000`
  - X_enrolled candidate @0x6113AF+0x31: `1efafefff8f8f9436f6e4f7574db02010c00d041030a00000000010106000001`
  - X_enrolled candidate @0x6113AF+0x32: `fafefff8f8f9436f6e4f7574db02010c00d041030a0000000001010600000101`
  - X_enrolled candidate @0x6113AF+0x33: `fefff8f8f9436f6e4f7574db02010c00d041030a000000000101060000010101`
  - X_enrolled candidate @0x6113AF+0x34: `fff8f8f9436f6e4f7574db02010c00d041030a00000000010106000001010106`
  - X_enrolled candidate @0x6113AF+0x35: `f8f8f9436f6e4f7574db02010c00d041030a0000000001010600000101010600`
  - X_enrolled candidate @0x6113AF+0x36: `f8f9436f6e4f7574db02010c00d041030a000000000101060000010101060000`
  - X_enrolled candidate @0x6113AF+0x37: `f9436f6e4f7574db02010c00d041030a00000000010106000001010106000000`
  - X_enrolled candidate @0x6113AF+0x38: `436f6e4f7574db02010c00d041030a0000000001010600000101010600000002`
  - X_enrolled candidate @0x6113AF+0x39: `6f6e4f7574db02010c00d041030a000000000101060000010101060000000203`
  - X_enrolled candidate @0x6113AF+0x3A: `6e4f7574db02010c00d041030a00000000010106000001010106000000020308`
  - X_enrolled candidate @0x6113AF+0x3B: `4f7574db02010c00d041030a0000000001010600000101010600000002030800`
  - X_enrolled candidate @0x6113AF+0x3C: `7574db02010c00d041030a000000000101060000010101060000000203080000`
  - X_enrolled candidate @0x6113AF+0x3D: `74db02010c00d041030a00000000010106000001010106000000020308000001`
  - X_enrolled candidate @0x6113AF+0x3E: `db02010c00d041030a0000000001010600000101010600000002030800000101`
  - X_enrolled candidate @0x6113AF+0x3F: `02010c00d041030a000000000101060000010101060000000203080000010180`
  - X_enrolled candidate @0x6113AF+0x40: `010c00d041030a0000000001010600000101010600000002030800000101807f`

## ifix_54 / 6.2.10.1027_5MB_DT_PRD_UPD.bin

- size 4,214,752 B, sha256 `4262bc3f2f50950c...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.2.0.1022_5MB_DT_PRD_UPD.bin

- size 4,214,736 B, sha256 `9289e8d7b1b42dee...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.3.1219_5MB_MB_PRD_UPD.bin

- size 4,219,168 B, sha256 `5cd00f5ce95e25f4...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.1.0.1042_5MB_DT_PRD_UPD.bin

- size 4,215,136 B, sha256 `e43c610d6bf65743...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.1.20.1059_5MB_MB_PRD_UPD.bin

- size 4,219,360 B, sha256 `2672a16846167bdd...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.2.20.1035_5MB_MB_PRD_UPD.bin

- size 4,219,424 B, sha256 `db3f625babcf26d4...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.2.0.1022_5MB_MB_PRD_UPD.bin

- size 4,219,424 B, sha256 `7107f2998352c0a9...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.4.1205_5MB_MB_PRD_UPD.bin

- size 4,219,168 B, sha256 `15ca228418732d07...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.41.1216_5MB_MB_PRD_UPD.bin

- size 4,219,168 B, sha256 `457faa89caface1f...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.31.1208_5MB_MB_PRD_UPD.bin

- size 4,219,168 B, sha256 `60448b5e53d172af...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.2.60.1066_5MB_DT_PRD_UPD.bin

- size 4,214,752 B, sha256 `a8ddaaba01d2e0ac...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.1.1.1045_5MB_DT_PRD_UPD.bin

- size 4,215,136 B, sha256 `d3b9374df64cdec2...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.40.1215_5MB_DT_PRD_UPD.bin

- size 4,214,944 B, sha256 `58133148b6430a9b...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.30.1203_5MB_MB_PRD_UPD.bin

- size 4,219,168 B, sha256 `9cdc24a8994a59e9...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.1.32.1076_5MB_DT_PRD_UPD.bin

- size 4,215,136 B, sha256 `6e3caf91cda6a8c6...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.2.1194_5MB_DT_PRD_UPD.bin

- size 4,214,944 B, sha256 `1bf6500d68cccfee...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.2.1194_5MB_MB_PRD_UPD.bin

- size 4,219,168 B, sha256 `e7fa2f5573e9368e...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.1.30.1074_5MB_DT_PRD_UPD.bin

- size 4,215,136 B, sha256 `6cfd7724c2c081a7...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.2.10.1027_5MB_MB_PRD_UPD.bin

- size 4,219,424 B, sha256 `994a0d621fb6b244...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.1.0.1042_5MB_MB_PRD_UPD.bin

- size 4,219,360 B, sha256 `484e73c625330ab9...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.30.1203_5MB_DT_PRD_UPD.bin

- size 4,214,944 B, sha256 `1e7c75ca681ea0fa...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.1.10.1052_5MB_MB_PRD_UPD.bin

- size 4,219,360 B, sha256 `22c2b7ea6d913db1...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.3.1195_5MB_DT_PRD_UPD.bin

- size 4,214,928 B, sha256 `92cc472bc9373cec...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.2.60.1066_5MB_MB_PRD_UPD.bin

- size 4,219,424 B, sha256 `158b0affc534c92c...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.2.20.1035_5MB_DT_PRD_UPD.bin

- size 4,214,752 B, sha256 `861d87add2dac9df...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.1.31.1075_5MB_MB_PRD_UPD.bin

- size 4,219,360 B, sha256 `bac68bed93665e7d...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.0.1184_5MB_MB_PRD_UPD.bin

- size 4,219,168 B, sha256 `143c74776eb75977...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.2.30.1040_5MB_DT_PRD_UPD.bin

- size 4,214,736 B, sha256 `fafc4c61b8af1018...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.1.10.1052_5MB_DT_PRD_UPD.bin

- size 4,215,120 B, sha256 `9ebfad6ed3f7cf22...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.0.1184_5MB_DT_PRD_UPD.bin

- size 4,214,944 B, sha256 `45cc007b97c6e588...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.2.40.1045_5MB_MB_PRD_UPD.bin

- size 4,219,424 B, sha256 `2383f9ed9d71a8a7...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.2.50.1062_5MB_DT_PRD_UPD.bin

- size 4,214,752 B, sha256 `b4c88b922f1e713f...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.1.20.1059_5MB_DT_PRD_UPD.bin

- size 4,215,136 B, sha256 `1c9c6526c559a1f4...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.2.50.1062_5MB_MB_PRD_UPD.bin

- size 4,219,424 B, sha256 `6016255c75228cbd...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.1.32.1076_5MB_MB_PRD_UPD.bin

- size 4,219,360 B, sha256 `b93ce1509ebc4c75...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.1.30.1074_5MB_MB_PRD_UPD.bin

- size 4,219,360 B, sha256 `9b3857e5b79c9a51...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.31.1208_5MB_DT_PRD_UPD.bin

- size 4,214,944 B, sha256 `e387590776b0d28f...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.2.30.1040_5MB_MB_PRD_UPD.bin

- size 4,219,424 B, sha256 `df0a0812035fd6ad...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.1.0.1042_5MB_MB_PRD_EXTR.bin

- size 6,279,168 B, sha256 `b6d0c995aef32454...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.0.1115_5MB_DT_PRE_UPD.bin

- size 4,214,624 B, sha256 `b7bc8f1c436528dc...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.1.10.1052_5MB_MB_PRD_EXTR.bin

- size 5,185,536 B, sha256 `0e53ca7f0d666026...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.2.10.1027_5MB_DT_PRD_EXTR.bin

- size 3,436,544 B, sha256 `8c2dc12bfab86bd4...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.0.1115_5MB_MB_PRE_UPD.bin

- size 4,218,784 B, sha256 `4f16a51fe959af8b...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.0.1184_5MB_DT_PRD_RGN.bin

- size 5,185,536 B, sha256 `a359ac5243161eed...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.2.50.1062_5MB_DT_PRD_EXTR.bin

- size 3,440,640 B, sha256 `e67da5363a904eb2...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.0.1115_5MB_DT_PRE_RGN.bin

- size 5,185,536 B, sha256 `25f94e721e029833...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.1.0.1038_5MB_MB_PRD_EXTR.bin

- size 4,173,824 B, sha256 `6a314a6562e362cd...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.2.1194_5MB_DT_PRD_EXTR.bin

- size 3,473,408 B, sha256 `757891ef66dd03a2...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.3.1195_5MB_MB_PRD_EXTR.bin

- size 6,287,360 B, sha256 `05e1f73ebde25a94...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.1.0.1042_5MB_DT_PRD_EXTR.bin

- size 3,510,272 B, sha256 `dab68c79b6b1631a...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.1.32.1076_5MB_DT_PRD_EXTR.bin

- size 3,510,272 B, sha256 `62757e9b6a3dbb54...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.30.1203_5MB_MB_PRD_RGN.bin

- size 5,185,536 B, sha256 `655968be6b01dd3d...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.3.7143_5MB_MB_PRE_UPD.bin

- size 4,219,168 B, sha256 `33beeddfc705f95d...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.30.1203_5MB_DT_PRD_RGN.bin

- size 5,185,536 B, sha256 `c3232aec6503ea3e...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.0.1115_5MB_MB_PRE_RGN.bin

- size 5,185,536 B, sha256 `c2ad45b958ec2658...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.1.20.1059_5MB_DT_PRD_EXTR.bin

- size 5,746,688 B, sha256 `0e9d15d093b61698...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.3.1195_5MB_DT_PRD_EXTR.bin

- size 3,473,408 B, sha256 `8ecdcd4217a1b0f2...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.0.1184_5MB_MB_PRD_RGN.bin

- size 5,185,536 B, sha256 `42e17b1f995dd83a...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.1.1.1045_5MB_MB_PRD_EXTR.bin

- size 5,185,536 B, sha256 `ff13d899214f0e25...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.31.1208_5MB_MB_PRD_EXTR.bin

- size 4,128,768 B, sha256 `f5bb4c8762fa7fca...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.40.1215_5MB_DT_PRD_EXTR.bin

- size 5,185,536 B, sha256 `dd12b3324041f562...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.31.1208_5MB_DT_PRD_EXTR.bin

- size 3,477,504 B, sha256 `e6d4b53d1061ec0c...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.40.1215_5MB_MB_PRD_EXTR.bin

- size 4,132,864 B, sha256 `04d7f7bec604c495...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.0.2.1194_5MB_MB_PRD_EXTR.bin

- size 4,128,768 B, sha256 `df6fc623cb7cf390...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.1.10.1052_5MB_DT_PRD_EXTR.bin

- size 5,304,320 B, sha256 `01ee1f102be4ebf8...`
- flash descriptor: no
- record/store GUID hits: 0

## ifix_54 / 6.1.1.1045_5MB_DT_PRD_EXTR.bin

- size 3,510,272 B, sha256 `1141383b5807198c...`
- flash descriptor: no
- record/store GUID hits: 0

