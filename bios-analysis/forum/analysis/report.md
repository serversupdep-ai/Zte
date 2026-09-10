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
  - 23,552 B `f9cdf1278185` -> collected/OptiPlex_7080_1.37.0/pw_1_23552.efi
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
  - 23,552 B `f9cdf1278185` -> collected/OptiPlex_7080_1.37.0/pw_1_23552.efi
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
  - 23,552 B `f9cdf1278185` -> collected/OptiPlex_7080_1.37.0/pw_1_23552.efi
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
  - 23,552 B `f9cdf1278185` -> collected/OptiPlex_7080_1.37.0/pw_1_23552.efi
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
  - 23,552 B `f9cdf1278185` -> collected/OptiPlex_7080_1.37.0/pw_1_23552.efi
  - 24,576 B `4cba53c8ace9` -> collected/OptiPlex_3090_2.0.7/pw_2_24576.efi

## dumps / ifix_13__Alienware Aurora R12 .bin

- size 33,554,432 B, sha256 `a4286118dfa8fa6f...`
- flash descriptor: yes — {'bios': [20971520, 33554431], 'me': [4096, 16781311]}
- record/store GUID hits: 0

