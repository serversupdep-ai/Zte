# 2018–2020 Dell `E7A8 -> 8FC8/CF1B` Transition Boundary & ChromeOS Wilco EC Audit

- **Capsules unpacked & audited**: `60`
- **Dell ChromeOS Wilco EC boards audited (`FLREG8`)**: `3`
- **Golden Overlaps (`unsealed EC` + `cmd 0x21 / 8FC8` in same platform)**: `56`

## 1. Dell ChromeOS Enterprise Wilco EC (`FLREG8` `0x001000..0x100FFF`)

| Board | Model | Version | Status | EC Slots (`PHCM` byte 6 & active H) |
|---|---|---|---|---|
| `wilco_sarien` | Dell Latitude 5400 Chromebook Enterprise (2019 Wilco EC) | `MrChromebox-2609.2_20261015` | `ok` | WILCO_PHCM_TAG0_primary byte6=0x80 H=7.9986 plain=False; WILCO_PHCM_TAG1_backup byte6=0x80 H=7.9983 plain=False |
| `wilco_arcada` | Dell Latitude 5300 2-in-1 Chromebook Enterprise (2019 Wilco EC) | `MrChromebox-2609.2` | `not_on_cdn` | - |
| `wilco_drallion` | Dell Latitude 7410 Chromebook Enterprise (2020 Wilco EC) | `MrChromebox-2609.2_20261015` | `ok` | WILCO_PHCM_TAG0_primary byte6=0x80 H=7.9987 plain=False; WILCO_PHCM_TAG1_backup byte6=0x80 H=7.9987 plain=False |

## 2. 2018–2020 Transition Capsule Matrix (`LVFS` + `Dell Wayback`)

| Model | Version (`slot`) | `8FC8/CF1B` EC Proto? | Unsealed EC? | GOLDEN? | EC Payloads (`kind`, `PHCM[6]`, `H`, `EC_ALPH72`) |
|---|---|:---:|:---:|:---:|---|
| Edge Gateway 5000/5100 | `1.15.1` (oldest) | YES | **YES** | **HIT!** | EXPLICIT_EC_SECTION(1408K, b6=None, H=1.752, unsealed=True, alph72=False); RAW_PFS_SUBCOMPONENT(34K, b6=None, H=5.318, unsealed=True, alph72 |
| G3 3500, G5 5500 | `1.21.0` (oldest) | YES | **YES** | **HIT!** | PHCM(140K, b6=0x80, H=7.999, unsealed=False, alph72=False); PHCM(142K, b6=0x80, H=7.999, unsealed=False, alph72=False); PHCM(144K, b6=0x80,  |
| G5 5000 | `1.5.1` (oldest) | YES | **YES** | **HIT!** | PHCM(85K, b6=0x84, H=7.998, unsealed=False, alph72=False); PHCM(82K, b6=0x84, H=7.997, unsealed=False, alph72=False); PHCM(169K, b6=0x84, H= |
| Inspiron 3490, Vostro 3490, Inspiron 3 | `1.17.1` (oldest) | YES | **YES** | **HIT!** | PHCM(192K, b6=0x01, H=6.973, unsealed=True, alph72=True); PHCM(320K, b6=0x01, H=6.922, unsealed=True, alph72=True); EXPLICIT_EC_SECTION(22K, |
| Latitude 3300 | `1.24.0` (oldest) | YES | **YES** | **HIT!** | PHCM(145K, b6=0x01, H=7.027, unsealed=True, alph72=True); PHCM(320K, b6=0x01, H=7.027, unsealed=True, alph72=True); RAW_PFS_SUBCOMPONENT(33K |
| Latitude 3300 | `1.33.0` (latest) | YES | **YES** | **HIT!** | PHCM(145K, b6=0x01, H=7.032, unsealed=True, alph72=True); PHCM(320K, b6=0x01, H=7.032, unsealed=True, alph72=True); RAW_PFS_SUBCOMPONENT(33K |
| Latitude 3310 | `1.24.0` (oldest) | YES | **YES** | **HIT!** | PHCM(192K, b6=0x01, H=7.03, unsealed=True, alph72=True); PHCM(320K, b6=0x01, H=7.03, unsealed=True, alph72=True); RAW_PFS_SUBCOMPONENT(36K,  |
| Latitude 3310 | `1.4.2` (oldest) | YES | **YES** | **HIT!** | PHCM(145K, b6=0x01, H=7.039, unsealed=True, alph72=True); PHCM(320K, b6=0x01, H=7.039, unsealed=True, alph72=True); RAW_PFS_SUBCOMPONENT(33K |
| Latitude 3310 2in1 | `1.4.0` (oldest) | YES | **YES** | **HIT!** | PHCM(192K, b6=0x01, H=7.027, unsealed=True, alph72=True); PHCM(320K, b6=0x01, H=7.027, unsealed=True, alph72=True); RAW_PFS_SUBCOMPONENT(36K |
| Latitude 3500, Latitude 3400 | `1.28.0` (oldest) | YES | **YES** | **HIT!** | PHCM(192K, b6=0x01, H=6.989, unsealed=True, alph72=True); PHCM(320K, b6=0x01, H=6.989, unsealed=True, alph72=True); RAW_PFS_SUBCOMPONENT(42K |
| Latitude 3500, Latitude 3400 | `1.38.0` (latest) | YES | **YES** | **HIT!** | PHCM(192K, b6=0x01, H=6.991, unsealed=True, alph72=True); PHCM(320K, b6=0x01, H=6.991, unsealed=True, alph72=True); RAW_PFS_SUBCOMPONENT(496 |
| Latitude 5X00 | `1.28.0` (oldest) | YES | **YES** | **HIT!** | PHCM(162K, b6=0x80, H=7.999, unsealed=False, alph72=False); PHCM(155K, b6=0x80, H=7.998, unsealed=False, alph72=False); PHCM(162K, b6=0x80,  |
| Latitude 5X00 | `1.37.0` (latest) | YES | **YES** | **HIT!** | PHCM(163K, b6=0x80, H=7.999, unsealed=False, alph72=False); PHCM(163K, b6=0x80, H=7.999, unsealed=False, alph72=False); PHCM(163K, b6=0x80,  |
| Latitude 5X00 | `1.7.2` (oldest) | YES | **YES** | **HIT!** | PHCM(160K, b6=0x80, H=7.998, unsealed=False, alph72=False); PHCM(155K, b6=0x80, H=7.998, unsealed=False, alph72=False); PHCM(160K, b6=0x80,  |
| Latitude 5X00 | `1.8.1` (oldest) | YES | **YES** | **HIT!** | PHCM(160K, b6=0x80, H=7.998, unsealed=False, alph72=False); PHCM(155K, b6=0x80, H=7.998, unsealed=False, alph72=False); PHCM(160K, b6=0x80,  |
| Latitude 5X00 | `1.9.2` (oldest) | YES | **YES** | **HIT!** | PHCM(160K, b6=0x80, H=7.999, unsealed=False, alph72=False); PHCM(155K, b6=0x80, H=7.998, unsealed=False, alph72=False); PHCM(160K, b6=0x80,  |
| Latitude 5X00/Precision 3540 | `1.34.1` (oldest) | YES | **YES** | **HIT!** | PHCM(170K, b6=0x80, H=7.999, unsealed=False, alph72=False); PHCM(164K, b6=0x80, H=7.998, unsealed=False, alph72=False); PHCM(170K, b6=0x80,  |
| Latitude 5X00/Precision 3540 | `1.43.1` (latest) | YES | **YES** | **HIT!** | PHCM(171K, b6=0x80, H=7.999, unsealed=False, alph72=False); PHCM(171K, b6=0x80, H=7.999, unsealed=False, alph72=False); PHCM(171K, b6=0x80,  |
| Latitude 5X91 | `1.19.0` (oldest) | YES | **YES** | **HIT!** | PHCM(192K, b6=0x01, H=6.948, unsealed=True, alph72=True); PHCM(320K, b6=0x01, H=6.948, unsealed=True, alph72=True); RAW_PFS_SUBCOMPONENT(37K |
| Latitude 5X91 | `1.30.0` (oldest) | YES | **YES** | **HIT!** | PHCM(168K, b6=0x80, H=7.998, unsealed=False, alph72=False); PHCM(160K, b6=0x80, H=7.999, unsealed=False, alph72=False); PHCM(320K, b6=0x80,  |
| Latitude 5X91 | `1.39.0` (latest) | YES | **YES** | **HIT!** | PHCM(168K, b6=0x80, H=7.998, unsealed=False, alph72=False); PHCM(160K, b6=0x80, H=7.999, unsealed=False, alph72=False); PHCM(320K, b6=0x80,  |
| Latitude 7390 2-in-1 | `1.29.1` (oldest) | YES | **YES** | **HIT!** | PHCM(147K, b6=0x00, H=6.954, unsealed=True, alph72=True); PHCM(141K, b6=0x00, H=6.935, unsealed=True, alph72=True); PHCM(320K, b6=0x00, H=6. |
| Latitude 7390 2-in-1 | `1.38.0` (latest) | YES | **YES** | **HIT!** | PHCM(147K, b6=0x00, H=6.955, unsealed=True, alph72=True); PHCM(141K, b6=0x00, H=6.935, unsealed=True, alph72=True); PHCM(320K, b6=0x00, H=6. |
| Latitude 7X00 | `1.31.0` (oldest) | YES | **YES** | **HIT!** | PHCM(160K, b6=0x80, H=7.999, unsealed=False, alph72=False); PHCM(154K, b6=0x80, H=7.999, unsealed=False, alph72=False); PHCM(160K, b6=0x80,  |
| Latitude 7X00 | `1.43.0` (latest) | YES | **YES** | **HIT!** | PHCM(161K, b6=0x80, H=7.999, unsealed=False, alph72=False); PHCM(161K, b6=0x80, H=7.999, unsealed=False, alph72=False); PHCM(161K, b6=0x80,  |
| Latitude 7X90 | `1.31.1` (oldest) | YES | **YES** | **HIT!** | PHCM(149K, b6=0x00, H=6.954, unsealed=True, alph72=True); PHCM(144K, b6=0x00, H=6.931, unsealed=True, alph72=True); PHCM(320K, b6=0x00, H=6. |
| Latitude 7X90 | `1.41.0` (latest) | YES | **YES** | **HIT!** | PHCM(149K, b6=0x00, H=6.954, unsealed=True, alph72=True); PHCM(144K, b6=0x00, H=6.931, unsealed=True, alph72=True); PHCM(320K, b6=0x00, H=6. |
| OptiPlex 3060 | `1.15.0` (oldest) | YES | **YES** | **HIT!** | RAW_PFS_SUBCOMPONENT(134K, b6=None, H=6.406, unsealed=True, alph72=False); RAW_PFS_SUBCOMPONENT(134K, b6=None, H=6.407, unsealed=True, alph7 |
| OptiPlex 3070 | `1.26.0` (oldest) | YES | **YES** | **HIT!** | RAW_PFS_SUBCOMPONENT(135K, b6=None, H=6.279, unsealed=True, alph72=False); RAW_PFS_SUBCOMPONENT(135K, b6=None, H=6.279, unsealed=True, alph7 |
| OptiPlex 3070 | `1.9.1` (oldest) | YES | **YES** | **HIT!** | RAW_PFS_SUBCOMPONENT(134K, b6=None, H=6.279, unsealed=True, alph72=False); RAW_PFS_SUBCOMPONENT(134K, b6=None, H=6.279, unsealed=True, alph7 |
| OptiPlex 5060 | `1.18.0` (oldest) | YES | **YES** | **HIT!** | RAW_PFS_SUBCOMPONENT(131K, b6=None, H=6.279, unsealed=True, alph72=False); RAW_PFS_SUBCOMPONENT(131K, b6=None, H=6.279, unsealed=True, alph7 |
| OptiPlex 5070 | `1.15.0` (oldest) | YES | **YES** | **HIT!** | RAW_PFS_SUBCOMPONENT(132K, b6=None, H=6.282, unsealed=True, alph72=False); RAW_PFS_SUBCOMPONENT(132K, b6=None, H=6.282, unsealed=True, alph7 |
| OptiPlex 5070 | `1.26.0` (oldest) | YES | **YES** | **HIT!** | RAW_PFS_SUBCOMPONENT(132K, b6=None, H=6.282, unsealed=True, alph72=False); RAW_PFS_SUBCOMPONENT(132K, b6=None, H=6.282, unsealed=True, alph7 |
| OptiPlex 7060 | `1.12.0` (oldest) | YES | **YES** | **HIT!** | RAW_PFS_SUBCOMPONENT(131K, b6=None, H=6.281, unsealed=True, alph72=False); RAW_PFS_SUBCOMPONENT(131K, b6=None, H=6.281, unsealed=True, alph7 |
| OptiPlex 7060 | `1.24.0` (latest) | YES | **YES** | **HIT!** | RAW_PFS_SUBCOMPONENT(131K, b6=None, H=6.278, unsealed=True, alph72=False); RAW_PFS_SUBCOMPONENT(131K, b6=None, H=6.278, unsealed=True, alph7 |
| OptiPlex 7070 Ultra | `1.27.0` (oldest) | YES | **YES** | **HIT!** | RAW_PFS_SUBCOMPONENT(35K, b6=None, H=3.92, unsealed=True, alph72=False); RAW_PFS_SUBCOMPONENT(35K, b6=None, H=3.913, unsealed=True, alph72=F |
| Precision 3630 Tower | `2.23.0` (oldest) | YES | **YES** | **HIT!** | RAW_PFS_SUBCOMPONENT(133K, b6=None, H=6.292, unsealed=True, alph72=False); RAW_PFS_SUBCOMPONENT(133K, b6=None, H=6.292, unsealed=True, alph7 |
| Precision 3930 Rack | `2.35.0` (oldest) | YES | **YES** | **HIT!** | PHCM(65K, b6=0x00, H=6.648, unsealed=True, alph72=False); PHCM(193K, b6=0x00, H=6.145, unsealed=True, alph72=False); RAW_PFS_SUBCOMPONENT(13 |
| Precision 5530 | `1.36.0` (oldest) | YES | **YES** | **HIT!** | PHCM(179K, b6=0x00, H=6.949, unsealed=True, alph72=True); PHCM(177K, b6=0x00, H=6.938, unsealed=True, alph72=True); PHCM(320K, b6=0x00, H=6. |
| Precision 5530 | `1.41.0` (latest) | YES | **YES** | **HIT!** | PHCM(179K, b6=0x00, H=6.949, unsealed=True, alph72=True); PHCM(177K, b6=0x00, H=6.938, unsealed=True, alph72=True); PHCM(320K, b6=0x00, H=6. |
| Precision 5530 | `1.42.0` (oldest) | YES | **YES** | **HIT!** | PHCM(179K, b6=0x00, H=6.949, unsealed=True, alph72=True); PHCM(177K, b6=0x00, H=6.938, unsealed=True, alph72=True); PHCM(320K, b6=0x00, H=6. |
| Precision 5540 | `1.36.0` (oldest) | YES | **YES** | **HIT!** | PHCM(194K, b6=0x80, H=7.999, unsealed=False, alph72=False); PHCM(191K, b6=0x80, H=7.998, unsealed=False, alph72=False); PHCM(194K, b6=0x80,  |
| Precision 7X30 | `1.33.0` (oldest) | YES | **YES** | **HIT!** | PHCM(162K, b6=0x80, H=7.999, unsealed=False, alph72=False); PHCM(140K, b6=0x00, H=6.951, unsealed=True, alph72=True); PHCM(320K, b6=0x80, H= |
| Precision 7X30 | `1.42.0` (latest) | YES | **YES** | **HIT!** | PHCM(162K, b6=0x80, H=7.999, unsealed=False, alph72=False); PHCM(140K, b6=0x00, H=6.951, unsealed=True, alph72=True); PHCM(320K, b6=0x80, H= |
| Precision 7X40 | `1.34.0` (oldest) | YES | **YES** | **HIT!** | PHCM(184K, b6=0x80, H=7.998, unsealed=False, alph72=False); PHCM(169K, b6=0x80, H=7.998, unsealed=False, alph72=False); PHCM(184K, b6=0x80,  |
| Precision Tower 3430 | `1.28.0` (oldest) | YES | **YES** | **HIT!** | RAW_PFS_SUBCOMPONENT(132K, b6=None, H=6.283, unsealed=True, alph72=False); RAW_PFS_SUBCOMPONENT(132K, b6=None, H=6.284, unsealed=True, alph7 |
| Vostro 5490, Vostro 5590, Inspiron 549 | `1.22.0` (oldest) | YES | **YES** | **HIT!** | PHCM(192K, b6=0x01, H=7.024, unsealed=True, alph72=True); PHCM(320K, b6=0x01, H=7.024, unsealed=True, alph72=True); EXPLICIT_EC_SECTION(22K, |
| XPS 13 7390 | `1.19.0` (oldest) | YES | **YES** | **HIT!** | PHCM(155K, b6=0x80, H=7.999, unsealed=False, alph72=False); PHCM(148K, b6=0x80, H=7.999, unsealed=False, alph72=False); PHCM(155K, b6=0x80,  |
| XPS 13 7390 | `1.29.0` (latest) | YES | **YES** | **HIT!** | PHCM(155K, b6=0x80, H=7.999, unsealed=False, alph72=False); PHCM(148K, b6=0x80, H=7.999, unsealed=False, alph72=False); PHCM(155K, b6=0x80,  |
| XPS 13 9370 | `1.12.1` (oldest) | YES | **YES** | **HIT!** | PHCM(147K, b6=0x00, H=6.952, unsealed=True, alph72=True); PHCM(320K, b6=0x00, H=6.952, unsealed=True, alph72=True); RAW_PFS_SUBCOMPONENT(33K |
| XPS 13 9380 | `1.17.0` (oldest) | YES | **YES** | **HIT!** | PHCM(151K, b6=0x80, H=7.999, unsealed=False, alph72=False); PHCM(148K, b6=0x80, H=7.999, unsealed=False, alph72=False); PHCM(320K, b6=0x80,  |
| XPS 13 9380 | `1.26.0` (latest) | YES | **YES** | **HIT!** | PHCM(152K, b6=0x80, H=7.998, unsealed=False, alph72=False); PHCM(148K, b6=0x80, H=7.999, unsealed=False, alph72=False); PHCM(320K, b6=0x80,  |
| XPS 15 7590/Precision 5540 | `1.24.0` (oldest) | YES | **YES** | **HIT!** | PHCM(193K, b6=0x80, H=7.998, unsealed=False, alph72=False); PHCM(191K, b6=0x80, H=7.998, unsealed=False, alph72=False); PHCM(193K, b6=0x80,  |
| XPS 15 9570/Precision 5530 | `1.22.1` (oldest) | YES | **YES** | **HIT!** | PHCM(179K, b6=0x00, H=6.946, unsealed=True, alph72=True); PHCM(177K, b6=0x00, H=6.938, unsealed=True, alph72=True); PHCM(320K, b6=0x00, H=6. |
| XPS 15 9570/Precision 5530 | `1.31.0` (latest) | YES | **YES** | **HIT!** | PHCM(179K, b6=0x00, H=6.949, unsealed=True, alph72=True); PHCM(177K, b6=0x00, H=6.938, unsealed=True, alph72=True); PHCM(320K, b6=0x00, H=6. |
| atitude 3301 | `1.27.0` (oldest) | YES | **YES** | **HIT!** | PHCM(192K, b6=0x01, H=7.004, unsealed=True, alph72=True); PHCM(320K, b6=0x01, H=7.004, unsealed=True, alph72=True); RAW_PFS_SUBCOMPONENT(42K |
| Inspiron 14 7000 Gaming/Inspiron 15 70 | `1.0.3` (oldest) | no | **YES** | no | PHCM(320K, b6=0x81, H=7.041, unsealed=False, alph72=True); PHCM(316K, b6=0x81, H=7.176, unsealed=False, alph72=True); PHCM(320K, b6=0x81, H= |
| Latitude 3390 2-in-1 | `1.9.0` (oldest) | no | **YES** | no | PHCM(320K, b6=0x01, H=7.013, unsealed=True, alph72=True); PHCM(252K, b6=0x01, H=7.013, unsealed=True, alph72=True); PHCM(320K, b6=0x01, H=7. |
| Wyse 5070 Thin Client | `1.15.1` (oldest) | no | **YES** | no | EXPLICIT_EC_SECTION(1764K, b6=None, H=6.123, unsealed=True, alph72=False) |
| EGW5200 | `102` (oldest) | no | no | no | none |
