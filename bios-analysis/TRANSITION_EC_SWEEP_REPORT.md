# 2018–2020 Dell `E7A8 -> 8FC8/CF1B` Transition Boundary & ChromeOS Wilco EC Audit

- **Capsules unpacked & audited**: `60`
- **Dell ChromeOS Wilco EC boards audited (`FLREG8`)**: `3`
- **Golden Overlaps (`unsealed EC` + `cmd 0x21 / 8FC8` in same platform)**: `0`

## 1. Dell ChromeOS Enterprise Wilco EC (`FLREG8` `0x001000..0x100FFF`)

| Board | Model | Version | Status | EC Slots (`PHCM` byte 6 & active H) |
|---|---|---|---|---|
| `wilco_sarien` | Dell Latitude 5400 Chromebook Enterprise (2019 Wilco EC) | `MrChromebox-2609.2_20261015` | `ok` | WILCO_PHCM_TAG0_primary byte6=0x80 H=7.9986 plain=False; WILCO_PHCM_TAG1_backup byte6=0x80 H=7.9983 plain=False |
| `wilco_arcada` | Dell Latitude 5300 2-in-1 Chromebook Enterprise (2019 Wilco EC) | `MrChromebox-2609.2` | `not_on_cdn` | - |
| `wilco_drallion` | Dell Latitude 7410 Chromebook Enterprise (2020 Wilco EC) | `MrChromebox-2609.2_20261015` | `ok` | WILCO_PHCM_TAG0_primary byte6=0x80 H=7.9987 plain=False; WILCO_PHCM_TAG1_backup byte6=0x80 H=7.9987 plain=False |

## 2. 2018–2020 Transition Capsule Matrix (`LVFS` + `Dell Wayback`)

| Model | Version (`slot`) | `8FC8/CF1B` EC Proto? | Unsealed EC? | GOLDEN? | EC Payloads (`kind`, `PHCM[6]`, `H`, `EC_ALPH72`) |
|---|---|:---:|:---:|:---:|---|
| EGW5200 | `102` (oldest) | - | - | - | `error:cannot access local variable 'pkg' where it is not associated with a value` |
| Edge Gateway 5000/5100 | `1.15.1` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| G3 3500, G5 5500 | `1.21.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| G5 5000 | `1.5.1` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Inspiron 14 7000 Gaming/Inspiron 15 7000 Gaming | `1.0.3` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Inspiron 3490, Vostro 3490, Inspiron 3590, Inspiron 3590, Vostro 3590, Vostro 3590, Inspiron 3790, Inspiron 5494, Inspiron 5594 | `1.17.1` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Latitude 3300 | `1.24.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Latitude 3300 | `1.33.0` (latest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Latitude 3310 | `1.24.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Latitude 3310 | `1.4.2` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Latitude 3310 2in1 | `1.4.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Latitude 3390 2-in-1 | `1.9.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Latitude 3500, Latitude 3400 | `1.28.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Latitude 3500, Latitude 3400 | `1.38.0` (latest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Latitude 5X00 | `1.28.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Latitude 5X00 | `1.37.0` (latest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Latitude 5X00 | `1.7.2` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Latitude 5X00 | `1.8.1` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Latitude 5X00 | `1.9.2` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Latitude 5X00/Precision 3540 | `1.34.1` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Latitude 5X00/Precision 3540 | `1.43.1` (latest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Latitude 5X91 | `1.19.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Latitude 5X91 | `1.30.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Latitude 5X91 | `1.39.0` (latest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Latitude 7390 2-in-1 | `1.29.1` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Latitude 7390 2-in-1 | `1.38.0` (latest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Latitude 7X00 | `1.31.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Latitude 7X00 | `1.43.0` (latest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Latitude 7X90 | `1.31.1` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Latitude 7X90 | `1.41.0` (latest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| OptiPlex 3060 | `1.15.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| OptiPlex 3070 | `1.26.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| OptiPlex 3070 | `1.9.1` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| OptiPlex 5060 | `1.18.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| OptiPlex 5070 | `1.15.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| OptiPlex 5070 | `1.26.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| OptiPlex 7060 | `1.12.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| OptiPlex 7060 | `1.24.0` (latest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| OptiPlex 7070 Ultra | `1.27.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Precision 3630 Tower | `2.23.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Precision 3930 Rack | `2.35.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Precision 5530 | `1.36.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Precision 5530 | `1.41.0` (latest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Precision 5530 | `1.42.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Precision 5540 | `1.36.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Precision 7X30 | `1.33.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Precision 7X30 | `1.42.0` (latest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Precision 7X40 | `1.34.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Precision Tower 3430 | `1.28.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Vostro 5490, Vostro 5590, Inspiron 5490, Inspiron 5498, Inspiron 5590, Inspiron 5598 | `1.22.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| Wyse 5070 Thin Client | `1.15.1` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| XPS 13 7390 | `1.19.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| XPS 13 7390 | `1.29.0` (latest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| XPS 13 9370 | `1.12.1` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| XPS 13 9380 | `1.17.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| XPS 13 9380 | `1.26.0` (latest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| XPS 15 7590/Precision 5540 | `1.24.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| XPS 15 9570/Precision 5530 | `1.22.1` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| XPS 15 9570/Precision 5530 | `1.31.0` (latest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
| atitude 3301 | `1.27.0` (oldest) | - | - | - | `error:'bytes' object has no attribute 'read_bytes'` |
