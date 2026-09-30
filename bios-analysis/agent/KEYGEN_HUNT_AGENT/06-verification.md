# How to verify a candidate artifact

1. **Is it a 3090/CF1B-class image?**
   - EC region at 0x82d464 (core-only, 0x6a60 bytes)
   - PHCM slots at 0x1000 / 0x41000 / 0x81000 (CSME MFS)
   - $FPT at 0x102000 with PSVN/UEP/IVBP/MFS/UTOK/HVMP/RSTR/FLOG/IMDP entries
2. **Does it contain the ENGINE? (the actual find)**
   - Standard AES S-box bytes (63 7c 77 7b f2 6b 6f c5 30 01 67 2b …) or
     T-tables, key-schedule code
   - handlers for I/O ports 0x910/0x911, the {21 00 03 06} open sequence,
     command 0x17 dispatch
   - NO landed SPI image has ever contained these — finding them = the
     missing artifact class #1
3. **Build identification**
   - PHCM record count (n = 0x635 on all four 3090 dumps)
   - slot body sha256 → look up in the determinism tables
     (02-cf1b-architecture.md)
4. **CSME correlation**: run MEA++ TnD (Windows) on the ME region → CSME
   family/version/SKU/date → match against Dell package versions to find
   which package (if any) belongs to the same factory build train.
5. **If a key candidate emerges**
   - unwrap test against held PHCM material (n9f4 class cdb03925…, n9fc class
     fbd98f4c…) must produce structured, non-noise plaintext
   - then the response→code map (dell_master_keygen.py) must reproduce a
     known-working code on a validation pair
