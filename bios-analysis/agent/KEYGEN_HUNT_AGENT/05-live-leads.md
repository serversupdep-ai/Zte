# Live leads (ranked)

1. **Dell factory/service EC firmware** — the only place the FULL EC image
   (engine + build key) exists outside silicon. Sweep the Dell package catalog
   for TGL-era desktops (OptiPlex 3080/3081/3090/7090, Latitude 3410/3420
   class) for EC payloads that are NOT core-only 0x6a60 regions and NOT
   sealed PHCM — i.e. real EC firmware images. Use MEA++ to correlate CSME
   builds. Also: Dell service/diagnostic ISOs and factory images sometimes
   carry EC update payloads.
2. **EC silicon vendor trail**: identify the 3090's EC part (board markings
   from repair threads); vendor SDK/firmware images circulate in repair
   circles and sometimes embed customer key material.
3. **GitHub / code search sweeps**: search for PHCM magic
   ("PHCM\x01\x01\x80\x03"), $FPT+PSVN strings, "212037" EC blobs, Dell
   service ISO extracts. A factory EC image may sit in someone's dump repo
   unexamined.
4. **Locked+patched dump PAIRS** (badcaps premium-gated: 3090 Micro
   B43SZQ3/6Q6F3L3/3GLD8L3; dr-bios 68894 Aug-2026 XM25QH256B pair): these
   show only the store-erase patch pattern (already understood) — LOW value
   UNLESS a pair spans a build's FIRST BOOT (then the wrap-material diff
   could expose the key-derivation step).
5. **Issue #5 volunteer (Route A live query)**: a live 3090 owner running
   dell_cf1b_master-linux would produce challenge→response pairs — valid for
   CONFIRMING a key candidate, not for deriving it. Still silent.
6. **Monthly re-scan** of the active venues (vinafix 3090 thread 45618,
   dr-bios, badcaps 3090/3080 threads, indiafix, pkbiosfix, t.me BIOS ARCHIVE
   channel pages): new dumps appear weekly; each new same-model dump gets the
   standard census → region-compare → PHCM-table treatment.
