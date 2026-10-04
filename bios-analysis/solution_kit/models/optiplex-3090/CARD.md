# OptiPlex 3090 — solution card (latest BIOS 2.30.0)

**Platform:** TGL · **the user's machine: service tag H2FS5S3, suffix CF1B**
**Suffix families seen on this model:** CF1B (primary) and 8FC8
**Latest BIOS:** 2.30.0 (LVFS; Dell's site tops at 2.28.0 of 2026-01-15).
**Package held and verified.**

## Key verification on the LATEST version

The 2.30.0 vault module (pw_4) is **byte-identical** to the 2.27.0 engine
this kit emulates — the keygen is valid verbatim on the latest BIOS.
EC build tags: 2.0.7 → 0x635 (this machine's exact EC build, in hand) /
0x5fc; 2.27.0 → 0x615; 2.30.0 → 0x615 main / 0x64f backup.

## What works on this model (in order of ease)

1. **Dell support (zero tools)** — recovery code with proof of ownership
   (confirmed working out of warranty for 8FC8-era machines, 2023-2025
   field reports). Type it, then Ctrl+Enter+Enter.
2. **Ask the machine's EC** (bootable Linux, root, bare metal):
   `sudo python3 dell_master_keygen.py --model optiplex-3090 --tag H2FS5S3 --suffix CF1B`
   CF1B master = first 16 bytes of the EC response.
   If the EC gates by state: reboot to the BIOS password prompt, then
   warm-reset into Linux WITHOUT removing power, and re-run.
3. **Computer shop: SPI patch (field-proven on this exact model).**
   32 MB chip (W25Q256 class; verify yours). The shop reads the chip, then:
   - `dell_unlock_image.py --state dump.bin` (check lock state first)
   - `dell_unlock_image.py --patch dump.bin --out unlocked.bin`
   - or `dellpwn_port.py clear-sivb dump.bin unlocked.bin`
     (SIVB vault at **0x891000**; default clear = 5552 B validated range;
     `--full` = whole 16 KB vault partition; never write past +0x4000 —
     the ME filesystem starts there).
   First boot after reflash: F12 → Manufacturing Mode → disable Absolute,
   write the service tag, Alt+F.
