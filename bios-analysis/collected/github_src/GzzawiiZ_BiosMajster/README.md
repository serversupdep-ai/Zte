# BiosMajster v1.0.0
### Professional BIOS Password Removal Tool
🇵🇱 Polski / 🇬🇧 English · Windows & Linux/Ubuntu

---


## Just install and run — that's it

### Windows
> Double-click `BiosMajster_Setup_v1.0.0.exe` → Next → Finish → done.
> No Python, no configuration, no command line needed.

### Linux / Ubuntu
> See **[INSTALL_LINUX.md](INSTALL_LINUX.md)** — 4 commands and you're running.

---

## Supported Devices

| Device | Method | Details |
|---|---|---|
| Dell Latitude 5500 | Static offset | 0x45000, wipes 16 KB |
| Lenovo ThinkBook 14 G3 ACL | Dynamic search | Finds "ThinkBook" → +12KB, wipes 32 bytes |

---

## Features

- 🇵🇱 / 🇬🇧 Auto-detects system language, flag toggle in header
- **Aa S / M / L / XL** font size control — persists across sessions
- Full Cycle mode: reads chip → backs up → patches → writes back
- Patch Only mode: patch a .bin file you already have
- **Automatic backup** — every original dump saved to `backup/` with timestamp
- Live colour-coded operation log
- Resizable window with maximize support

---

## Files

```
BiosMajster/
├── main.py              ← Windows backend (pywebview)
├── main_linux.py        ← Linux/Ubuntu backend (pywebview GTK)
├── index.html           ← Shared UI — PL/EN, high contrast, font size control
├── BiosMajster.spec     ← PyInstaller Windows build config
├── setup.iss            ← Inno Setup Windows installer script
├── INSTALL_LINUX.md     ← Linux step-by-step install guide
└── README.md            ← This file
```

---

## Building from source

### Windows — build .exe then installer

```bash
# 1. Install build tools
pip install pywebview pyinstaller

# 2. Build standalone exe
pyinstaller BiosMajster.spec
# → dist/BiosMajster.exe

# 3. (Optional) Download flashrom.exe into dist/
#    https://flashrom.org/Downloads

# 4. Build installer
#    Open setup.iss in Inno Setup 6 (https://jrsoftware.org/isinfo.php)
#    Click Build → Compile
# → installer_output/BiosMajster_Setup_v1.0.0.exe
```

### Linux — build standalone binary

```bash
pip3 install pywebview pyinstaller
pyinstaller --onefile --windowed --add-data "index.html:." \
            --name BiosMajster main_linux.py
# → dist/BiosMajster
```

---

## Adding New Devices

**`main.py` / `main_linux.py`** — add entry to `DEVICE_PROFILES`:
```python
"my_device": {
    "name":        "My Device Name",
    "method":      "static",   # or "search"
    "offset":      0x12345,    # static only
    "wipe_length": 32,
    "chip":        "W25Q128JV",  # or None for auto-detect
},
```

**`index.html`** — add card in `<div class="dev-cards">`:
```html
<button class="dev-card" data-device="my_device" onclick="selDev(this)">
  <div class="dev-name">My Device Name</div>
  <div class="dev-meta">STATIC · 0x12345 · 32B WIPE</div>
</button>
```

Add to JS `PROFILES` object:
```js
my_device: {
  method: l => l==='pl' ? 'Stały offset' : 'Static offset',
  offset: () => '0x12345',
  wipe:   () => '32 bytes',
  chip:   () => 'W25Q128JV',
}
```

---

## Backup system

Every time you run BiosMajster, the original `.bin` is automatically saved:
```
BiosMajster/
└── backup/
    ├── bios_dump_20260427_110217.bin
    ├── bios_dump_20260428_093045.bin
    └── 14_g3_acl_pass_20260429_141200.bin
```
If anything goes wrong you always have the original to restore from.
