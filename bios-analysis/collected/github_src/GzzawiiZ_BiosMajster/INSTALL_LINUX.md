# BiosMajster — Linux / Ubuntu Installation Guide

## Step 1 — Install system dependencies

```bash
sudo apt update
sudo apt install -y \
    python3 \
    python3-pip \
    python3-gi \
    python3-gi-cairo \
    gir1.2-gtk-3.0 \
    gir1.2-webkit2-4.0 \
    flashrom
```

## Step 2 — Install Python package

```bash
pip3 install pywebview
```

## Step 3 — Fix programmer port permissions (one-time)

This lets flashrom access your USB programmer without sudo every time:

```bash
sudo usermod -aG dialout $USER
```

**Log out and log back in** for the change to take effect.

## Step 4 — Run BiosMajster

```bash
cd BiosMajster
python3 main_linux.py
```

The app will auto-detect your programmer port (`/dev/ttyACM0` or `/dev/ttyUSB0`).
On first launch with flashrom it will show a graphical password prompt (pkexec).

---

## Optional: Create a desktop shortcut

Create the file `~/.local/share/applications/biosmajster.desktop`:

```ini
[Desktop Entry]
Name=BiosMajster
Comment=BIOS Password Removal Tool
Exec=python3 /path/to/BiosMajster/main_linux.py
Icon=/path/to/BiosMajster/icon.png
Terminal=false
Type=Application
Categories=Utility;
```

Then make it executable:
```bash
chmod +x ~/.local/share/applications/biosmajster.desktop
```

---

## Optional: Build standalone binary (no Python needed)

```bash
pip3 install pyinstaller

pyinstaller --onefile \
            --windowed \
            --add-data "index.html:." \
            --name BiosMajster \
            main_linux.py
```

Output: `dist/BiosMajster` — copy anywhere and run directly.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `No module named 'webview'` | `pip3 install pywebview` |
| `No module named 'gi'` | `sudo apt install python3-gi` |
| `WebKit not found` | `sudo apt install gir1.2-webkit2-4.0` |
| Blank white window | `sudo apt install gir1.2-webkit2-4.1` (Ubuntu 22+) |
| `flashrom: permission denied` | `sudo usermod -aG dialout $USER` then re-login |
| Port not detected | Check `ls /dev/ttyACM* /dev/ttyUSB*` and enter manually |
