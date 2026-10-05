"""
BiosMajster — BIOS Password Removal Tool
Bilingual (PL/EN) | pywebview desktop app

Install:
  pip install pywebview

Run:
  python main.py
"""

import webview
import threading
import subprocess
import time
import os
import shutil

# =============================================================================
# DEVICE PROFILES — add new devices here
# =============================================================================
DEVICE_PROFILES = {
    "dell": {
        "name":        "Dell Latitude 5500",
        "method":      "static",
        "offset":      0x45000,
        "wipe_length": 0x4000,
        "chip":        "W25Q64JV-.Q",
    },
    "thinkbook": {
        "name":        "Lenovo ThinkBook 14 G3 ACL",
        "method":      "search",
        "search_term": b"ThinkBook",
        "block_align": 0xFF,
        "jump":        0x3000,
        "wipe_length": 32,
        "chip":        None,
    },
}

# =============================================================================
# LOG MESSAGES — bilingual
# =============================================================================
MSG = {
    "en": {
        "step1":     "[ STEP 1 ]  Reading BIOS chip",
        "step2":     "[ STEP 2 ]  Patching binary",
        "step3":     "[ STEP 3 ]  Writing patched binary",
        "loading":   "File loaded: {:,} bytes ({:.1f} MB)",
        "found_at":  "Password region found at: {} ({} bytes)",
        "encrypted": "Encrypted data: {} ...",
        "wiped":     "Wiped {} bytes with 0xFF ✓",
        "saved":     "Saved: {}",
        "waiting":   "Waiting 3 seconds...",
        "done":      "✓  BIOS password successfully removed",
        "already":   "WARNING: Region already all FF — may be already unlocked",
        "too_small": "File too small for offset {}",
        "not_found": "Search term '{}' not found in binary.",
        "verify":    "Verifying write...",
        "verified":  "Verification passed ✓",
        "backup":    "Backup saved: {}",
        "backup_skip":"Backup already exists, skipping: {}",
        "backup_fail":"WARNING: Could not create backup: {}",
    },
    "pl": {
        "step1":     "[ KROK 1 ]  Odczyt układu BIOS",
        "step2":     "[ KROK 2 ]  Patchowanie pliku binarnego",
        "step3":     "[ KROK 3 ]  Zapis spatchowanego pliku",
        "loading":   "Plik załadowany: {:,} bajtów ({:.1f} MB)",
        "found_at":  "Znaleziono region hasła: {} ({} bajtów)",
        "encrypted": "Zaszyfrowane dane: {} ...",
        "wiped":     "Nadpisano {} bajtów wartością 0xFF ✓",
        "saved":     "Zapisano: {}",
        "waiting":   "Oczekiwanie 3 sekundy...",
        "done":      "✓  Hasło BIOS zostało pomyślnie usunięte",
        "already":   "OSTRZEŻENIE: Region już jest FF — może być już odblokowany",
        "too_small": "Plik za mały dla offsetu {}",
        "not_found": "Nie znaleziono ciągu '{}' w pliku binarnym.",
        "verify":    "Weryfikacja zapisu...",
        "verified":  "Weryfikacja zakończona ✓",
        "backup":    "Kopia zapasowa zapisana: {}",
        "backup_skip":"Kopia już istnieje, pomijam: {}",
        "backup_fail":"OSTRZEŻENIE: Nie udało się utworzyć kopii: {}",
    }
}


def m(key, lang, *args):
    tmpl = MSG.get(lang, MSG["en"]).get(key, key)
    return tmpl.format(*args) if args else tmpl



# =============================================================================
# BACKUP
# =============================================================================
def backup_dump(input_path, log_fn, lang):
    """
    Copies input_path into <app_dir>/backup/ with a timestamp suffix.
    Always runs before any patching so the original is never lost.
    """
    try:
        app_dir    = os.path.dirname(os.path.abspath(__file__))
        backup_dir = os.path.join(app_dir, "backup")
        os.makedirs(backup_dir, exist_ok=True)

        from datetime import datetime
        ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = os.path.basename(input_path)
        name, ext = os.path.splitext(base_name)
        dest      = os.path.join(backup_dir, f"{name}_{ts}{ext}")

        if os.path.exists(dest):
            log_fn(m("backup_skip", lang, dest), "muted")
            return dest

        shutil.copy2(input_path, dest)
        log_fn(m("backup", lang, dest), "ok")
        return dest

    except Exception as e:
        log_fn(m("backup_fail", lang, str(e)), "warn")
        return None

# =============================================================================
# PATCH LOGIC
# =============================================================================
def find_password_offset(data, profile):
    method = profile["method"]
    if method == "static":
        offset = profile["offset"]
        length = profile["wipe_length"]
        if len(data) < offset + length:
            raise ValueError(f"File too small for offset {hex(offset)}")
        return offset, length
    elif method == "search":
        term  = profile["search_term"]
        found = data.find(term)
        if found == -1:
            raise ValueError(f"Search term '{term.decode()}' not found.")
        block_start = found & ~profile["block_align"]
        offset      = block_start + profile["jump"]
        length      = profile["wipe_length"]
        if len(data) < offset + length:
            raise ValueError(f"Offset {hex(offset)} exceeds file size.")
        return offset, length
    else:
        raise ValueError(f"Unknown method: {method}")


def patch_binary(input_path, profile, log, lang):
    with open(input_path, "rb") as f:
        data = bytearray(f.read())
    log(m("loading", lang, len(data), len(data) / (1024 * 1024)), "info")

    offset, length = find_password_offset(data, profile)
    log(m("found_at", lang, hex(offset), length), "info")

    region = data[offset:offset + min(length, 32)]
    if region == b"\xFF" * len(region):
        log(m("already", lang), "warn")
    else:
        log(m("encrypted", lang, region[:16].hex(' ').upper()), "warn")

    data[offset:offset + length] = b"\xFF" * length
    log(m("wiped", lang, length), "ok")

    base, ext = os.path.splitext(input_path)
    out = f"{base}_unlocked{ext}"
    with open(out, "wb") as f:
        f.write(data)
    log(m("saved", lang, out), "ok")
    return out


def run_flashrom(programmer, chip, action, bin_path, log, lang):
    chip_arg = f'-c "{chip}"' if chip else ""
    flag     = "-r" if action == "read" else "-w"
    cmd      = f'flashrom -p {programmer} {chip_arg} {flag} "{bin_path}" --progress'
    log(f"$ {cmd}", "muted")
    proc = subprocess.Popen(
        cmd, shell=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    for line in proc.stdout:
        line = line.strip()
        if line:
            log(line, "info")
    proc.wait()
    if proc.returncode != 0:
        raise RuntimeError(f"flashrom exited with code {proc.returncode}")


# =============================================================================
# PYWEBVIEW API BRIDGE
# =============================================================================
class API:
    def __init__(self):
        self._window = None

    def set_window(self, window):
        self._window = window

    def browse_file(self):
        result = self._window.create_file_dialog(
            webview.OPEN_DIALOG,
            allow_multiple=False,
            file_types=("Binary Files (*.bin)", "All Files (*.*)")
        )
        return result[0] if result else None

    def start_unlock(self, params):
        threading.Thread(
            target=self._run_flow, args=(params,), daemon=True
        ).start()
        return {"ok": True}

    def _run_flow(self, params):
        device_key = params.get("device", "thinkbook")
        mode       = params.get("mode", "patch")
        port       = params.get("port", "serprog:dev=COM3")
        file_path  = params.get("file", "")
        lang       = params.get("lang", "en")
        profile    = DEVICE_PROFILES[device_key]

        def log(msg, t="info"):
            self._js(f'onLog({repr(msg)}, {repr(t)})')

        def step(n):
            self._js(f'onStep({n})')

        def progress(pct):
            self._js(f'onProgress({pct})')

        try:
            if mode == "full":
                step(1); progress(5)
                log(m("step1", lang), "section")
                if not file_path:
                    file_path = os.path.join(
                        os.path.expanduser("~"), "Desktop", "bios_dump.bin"
                    )
                run_flashrom(port, profile.get("chip"), "read", file_path, log, lang)
                log(m("waiting", lang), "muted")
                time.sleep(3)
                progress(33)
            else:
                log("[ PATCH ONLY MODE ]", "muted")

            # ── Backup original before any patching ──────────────────
            log(m("backup_section", lang) if "backup_section" in MSG.get(lang,{}) else "[ BACKUP ]  Saving original dump...", "section")
            backup_dump(file_path, log, lang)

            step(2); progress(40)
            log(m("step2", lang), "section")
            unlocked_path = patch_binary(file_path, profile, log, lang)
            progress(66)

            if mode == "full":
                step(3); progress(70)
                log(m("waiting", lang), "muted")
                time.sleep(3)
                log(m("step3", lang), "section")
                run_flashrom(port, profile.get("chip"), "write", unlocked_path, log, lang)
                log(m("verify", lang), "info")
                time.sleep(1)
                log(m("verified", lang), "ok")
                progress(95)

            step(4); progress(100)
            log("", "info")
            log(m("done", lang), "ok")
            self._js("onComplete(true)")

        except Exception as e:
            log(f"ERROR: {e}", "error")
            self._js("onComplete(false)")

    def _js(self, code):
        if self._window:
            self._window.evaluate_js(code)


# =============================================================================
# ENTRY POINT
# =============================================================================
if __name__ == "__main__":
    api    = API()
    window = webview.create_window(
        title            = "BiosMajster v1.0.0",
        url              = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html"),
        js_api           = api,
        width            = 900,
        height           = 600,
        min_size         = (720, 520),   # minimum usable size when resizing
        resizable        = True,         # enables resize + maximise button
        background_color = "#080a0c",
    )
    api.set_window(window)
    webview.start(debug=False)
