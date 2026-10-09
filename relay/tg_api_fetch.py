#!/usr/bin/env python3
"""tg_api_fetch.py — Telegram-API (MTProto) document downloader for the relay.

WHY: t.me web pages never serve channel DOCUMENTS over plain HTTP (photos
only, via telesco.pe). File bytes flow exclusively through MTProto with a
logged-in session. This script is that path — run on the GitHub Actions
relay runner, reading credentials from GitHub repo SECRETS so nothing
sensitive ever appears in chat or in the repo.

ONE-TIME SETUP (never paste these values in chat — repo Secrets only):
  1. Open the t.me/biosarchive channel in the Telegram app and Join (free,
     public channel) with a normal account.
  2. Log in at https://my.telegram.org with that account ->
     "API development tools" -> create app -> note api_id + api_hash.
  3. Mint a session string on your own machine (interactive):
       pip install pyrogram tgcrypto
       python3 -c "import pyrogram; from pyrogram import Client; \
c=Client('mint', api_id=API_ID, api_hash='API_HASH'); c.start(); \
print(c.export_session_string()); c.stop()"
     (enter the account phone number + the login code Telegram sends.)
  4. GitHub repo -> Settings -> Secrets and variables -> Actions -> add:
       TG_API_ID, TG_API_HASH, TG_SESSION
  5. Done. Every relay run (fetch-files.yml) then downloads the targets
     below automatically; results land in bios-analysis/collected/raw/.

TARGETS (biosarchive free attachments — WATCHLOG cycle 21; refresh freely):
  30339  OptiPlex 7470 AIO IPCFL-GL "MCU" 32MB & 512KB  (2019 EC-class
         chip read; if the 512KB MCU image is pre-sealing plaintext EC
         code, it completes the engine — TOP PRIORITY)
  24189  EDW40 LA-H451P 2019 MEC1515-NB (8FC8-family EC silicon reads:
         UC3/UM3/UPD3/UT2)
  30462  Latitude 3310 19717-1 8MB & 16MB (3410-class companion reads)
"""
import os

TARGETS = [
    ("biosarchive", 30339, "tg_7470AIO_MCU"),
    ("biosarchive", 24189, "tg_EDW40_MEC1515NB"),
    ("biosarchive", 30462, "tg_3310_19717"),
]
OUTBASE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "..", "bios-analysis", "collected", "raw")


def main():
    api_id = os.environ.get("TG_API_ID")
    api_hash = os.environ.get("TG_API_HASH")
    session = os.environ.get("TG_SESSION")
    if not (api_id and api_hash and session):
        print("tg_api_fetch: TG_API_ID/TG_API_HASH/TG_SESSION unset — skip")
        return 0
    from pyrogram import Client  # noqa: imported only when configured
    app = Client("relay", api_id=int(api_id), api_hash=api_hash,
                 session_string=session)
    out = os.path.abspath(OUTBASE)
    got = 0
    with app:
        for chan, mid, tag in TARGETS:
            d = os.path.join(out, tag)
            os.makedirs(d, exist_ok=True)
            try:
                msgs = app.get_messages(chan, mid)
            except Exception as e:
                print(f"{chan}/{mid}: get_messages failed: {e}")
                continue
            for m in ([msgs] if not isinstance(msgs, list) else msgs):
                try:
                    if m and m.document:
                        p = m.download(file_name=os.path.join(
                            d, m.document.file_name or f"doc_{mid}.bin"))
                        print("downloaded:", p)
                        got += 1
                    if m and m.photo:
                        p = m.download(file_name=os.path.join(
                            d, f"photo_{mid}.jpg"))
                        print("downloaded:", p)
                        got += 1
                except Exception as e:
                    print(f"{chan}/{mid}: download failed: {e}")
    print(f"tg_api_fetch: done ({got} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
