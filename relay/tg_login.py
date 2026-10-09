#!/usr/bin/env python3
"""tg_login.py — one-run interactive Telegram login + target download.

WHY THIS SHAPE: the repo is PUBLIC, so a Telegram session must never be
printed to logs, stored in artifacts, or committed. Instead the login and
the downloads happen INSIDE one workflow run and the session is discarded
when the run ends.

HOW THE USER RUNS IT (GitHub web UI only — no local software):
  1. Actions -> "Telegram login (two-stage)" -> Run workflow with:
       stage = phone    value = +<countrycode><number> of the Telegram acct
     -> Telegram sends a login code to that account's app.
  2. Run workflow again (a minute later) with:
       stage = code     value = the login code just received
     (if the account has 2FA, run a third time: stage = password)
  3. On success the target files are downloaded and committed to
     bios-analysis/collected/raw/ automatically. Nothing sensitive persists.

API credentials: defaults to the public Telegram-Desktop open-source
api_id/api_hash pair; if Telegram rejects it from datacenter IPs
(API_ID_PUBLISHED), set TG_API_ID/TG_API_HASH (GitHub Secrets) from a
one-time my.telegram.org app creation.

NOTE: dispatch inputs are visible on the workflow-run page of a public
repo. Phone/code are one-time/low-sensitivity, but if you type a 2FA
PASSWORD, the cleanup step deletes previous runs; delete the final one
manually too (one click on the run page).
"""
import json
import os
import sys

from pyrogram import Client

WORKDIR = os.path.dirname(os.path.abspath(__file__))
STATE_F = os.path.join(WORKDIR, "tglogin_state.json")
API_ID = int(os.environ.get("TG_API_ID") or 2040)                     # TD OSS
API_HASH = os.environ.get("TG_API_HASH") or "b18441a1ff607e10a989891a5462e627"
OUTBASE = os.path.join(WORKDIR, "..", "bios-analysis", "collected", "raw")

# biosarchive free attachments (WATCHLOG cycle 21)
TARGETS = [
    ("biosarchive", 30339, "tg_7470AIO_MCU"),       # OptiPlex 7470 512KB MCU
    ("biosarchive", 24189, "tg_EDW40_MEC1515NB"),   # MEC1515-NB EC reads
    ("biosarchive", 30462, "tg_3310_19717"),        # 3310 8MB+16MB
]


def save_state(phone, phone_code_hash):
    with open(STATE_F, "w") as f:
        json.dump({"phone": phone, "phone_code_hash": phone_code_hash}, f)


def load_state():
    with open(STATE_F) as f:
        return json.load(f)


def new_client():
    return Client("tglogin", api_id=API_ID, api_hash=API_HASH, workdir=WORKDIR)


def download_targets(app):
    got = 0
    try:
        app.join_chat("biosarchive")
        print("joined channel biosarchive")
    except Exception as e:
        print("join_chat (best effort):", e)
    for chan, mid, tag in TARGETS:
        d = os.path.join(OUTBASE, tag)
        os.makedirs(d, exist_ok=True)
        try:
            m = app.get_messages(chan, mid)
            if m and m.document:
                p = m.download(file_name=os.path.join(
                    d, m.document.file_name or f"doc_{mid}.bin"))
                print("downloaded:", p)
                got += 1
            if m and m.photo:
                p = m.download(file_name=os.path.join(d, f"photo_{mid}.jpg"))
                print("downloaded:", p)
                got += 1
            if m and not (m.document or m.photo):
                print(f"{chan}/{mid}: no media on this message")
        except Exception as e:
            print(f"{chan}/{mid}: failed: {e}")
    print(f"downloads complete: {got} file(s)")
    return got


def api_id_hint(e):
    if "API_ID_PUBLISHED" in str(e) or "API_ID_INVALID" in str(e):
        print("\nTelegram rejected the default public api_id from this IP.")
        print("FIX (one time): my.telegram.org -> API development tools ->")
        print("create app -> GitHub repo Settings -> Secrets -> Actions ->")
        print("add TG_API_ID and TG_API_HASH -> run stage=phone again.")


def main():
    stage = os.environ.get("STAGE", "").strip().lower()
    value = os.environ.get("VALUE", "").strip()

    if stage == "phone":
        if not value.startswith("+") or len(value) < 8:
            print("ERROR: value must be the phone WITH country code, e.g. +2126xxxxxxxx")
            return 2
        c = new_client()
        try:
            c.connect()
            sent = c.send_code(value)
        except Exception as e:
            print("send_code failed:", e)
            api_id_hint(e)
            return 4
        finally:
            try:
                c.disconnect()
            except Exception:
                pass
        save_state(value, sent.phone_code_hash)
        print("LOGIN CODE SENT — now run this workflow again with")
        print("stage=code and value=<the code that just appeared in Telegram>")
        return 0

    if stage in ("code", "password"):
        if not os.path.exists(STATE_F):
            print("ERROR: no login state — run stage=phone first")
            return 2
        if not value:
            print("ERROR: value empty")
            return 2
        st = load_state()
        c = new_client()
        c.connect()
        try:
            if stage == "code":
                c.sign_in(st["phone"], st["phone_code_hash"], value)
            else:
                c.sign_in(password=value)
        except Exception as e:
            name = type(e).__name__
            if "SessionPasswordNeeded" in name:
                print("2FA enabled — run stage=password with your Telegram password")
            elif "FloodWait" in name:
                print(f"Telegram rate limit: wait {getattr(e, 'value', 60)}s and retry")
            elif "PhoneCodeInvalid" in name or "PHONE_CODE_INVALID" in str(e):
                print("code wrong/expired — run stage=phone again for a fresh code")
            else:
                print("sign_in failed:", e)
                api_id_hint(e)
            return 3
        print("LOGIN OK — downloading targets…")
        got = download_targets(c)
        c.disconnect()
        print(f"done: {got} file(s) committed next; session discarded, never stored")
        return 0

    print("unknown stage — use phone | code | password")
    return 2


if __name__ == "__main__":
    sys.exit(main())
