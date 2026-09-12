#!/bin/sh
# run_route_a.sh — one-command master-code readout for the target machine.
# Default target: OptiPlex 3090, service tag H2FS5S3, suffix family CF1B.
#
# WHAT IT DOES (read-only — nothing is written to or enrolled in the EC):
#   1. fetches dell_cf1b_master.c from the project repo (or uses a local copy)
#   2. builds it with gcc/cc
#   3. runs it against the machine's own EC mailbox (ports 0x910/0x911,
#      cmd 0x21 sub 3 type 6 — the same session the BIOS itself uses)
#   4. if the session is gated/short, automatically runs the diagnostic probe
#
# REQUIREMENTS: bare-metal Linux as root (a VM will NOT work), internet OR a
# pre-downloaded dell_cf1b_master.c next to this script.
#
# Usage:
#   sudo sh run_route_a.sh                 # H2FS5S3 + CF1B (this machine)
#   sudo sh run_route_a.sh -t XXXXXXX -f CF1B   # any tag/family override
set -u

TAG="H2FS5S3"
FAM="CF1B"
while [ $# -ge 2 ]; do
    case "$1" in
        -t) TAG="$2"; shift 2 ;;
        -f) FAM="$2"; shift 2 ;;
        *) shift ;;
    esac
done

URLBASE="https://raw.githubusercontent.com/serversupdep-ai/Zte/arena/01a087e2-zte/bios-analysis"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root:  sudo sh $0" >&2
    exit 1
fi

# 1. source file: local copy first, else download
if [ ! -f dell_cf1b_master.c ]; then
    echo "[*] downloading dell_cf1b_master.c ..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o dell_cf1b_master.c "$URLBASE/dell_cf1b_master.c" || {
            echo "[-] download failed. Pre-download dell_cf1b_master.c (and" >&2
            echo "    dell_cf1b_probe.c) and place them next to this script." >&2
            exit 1; }
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O dell_cf1b_master.c "$URLBASE/dell_cf1b_master.c" || {
            echo "[-] download failed. Pre-download dell_cf1b_master.c (and" >&2
            echo "    dell_cf1b_probe.c) and place them next to this script." >&2
            exit 1; }
    else
        echo "[-] no curl/wget. Pre-download dell_cf1b_master.c and place it" >&2
        echo "    next to this script." >&2
        exit 1
    fi
fi

# 2. compiler
CC=""
for c in cc gcc clang; do
    command -v "$c" >/dev/null 2>&1 && { CC="$c"; break; }
done
if [ -z "$CC" ]; then
    echo "[*] no compiler found — trying apt ..."
    apt-get update -qq && apt-get install -y -qq gcc >/dev/null 2>&1 && CC=gcc
fi
[ -z "$CC" ] && { echo "[-] no C compiler available. Install gcc and re-run." >&2; exit 1; }

# 3. build + run
echo "[*] building with $CC ..."
"$CC" -O2 -o dell_cf1b_master dell_cf1b_master.c || exit 1

echo
echo "=== MASTER-CODE READOUT — tag $TAG, family $FAM ==="
./dell_cf1b_master -t "$TAG" -f "$FAM"
RC=$?

if [ "$RC" -ne 0 ]; then
    echo
    echo "[*] primary session did not complete — running diagnostic probe ..."
    if [ ! -f dell_cf1b_probe.c ]; then
        command -v curl >/dev/null 2>&1 && \
            curl -fsSL -o dell_cf1b_probe.c "$URLBASE/dell_cf1b_probe.c"
        command -v wget >/dev/null 2>&1 && [ ! -f dell_cf1b_probe.c ] && \
            wget -q -O dell_cf1b_probe.c "$URLBASE/dell_cf1b_probe.c"
    fi
    if [ -f dell_cf1b_probe.c ]; then
        "$CC" -O2 -o dell_cf1b_probe dell_cf1b_probe.c 2>/dev/null && \
            ./dell_cf1b_probe --family "$FAM"
    fi
    echo
    echo "Keep BOTH outputs — they pin down exactly how this EC gates the"
    echo "session. Tips: bare metal (not VM), and if the EC gates by state,"
    echo "re-run while the BIOS challenge screen is up (reboot to the prompt,"
    echo "then warm-reset into Linux without removing power)."
fi
exit "$RC"
