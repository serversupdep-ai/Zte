#!/bin/sh
# dell_donor_factory.sh — turn ANY one working machine of a model into that
# model's master-password keygen (donor-GENERATE method).
#
# WHY THIS WORKS
#   The BIOS hands the service tag to the EC over the mailbox (ports
#   0x910/0x911, session type-6 GENERATE) and the EC returns the 32-byte
#   response the master password is derived from. The EC has no
#   "wrong tag" status (its status vocabulary is {0,2,6,9,14} — verified
#   from the module RE, CF1B_FINDINGS §11.22.3), so a donor machine can
#   generate the code for ANY service tag of the same model + EC build.
#
# WHAT YOU NEED
#   * any ONE working (bootable, unlocked) machine of the SAME model and
#     BIOS/EC generation as the locked machine
#   * a Linux live USB (any distro), boot it, open a terminal
#   * this script + dell_master_keygen.py on a USB stick
#
# USAGE (as root on the donor machine)
#   sudo sh dell_donor_factory.sh <model-id> <TARGETTAG> <SUFFIX>
#   example:
#   sudo sh dell_donor_factory.sh optiplex-3090 H2FS5S3 CF1B
#
# model ids: latitude-3410 latitude-3420 optiplex-3080 optiplex-3090
#            optiplex-3090uff
set -e
MODEL="$1"; TAG="$2"; SUFFIX="$3"
[ -z "$MODEL" ] || [ -z "$TAG" ] || [ -z "$SUFFIX" ] && {
  echo "usage: sudo sh dell_donor_factory.sh <model-id> <TARGETTAG> <SUFFIX>"; exit 1; }
[ "$(id -u)" = "0" ] || { echo "run as root (sudo)"; exit 1; }
[ -e /dev/port ] || { echo "/dev/port missing — boot with the live USB (not a VM)"; exit 1; }
DIR=$(dirname "$0")
echo "== donor GENERATE: model $MODEL, target tag $TAG-$SUFFIX"
echo "== this machine's EC computes the code for the TARGET machine's tag"
python3 "$DIR/dell_master_keygen.py" --model "$MODEL" --tag "$TAG" --suffix "$SUFFIX" --oracle local
