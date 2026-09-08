#!/usr/bin/env python3
"""
Legacy Samsung network-unlock code extractor -- and the proof that no Samsung
keygen exists.

READ THIS FIRST, because it is the opposite of what you probably expect.

Every other brand in unlock.py computes its code: f(IMEI) -> code. Samsung never
did, not even on 2011 hardware. Samsung *stored* the code, as eight ASCII
digits, at a fixed offset inside the EFS partition, where it was written at the
factory. So:

  * There is no Samsung keygen to write. Not "I could not find one" -- there is
    no function to invert, because there was never a function.
  * What exists instead is a *reader*. If you have nv_data.bin off a Galaxy S
    4G (SGH-T959V / SGH-T959W), the code is sitting in it as plain text.

This is a port of fbis251/sgs4g-unlock-code-finder (ANSI C, GPL-3.0), with the
stricter validation from fbis251/Galaxy-S-Unlocker-for-PC (D). Both are on
GitHub; both take a filename and NEITHER references the IMEI anywhere. I
checked: `grep -i imei` across both projects returns nothing.

Layout, from unlocker.h and unlocker.d verbatim:

  offset 0x1468   0xFF                      validation byte
  offset 0x1469   13 bytes                  lock status + code block
  offset 0x1469   byte 0                    lock status: 0x00 unlocked, 0x01 locked
  offset 0x146E   8 bytes, ASCII '0'-'9'    THE UNLOCK CODE   (0x1469 + 5)

Run:  python3 samsung_nvdata.py nv_data.bin
      python3 samsung_nvdata.py --self-test
"""

import sys

# --- constants, exactly as defined upstream --------------------------------
MAGIC_OFFSET = 0x1469       # lock status + ASCII code block starts here
BLOCK_LENGTH = 13           # bytes in that block (CODE_LENGTH in unlocker.h)
CODE_OFFSET = 5             # ASCII code starts this far into the block
END_OFFSET = MAGIC_OFFSET + BLOCK_LENGTH      # 0x1476
FIRST_BYTE = 0xFF           # byte immediately before MAGIC_OFFSET
UNLOCKED = 0x00
LOCKED = 0x01

# Unlock code: bytes 5..13 of the block, i.e. 0x146E..0x1476.
# 0x1469 + 5 == 0x146E, which is the offset the upstream README calls "magic".
CODE_START = MAGIC_OFFSET + CODE_OFFSET       # 0x146E
CODE_DIGITS = 8

TARGET_MODELS = ('SGH-T959V', 'SGH-T959W')


class NotExtractable(Exception):
    """Raised when the file is not a usable nv_data.bin."""


def extract(data):
    """Pull the stored unlock code and lock status out of nv_data.bin bytes.

    Returns a dict: valid, reason, code, lock_status, lock_text.
    Never raises -- check `valid`.
    """
    res = {'valid': False, 'reason': None, 'code': None,
           'lock_status': None, 'lock_text': 'unknown'}

    if len(data) < END_OFFSET:
        res['reason'] = ('file is %d bytes; the code block ends at 0x%X (%d)'
                         % (len(data), END_OFFSET, END_OFFSET))
        return res

    if data[MAGIC_OFFSET - 1] != FIRST_BYTE:
        res['reason'] = ('validation byte at 0x%X is 0x%02X, expected 0x%02X -- '
                         'not a valid nv_data.bin, or the wrong model'
                         % (MAGIC_OFFSET - 1, data[MAGIC_OFFSET - 1], FIRST_BYTE))
        return res

    raw = data[CODE_START:CODE_START + CODE_DIGITS]
    if len(raw) != CODE_DIGITS:
        res['reason'] = 'short read at 0x%X' % CODE_START
        return res

    for i, b in enumerate(raw):
        if not (0x30 <= b <= 0x39):          # '0'..'9'
            res['reason'] = ('byte %d of the code (0x%X) is 0x%02X, not an '
                             'ASCII digit' % (i, CODE_START + i, b))
            return res

    res['valid'] = True
    res['code'] = raw.decode('ascii')
    res['lock_status'] = data[MAGIC_OFFSET]
    res['lock_text'] = {UNLOCKED: 'Unlocked', LOCKED: 'Locked'}.get(
        res['lock_status'], 'Unknown')
    return res


def report(path_or_bytes):
    if isinstance(path_or_bytes, (bytes, bytearray)):
        data, label = bytes(path_or_bytes), '(memory)'
    else:
        label = path_or_bytes
        with open(path_or_bytes, 'rb') as fh:
            data = fh.read()
        # Upstream reads only the block; a real EFS image is much larger, and
        # the rest is irrelevant here.

    r = extract(data)
    out = ['nv_data.bin   : %s' % label,
           'size          : %d bytes' % len(data),
           'code at 0x%X  : %s' % (CODE_START, r['code'] or '--'),
           'lock status   : %s' % r['lock_text']]
    if not r['valid']:
        out.append('INVALID       : %s' % r['reason'])
    else:
        out += ['',
                'That 8-digit value is the NCK. Enter it with a foreign SIM',
                'inserted, or via #7465625*638*%s# with no SIM.' % r['code'],
                '',
                'Note what just happened: nothing was computed. The IMEI was',
                'never used -- these tools do not even accept one. The code was',
                'written into EFS at the factory and you have read it back.',
                '',
                'That is why there is no Samsung keygen. On models that do not',
                'expose it as plaintext -- which is every model after this',
                'generation -- the only copy is on the carrier server.']
    return out


# --- test fixture -----------------------------------------------------------
def make_nvdata(code='12345678', lock=LOCKED, size=0x2000):
    """Build a synthetic nv_data.bin with the documented layout."""
    buf = bytearray(b'\x00' * size)
    buf[MAGIC_OFFSET - 1] = FIRST_BYTE
    buf[MAGIC_OFFSET] = lock
    for i, ch in enumerate(code):
        buf[CODE_START + i] = ord(ch)
    return bytes(buf)


def self_test():
    failures = []

    def check(label, got, want):
        ok = got == want
        print('  [%s] %s' % ('PASS' if ok else 'FAIL', label))
        if not ok:
            failures.append(label)

    print('layout constants match the upstream headers')
    check('MAGIC_OFFSET is 0x1469', MAGIC_OFFSET, 0x1469)
    check('CODE_START is 0x146E', CODE_START, 0x146E)
    check('CODE_START is the README magic offset', CODE_START,
          int('146E', 16))
    check('block ends at 0x1476', END_OFFSET, 0x1476)
    check('CODE_START == MAGIC_OFFSET + CODE_OFFSET',
          CODE_START, MAGIC_OFFSET + CODE_OFFSET)

    print('\nextraction')
    r = extract(make_nvdata('12345678'))
    check('a well-formed file is valid', r['valid'], True)
    check('the code comes back intact', r['code'], '12345678')
    check('locked status is reported', r['lock_text'], 'Locked')
    check('unlocked status is reported',
          extract(make_nvdata('12345678', UNLOCKED))['lock_text'], 'Unlocked')
    check('unknown status is reported',
          extract(make_nvdata('12345678', 0x7F))['lock_text'], 'Unknown')
    for c in ('00000000', '99999999', '27382729', '08675309'):
        check('round-trips %s' % c, extract(make_nvdata(c))['code'], c)
    # The code must come from the documented offset and nowhere else: put a
    # different digit string elsewhere and confirm it is ignored.
    decoy = bytearray(make_nvdata('12345678'))
    for i, ch in enumerate('99999999'):
        decoy[0x1000 + i] = ord(ch)
    check('ignores digits stored at other offsets',
          extract(bytes(decoy))['code'], '12345678')

    print('\nrejection')
    check('too-short file is rejected',
          extract(b'\x00' * 100)['valid'], False)
    check('short file says why',
          'file is 100 bytes' in extract(b'\x00' * 100)['reason'], True)
    bad = bytearray(make_nvdata('12345678'))
    bad[MAGIC_OFFSET - 1] = 0x00
    check('wrong validation byte is rejected', extract(bytes(bad))['valid'], False)
    check('the validation failure names the offset',
          '0x1468' in extract(bytes(bad))['reason'], True)
    nonascii = bytearray(make_nvdata('12345678'))
    nonascii[CODE_START + 3] = 0x41            # 'A'
    check('a non-digit in the code is rejected',
          extract(bytes(nonascii))['valid'], False)
    check('the digit failure names the byte',
          '0x1471' in extract(bytes(nonascii))['reason'], True)
    empty = bytearray(make_nvdata('12345678'))
    for i in range(CODE_DIGITS):
        empty[CODE_START + i] = 0x00
    check('an all-zero code region is rejected, not read as 00000000',
          extract(bytes(empty))['valid'], False)
    check('extract never raises on garbage',
          extract(bytes(range(256)) * 40)['valid'], False)

    print('\nthe point of the exercise')
    check('the public API takes no IMEI',
          'imei' in extract.__code__.co_varnames, False)
    check('make_nvdata takes no IMEI',
          'imei' in make_nvdata.__code__.co_varnames, False)
    check('no IMEI parameter anywhere in the module',
          'imei' in [v for f in (extract, make_nvdata, report)
                      for v in f.__code__.co_varnames], False)
    check('report explains nothing was computed',
          any('nothing was computed' in l for l in report(make_nvdata())), True)

    print('\n%d failure(s)' % len(failures))
    return 1 if failures else 0


def main(argv):
    if '--self-test' in argv:
        return self_test()
    if '--demo' in argv:
        print('\n'.join(report(make_nvdata('27382729', LOCKED))))
        return 0
    if len(argv) < 2 or argv[1].startswith('--'):
        print(__doc__.strip())
        print('\nusage: samsung_nvdata.py <nv_data.bin> | --self-test | --demo')
        print('target models: %s' % ', '.join(TARGET_MODELS))
        return 0
    try:
        print('\n'.join(report(argv[1])))
    except OSError as e:
        print('cannot read %s: %s' % (argv[1], e))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
