#!/usr/bin/env python3
"""
Reference implementation of the unlock-code ("NCK") algorithms documented in
alexanderritola/Go-Unlock-Code-Calculator @ 8cabc40 (master, 2013-01-28),
plus one modern ZTE-family algorithm for contrast.

This is a line-by-line port, written so the arithmetic can be read next to the
Go source.  Run `python3 unlock.py --self-test` to re-run the verification
vectors described in MECHANISM.md.

These schemes are all offline, IMEI-derived and long obsolete.  Use only on
hardware you own and are entitled to unlock.
"""

import hashlib
import hmac
import sys

# --------------------------------------------------------------------------
# 1. ZTE v1  -- Go: ZTE.go zteOld()
# --------------------------------------------------------------------------
# The Go comment calls this "zteB02".  It ignores the 3-digit TAC prefix and
# the trailing Luhn check digit, works on the 12 middle digits, and mixes them
# with a fixed 12-entry magic vector.
ZTE_V1_MAGIC = (6, 8, 8, 9, 5, 0, 0, 0, 0, 0, 0, 0)


def zte_v1_digits(imei):
    """The 12 digits the v1 algorithm actually consumes: imei[3:15]."""
    return [int(c) for c in imei[3:15]]


def zte_v1(imei):
    d = zte_v1_digits(imei)
    crosssum = sum(d)
    nck = [(d[i] * crosssum + d[11 - i] * 8 + ZTE_V1_MAGIC[i]) % 10 for i in range(12)]
    # SPCK is just NCK offset by the mirrored digit -- it leaks nothing new.
    spck = [(nck[i] + d[11 - i]) % 10 for i in range(12)]
    return ''.join(map(str, nck)), ''.join(map(str, spck))


# --------------------------------------------------------------------------
# 2. ZTE v2 / v3  -- Go: ZTE.go zteB03() / zteB04()
# --------------------------------------------------------------------------
# Go puts '*' and '&' at the same precedence level (level 5, left-associative),
# so `A & 0xFF * 0x09` parses as `(A & 0xFF) * 9` -- the intended reading.
#
#   key[i] = ((pre[i] + pre[i+8]) * 9) / 255          # v2 / B03
#   key[i] = ((pre[i] + pre[i+8] + pre[i+4] + 40) * 9) / 255   # v3 / B04
#
# Both truncate to 0..9, so the NCK is 8 characters drawn from 0-9.
def _zte_md5_keys(imei, v3):
    pre = list(hashlib.md5(imei.encode()).digest())
    out = ''
    for i in range(8):
        total = pre[i] + pre[i + 8]
        if v3:
            total += pre[i + 4] + 40
        out += '%x' % (((total & 0xFF) * 9) // 0xFF)
    return out


def zte_v2(imei):
    return _zte_md5_keys(imei, v3=False)


def zte_v3(imei):
    return _zte_md5_keys(imei, v3=True)


# --------------------------------------------------------------------------
# 3. Huawei v1  -- Go: Huawei.go HuaweiOld() / HuaweiCode()
# --------------------------------------------------------------------------
# Two fixed passphrases are MD5'd; hex chars 8..24 become the per-purpose salt.
# Then MD5(imei + salt) is XOR-folded 4:1 into four bytes, forced into the
# range 0x02000000..0x03FFFFFF so the code is always 8 digits.
HUAWEI_UNLOCK_PASSPHRASE = "hwe620datacard"   # -> salt 5e8dd316726b0335
HUAWEI_FLASH_PASSPHRASE = "e630upgrade"      # -> salt 97b7bc6be525ab44


def huawei_salt(passphrase):
    return hashlib.md5(passphrase.encode()).hexdigest()[8:24]


def huawei_code(imei, salt):
    digest = hashlib.md5((imei + salt).lower().encode()).digest()
    folded = [digest[i] ^ digest[i + 4] ^ digest[i + 8] ^ digest[i + 12] for i in range(4)]
    folded[0] = (folded[0] & 0x01) | 0x02          # & 0x1FFFFFF then | 0x2000000
    return int.from_bytes(bytes(folded), 'big')


def huawei_old(imei):
    return (huawei_code(imei, huawei_salt(HUAWEI_UNLOCK_PASSPHRASE)),
            huawei_code(imei, huawei_salt(HUAWEI_FLASH_PASSPHRASE)))


# --------------------------------------------------------------------------
# 4. BlackBerry MEP  -- Go: Blackberry.go
# --------------------------------------------------------------------------
# createPrivatePass XORs a per-model 16-byte secret out of findMEP.go against a
# fixed array and zero-pads it to 64 bytes.  makeSHA1 then hand-rolls
# HMAC-SHA1 with that 64-byte key, once per MEP slot 1..5.  makeCode keeps the
# last decimal digit of the first 16 digest bytes (8 for a short list of MEPs).
BB_STATIC = (0x16, 0x27, 0x99, 0xC2, 0xC8, 0x99, 0xB8, 0xC9,
             0xDE, 0xED, 0x77, 0xA2, 0x62, 0xD2, 0x66, 0x5E)
BB_8DIGIT_MEPS = {"MEP-23361-001", "MEP-30218-002", "MEP-15326-002", "MEP-04626-002",
                  "MEP-27501-003", "MEP-31845-001", "MEP-22793-001", "MEP-04103-001"}


def bb_private_pass(mep16):
    return bytes(BB_STATIC[i] ^ mep16[i] for i in range(16)) + bytes(48)


def bb_code(digest_bytes, mep_name, size=None):
    size = size or (8 if mep_name in BB_8DIGIT_MEPS else 16)
    return ''.join(str(digest_bytes[i] % 10) for i in range(size))


def bb_message(imei, mep_number, go_faithful=True):
    """makeSHA1 builds `fmt.Sprintf("%02X", strIMEI) + "0" + n`.

    %X on a *string* is "base 16, two characters per byte" (Go fmt docs), so
    with go_faithful=True the IMEI is hex-encoded first -- see BUGS in
    MECHANISM.md.  Set it False for the behaviour the author almost certainly
    intended.
    """
    head = imei.encode().hex().upper() if go_faithful else imei
    return (head + "0" + str(mep_number)).encode()


def bb_mep_codes(imei, mep16, mep_name="", go_faithful=True):
    key = bb_private_pass(mep16)
    return {n: bb_code(hmac.new(key, bb_message(imei, n, go_faithful), hashlib.sha1).digest(), mep_name)
            for n in range(1, 6)}


# --------------------------------------------------------------------------
# 5. Alcatel C700 family  -- Go: Alcatel.go alcatelC700Calc()
# --------------------------------------------------------------------------
# Swap adjacent IMEI digits, prepend "08", permute 2-char chunks by a
# model-specific order, prepend a model byte, SHA1 the 28-byte result, then
# XOR five digest bytes together four times (indices chosen by a model-specific
# table) and read the 4 bytes as a decimal number.
ALCATEL_MODELS = {
    # name: (nck_byte, spck_byte, permutation, xor-order)
    'C820':        ('8F', 'BE', '876543210', '110A090201100B0803000F0C0704130E0D060512'),
    'C825':        ('8F', 'BE', '876543210', '110A090201100B0803000F0C0704130E0D060512'),
    'C700':        ('3C', 'E2', '785432106', '0B121307000C110806010D100905020E0F0A0403'),
    'C701':        ('3C', 'E2', '785432106', '0B121307000C110806010D100905020E0F0A0403'),
    'C717':        ('3C', 'E2', '785432106', '0B121307000C110806010D100905020E0F0A0403'),
    'EL03':        ('3C', 'E2', '785432106', '0B121307000C110806010D100905020E0F0A0403'),
    'MissSixty':   ('6C', 'B9', '456132807', '0503011311040200121007090B0D0F06080A0C0E'),
    'S520':        ('6C', 'B9', '456132807', '0503011311040200121007090B0D0F06080A0C0E'),
    'S215':        ('74', '9A', '547682031', '0504010D0F0C06070A0010080B0E031202111309'),
    'S218':        ('74', '9A', '547682031', '0504010D0F0C06070A0010080B0E031202111309'),
    'S219':        ('74', '9A', '547682031', '0504010D0F0C06070A0010080B0E031202111309'),
    'S320':        ('74', '9A', '547682031', '0504010D0F0C06070A0010080B0E031202111309'),
    'S321':        ('74', '9A', '547682031', '0504010D0F0C06070A0010080B0E031202111309'),
}


def _alcatel_calc(imei, tag, perm, xorn):
    simei = imei + "0"
    swapped = "08"
    for i in range(0, len(simei) - 1, 2):
        swapped += simei[i + 1] + simei[i]
    chunks = [swapped[j:j + 2] for j in range(0, 18, 2)]
    order = [int(c) for c in perm[:len(perm) - 1]]      # Go fills 8 of 9 slots
    order += [0] * (9 - len(order))
    permuted = ''.join(chunks[order[i]] for i in range(9))
    digest = hashlib.sha1(bytes.fromhex(tag + swapped + swapped + permuted)).digest()
    xorder = bytes.fromhex(xorn)
    doxor = list(xorder[:len(xorder) - 1])              # Go fills 19 of 20 slots
    doxor += [0] * (20 - len(doxor))
    pre = ''
    for i in range(0, 19, 5):
        pre += '%02x' % (digest[doxor[i]] ^ digest[doxor[i + 1]] ^ digest[doxor[i + 2]]
                         ^ digest[doxor[i + 3]] ^ digest[doxor[i + 4]])
    return str(int(pre, 16))


def alcatel(model, imei):
    tag_n, tag_s, perm, xorn = ALCATEL_MODELS[model]
    return _alcatel_calc(imei, tag_n, perm, xorn), _alcatel_calc(imei, tag_s, perm, xorn)


# --------------------------------------------------------------------------
# 6. Modern contrast: ZXIC ZX297520V3 / Hisense H220m
# --------------------------------------------------------------------------
# kozik47/zte-imei-unlock.  A 10-entry digit substitution map plus an
# 8-wide sliding window sum, mod 10.  Structurally the same idea as ZTE v1 --
# a fixed per-model secret table -- just not MD5-based.  Adding 5 to every
# mapped value shifts each window sum by 8*5 = 40, which is 0 mod 10, so two
# distinct maps produce identical codes (the repo documents this ambiguity).
H220M_MAP = {0: 1, 1: 3, 2: 5, 3: 7, 4: 9, 5: 0, 6: 2, 7: 4, 8: 6, 9: 8}


def h220m(imei, table=None):
    table = table or H220M_MAP
    d = [table[int(c)] if c.isdigit() else 0 for c in imei[:15]]
    return ''.join(str(sum(d[i:i + 8]) % 10) for i in range(8))


# --------------------------------------------------------------------------
def self_test():
    failures = []

    def check(label, got, want):
        ok = got == want
        print('  [%s] %-52s %s' % ('PASS' if ok else 'FAIL', label, got))
        if not ok:
            failures.append((label, got, want))

    print('salt derivation (independently confirmed with coreutils md5sum)')
    check('md5("hwe620datacard")[8:24]', huawei_salt(HUAWEI_UNLOCK_PASSPHRASE), '5e8dd316726b0335')
    check('md5("e630upgrade")[8:24]', huawei_salt(HUAWEI_FLASH_PASSPHRASE), '97b7bc6be525ab44')

    print('\nZTE v1 vs published tools.texby.com NCK/SPCK pair')
    # Recover the 12 consumed digits straight out of the published pair:
    # SPCK[i] = (NCK[i] + d[11-i]) % 10  =>  d[11-i] = (SPCK[i] - NCK[i]) % 10
    pub_nck, pub_spck = '185553270348', '184709110429'
    recovered = [(int(pub_spck[i]) - int(pub_nck[i])) % 10 for i in range(12)][::-1]
    check('recovered imei[3:15]', ''.join(map(str, recovered)), '181049652900')
    n, s = zte_v1('XXX' + ''.join(map(str, recovered)) + '0')
    check('zte_v1 NCK ', n, pub_nck)
    check('zte_v1 SPCK', s, pub_spck)

    print('\nHuawei v1 vs independent reference implementation')
    def reference(imei, salt):
        dg = hashlib.md5((imei + salt).lower().encode()).digest()
        c = 0
        for i in range(4):
            c += (dg[i] ^ dg[i + 4] ^ dg[i + 8] ^ dg[i + 12]) << (3 - i) * 8
        return (c & 0x1FFFFFF) | 0x2000000
    salts = (huawei_salt(HUAWEI_UNLOCK_PASSPHRASE), huawei_salt(HUAWEI_FLASH_PASSPHRASE))
    cases = [(str(10**14 + k).zfill(15), sa) for k in range(20000) for sa in salts]
    check('agrees on %d (imei, salt) pairs' % len(cases),
          all(huawei_code(i, sa) == reference(i, sa) for i, sa in cases), True)

    print('\nBlackBerry makeSHA1 is hand-rolled HMAC-SHA1')
    def handrolled(key, msg):                     # literal transcription of makeSHA1
        ipad = bytes(b ^ 0x36 for b in key)
        opad = bytes(b ^ 0x5C for b in key)
        inner = hashlib.sha1(ipad + msg).digest()
        return hashlib.sha1(opad + inner).digest().hex().upper()
    key = bb_private_pass([1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0])
    check('MEP1..MEP5 match stdlib hmac',
          all(handrolled(key, bb_message('351234567891239', n))
              == hmac.new(key, bb_message('351234567891239', n), hashlib.sha1).hexdigest().upper()
              for n in range(1, 6)), True)
    print('  info: Go-faithful message for MEP1 is %s' % bb_message('351234567891239', 1).decode())
    check('the %02X quirk changes the code',
          bb_mep_codes('351234567891239', [1] * 8 + [0] * 8, 'MEP-04103-001', True)
          != bb_mep_codes('351234567891239', [1] * 8 + [0] * 8, 'MEP-04103-001', False), True)

    print('\nModern ZTE-family algorithm vs published example')
    check('h220m(987654321098767)', h220m('987654321098767'), '16159363')
    dual = {k: (v + 5) % 10 for k, v in H220M_MAP.items()}
    check('dual map yields the same code', h220m('987654321098767', dual), '16159363')

    print('\nshape invariants over 5000 IMEIs')
    ok = True
    for k in range(5000):
        imei = str(10**14 + k * 7919).zfill(15)
        a, b = huawei_old(imei)
        if not (0x2000000 <= a <= 0x3FFFFFF and len(str(a)) == 8):
            ok = False
        nn, ss = zte_v1(imei)
        if not (len(nn) == 12 and len(ss) == 12 and nn.isdigit() and ss.isdigit()):
            ok = False
        for c in (zte_v2(imei), zte_v3(imei)):
            if not (len(c) == 8 and c.isdigit()):
                ok = False
    check('all outputs in range', ok, True)

    print('\n%d failure(s)' % len(failures))
    return 1 if failures else 0


def main(argv):
    if '--self-test' in argv:
        return self_test()
    if len(argv) < 2 or not argv[1].isdigit() or len(argv[1]) < 15:
        print('usage: unlock.py <15-digit IMEI> [alcatel-model] | --self-test')
        return 2
    imei = argv[1][:15]
    print('IMEI            :', imei)
    print('ZTE v1  NCK     :', zte_v1(imei)[0])
    print('ZTE v1  SPCK    :', zte_v1(imei)[1])
    print('ZTE v2  NCK     :', zte_v2(imei))
    print('ZTE v3  NCK     :', zte_v3(imei))
    print('Huawei unlock   : %08d' % huawei_old(imei)[0])
    print('Huawei flash    : %08d' % huawei_old(imei)[1])
    if len(argv) > 2:
        model = argv[2]
        if model not in ALCATEL_MODELS:
            print('unknown alcatel model; try one of:', ', '.join(sorted(ALCATEL_MODELS)))
            return 2
        print('Alcatel %s NCK  : %s' % (model, alcatel(model, imei)[0]))
        print('Alcatel %s SPCK : %s' % (model, alcatel(model, imei)[1]))
    print('H220m-class     :', h220m(imei))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
