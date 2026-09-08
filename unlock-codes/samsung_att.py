#!/usr/bin/env python3
"""
Samsung / AT&T unlock support -- current models.

Read this before anything else
------------------------------
There is **no algorithm here**, because there is no public algorithm.

Every scheme in `unlock.py` next to this file is an *offline, IMEI-derived*
function that was extracted from 2007-2014 firmware. Current Samsung hardware
sold by AT&T does not work that way:

  * Newer Samsung handsets take a **16-digit** NCK (plus MCK and RGCK),
    not the 8-digit code of the legacy schemes.
  * AT&T issues those codes **from its own server** after an eligibility
    check, or completes the unlock silently over the air. Nothing is
    computed on the handset from the IMEI alone.
  * `samsung_att_nck()` below therefore raises instead of returning a
    number. That is deliberate: a plausible-looking wrong code does not
    fail harmlessly. Samsung basebands allow a handful of attempts
    (AT&T's own instructions say 5 or 10 depending on model) and then
    freeze, after which an MCK is needed -- and MCKs are also
    server-issued. A fake calculator is a brick generator.

What this module *does* provide:

  * IMEI validation (Luhn) and TAC handling
  * a lookup table of AT&T's current Samsung models (models/att-samsung.json)
  * code-format classification, so a code you were given can be sanity-checked
    before it is typed into a phone
  * the AT&T eligibility rules and the official unlock path
  * a verifier + benchmark for the SHA-256-chain shape that modern
    (non-Samsung-specific) schemes use, which is why these codes are looked
    up rather than computed

Run `python3 samsung_att.py --self-test`.
"""

import hashlib
import json
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_MODEL_FILE = os.path.join(_HERE, 'models', 'att-samsung.json')

# Samsung service codes (documented in AT&T's own ATTDeviceUnlockCodeInstructions.pdf)
LOCK_STATUS_CODE = '*#865625#'
LEGACY_NCK_ENTRY = '#7465625*638*'      # older Samsung / SLM handsets
LEGACY_NCK_ALT = '#0111*'               # SGH-A127/C207/D307/... family

# Attempt limits, per AT&T's instructions (varies by model).
ATTEMPT_LIMITS = (5, 10)


class NotCalculable(Exception):
    """Raised when a caller asks for a code that cannot be computed locally."""


# --------------------------------------------------------------------------
# IMEI
# --------------------------------------------------------------------------
def luhn_check_digit(body14):
    """Luhn check digit for the first 14 digits of an IMEI."""
    if len(body14) != 14 or not body14.isdigit():
        raise ValueError('need exactly 14 digits')
    total = 0
    for i, ch in enumerate(body14):
        d = int(ch)
        if i % 2 == 1:                       # double every second digit from the right
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return (10 - total % 10) % 10


def imei_valid(imei):
    imei = ''.join(c for c in imei if c.isdigit())
    return len(imei) == 15 and luhn_check_digit(imei[:14]) == int(imei[14])


def tac(imei):
    """Type Allocation Code -- the first 8 digits, which identify the model."""
    digits = ''.join(c for c in imei if c.isdigit())
    if len(digits) < 8:
        raise ValueError('IMEI too short')
    return digits[:8]


# The pre-2004 TAC ambiguity, and the trap it sets.
#
# Before 2004 the TAC was 6 digits plus a 2-digit Final Assembly Code, and a
# common heuristic for reading *legacy* IMEIs is:
#
#     starts '01' and first8 < '01015900'  -> 6-digit TAC
#     starts '35' and first8 < '35150100'  -> 6-digit TAC
#
# That rule disambiguates genuinely old handsets. It is NOT a claim that the
# 8-digit space below those thresholds is frozen. GSMA allocates 8-digit TACs
# in that range today, so applying it to a modern IMEI sends you into stale
# databases and produces confident nonsense. This file made exactly that
# mistake once: 35001262 was read as 6-digit TAC 350012 ("Kapsch AG GSM-R MT",
# from a 2018 phone-types list) when it is an 8-digit TAC with a live unit
# population on a 2022 Galaxy A53 5G.
#
# Default to 8 digits. Only consider the 6-digit reading when there is
# independent evidence the handset predates 2004.
PRE2004_6DIGIT_TAC = ("starts '01' and first8 < 01015900, or "
                      "starts '35' and first8 < 35150100")


def describe_imei(imei):
    """Split and describe an IMEI without applying the legacy heuristic."""
    digits = ''.join(c for c in imei if c.isdigit())
    if not imei_valid(digits):
        raise ValueError('%r is not a valid 15-digit IMEI (Luhn check failed)' % imei)
    d = {
        'imei': digits,
        'tac': digits[:8],
        'serial': digits[8:14],
        'check_digit': digits[14],
        'tac_is_8_digit': True,
        'legacy_6digit_reading_possible': (digits[:2] in ('01', '35')) and (
            (digits[:2] == '01' and digits[:8] < '01015900')
            or (digits[:2] == '35' and digits[:8] < '35150100')),
    }
    d['legacy_6digit_tac'] = digits[:6] if d['legacy_6digit_reading_possible'] else None
    d['legacy_fac'] = digits[6:8] if d['legacy_6digit_reading_possible'] else None
    d['matched_models'] = lookup_tac(digits[:8])
    d['tac_source'] = d['matched_models'][0].get('tac_source') if d['matched_models'] else None
    return d


def report_imei(imei):
    d = describe_imei(imei)
    lines = [
        'IMEI        : %s' % d['imei'],
        '  TAC       : %s   (8 digits -- the default and correct reading)' % d['tac'],
        '  serial    : %s' % d['serial'],
        '  check     : %s   (Luhn OK)' % d['check_digit'],
    ]
    if d['matched_models']:
        lines.append('  model     : ' + ', '.join(
            '%s (%s)' % (m['name'], m['model'] or '?') for m in d['matched_models']))
        if d['tac_source']:
            lines.append('  tac source: %s' % d['tac_source'])
    else:
        lines.append('  model     : TAC not in models/att-samsung.json. That file is'
                     ' NOT exhaustive (see _meta.complete=false) and holds very few'
                     ' TACs at all -- a miss says nothing about the device.')
    if d['legacy_6digit_reading_possible']:
        lines += [
            '',
            '  NOTE: this IMEI falls in the pre-2004 range (%s), so a 6-digit' % PRE2004_6DIGIT_TAC,
            '  reading is *arithmetically* possible: TAC %s + FAC %s.' % (
                d['legacy_6digit_tac'], d['legacy_fac']),
            '  Do NOT use it unless the handset verifiably predates 2004. Stale TAC',
            '  databases map those 6-digit codes to long-dead equipment and will',
            '  happily misidentify a modern phone.',
        ]
    return '\n'.join(lines)



# --------------------------------------------------------------------------
# Code formats
# --------------------------------------------------------------------------
def classify_code(code):
    """Sanity-check a code before it is typed into a handset.

    Returns (kind, explanation).  This does NOT tell you the code is correct
    for the device -- nothing can -- only that it has the right shape.
    """
    code = ''.join(c for c in code if c.isdigit())
    if len(code) == 8:
        return ('legacy-8', '8-digit NCK. Legacy Samsung (pre-~2016) and many '
                            'non-Samsung handsets. Enter when the phone prompts '
                            'for a Network Unlock Code / SIM Network Unlock PIN.')
    if len(code) == 16:
        return ('modern-16', '16-digit code. Newer Samsung handsets (NCK, MCK or '
                             'RGCK). AT&T instructions: dial %s, choose '
                             'Network Lock, and enter all 16 digits.' % LOCK_STATUS_CODE)
    if len(code) == 15:
        return ('suspicious-15', '15 digits matches an IMEI length, not a Samsung '
                                 'code. Check you were not sent the IMEI by mistake.')
    return ('invalid', 'Samsung/AT&T codes are 8 or 16 digits. This is %d. Do not '
                       'enter it -- a wrong attempt counts against the limit.' % len(code))


# --------------------------------------------------------------------------
# Model table
# --------------------------------------------------------------------------
def load_models():
    with open(_MODEL_FILE) as fh:
        return json.load(fh)


def models_by_name():
    return {m['name']: m for m in load_models()['models']}


def lookup(query):
    """Find a model by name fragment or model number."""
    q = query.strip().upper()
    out = []
    for m in load_models()['models']:
        hay = ' '.join(str(v) for v in (m['model'], m['name']) if v).upper()
        if q in hay:
            out.append(m)
    return out


def lookup_tac(tac8):
    """Find a model by 8-digit TAC.

    TAC coverage in this table is sparse and each hit carries a `tac_source`
    field describing where the binding came from. A miss means the TAC is not
    in this file, not that the device is unidentifiable.
    """
    tac8 = ''.join(c for c in tac8 if c.isdigit())
    if len(tac8) != 8:
        raise ValueError('TAC is 8 digits')
    return [m for m in load_models()['models'] if m.get('tac') == tac8]


# --------------------------------------------------------------------------
# AT&T process
# --------------------------------------------------------------------------
ATT_PORTAL = 'https://www.att.com/deviceunlock'
ATT_STATUS = 'https://www.att.com/deviceunlock/status'
ATT_PDF = 'https://www.att.com/idpassets/support/pdf/ATTDeviceUnlockCodeInstructions.pdf'

# Transcribed from AT&T's own published requirements page (att.com/legal, KM1258553).
ATT_ELIGIBILITY = [
    'Device not reported lost or stolen, and not involved in fraud.',
    'Contract or installment plan completed (including early termination fees). '
    'Pay off early, then re-request after 24 hours.',
    'Device not active on another AT&T account.',
    'If you upgraded early: wait 14 days to unlock the old device '
    '(30 days for business customers).',
    'Service active at least 60 days with no past-due or unpaid balance.',
    'AT&T PREPAID: at least 6 months of active service.',
    'Military: email TCS/PCS orders; installment plans and contracts waived.',
    'Business-owned devices require company authorisation.',
]


def att_instructions(model_query=None):
    lines = [
        'AT&T Samsung unlock -- official path',
        '  1. Check eligibility against the rules below.',
        '  2. Submit the request at %s' % ATT_PORTAL,
        '     (account holder: "I have a mobile number"; everyone else:'
        ' "I don\'t have an AT&T wireless number").',
        '  3. Confirm the email AT&T sends, or the request never processes.',
        '  4. On approval AT&T either pushes a server-side/OTA unlock (nothing to'
        ' type) or issues a code.',
        '  5. Insert a non-AT&T SIM. If a code is requested, enter exactly what'
        ' AT&T sent. Track status at %s' % ATT_STATUS,
        '',
        '  Do NOT guess. %d-%d attempts depending on model, then the baseband'
        ' freezes and needs an MCK, which is also server-issued.' % ATTEMPT_LIMITS,
        '',
        'Samsung service codes (AT&T %s):' % ATT_PDF.rsplit('/', 1)[-1],
        '  %s  lock status / SIM unlock menu' % LOCK_STATUS_CODE,
        '  %s  legacy 8-digit NCK entry' % LEGACY_NCK_ENTRY,
        '',
        'AT&T eligibility requirements:',
    ]
    lines += ['  - ' + r for r in ATT_ELIGIBILITY]
    if model_query:
        hits = lookup(model_query)
        if hits:
            lines += ['', 'Matched models for %r:' % model_query]
            for m in hits:
                lines.append('  %-12s %-22s (%s)' % (m['model'] or '?', m['name'], m['source']))
    return '\n'.join(lines)


# --------------------------------------------------------------------------
# The honest API
# --------------------------------------------------------------------------
def samsung_att_nck(imei):
    """Raise. There is no local algorithm for current AT&T Samsung handsets."""
    if not imei_valid(imei):
        raise ValueError('%r is not a valid 15-digit IMEI (Luhn check failed)' % imei)
    raise NotCalculable(
        "A current AT&T Samsung NCK cannot be computed from the IMEI.\n"
        "AT&T issues it server-side after an eligibility check, or unlocks the\n"
        "device over the air. Use %s\n"
        "See att_instructions() for the full process." % ATT_PORTAL)


# --------------------------------------------------------------------------
# Why: the shape of a modern scheme
# --------------------------------------------------------------------------
# A scheme of this shape was described publicly on XDA (2017) for handsets that
# keep SALT and HASH in a protected "trim area":
#
#     h = sha256(NCK || SALT)
#     repeat 9 times: h = sha256(h)
#     accept iff h == HASH
#
# The handset never learns how the NCK was produced -- it can only *check* one.
# The NCK is effectively a preimage, so the carrier can issue random codes and
# no amount of firmware analysis yields a generator. (This is documented for
# Sony-family trim-area devices; Samsung's current internal scheme is not
# public. It is included because it explains the general transition.)
CHAIN_ROUNDS = 10


def sha256_chain(nck, salt, rounds=CHAIN_ROUNDS):
    h = hashlib.sha256(nck + salt).digest()
    for _ in range(rounds - 1):
        h = hashlib.sha256(h).digest()
    return h


def chain_verify(nck, salt, target, rounds=CHAIN_ROUNDS):
    return sha256_chain(nck, salt, rounds) == target


def benchmark_chain(guesses=20000):
    """Measure guesses/s for a 10-round chain on this machine."""
    salt = b'\x00' * 16
    t0 = time.perf_counter()
    for i in range(guesses):
        sha256_chain(('%016d' % i).encode(), salt)
    return guesses / (time.perf_counter() - t0)


# --------------------------------------------------------------------------
def self_test():
    failures = []

    def check(label, got, want):
        ok = got == want
        print('  [%s] %-50s %s' % ('PASS' if ok else 'FAIL', label, got))
        if not ok:
            failures.append(label)

    print('IMEI / Luhn  (vectors from python-stdnum\'s published doctests)')
    check('356868000041418 valid', imei_valid('356868000041418'), True)
    check('35686800-004141-8 normalised', imei_valid('35686800-004141-8'), True)
    check('354178036859781 -> InvalidChecksum', imei_valid('354178036859781'), False)
    check('3568680000414120 is a 16-digit IMEISV', imei_valid('3568680000414120'), False)
    check('luhn_check_digit("35686800004141")', luhn_check_digit('35686800004141'), 8)
    check('tac()', tac('356868000041418'), '35686800')
    # every digit position must matter
    base = '356868000041418'
    check('single-digit corruption detected',
          all(not imei_valid(base[:i] + str((int(base[i]) + 1) % 10) + base[i + 1:])
              for i in range(15)), True)

    print('\ncode classification')
    check('2738272959528493 (cellunlocker sample)', classify_code('2738272959528493')[0], 'modern-16')
    check('7516949416952725 (MCK sample)', classify_code('7516949416952725')[0], 'modern-16')
    check('12345678', classify_code('12345678')[0], 'legacy-8')
    check('15 digits (an IMEI, not a code)', classify_code('356868000041412')[0], 'suspicious-15')
    check('1234567', classify_code('1234567')[0], 'invalid')

    print('\nmodel table')
    data = load_models()
    names = models_by_name()
    check('models loaded', len(data['models']) > 0, True)
    check('Galaxy S26 Ultra model', names['Galaxy S26 Ultra']['model'], 'SM-S948U')
    check('Galaxy S25 model', names['Galaxy S25']['model'], 'SM-S931U')
    check('Galaxy Z Fold7 model', names['Galaxy Z Fold7']['model'], 'SM-F966U')
    check('Galaxy A53 5G present (2022)', names['Galaxy A53 5G']['model'], 'SM-A536U')
    check('table declares itself incomplete', data['_meta']['complete'], False)
    check('lookup("S26") hits', sorted(m['name'] for m in lookup('S26')),
          ['Galaxy S26', 'Galaxy S26 FE', 'Galaxy S26 Plus', 'Galaxy S26 Ultra'])
    check('every entry sourced', all(m['source'] in ('att', 'press') for m in data['models']), True)
    att_only = [m for m in data['models'] if m['source'] == 'att' and m['model']]
    check('att-sourced entries with model numbers', len(att_only) >= 15, True)
    check('model numbers are unique',
          len({m['model'] for m in data['models'] if m['model']})
          == len([m for m in data['models'] if m['model']]), True)

    print('\nTAC interpretation (the bug this guards against)')
    d = describe_imei('350012623050961')          # AT&T Galaxy A53 5G, SM-A536U
    check('TAC is read as 8 digits', d['tac'], '35001262')
    check('serial / check digit split', (d['serial'], d['check_digit']), ('305096', '1'))
    check('legacy 6-digit reading is flagged', d['legacy_6digit_reading_possible'], True)
    check('...but NOT applied', d['tac_is_8_digit'], True)
    check('TAC resolves in the model table',
          [m['model'] for m in d['matched_models']], ['SM-A536U'])
    check('TAC binding always carries provenance',
          all(m.get('tac_source') for m in data['models'] if m.get('tac')), True)
    check('provenance is surfaced in the report',
          'Swappa TAC catalog' in report_imei('350012623050961'), True)
    check('report warns about the stale-DB trap',
          'pre-2004' in report_imei('350012623050961'), True)
    # an IMEI outside the legacy range must not be flagged at all
    check('modern TAC not flagged', describe_imei('356868000041418')['legacy_6digit_reading_possible'], False)
    check('modern TAC has no legacy fields', describe_imei('356868000041418')['legacy_6digit_tac'], None)

    print('\nno local generator (this is the point)')
    try:
        samsung_att_nck('356868000041418')
        raised = 'no'
    except NotCalculable:
        raised = 'NotCalculable'
    check('samsung_att_nck refuses', raised, 'NotCalculable')
    try:
        samsung_att_nck('123456789012345')
        raised = 'no'
    except ValueError:
        raised = 'ValueError'
    check('rejects a bad IMEI first', raised, 'ValueError')

    print('\nSHA-256 chain verifier')
    salt = os.urandom(16)
    nck = b'2738272959528493'
    check('accepts the right NCK', chain_verify(nck, salt, sha256_chain(nck, salt)), True)
    check('rejects a wrong NCK', chain_verify(b'0000000000000000', salt, sha256_chain(nck, salt)), False)
    check('rounds matter', sha256_chain(nck, salt, 10) != sha256_chain(nck, salt, 11), True)

    rate = benchmark_chain(5000)
    print('  info: measured %.0f guesses/s on this machine' % rate)
    check('rate is plausible (>1000/s)', rate > 1000, True)

    print('\n%d failure(s)' % len(failures))
    return 1 if failures else 0


def main(argv):
    if '--self-test' in argv:
        return self_test()
    if len(argv) < 2:
        print(__doc__)
        print('usage: samsung_att.py --self-test')
        print('       samsung_att.py --imei <15-digit IMEI>')
        print('       samsung_att.py --models [fragment]')
        print('       samsung_att.py --unlock [model fragment]')
        print('       samsung_att.py --check <code>')
        return 2
    cmd = argv[1]
    if cmd == '--imei':
        if len(argv) < 3:
            print('give me an IMEI')
            return 2
        try:
            print(report_imei(argv[2]))
        except ValueError as exc:
            print('ERROR: %s' % exc)
            return 1
        print()
        print(att_instructions())
    elif cmd == '--models':
        frag = argv[2] if len(argv) > 2 else ''
        for m in (lookup(frag) if frag else load_models()['models']):
            print('%-12s %-24s %s %s' % (m['model'] or '?', m['name'],
                                         m['year'] or '', m['source']))
    elif cmd == '--unlock':
        print(att_instructions(argv[2] if len(argv) > 2 else None))
    elif cmd == '--check':
        if len(argv) < 3:
            print('give me a code')
            return 2
        kind, why = classify_code(argv[2])
        print('%s: %s' % (kind, why))
    else:
        print('unknown command %r' % cmd)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
