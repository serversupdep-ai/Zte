#!/usr/bin/env python3
"""
AT&T Samsung Galaxy A53 5G (SM-A536U) -- practical unlock helper.

This does NOT generate a code. See MECHANISM.md section 4 for why no code for
this handset can be generated anywhere. What this does instead is remove every
other obstacle between you and AT&T issuing one, and stop you burning attempts.

Model profile facts, with sources:

  * No eSIM. The A53 has no eSIM hardware in ANY region -- Samsung's A-series
    did not get eSIM until the A54 (March 2023). Consequence: you cannot test
    or complete the unlock with an eSIM. You need a physical nano-SIM from
    another carrier on hand before you start.
  * Single SIM on carrier variants. AT&T's SM-A536U has one nano-SIM slot.
    Dual SIM is unlocked-variant only, and US units reportedly never enabled it.
  * 16-digit NCK. Samsung moved from 8-digit (pre-2019, IMEI-calculable) to
    16-digit with the 2019 models (S10/Note 10 on AT&T). The A53 is 2022.
  * Released 2022-03-24, Exynos 1280.

Run:  python3 a53_att.py                       (guided walkthrough)
      python3 a53_att.py --check CODE [--imei N]   (verify before you type it)
      python3 a53_att.py --attempts            (attempts left before a freeze)
      python3 a53_att.py --self-test
"""

import json
import os
import re
import sys

MODEL = 'SM-A536U'
RELEASED = '2022-03-24'
CODE_DIGITS = 16
ATTEMPT_BUDGET = (5, 10)          # per AT&T's instructions, varies by model
LOCK_STATUS_CODE = '*#7465625#'
ALT_LOCK_STATUS = '#7465625*638*#'
ATT_PORTAL = 'https://www.att.com/deviceunlock'
ATT_STATUS = 'https://www.att.com/deviceunlockstatus'
ATT_MCC_MNC = ('310410', '310380')  # AT&T, used only by the legacy service-menu path

# A53 variants, so you can confirm you actually have the AT&T one.
VARIANTS = {
    'SM-A536U':   'US carrier (AT&T and others) -- single SIM, no eSIM',
    'SM-A536U1':  'US factory unlocked -- single SIM, no eSIM',
    'SM-A536B':   'International / Europe',
    'SM-A536B/DS':'International dual SIM',
    'SM-A536E':   'India / Asia',
    'SM-A536E/DS':'India / Asia dual SIM',
    'SM-A536V':   'Verizon',
    'SM-A536W':   'Canada',
    'SM-A536N':   'Korea',
    'SM-A5360':   'China',
    'SM-S536DL':  'TracFone / Total Wireless',
}


def profile():
    return [
        'AT&T Samsung Galaxy A53 5G',
        '  model      : %s' % MODEL,
        '  released   : %s' % RELEASED,
        '  chipset    : Exynos 1280',
        '  SIM        : single physical nano-SIM. NO eSIM in any region.',
        '  code type  : %d-digit NCK (not the 8-digit pre-2019 format)' % CODE_DIGITS,
        '  attempts   : %d-%d wrong tries, then the baseband freezes and needs' % ATTEMPT_BUDGET,
        '               an MCK, which AT&T must also issue.',
    ]


def preflight():
    return [
        'BEFORE you request anything',
        '',
        '1. Confirm it is the AT&T model. Dial *#06# for the IMEI, then',
        '   Settings > About phone > Model number. You want %s.' % MODEL,
        '   Other A53 variants:',
    ] + ['     %-12s %s' % (k, v) for k, v in VARIANTS.items()] + [
        '',
        '2. CHECK WHETHER IT IS ALREADY UNLOCKED. This costs nothing and a',
        '   fair number of AT&T handsets are already open:',
        '     dial %s' % LOCK_STATUS_CODE,
        '   (or %s)' % ALT_LOCK_STATUS,
        '   Look for Network lock / Subset lock / SP lock. All OFF = unlocked,',
        '   stop here. If nothing happens, the firmware does not expose the',
        '   service menu -- insert a non-AT&T SIM instead and see if it asks',
        '   for a code. No prompt = already unlocked.',
        '',
        '3. Get a physical nano-SIM from another carrier. NOT an eSIM -- this',
        '   phone has no eSIM hardware, so an eSIM cannot be used to test or',
        '   to complete the unlock.',
        '',
        '4. Do not factory reset before unlocking. AT&T verifies the device',
        '   association and a reset can drop the IMEI from the account.',
        '',
        '5. Do not enter any code you did not get from AT&T. Every wrong',
        '   entry costs one of %d-%d attempts.' % ATTEMPT_BUDGET,
    ]


def eligibility():
    return [
        'AT&T eligibility (att.com/legal, KM1258553)',
        '  - Device not reported lost, stolen, or involved in fraud',
        '  - Contract or installment plan completed (pay off early, then',
        '    re-request after 24 hours once billing syncs)',
        '  - Not active on another AT&T account',
        '  - Early upgrade: wait 14 days (30 for business)',
        '  - Service active at least 60 days, no past-due balance',
        '  - AT&T PREPAID: at least 6 months of active paid service',
        '  - Military: TCS/PCS orders waive installment and contract completion',
        '  - Business devices: company must authorise',
        '',
        'Which situation are you in?',
        '  account holder, paid off, 60+ days   -> submit, expect 1-2 business days',
        '  bought secondhand, not on account    -> same portal, choose',
        '                                          "I don\'t have an AT&T wireless number"',
        '  still financed                       -> pay off, wait 24h, then submit',
        '  AT&T Prepaid                         -> 6 months paid; check for the',
        '                                          built-in Unlock app first',
        '  reported lost/stolen                 -> nothing unlocks it, ever',
    ]


def request():
    return [
        'Requesting',
        '  1. %s' % ATT_PORTAL,
        '  2. IMEI: your 15-digit IMEI from *#06# (use IMEI 1, not IMEI 2)',
        '  3. Confirm the email AT&T sends. UNCONFIRMED REQUESTS NEVER PROCESS.',
        '     The link expires after 24 hours -- if it lapses, start over.',
        '  4. On approval AT&T either pushes an OTA unlock (nothing to type)',
        '     or emails a %d-digit NCK.' % CODE_DIGITS,
        '  5. Track at %s with the request number from that email.' % ATT_STATUS,
        '',
        '  If you lose the code, submit a NEW request -- AT&T generates a fresh',
        '  one rather than re-sending, which is the clearest proof that codes',
        '  are not sitting in a database to be retrieved.',
    ]


def entering_code():
    return [
        'Entering the code once AT&T sends it',
        '  1. Power off. Insert the non-AT&T nano-SIM.',
        '  2. Power on. Wait for "SIM network unlock PIN" or "Network Control Key".',
        '  3. Enter all %d digits exactly as sent. No spaces, no dashes.' % CODE_DIGITS,
        '  4. "Network Lock Successful" = done, permanently.',
        '',
        '  If you were given an MCK/defreeze code as well, enter the MCK first.',
        '  It will report "unsuccessful" -- that is expected and does not consume',
        '  an attempt. Then enter the NCK.',
        '',
        '  RGCK (regional lock code), if provided, is entered the same way as the',
        '  NCK and only applies to region-restricted units.',
        '',
        '  Wi-Fi off while doing this. Some reports of the prompt not appearing',
        '  with Wi-Fi active.',
    ]


# --------------------------------------------------------------------------
# Code verifier -- the last gate before a code costs you an attempt
# --------------------------------------------------------------------------
#
# The NCK cannot be computed, and it cannot be retrieved from anywhere. The
# only place it exists is the email AT&T sends after approving a request.
# Everything this tool can still do for you is make that one entry count:
# catch the failure modes that waste attempts, which are overwhelmingly
# transcription errors and codes bought from resellers.

ATTEMPT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            '.a53_attempts.json')

# Codes resellers and "free NCK" pages hand out. These are not real NCKs; they
# are the same handful of values served to everyone. Entering one on an A53
# burns an attempt and, repeated, freezes the baseband.
KNOWN_BAD = {
    '0000000000000000': 'all zeros -- placeholder',
    '1111111111111111': 'all ones -- placeholder',
    '8888888888888888': 'all eights -- placeholder',
    '9999999999999999': 'all nines -- placeholder',
    '1234567890123456': 'ascending sequence -- placeholder',
    '0123456789012345': 'ascending sequence -- placeholder',
    '0987654321098765': 'descending sequence -- placeholder',
    '1212121212121212': 'repeating pattern -- placeholder',
    '0000000000000001': 'placeholder',
}


def _digit_runs(digits, run=6):
    """True if the string contains an ascending or descending run of >= `run`."""
    asc = dsc = 1
    for i in range(1, len(digits)):
        a, b = digits[i - 1], digits[i]
        asc = asc + 1 if ord(b) == ord(a) + 1 else 1
        dsc = dsc + 1 if ord(b) == ord(a) - 1 else 1
        if asc >= run or dsc >= run:
            return True
    return False


def _same_digit_run(digits, run=6):
    m = re.search(r'(.)\1{%d,}' % (run - 1), digits)
    return m.group(0) if m else None


def check_code(code, imei=None, model=MODEL, expect=CODE_DIGITS):
    """Verdict on a candidate code BEFORE it is typed into the handset.

    Returns a dict: digits, verdict ('enter'|'caution'|'do not enter'),
    blocks, warnings, notes. A clean code yields no blocks and no warnings.

    This never confirms a code is correct -- nothing can. It only catches
    the wrong-shape and known-junk cases, which is where attempts actually die.
    """
    raw = code.strip()
    letters = [c for c in raw if c.isalpha()]
    digits = ''.join(c for c in raw if c.isdigit())

    blocks, warnings, notes = [], [], []

    if letters:
        blocks.append(
            'contains %d letter(s) (%s). A Samsung NCK is digits only. A code '
            'with letters in it is a serial number, a hex placeholder, or a '
            'code for different hardware.' % (len(letters), ''.join(letters)))

    stripped = len(raw) - len(digits) - len(letters)
    if stripped > 0 and not letters:
        notes.append('stripped %d separator character(s) -- enter digits only, '
                     'no spaces or dashes' % stripped)

    if len(digits) != expect:
        if len(digits) == 8:
            blocks.append(
                '8 digits. That is the pre-2019 Samsung format, and it is what '
                'most third-party resellers sell. The %s is a 2022 handset and '
                'takes a %d-digit code. If AT&T itself sent you 8 digits, that '
                'is a mismatch worth raising with them before typing anything.'
                % (model, expect))
        elif len(digits) == 15:
            blocks.append(
                '15 digits is IMEI length, not code length. You were probably '
                'sent or are about to retype the IMEI.')
        elif len(digits) == 0:
            blocks.append('no digits at all.')
        else:
            blocks.append(
                '%d digits. AT&T/Samsung codes for this handset are %d. Do not '
                'enter it.' % (len(digits), expect))

    if digits.lower() in KNOWN_BAD:
        blocks.append('known junk value (%s)' % KNOWN_BAD[digits.lower()])

    if imei:
        idig = ''.join(c for c in imei if c.isdigit())
        if idig and digits:
            if idig in digits:
                blocks.append('contains the full IMEI %s -- a real NCK never '
                              'does.' % idig)
            elif digits in idig:
                blocks.append('is a substring of the IMEI -- not a code.')
            elif len(digits) >= 8 and len(idig) >= 8:
                # Same-position head or tail overlap. Deliberately positional:
                # the dead calculators emitted digits derived from the IMEI's
                # own ends, so an exact end match is the signature to catch.
                if digits[-8:] == idig[-8:]:
                    blocks.append('the last 8 digits are the IMEI\'s last 8 (%s) '
                                  '-- looks derived from it.' % idig[-8:])
                elif digits[:8] == idig[:8]:
                    blocks.append('the first 8 digits are the IMEI\'s TAC (%s) '
                                  '-- looks derived from it.' % idig[:8])

    # Numeric part of the model designation: 'SM-A536U' -> '536'.
    suffix = model.split('-')[-1] if '-' in model else model
    tail = ''.join(c for c in suffix if c.isdigit())
    if len(tail) >= 3 and digits:
        if len(digits) >= 8 and digits[-len(tail):] == tail:
            lead = digits[:-len(tail)]
            if set(lead) <= {'0'}:
                blocks.append('is the model number %s padded with zeros -- a '
                              'filler value, not a code.' % tail)
            else:
                warnings.append('ends in the model number %s. A %d-digit match '
                                'like that is a 1-in-%d coincidence, so it is '
                                'usually a placeholder.'
                                % (tail, len(tail), 10 ** len(tail)))

    run = _same_digit_run(digits)
    if run:
        blocks.append('%d identical digits in a row (%s) -- real NCKs are '
                      'effectively random.' % (len(run), run))
    if len(digits) >= 8 and _digit_runs(digits):
        warnings.append('contains a long ascending or descending run -- real '
                        'NCKs are uniformly random, so this is unusual.')
    if digits and len(set(digits)) == 1:
        blocks.append('every digit identical.')
    if digits == digits[::-1] and len(digits) >= 8:
        warnings.append('palindrome -- not impossible, but worth a double check '
                        'against the source.')

    if blocks:
        verdict = 'do not enter'
    elif warnings:
        verdict = 'caution'
    else:
        verdict = 'enter'

    return {'input': raw, 'digits': digits, 'n': len(digits), 'expect': expect,
            'verdict': verdict, 'blocks': blocks, 'warnings': warnings,
            'notes': notes}


def code_report(result):
    """Human-readable version of check_code()."""
    head = {'enter': 'VERDICT: safe to enter',
            'caution': 'VERDICT: probably fine, but check the source first',
            'do not enter': 'VERDICT: DO NOT ENTER -- this will cost an attempt'}
    out = ['code      : %s' % (result['digits'] or '(empty)'),
           'length    : %d (expected %d)' % (result['n'], result['expect']),
           head[result['verdict']]]
    for b in result['blocks']:
        out.append('  BLOCK  %s' % b)
    for w in result['warnings']:
        out.append('  WARN   %s' % w)
    for n in result['notes']:
        out.append('  note   %s' % n)
    if result['verdict'] == 'enter':
        out += ['',
                'Clean shape says nothing about correctness -- only AT&T\'s own',
                'server knows that. What it does tell you is that you did not',
                'mangle the transcription, which is the common failure.',
                '',
                'Before you type it: MCK first if you were given one (it will',
                'report failure by design and costs nothing), Wi-Fi off, and',
                'enter all %d digits in one go.' % CODE_DIGITS]
    elif result['verdict'] == 'do not enter':
        out += ['',
                'Every wrong entry spends one of %d-%d attempts, then the'
                % ATTEMPT_BUDGET,
                'baseband freezes and only an AT&T MCK resets it. Where did',
                'this code come from? If not from AT&T\'s unlock email, it is',
                'not a code for this phone.']
    return out


# --------------------------------------------------------------------------
# Attempt tracker
# --------------------------------------------------------------------------
def _load_attempts(path=None):
    path = path or ATTEMPT_FILE
    if not os.path.exists(path):
        return {'failures': [], 'success': False}
    try:
        with open(path) as fh:
            return json.load(fh)
    except (ValueError, OSError):
        return {'failures': [], 'success': False}


def _save_attempts(state, path=None):
    path = path or ATTEMPT_FILE
    with open(path, 'w') as fh:
        json.dump(state, fh, indent=2, sort_keys=True)
        fh.write('\n')


def attempts_left(state):
    """(remaining_at_worst_case, remaining_at_best_case) given the budget."""
    used = len(state['failures'])
    return (max(0, ATTEMPT_BUDGET[0] - used), max(0, ATTEMPT_BUDGET[1] - used))


def log_attempt(digest, outcome='fail', path=None):
    state = _load_attempts(path)
    if outcome == 'success':
        state['success'] = True
    else:
        state['failures'].append(digest)
    _save_attempts(state, path)
    return state


def attempts_report(path=None):
    state = _load_attempts(path)
    worst, best = attempts_left(state)
    out = ['Attempt tracker for %s' % MODEL,
           '  logged failures : %d' % len(state['failures']),
           '  attempt budget  : %d-%d before the baseband freezes' % ATTEMPT_BUDGET]
    if state['success']:
        out.append('  status          : a successful entry is logged. Done.')
    elif worst <= 0:
        out += ['  status          : STOP. On the strict reading you have used the',
                '                  whole budget. Treat the phone as frozen and get',
                '                  an MCK from AT&T rather than trying again.']
    else:
        out.append('  remaining       : %d to %d tries' % (worst, best))
    if not state['failures'] and not state['success']:
        out.append('  (nothing logged yet -- use --log-fail / --log-success)')
    return out


TROUBLESHOOTING = {
    'no prompt': [
        'Phone does not ask for a code, or shows "SIM Not Supported":',
        '  - "SIM Not Supported" IS the network lock on this model. It is the',
        '    same condition as being asked for a code; the firmware just shows',
        '    a banner instead of a keypad. You still need the NCK from AT&T.',
        '  - It is most likely already unlocked if the foreign SIM registers',
        '    at all. Dial %s and check Network / Subset / SP lock are OFF.'
        % LOCK_STATUS_CODE,
        '  - Wi-Fi off, then reboot with the foreign SIM already inserted.',
        '  - Toggle airplane mode on and off with the foreign SIM in place.',
        '  - Try %s to reach the prompt directly.' % ALT_LOCK_STATUS,
        '  - Confirm the SIM itself is active on its own network. A dead or',
        '    inactive SIM is not detected as foreign and triggers no prompt.',
    ],
    'code error': [
        '"Code Error" or "SIM Network Unlock Unsuccessful" on a code AT&T sent:',
        '  - Stop. Do not retry the same code repeatedly; each try counts.',
        '  - Confirm you used the NCK, not the MCK, and all %d digits.' % CODE_DIGITS,
        '  - Confirm AT&T approved THIS IMEI. Check %s' % ATT_STATUS,
        '  - If AT&T shows approved and the code still fails, contact AT&T with',
        '    the request number. Do not buy a third-party code as a fallback --',
        '    a wrong one spends the remaining attempts.',
    ],
    'frozen': [
        'Phone says frozen / blocked / "enter Master Unlock Code":',
        '  - You have exhausted the attempt counter.',
        '  - Only an MCK from AT&T resets it. Submit a new unlock request and',
        '    ask specifically for the defreeze/MCK code.',
        '  - There is no software workaround. Anything claiming one will spend',
        '    money and burn the device.',
    ],
    'denied': [
        'AT&T denied the request:',
        '  - %s shows the reason.' % ATT_STATUS,
        '  - "commitment not met" -> installment balance not zero, or billing',
        '    has not synced. Wait 24h after the balance clears, re-request.',
        '  - "not eligible" -> under 60 days active, or past-due balance.',
        '  - lost/stolen flag -> not recoverable by unlocking.',
        '  - Otherwise call 611 and ask for Device Unlock Escalation.',
    ],
    'data broken': [
        'Unlocked but no data or MMS on the new carrier:',
        '  - APN settings. Enter the new carrier\'s APN under',
        '    Settings > Connections > Mobile networks > Access Point Names.',
        '  - The AT&T build may not carry the new carrier\'s APN profile.',
    ],
}


def troubleshooting(symptom=None):
    if symptom:
        key = symptom.strip().lower()
        for k, v in TROUBLESHOOTING.items():
            if key in k or k in key:
                return v
        return ['No match for %r. Known keys: %s' % (symptom, ', '.join(TROUBLESHOOTING))]
    out = ['Troubleshooting']
    for v in TROUBLESHOOTING.values():
        out += [''] + v
    return out


def guided():
    for block in (profile, preflight, eligibility, request, entering_code, troubleshooting):
        print('\n' + '=' * 68)
        print('\n'.join(block()))
    print('\n' + '=' * 68)


def self_test():
    failures = []

    def check(label, got, want):
        ok = got == want
        print('  [%s] %s' % ('PASS' if ok else 'FAIL', label))
        if not ok:
            failures.append(label)

    print('A53 profile')
    check('model is SM-A536U', MODEL, 'SM-A536U')
    check('code length is 16', CODE_DIGITS, 16)
    check('no eSIM documented', any('NO eSIM' in l for l in profile()), True)
    check('variant table non-empty', len(VARIANTS) >= 10, True)
    check('AT&T model described as single SIM', 'single SIM' in VARIANTS['SM-A536U'], True)
    check('U1 (unlocked) distinguished from U', VARIANTS['SM-A536U1'] != VARIANTS['SM-A536U'], True)

    print('\ncontent integrity')
    check('preflight warns against eSIM testing',
          any('eSIM' in l for l in preflight()), True)
    check('preflight checks lock status first',
          any(LOCK_STATUS_CODE in l for l in preflight()), True)
    check('eligibility lists the 60-day rule',
          any('60 days' in l for l in eligibility()), True)
    check('request flow covers the 24h email expiry',
          any('24 hours' in l for l in request()), True)
    check('code entry states the digit count',
          any('%d-digit' % CODE_DIGITS in l or '%d digits' % CODE_DIGITS in l
              for l in entering_code()), True)
    check('MCK-is-expected-to-fail note present',
          any('unsuccessful' in l.lower() for l in entering_code()), True)
    check('SIM Not Supported alert documented',
          any('SIM Not Supported' in l for l in TROUBLESHOOTING['no prompt']), True)

    print('\ncode verifier')
    good = '2738272959528493'
    check('a clean 16-digit code passes', check_code(good)['verdict'], 'enter')
    check('clean code has no blocks', check_code(good)['blocks'], [])
    check('clean code has no warnings', check_code(good)['warnings'], [])
    check('separators are stripped and noted',
          check_code('2738 2729-5952 8493')['verdict'], 'enter')
    check('separator stripping is reported',
          bool(check_code('2738-2729-5952-8493')['notes']), True)
    check('8-digit legacy code is blocked',
          check_code('40760382')['verdict'], 'do not enter')
    check('8-digit block names the real reason',
          any('pre-2019' in b for b in check_code('40760382')['blocks']), True)
    check('15-digit IMEI-shaped input is blocked',
          check_code('350012623050961')['verdict'], 'do not enter')
    check('all-zero placeholder is blocked',
          check_code('0000000000000000')['verdict'], 'do not enter')
    check('KNOWN_BAD entries are all blocked',
          [check_code(c)['verdict'] for c in KNOWN_BAD],
          ['do not enter'] * len(KNOWN_BAD))
    check('a digit run is blocked',
          check_code('2738000000008493')['verdict'], 'do not enter')
    check('a long ascending run warns',
          check_code('2738270123458493')['verdict'], 'caution')
    imei = '350012623050961'
    check('the IMEI itself is caught',
          check_code(imei, imei=imei)['verdict'], 'do not enter')
    check('the IMEI padded to 16 is caught',
          check_code(imei + '7', imei=imei)['verdict'], 'do not enter')
    check('the IMEI block names the IMEI',
          any(imei in b for b in check_code(imei + '7', imei=imei)['blocks']), True)
    check('IMEI tail reuse is caught',
          check_code('27382729' + imei[-8:], imei=imei)['verdict'], 'do not enter')
    check('IMEI head (TAC) reuse is caught',
          check_code(imei[:8] + '29595284', imei=imei)['verdict'], 'do not enter')
    check('an unrelated 16-digit code is not flagged as IMEI-derived',
          check_code(good, imei=imei)['verdict'], 'enter')
    check('letters are blocked, not silently stripped',
          check_code('0123456789ABCDEF')['verdict'], 'do not enter')
    check('the letter block says digits only',
          any('digits only' in b for b in check_code('0123456789ABCDEF')['blocks']), True)
    check('model-number filler is caught',
          check_code('0000000000053600')['verdict'], 'do not enter')
    # The line above would also pass on the zero-run detector alone, so pin the
    # model check itself with a lead that has no digit run and is not all zeros.
    # With a real lead the model check warns rather than blocks, which is the
    # intended split: zeros + model number = filler (block), otherwise flag it.
    check('model check fires on its own, not via the zero-run detector',
          any('model number' in w
              for w in check_code('7979797979797536')['warnings']), True)
    check('model check warns rather than blocks on a non-zero lead',
          check_code('7979797979797536')['verdict'], 'caution')
    check('model check blocks only when the lead is all zeros',
          any('model number' in b
              for b in check_code('0000000000000536')['blocks']), True)
    check('model-number suffix warns',
          check_code('2738272959580536')['verdict'], 'caution')
    check('the suffix warning names the model tail',
          any('536' in w for w in check_code('2738272959580536')['warnings']), True)
    check('verifier never claims correctness',
          any('correct' in l for l in code_report(check_code(good))
              if 'nothing about correctness' not in l), False)
    check('blocked verdict says do not enter',
          'DO NOT ENTER' in '\n'.join(code_report(check_code('40760382'))), True)
    check('empty input is blocked', check_code('')['verdict'], 'do not enter')

    print('\nattempt tracker')
    tmp = ATTEMPT_FILE + '.selftest'
    if os.path.exists(tmp):
        os.remove(tmp)
    fresh = _load_attempts(tmp)
    check('fresh state has no failures', len(fresh['failures']), 0)
    check('fresh budget is the documented range', attempts_left(fresh), ATTEMPT_BUDGET)
    s1 = log_attempt('aaaa', 'fail', tmp)
    check('a failure is logged', len(s1['failures']), 1)
    check('worst case drops by one', attempts_left(s1)[0], ATTEMPT_BUDGET[0] - 1)
    s5 = s1
    for i in range(4):
        s5 = log_attempt('bbbb%d' % i, 'fail', tmp)
    check('after 5 failures worst case is 0', attempts_left(s5)[0], 0)
    check('after 5 failures the report says STOP',
          any('STOP' in l for l in attempts_report(tmp)), True)
    s6 = log_attempt('good', 'success', tmp)
    check('success is recorded', s6['success'], True)
    check('state survives a reload', _load_attempts(tmp)['success'], True)
    os.remove(tmp)
    check('default attempt file is gitignored',
          os.path.basename(ATTEMPT_FILE) in
          open(os.path.join(os.path.dirname(ATTEMPT_FILE), '..', '.gitignore')).read(),
          True)

    print('\ntroubleshooting routing')
    for key in TROUBLESHOOTING:
        check('routes %r' % key, troubleshooting(key)[0], TROUBLESHOOTING[key][0])
    check('unknown key is handled', 'No match' in troubleshooting('zzz')[0], True)
    check('no advice to guess codes',
          not any('try random' in l.lower() or 'guess' in l.lower()
                  for v in TROUBLESHOOTING.values() for l in v), True)
    check('frozen path says only AT&T can fix',
          any('MCK from AT&T' in l for l in TROUBLESHOOTING['frozen']), True)

    print('\n%d failure(s)' % len(failures))
    return 1 if failures else 0


def usage():
    print('usage: a53_att.py [options]')
    print('')
    print('  (no args)                 guided walkthrough')
    print('  --check CODE [--imei N]   verify a code BEFORE typing it')
    print('  --log-fail CODE           record a failed attempt')
    print('  --log-success             record that the phone unlocked')
    print('  --attempts                show the attempt budget left')
    print('  --reset-attempts          clear the attempt log')
    print('  <symptom>                 jump to a troubleshooting path')
    print('  --self-test               run the checks')
    print('')
    print('symptoms: ' + ', '.join(TROUBLESHOOTING))
    return 0


def main(argv):
    if '--self-test' in argv:
        return self_test()
    if '--help' in argv or '-h' in argv:
        return usage()

    def arg_after(flag):
        if flag in argv:
            i = argv.index(flag)
            if i + 1 < len(argv):
                return argv[i + 1]
        return None

    code = arg_after('--check')
    if code is not None:
        res = check_code(code, imei=arg_after('--imei'))
        print('\n'.join(code_report(res)))
        return {'enter': 0, 'caution': 1, 'do not enter': 2}[res['verdict']]

    code = arg_after('--log-fail')
    if code is not None:
        digits = ''.join(c for c in code if c.isdigit())
        # Store only a prefix -- enough to spot a repeated mistake, not the code.
        log_attempt(digits[:4] + '...' if digits else '(empty)', 'fail')
        print('\n'.join(attempts_report()))
        return 2

    if '--log-success' in argv:
        log_attempt('', 'success')
        print('\n'.join(attempts_report()))
        return 0

    if '--reset-attempts' in argv:
        if os.path.exists(ATTEMPT_FILE):
            os.remove(ATTEMPT_FILE)
        print('attempt log cleared.')
        return 0

    if '--attempts' in argv:
        print('\n'.join(attempts_report()))
        return 0

    rest = [a for a in argv[1:] if not a.startswith('--')]
    if rest:
        print('\n'.join(troubleshooting(' '.join(rest))))
        return 0

    guided()
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
