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

Run:  python3 a53_att.py            (guided walkthrough)
      python3 a53_att.py --self-test
"""

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


TROUBLESHOOTING = {
    'no prompt': [
        'Phone does not ask for a code after inserting a foreign SIM:',
        '  - It is most likely already unlocked. Dial %s and check' % LOCK_STATUS_CODE,
        '    Network / Subset / SP lock are all OFF.',
        '  - Wi-Fi off, then reboot with the foreign SIM.',
        '  - Try %s to reach the prompt directly.' % ALT_LOCK_STATUS,
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


def main(argv):
    if '--self-test' in argv:
        return self_test()
    if len(argv) > 1 and argv[1] == '--help':
        print('usage: a53_att.py [--self-test | --help | <troubleshooting key>]')
        print('troubleshooting keys: ' + ', '.join(TROUBLESHOOTING))
        return 0
    if len(argv) > 1:
        print('\n'.join(troubleshooting(' '.join(argv[1:]))))
        return 0
    guided()
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
