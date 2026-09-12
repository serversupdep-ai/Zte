#!/usr/bin/env python3
"""extract_rex98_gui.py — reproducible analysis of the Rex98 GUI v1.0 release.

The GUI ("Dell BIOS Tools V2.1") was relay-fetched from Google Drive by
.github/workflows/fetch-rex98-gui.yml (run 34597647715) and committed at
bios-analysis/forum/patcher_analysis/rex98_gui_v1.0/ (archive.rar +
extracted "Dell BiosTools/" PyInstaller onedir tree, Python 3.13/Tkinter).

This script re-derives the analysis of REPORT §13.13:
  1. unpack the PyInstaller CArchive from DellBiosTools.exe
     (pyinstxtractor-ng — pip install pyinstxtractor-ng xdis)
  2. dump the main script's string constants (the keygen table bank,
     the 8FC8 patcher patterns, the UI strings)
  3. verify which of the seven module tables are present/absent
  4. locate the keygen functions in the xdis disassembly
     (pydisasm — the pyc is Python 3.13, so 3.11 hosts cannot marshal it)

Run:  python3 bios-analysis/extract_rex98_gui.py
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
EXE = os.path.join(HERE, 'forum', 'patcher_analysis', 'rex98_gui_v1.0',
                   'Dell BiosTools', 'DellBiosTools.exe')

# The seven 72-char tables of the pw-module bank (REPORT §13.12)
TABLES = {
    '8FC8  (module @0xA280)': '0Q2drGk99WLJ1EGnqR5y3DGr16hN4seZPRM2zz2pzcU7JaBXIjbkGZrkQFMxN[Z638myIL2r',
    'BF97  (module @0xAB50)': '0Q2drGk99rkQFMxN[Z5y3DGr16h638myIL2rzz2pzcU7JWLJ1EGnqRN4seZPRM2aBXIjbkGZ',
    'E7A8  (module @0xA300)': 'Q92G0drk9y63r5DG1hLqJGW1EnRk[QxrFMNZ328I6myLr4MsPNeZR2z72czpzUJBGXbaIjkZ',
    '1D3B  (module @0xAA60)': '0BfIUG1kuPvc8A9Nl5DLZYSno7Ka6HMgqsJWm65yCQR94b21OTp7VFX2z0jihE33d4xtrew0',
    '1F66  (module @0xAAB0)': '0ewr3d4xtUG1ku0BfIp7VFb21OTSno7KDLZYqsJWa6HMgCQR94m65y9Nl5Pvc8AjihE3X2z0',
    '6FF1  (module @0xAB00)': '08rptBxfbGVMz38IiSoeb360MKcLf4QtBCbWVzmH5wmZUcRR5DZG2xNCEv1nFtzsZB2bw1X0',
    '2A7B  (module @0xAA10)': '012345679abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0',
}

# §13 EC-challenge material that must NOT appear in any public tool
NEVER_PUBLIC = ['8dfc7b25', 'b7a777d1', '6e978d37', 'challenge', 'salt',
                'SMM', 'probe', '0x910']


def main():
    assert os.path.isfile(EXE), f'missing {EXE}'
    td = tempfile.mkdtemp(prefix='rx98')
    shutil.copy(EXE, td)
    subprocess.run([sys.executable, '-m', 'pyinstxtractor_ng',
                    os.path.join(td, 'DellBiosTools.exe')],
                   check=True, capture_output=True, cwd=td)
    pyc = os.path.join(td, 'DellBiosTools.exe_extracted', 'DellBiosTools.pyc')
    d = open(pyc, 'rb').read()
    print(f'main script: DellBiosTools.pyc, {len(d)} bytes (Python 3.13)')

    print('\n--- seven-table bank presence ---')
    for name, t in TABLES.items():
        print(f'  {"PRESENT" if t.encode() in d else "ABSENT ":s}  {name}')

    print('\n--- EC-challenge material (expected absent) ---')
    for pat in NEVER_PUBLIC:
        print(f'  {pat:10s}: {"LEAKED!" if pat.encode() in d else "absent"}')

    print('\n--- 8FC8 patcher constants (expected present) ---')
    for pat in ('5AA5F00F03', '00FCAA', '00FDAA', '00FC00', '00FD00'):
        print(f'  {pat}: {"present" if pat.encode() in d else "absent"}')

    print('\n--- keygen functions in disassembly ---')
    r = subprocess.run(['pydisasm', pyc], capture_output=True, text=True)
    for m in re.finditer(r'# Method Name:\s+(\S+)', r.stdout):
        fn = m.group(1)
        if any(k in fn for k in ('calculateE7A8', 'keygenDell',
                                 'calculateSuffix', 'resultToString',
                                 'blockEncode', 'Encoder')):
            print(f'  {fn}')

    print('\nKey UI strings:')
    for s in re.findall(rb'[\x20-\x7e]{20,}', d):
        t = s.decode('latin1')
        if any(k in t for k in ('8FC8', 'Rex98', 'Techshack', 'master',
                                'Common Tags')):
            print(f'  {t[:90]}')

    shutil.rmtree(td, ignore_errors=True)
    print('\nDone — see REPORT.md §13.13 for interpretation.')


if __name__ == '__main__':
    main()
