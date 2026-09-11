#!/usr/bin/env python3
"""Cross-validate our dell_keygen.keygen_e7a8 against the PUBLIC
chromebreakerdev/DellBIOSTools E7A8 implementation (Algorithm.md path),
byte-for-byte, on shared test serials.
"""
import sys, os

HERE = os.path.dirname(os.path.abspath(__file__))
PUBLIC = os.environ.get('DELLBIOSTOOLS_SRC') or '/tmp/dellbiostools/DellBiosTools.pyw'
PUBLIC_URL = ('https://raw.githubusercontent.com/chromebreakerdev/'
              'DellBIOSTools/main/DellBiosTools.pyw')
PUBLIC_FALLBACK = os.path.join(HERE, 'collected', 'DellBiosTools.pyw')


def get_public_source():
    """Locate the public tool's source: env override, local clone, repo
    snapshot, or fetch from GitHub raw (last resort)."""
    for p in (PUBLIC, PUBLIC_FALLBACK):
        if os.path.isfile(p):
            return open(p, encoding='utf-8', errors='replace').read()
    import urllib.request
    with urllib.request.urlopen(PUBLIC_URL, timeout=30) as r:
        return r.read().decode('utf-8', errors='replace')

def load_public():
    """Extract ONLY the pure algorithm code (functions/classes/simple
    assignments) from the public tool via AST — the file's module-level
    header runs subprocess/ctypes/open at import, which kills a headless
    process, so we never exec the raw source."""
    import ast
    src = get_public_source()
    tree = ast.parse(src)
    keep = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            keep.append(node)
        elif isinstance(node, ast.Assign) and all(
                isinstance(t, ast.Name) for t in node.targets):
            # only PURE literal assignments (encscans/extraCharacters/…);
            # drop any whose value contains a Call (app_base_path() etc.)
            if not any(isinstance(n, ast.Call) for n in ast.walk(node.value)):
                keep.append(node)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            keep.append(node)
        # skip imports entirely - ns pre-seeds hashlib/typing.List; skip
        # Expr/If/Try/With (GUI bootstrap + subprocess/ctypes header)
    core = ast.Module(body=keep, type_ignores=[])
    import hashlib
    from typing import List, Optional, Dict, Tuple, Any
    ns = {'hashlib': hashlib, 'List': List, 'Optional': Optional,
          'Dict': Dict, 'Tuple': Tuple, 'Any': Any, '__name__': 'public_core'}
    exec(compile(core, 'DellBiosTools_core.py', 'exec'), ns)
    return ns

def load_ours():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        'dk', os.path.join(HERE, 'dell_keygen.py'))
    dk = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dk)
    return dk

def main():
    ns = load_public()
    dk = load_ours()
    serials = ["1A2B3C4", "7QJ4H42", "H2FS5S3", "5W91H73", "62QB9R3"]
    print(f'{"serial":9s} | {"public tool (enc1/enc2)":45s} | match')
    ok = True
    for s in serials:
        theirs = ns['keygenDell'](s, "E7A8", 0)
        ours = dk.keygen_e7a8(s)
        m = theirs == ours
        ok &= m
        print(f'{s:9s} | {theirs[0]}/{theirs[1]:35s} | {"YES" if m else "NO  <<< MISMATCH"}')
        print(f'{"":9s} | ours: {ours[0]}/{ours[1]}')
    print('RESULT:', 'PASS - byte-identical E7A8 derivation' if ok else 'FAIL')

if __name__ == '__main__':
    main()
