#!/usr/bin/env python3
"""Regression checks added after review (2026-10-07).

R1: RFC 3339 timestamps take ASCII digits only. Python's \\d also matches
other Unicode decimal digits, so the parser accepted e.g. an Arabic-Indic
year in issuedAt. Every accept case is mutated so issuedAt uses
Arabic-Indic digits, and each must now be rejected (exit 1). armedAt is
parsed by the same function, so the parser-level check below covers it.
"""
import json, os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import aee_verify  # noqa: E402

ARABIC = str.maketrans("0123456789", "٠١٢٣٤٥٦٧٨٩")
fails = []

# parser level: the shared timestamp regex must not match non-ASCII digits
if aee_verify.TS_RE.match("2026-06-23T16:08:07Z") is None:
    fails.append("TS_RE rejects a valid ASCII timestamp")
if aee_verify.TS_RE.match("2026-06-23T16:08:07Z".translate(ARABIC)) is not None:
    fails.append("TS_RE accepts Arabic-Indic digits")
if aee_verify.TS_RE.match("٢026-06-23T16:08:07Z") is not None:
    fails.append("TS_RE accepts one Arabic-Indic digit in the year")

def set_issued(o):
    hit = False
    if isinstance(o, dict):
        for k, v in o.items():
            if k == "issuedAt" and isinstance(v, str):
                o[k] = v.translate(ARABIC); hit = True
            else:
                hit = set_issued(v) or hit
    elif isinstance(o, list):
        for v in o:
            hit = set_issued(v) or hit
    return hit

with open(os.path.join(HERE, "expectations.json")) as f:
    exp = json.load(f)
n = 0
for name in sorted(exp):
    if exp[name].get("verdict") != "accept":
        continue
    with open(os.path.join(HERE, "cases", name + ".json"), encoding="utf-8") as f:
        st = json.load(f)
    if not set_issued(st):
        continue
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as t:
        json.dump(st, t, ensure_ascii=False)
    env = dict(os.environ); env.pop("AEE_SUBSTRATE_KEYS", None)
    p = subprocess.run([sys.executable, os.path.join(ROOT, "aee_verify.py"), t.name], capture_output=True, env=env)
    os.unlink(t.name)
    n += 1
    if p.returncode != 1:
        fails.append(f"{name}: Arabic-Indic issuedAt exit {p.returncode}, want 1")
print(f"regressions: {n} mutated accept cases, {len(fails)} failures")
for x in fails: print("  FAIL", x)
sys.exit(1 if fails or n == 0 else 0)
