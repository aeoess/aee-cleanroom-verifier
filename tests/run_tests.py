#!/usr/bin/env python3
"""Run the verifier CLI over every case in tests/cases, twice per case
(with AEE_SUBSTRATE_KEYS set and unset), and compare against
tests/expectations.json. Also runs tests/test_primitives.py.
Exit 0 only if every check passes."""

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
VERIFIER = [sys.executable, os.path.join(ROOT, "aee_verify.py")]


def run(path, keyfile):
    env = dict(os.environ)
    env.pop("AEE_SUBSTRATE_KEYS", None)
    if keyfile:
        env["AEE_SUBSTRATE_KEYS"] = os.path.join(HERE, "keys", keyfile + ".json")
    p = subprocess.run(VERIFIER + [path], capture_output=True, env=env)
    lines = p.stdout.decode().strip().splitlines()
    last = json.loads(lines[-1]) if lines else None
    return p.returncode, last, p.stderr.decode()


def main():
    failures = []
    prim = subprocess.run([sys.executable, os.path.join(HERE, "test_primitives.py")])
    if prim.returncode != 0:
        failures.append("test_primitives.py failed")
    with open(os.path.join(HERE, "expectations.json")) as f:
        exp = json.load(f)
    n = 0
    for name in sorted(exp):
        e = exp[name]
        path = os.path.join(HERE, "cases", name + ".json")
        for keyed in (True, False):
            n += 1
            code, out, err = run(path, e["keyfile"] if keyed else None)
            tag = "%s [%s]" % (name, "key" if keyed else "nokey")
            want_exit = 0 if e["verdict"] == "accept" else 1
            problems = []
            if code != want_exit:
                problems.append("exit %d != %d" % (code, want_exit))
            if not isinstance(out, dict):
                problems.append("no JSON last line")
            else:
                if out.get("verdict") != e["verdict"]:
                    problems.append("verdict %r" % out.get("verdict"))
                if e["verdict"] == "accept":
                    if out.get("result") != e["result"]:
                        problems.append("result %r != %r" % (out.get("result"), e["result"]))
                    if out.get("codes"):
                        problems.append("codes on accept %r" % out.get("codes"))
                    want_t = e["tiersWithKey"] if keyed else e["tiersWithoutKey"]
                    if want_t is not None and out.get("tiers") != want_t:
                        problems.append("tiers %r != %r" % (out.get("tiers"), want_t))
                else:
                    missing = [c for c in e["codes"] if c not in out.get("codes", [])]
                    if missing:
                        problems.append("missing codes %r (got %r)" % (missing, out.get("codes")))
                    if e.get("primaryCode") and out.get("primaryCode") != e["primaryCode"]:
                        problems.append("primaryCode %r != %r" % (out.get("primaryCode"), e["primaryCode"]))
            if problems:
                failures.append("%s: %s\n%s" % (tag, "; ".join(problems), err))
    # CLI conventions: stdin via "-", usage error, unreadable file
    sample = os.path.join(HERE, "cases", "ok-all-clean-pass.json")
    with open(sample, "rb") as f:
        p = subprocess.run(VERIFIER + ["-"], stdin=f, capture_output=True)
    n += 1
    if p.returncode != 0 or json.loads(p.stdout.decode().splitlines()[-1]).get("result") != "pass":
        failures.append("stdin mode")
    p = subprocess.run(VERIFIER, capture_output=True)
    n += 1
    if p.returncode != 2:
        failures.append("usage error exit %d" % p.returncode)
    p = subprocess.run(VERIFIER + [os.path.join(HERE, "cases", "does-not-exist.json")], capture_output=True)
    n += 1
    if p.returncode != 2 or "AEE-INPUT-UNREADABLE" not in p.stdout.decode():
        failures.append("unreadable file")
    for f in failures:
        print("FAIL", f)
    print("%d case runs, %d failures" % (n, len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
