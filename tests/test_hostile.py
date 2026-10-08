"""Spec-derived regressions. No study cases or outside verifier inputs."""
from pathlib import Path
import importlib.util, sys, json, copy
root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
sys.path.insert(0, str(root / 'tests'))
import aee_verify as a
import gen_cases as g
failures = []
checks = 0
group = sys.argv[2] if len(sys.argv) > 2 else "all"
category = "refs"
def check(ok, label):
    global checks
    if group not in ("all", category): return
    checks += 1
    if not ok: failures.append(label)
def run(s, expected, label):
    st, _ = g.finalize(s)
    for keys in ([], [g.PUB]):
        v = a.Verifier(json.dumps(st).encode(), keys)
        ok = v.run()
        check(ok is expected, label + (' keyed' if keys else ' unkeyed'))
        if expected and ok:
            check(v.result == 'fail', label + ' result stays fail')
            check(v.tiers == (['attested', 'attested'] if keys else ['unattested', 'unattested']), label + ' tiers')
for spelling in ('float', 'exponent', 'negative-zero'):
    st, _ = g.finalize(g.base_spec())
    st['predicate']['attackResults'][0]['observationRefs'] = [0.0]
    st['predicate']['attackResults'][1]['observationRefs'] = [1.0, 2.0]
    raw = json.dumps(st)
    if spelling == 'exponent':
        raw = raw.replace('[0.0]', '[0e0]').replace('[1.0, 2.0]', '[1e0, 2e0]')
    if spelling == 'negative-zero': raw = raw.replace('[0.0]', '[-0.0]')
    for keys in ([], [g.PUB]):
        v = a.Verifier(raw.encode(), keys)
        ok = v.run()
        check(ok, spelling + ' integral refs accepted')
        check(ok and v.result == 'fail', spelling + ' result unchanged')
        check(ok and v.tiers == (['attested', 'attested'] if keys else ['unattested', 'unattested']), spelling + ' tiers')
for value in (0.5, True, '0', -1, 3, None):
    s = g.base_spec()
    g.P(s)['attackResults'][0]['observationRefs'] = [value]
    run(s, False, 'bad ref ' + repr(value))
category = "chain"
# All carried chain members are syntax checked in the reserved-member walk.
bad_chains = [
    {'aeeChainScope': ['subject']},
    {'aeePrevRunBinding': '0' * 64},
    {'aeeRunSeq': 0, 'aeeChainScope': []},
    {'aeeRunSeq': 1.5, 'aeeChainScope': []},
    {'aeeRunSeq': 1},
    {'aeeRunSeq': 1, 'aeeChainScope': 'subject'},
    {'aeeRunSeq': 1, 'aeeChainScope': ['unknown']},
    {'aeeRunSeq': 1, 'aeeChainScope': ['subject', 'subject']},
    {'aeeRunSeq': 1, 'aeeChainScope': [], 'aeePrevRunBinding': '0' * 64},
    {'aeeRunSeq': 2, 'aeeChainScope': []},
    {'aeeRunSeq': 2, 'aeeChainScope': [], 'aeePrevRunBinding': 'bad'},
]
for kind, index in [('interception', 0), ('arming', 1), ('sealed', 2), ('examination', 0)]:
    for change in [None, {'aeeRunSeq': 1, 'aeeChainScope': ['subject']}] + bad_chains:
        s = g.base_spec()
        if kind == 'examination':
            s['records'][0]['aeeKind'] = kind
            s['records'][0]['aeeMethod'] = 'reconstructed'
            del s['records'][0]['aeePayloadCommitment']
            r = g.P(s)['attackResults'][0]
            r['method'] = 'reconstructed'
            r['attribution'] = 'paired'
            del g.ENV(s)['corpus']['manifest']['expectedPayloads']
        if change: s['records'][index].update(change)
        run(s, change is None or change not in bad_chains, kind + ' ' + repr(change))
category = "jcs"
# RFC 8785 emits these characters literally, in names and values.
for cp in (0x2028, 0x2029):
    text = chr(cp)
    check(a.jcs(text) == b'"' + text.encode() + b'"', 'literal JCS ' + hex(cp))
    s = g.base_spec()
    s['records'][0][text] = text
    run(s, True, 'JCS record ' + hex(cp))
for failure in failures: print('FAIL', failure)
print(str(checks) + ' checks, ' + str(len(failures)) + ' failures')
sys.exit(bool(failures))
