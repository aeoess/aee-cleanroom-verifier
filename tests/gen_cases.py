#!/usr/bin/env python3
"""Generate test statements derived from the spec text (own cases only).

Each case is a JSON statement in tests/cases/<name>.json plus an expectation
entry in tests/cases/expectations.json. Records are signed with a fixed,
test-only Ed25519 key (tests/keys/). Builders use the verifier's own JCS,
PAE, Merkle and Ed25519 helpers to assemble statements; tests/test_primitives.py
checks those helpers against independent known values.
"""

import base64
import copy
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import aee_verify as V  # noqa: E402

CASES = os.path.join(HERE, "cases")
KEYS = os.path.join(HERE, "keys")
SECRET = hashlib.sha256(b"emse-aee-build test-only substrate key").digest()
WRONG_SECRET = hashlib.sha256(b"emse-aee-build some other key").digest()
PUB = V.ed25519_public(SECRET)
WRONG_PUB = V.ed25519_public(WRONG_SECRET)
PTYPE = "application/vnd.example.aee-observation+json"


def h(s):
    return hashlib.sha256(s.encode()).hexdigest()


COMMIT_CO = h("commitment of CO-EXFIL-1 payload")
COMMIT_OTHER = h("commitment of something else")
AUTO = "__AUTO__"


def base_spec():
    """A complete statement description; finalize() fills derived values."""
    return {
        "statement": {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "tool-image", "digest": {"sha256": h("subject")}}],
            "predicateType": V.PREDICATE_TYPE,
            "predicate": {
                "result": "fail",
                "observationEnvironment": {
                    "substrate": {"name": "substrate-img", "digest": {"sha256": h("substrate")}},
                    "corpus": {
                        "name": "corpus-x",
                        "uri": "pkg:example/corpus-x@1.0.0",
                        "digest": {"sha256": AUTO},
                        "manifest": {
                            "classes": {"CO": ["CO-EXFIL-1"], "FS": ["FS-WRITE-1"]},
                            "expectedPayloads": {"CO-EXFIL-1": [COMMIT_CO]},
                        },
                    },
                    "catchPolicy": {"digest": {"sha256": h("catch-policy")}},
                    "networkPosture": {"posture": "sinkhole", "digest": {"sha256": h("posture-config")}},
                    "observationVocabulary": {
                        "digest": {"sha256": AUTO},
                        "labels": ["egress_captured", "no_egress"],
                        "caught": ["egress_captured"],
                    },
                    "runEntropy": {"digest": {"sha256": h("run-entropy-1")}},
                },
                "coverage": {"assessedClasses": ["CO", "FS"], "outOfScope": {}, "routedElsewhere": {}},
                "attackResults": [
                    {"attackId": "CO-EXFIL-1", "containmentObserved": "egress_captured",
                     "basis": "substrate", "method": "intercepted", "attribution": "pinned",
                     "actualLayer": "policy.egress_sinkhole", "observationRefs": [0]},
                    {"attackId": "FS-WRITE-1", "containmentObserved": "no_egress",
                     "basis": "substrate", "method": "intercepted", "attribution": "paired",
                     "actualLayer": "none", "observationRefs": [1, 2]},
                ],
                "observationRecords": AUTO,
                "batchRoot": AUTO,
                "doesNotAssert": ["behavior outside the thrown corpus"],
                "issuedAt": "2026-06-23T16:08:07Z",
            },
        },
        # payload dicts; AUTO members are filled by finalize()
        "records": [
            {"aeeKind": "interception", "aeeMethod": "intercepted", "aeeRunBinding": AUTO,
             "aeePayloadCommitment": [COMMIT_CO], "dst": "10.0.0.9:443"},
            {"aeeKind": "arming", "aeeMethod": "intercepted", "aeeRunBinding": AUTO,
             "armedAt": "2026-06-23T16:00:00Z", "aeePostureDigest": AUTO,
             "aeeAssessedAttacks": ["CO-EXFIL-1", "FS-WRITE-1"]},
            {"aeeKind": "sealed", "aeeMethod": "intercepted", "aeeRunBinding": AUTO,
             "aeeStillArmed": True, "aeeDropCount": 0, "aeePostureDigest": AUTO,
             "aeeObservedSet": AUTO, "aeeObservedAttacks": ["CO-EXFIL-1"]},
        ],
        "ptypes": {},        # index -> payloadType override
        "raw_payloads": {},  # index -> exact bytes override (after AUTO fill)
        "sign_with": {},     # index -> secret override
        "extra_entries": [],  # appended envelope entries (already-built dicts)
        "urlsafe": set(),
    }


def P(spec):
    return spec["statement"]["predicate"]


def ENV(spec):
    return P(spec)["observationEnvironment"]


def compute_binding(st):
    env = st["predicate"]["observationEnvironment"]
    obj = {
        "aeeBindingVersion": "2",
        "catchPolicy": env["catchPolicy"]["digest"]["sha256"],
        "corpus": env["corpus"]["digest"]["sha256"],
        "networkPosture": V.sha256_hex(V.jcs(env["networkPosture"])),
        "observationVocabulary": env["observationVocabulary"]["digest"]["sha256"],
        "runEntropy": env["runEntropy"]["digest"]["sha256"],
        "subject": st["subject"][0]["digest"]["sha256"],
        "substrate": env["substrate"]["digest"]["sha256"],
    }
    return V.sha256_hex(V.jcs(obj))


def b64(b, urlsafe=False):
    if urlsafe:
        return base64.urlsafe_b64encode(b).decode().rstrip("=")
    return base64.b64encode(b).decode()


def finalize(spec, binding_override=None):
    st = copy.deepcopy(spec["statement"])
    env = st["predicate"]["observationEnvironment"]
    if env["corpus"]["digest"]["sha256"] == AUTO:
        env["corpus"]["digest"]["sha256"] = V.sha256_hex(V.jcs(env["corpus"]["manifest"]))
    voc = env["observationVocabulary"]
    if voc["digest"]["sha256"] == AUTO:
        voc["digest"]["sha256"] = V.sha256_hex(V.jcs({"caught": voc["caught"], "labels": voc["labels"]}))
    binding = None
    try:
        binding = compute_binding(st)
    except (KeyError, TypeError):
        pass
    if binding_override is not None:
        binding = binding_override
    posture_pin = env["networkPosture"]["digest"]["sha256"]

    payloads = [copy.deepcopy(p) for p in spec["records"]]
    for p in payloads:
        for k, v in list(p.items()):
            if v == AUTO and k == "aeeRunBinding":
                p[k] = binding
            elif v == AUTO and k == "aeePostureDigest":
                p[k] = posture_pin
    entries = [None] * len(payloads)

    def build(i):
        p = payloads[i]
        body = spec["raw_payloads"].get(i)
        if body is None:
            body = V.jcs(p)
        ptype = spec["ptypes"].get(i, PTYPE)
        secret = spec["sign_with"].get(i, SECRET)
        sig = V.ed25519_sign(secret, V.pae(ptype, body))
        return body, {"payload": b64(body, i in spec["urlsafe"]), "payloadType": ptype,
                      "signatures": [{"keyid": "substrate-test", "sig": b64(sig)}]}

    bodies = {}
    # first everything without an AUTO observed set
    for i, p in enumerate(payloads):
        if p.get("aeeObservedSet") != AUTO:
            bodies[i], entries[i] = build(i)
    leaves = set()
    for i, p in enumerate(payloads):
        if i in bodies and p.get("aeeKind") in ("interception", "examination"):
            leaves.add(V.leaf_hash(V.pae(entries[i]["payloadType"], bodies[i])).hex())
    obs = V.sha256_hex(V.jcs(sorted(leaves)))
    for i, p in enumerate(payloads):
        if p.get("aeeObservedSet") == AUTO:
            p["aeeObservedSet"] = obs
            bodies[i], entries[i] = build(i)
    entries = entries + list(spec["extra_entries"])

    pred = st["predicate"]
    if pred.get("observationRecords") == AUTO:
        if entries:
            pred["observationRecords"] = entries
        else:
            del pred["observationRecords"]
    if pred.get("batchRoot") == AUTO:
        recs = pred.get("observationRecords") or []
        if recs:
            leaves = [V.leaf_hash(V.pae(e["payloadType"], V.b64decode_dsse(e["payload"]))) for e in recs]
            pred["batchRoot"] = V.merkle_root(leaves).hex()
        else:
            del pred["batchRoot"]
    return st, binding


def recompute_root(st):
    recs = st["predicate"]["observationRecords"]
    leaves = [V.leaf_hash(V.pae(e["payloadType"], V.b64decode_dsse(e["payload"]))) for e in recs]
    st["predicate"]["batchRoot"] = V.merkle_root(leaves).hex()


def dump(st):
    return json.dumps(st, indent=2, ensure_ascii=False).encode("utf-8")


CASE_LIST = []


def case(name, data, verdict, result=None, codes=None, tiers_key=None, tiers_nokey=None, keyfile="good", primary=None):
    if isinstance(data, dict):
        data = dump(data)
    CASE_LIST.append((name, data, {
        "verdict": verdict, "result": result, "codes": codes or [],
        "tiersWithKey": tiers_key, "tiersWithoutKey": tiers_nokey, "keyfile": keyfile,
        "primaryCode": primary}))


# ---------------------------------------------------------------- positives

def positives():
    s = base_spec()
    st, _ = finalize(s)
    case("ok-base-fail-caught-pinned", st, "accept", "fail",
         tiers_key=["attested", "attested"], tiers_nokey=["unattested", "unattested"])
    case("ok-base-wrong-key-unattested", st, "accept", "fail",
         tiers_key=["unattested", "unattested"], tiers_nokey=["unattested", "unattested"], keyfile="wrong")

    # all clean, substrate intercepted -> pass
    s = base_spec()
    m = ENV(s)["corpus"]["manifest"]
    del m["expectedPayloads"]
    P(s)["result"] = "pass"
    P(s)["attackResults"] = [
        {"attackId": "CO-EXFIL-1", "containmentObserved": "no_egress", "basis": "substrate",
         "method": "intercepted", "attribution": "paired", "actualLayer": "none", "observationRefs": [0, 1]},
        {"attackId": "FS-WRITE-1", "containmentObserved": "no_egress", "basis": "substrate",
         "method": "intercepted", "attribution": "paired", "actualLayer": "none", "observationRefs": [0, 1]},
    ]
    s["records"] = [s["records"][1], s["records"][2]]
    s["records"][1]["aeeObservedAttacks"] = []
    st, _ = finalize(s)
    case("ok-all-clean-pass", st, "accept", "pass",
         tiers_key=["attested", "attested"], tiers_nokey=["unattested", "unattested"])
    pass_spec = s

    # producer extensions, predicate-level aee*/evidenceTier ignored, extra payload member
    s = copy.deepcopy(pass_spec)
    P(s)["aeeSomething"] = "ignored"
    P(s)["evidenceTier"] = "attested"
    P(s)["attackResults"][0]["observationSelectors"] = ["a", "b", "c"]
    s["records"][0]["producerSeverity"] = 5
    st, _ = finalize(s)
    case("ok-ignored-members", st, "accept", "pass",
         tiers_key=["attested", "attested"], tiers_nokey=["unattested", "unattested"])

    # sealed with drop count within declared bound; arming with explicit binding version + chain
    s = copy.deepcopy(pass_spec)
    s["records"][1]["aeeDropCount"] = 2
    s["records"][1]["aeeDropBound"] = 3
    s["records"][0]["aeeBindingVersion"] = "2"
    s["records"][0]["aeeRunSeq"] = 2
    s["records"][0]["aeePrevRunBinding"] = h("previous run")
    s["records"][0]["aeeChainScope"] = ["corpus", "subject"]
    st, _ = finalize(s)
    case("ok-dropbound-chain-version", st, "accept", "pass",
         tiers_key=["attested", "attested"], tiers_nokey=["unattested", "unattested"])

    # chain genesis
    s = copy.deepcopy(pass_spec)
    s["records"][0]["aeeRunSeq"] = 1
    s["records"][0]["aeeChainScope"] = []
    st, _ = finalize(s)
    case("ok-chain-genesis-empty-scope", st, "accept", "pass")

    # issuedAt with +00:00 and -00:00, fractional seconds
    for nm, ts in (("plus", "2026-06-23T16:08:07+00:00"), ("minus", "2026-06-23T16:08:07.250-00:00")):
        s = copy.deepcopy(pass_spec)
        P(s)["issuedAt"] = ts
        st, _ = finalize(s)
        case("ok-issuedat-%s-zero" % nm, st, "accept", "pass")

    # armedAt equal to issuedAt
    s = copy.deepcopy(pass_spec)
    s["records"][0]["armedAt"] = "2026-06-23T16:08:07Z"
    st, _ = finalize(s)
    case("ok-armedat-equals-issuedat", st, "accept", "pass")

    # artifact-only statement: no records, no runEntropy, no batchRoot -> pass_indirect
    s = base_spec()
    del ENV(s)["corpus"]["manifest"]["expectedPayloads"]
    del ENV(s)["runEntropy"]
    P(s)["result"] = "pass_indirect"
    P(s)["attackResults"] = [
        {"attackId": "CO-EXFIL-1", "containmentObserved": "no_egress", "basis": "artifact",
         "method": "intercepted", "attribution": "paired", "actualLayer": "none"},
        {"attackId": "FS-WRITE-1", "containmentObserved": "no_egress", "basis": "artifact",
         "method": "reconstructed", "attribution": "paired", "actualLayer": "none", "observationRefs": []},
    ]
    s["records"] = []
    st, _ = finalize(s)
    case("ok-artifact-only-pass-indirect", st, "accept", "pass_indirect",
         tiers_key=["declared", "declared"], tiers_nokey=["declared", "declared"])
    artifact_spec = s

    # fully skipped run: every class outOfScope -> degraded (zero rows)
    s = copy.deepcopy(artifact_spec)
    P(s)["coverage"] = {"assessedClasses": [], "outOfScope": {"CO": "no vantage", "FS": "no vantage"},
                        "routedElsewhere": {}}
    P(s)["attackResults"] = []
    P(s)["result"] = "degraded"
    st, _ = finalize(s)
    case("ok-fully-skipped-degraded", st, "accept", "degraded", tiers_key=[], tiers_nokey=[])

    # degraded with substrate evidence: FS routed elsewhere, arming declared both (subset rule)
    s = copy.deepcopy(pass_spec)
    P(s)["coverage"] = {"assessedClasses": ["CO"], "outOfScope": {}, "routedElsewhere": {"FS": "other lab"}}
    P(s)["attackResults"] = P(s)["attackResults"][:1]
    P(s)["result"] = "degraded"
    st, _ = finalize(s)
    case("ok-degraded-partway-loss", st, "accept", "degraded",
         tiers_key=["attested"], tiers_nokey=["unattested"])

    # reconstructed substrate clean row with examination -> pass_indirect
    s = copy.deepcopy(pass_spec)
    s["records"].append({"aeeKind": "examination", "aeeMethod": "reconstructed", "aeeRunBinding": AUTO,
                         "states": ["snap-0", "snap-1"]})
    P(s)["attackResults"][1]["method"] = "reconstructed"
    P(s)["attackResults"][1]["observationRefs"] = [2]
    P(s)["result"] = "pass_indirect"
    st, _ = finalize(s)
    case("ok-reconstructed-examination", st, "accept", "pass_indirect",
         tiers_key=["attested", "attested"], tiers_nokey=["unattested", "unattested"])

    # caught reconstructed row with examination -> fail
    s2 = copy.deepcopy(s)
    P(s2)["attackResults"][1]["containmentObserved"] = "egress_captured"
    P(s2)["attackResults"][1]["actualLayer"] = "none"  # observed, nothing acted
    P(s2)["result"] = "fail"
    st, _ = finalize(s2)
    case("ok-caught-reconstructed-none-layer", st, "accept", "fail")

    # fail-closed artifact row (label outside vocabulary, 0.4 basis spelling) -> valid fail
    s = copy.deepcopy(artifact_spec)
    P(s)["attackResults"][0]["containmentObserved"] = "unknown_label"
    P(s)["attackResults"][1]["basis"] = "artifact_reported"
    P(s)["result"] = "fail"
    st, _ = finalize(s)
    case("ok-fail-closed-artifact-rows", st, "accept", "fail",
         tiers_key=["declared", "declared"], tiers_nokey=["declared", "declared"])

    # attribution missing on a row WITH an expectation entry -> fail-closed, still valid
    s = copy.deepcopy(artifact_spec)
    ENV(s)["corpus"]["manifest"]["expectedPayloads"] = {"CO-EXFIL-1": [COMMIT_CO]}
    del P(s)["attackResults"][0]["attribution"]
    P(s)["result"] = "fail"
    st, _ = finalize(s)
    case("ok-attribution-missing-with-entry-fails", st, "accept", "fail")

    # unrecognized kind and moat-drop/uncommitted-observation carried; unknown kind referenced beside covering ones
    s = copy.deepcopy(pass_spec)
    s["records"].append({"aeeKind": "hardware-quote", "aeeMethod": "intercepted", "aeeRunBinding": AUTO})
    s["records"].append({"aeeKind": "moat-drop", "aeeMethod": "intercepted", "aeeRunBinding": AUTO})
    s["records"].append({"aeeKind": "uncommitted-observation", "aeeMethod": "intercepted",
                         "aeeRunBinding": AUTO})
    P(s)["attackResults"][0]["observationRefs"] = [0, 1, 2]
    st, _ = finalize(s)
    case("ok-noncovering-kinds-carried", st, "accept", "pass",
         tiers_key=["attested", "attested"], tiers_nokey=["unattested", "unattested"])

    # url-safe unpadded base64 payload
    s = copy.deepcopy(pass_spec)
    s["urlsafe"] = {0, 1}
    st, _ = finalize(s)
    case("ok-urlsafe-base64", st, "accept", "pass")

    # depth exactly 128 (outermost { is depth 1) in a producer extension member
    s = copy.deepcopy(pass_spec)
    st, _ = finalize(s)
    nested = 0
    for _ in range(126):  # statement(1) > predicate(2) > arrays at depth 3..128
        nested = [nested]
    st["predicate"]["ext"] = nested
    case("ok-depth-128", st, "accept", "pass")

    # BMP strings everywhere, vocabulary sorted by UTF-16 code unit with a high-BMP label
    s = copy.deepcopy(pass_spec)
    voc = ENV(s)["observationVocabulary"]
    voc["labels"] = ["egress_captured", "no_egress", "דּlabel"]
    st, _ = finalize(s)
    case("ok-vocab-high-bmp", st, "accept", "pass")

    # DSSE-enveloped statement (extension)
    s = copy.deepcopy(pass_spec)
    st, _ = finalize(s)
    body = V.jcs(st)
    env = {"payloadType": "application/vnd.in-toto+json", "payload": b64(body),
           "signatures": [{"keyid": "producer", "sig": b64(V.ed25519_sign(WRONG_SECRET, V.pae("application/vnd.in-toto+json", body)))}]}
    case("ok-dsse-enveloped-statement", env, "accept", "pass")


# ---------------------------------------------------------------- negatives

def mutate(name, codes, fn, base=None, **kw):
    s = copy.deepcopy(base or base_spec())
    out = fn(s)
    if not (isinstance(out, dict) and "_type" in out):  # mutators may return popped values
        st, _ = finalize(s)
    else:
        st = out
    case(name, st, "reject", codes=codes, **kw)


def raw_case(name, codes, text):
    case(name, text if isinstance(text, bytes) else text.encode("utf-8"), "reject", codes=codes)


def negatives():
    st, _ = finalize(base_spec())
    good = dump(st)
    txt = good.decode("utf-8")

    # --- byte-level / strict I-JSON
    raw_case("bad-dup-member-deep", ["AEE-JSON-DUPLICATE-MEMBER"],
             txt.replace('"posture": "sinkhole",', '"posture": "sinkhole", "posture": "sinkhole",'))
    raw_case("bad-dup-member-escaped-name", ["AEE-JSON-DUPLICATE-MEMBER"],
             txt.replace('"issuedAt":', '"issuedAt": "2026-06-23T16:08:07Z", "\\u0069ssuedAt":'))
    raw_case("bad-overlong-utf8", ["AEE-JSON-INVALID-UTF8"],
             good.replace(b"behavior outside", b"behavior \xc0\xafoutside"))
    raw_case("bad-cesu8-surrogate", ["AEE-JSON-INVALID-UTF8"],
             good.replace(b"behavior outside", b"behavior \xed\xa0\x80outside"))
    raw_case("bad-unpaired-high-escape", ["AEE-JSON-UNPAIRED-SURROGATE"],
             txt.replace("behavior outside", "behavior \\ud800 outside"))
    raw_case("bad-unpaired-low-escape", ["AEE-JSON-UNPAIRED-SURROGATE"],
             txt.replace("behavior outside", "behavior \\udc00 outside"))
    raw_case("bad-escape-plus-sign", ["AEE-JSON-BAD-ESCAPE"],
             txt.replace("behavior outside", "behavior \\u+041 outside"))
    raw_case("bad-escape-three-hex", ["AEE-JSON-BAD-ESCAPE"],
             txt.replace("behavior outside", "behavior \\u041 outside"))
    raw_case("bad-noncharacter-escaped", ["AEE-JSON-NONCHARACTER"],
             txt.replace("behavior outside", "behavior \\ufdd0 outside"))
    raw_case("bad-noncharacter-raw-member-name", ["AEE-JSON-NONCHARACTER"],
             txt.replace('"doesNotAssert"', '"x\U0001FFFF": 1, "doesNotAssert"'))
    raw_case("bad-raw-control-char", ["AEE-JSON-CONTROL-CHAR"],
             txt.replace("behavior outside", "behavior\x01outside"))
    nested = 0
    for _ in range(127):  # arrays at depth 3..129
        nested = [nested]
    st2 = copy.deepcopy(st)
    st2["predicate"]["ext"] = nested
    case("bad-depth-129", dump(st2), "reject", codes=["AEE-JSON-DEPTH"])
    raw_case("bad-trailing-content", ["AEE-JSON-SYNTAX"], txt + "x")
    raw_case("bad-bom", ["AEE-JSON-SYNTAX"], b"\xef\xbb\xbf" + good)

    # --- statement shape
    mutate("bad-predicate-type-v06", ["AEE-PREDICATE-TYPE"],
           lambda s: s["statement"].__setitem__("predicateType", V.PREDICATE_TYPE.replace("v0.7", "v0.6")))
    mutate("bad-two-subjects", ["AEE-SUBJECT-COUNT"],
           lambda s: s["statement"]["subject"].append({"name": "b", "digest": {"sha256": h("b")}}))
    mutate("bad-subject-digest-uppercase", ["AEE-DIGEST-FORMAT"],
           lambda s: s["statement"]["subject"][0]["digest"].__setitem__("sha256", h("subject").upper()))
    mutate("bad-catchpolicy-digest-missing", ["AEE-DIGEST-FORMAT"],
           lambda s: ENV(s)["catchPolicy"].__setitem__("digest", {"sha512": h("x")}))
    mutate("bad-result-mismatch", ["AEE-RESULT-MISMATCH"], lambda s: P(s).__setitem__("result", "pass"))
    mutate("bad-result-uppercase", ["AEE-RESULT-VALUE"], lambda s: P(s).__setitem__("result", "FAIL"))
    mutate("bad-posture-unregistered", ["AEE-POSTURE-VOCAB"],
           lambda s: ENV(s)["networkPosture"].__setitem__("posture", "open"))
    mutate("bad-posture-absent", ["AEE-POSTURE-VOCAB"], lambda s: ENV(s)["networkPosture"].pop("posture"))
    mutate("bad-retired-does-not-assert", ["AEE-RETIRED-SPELLING"],
           lambda s: P(s).__setitem__("does_not_assert", []))
    mutate("bad-issuedat-lowercase-z", ["AEE-ISSUEDAT-PROFILE"],
           lambda s: P(s).__setitem__("issuedAt", "2026-06-23T16:08:07z"))
    mutate("bad-issuedat-lowercase-t", ["AEE-ISSUEDAT-PROFILE"],
           lambda s: P(s).__setitem__("issuedAt", "2026-06-23t16:08:07Z"))
    mutate("bad-issuedat-nonzero-offset", ["AEE-ISSUEDAT-PROFILE"],
           lambda s: P(s).__setitem__("issuedAt", "2026-06-23T21:08:07+05:00"))
    mutate("bad-issuedat-feb-30", ["AEE-ISSUEDAT-PROFILE"],
           lambda s: P(s).__setitem__("issuedAt", "2026-02-30T16:08:07Z"))
    mutate("bad-issuedat-missing", ["AEE-ISSUEDAT-PROFILE"], lambda s: P(s).pop("issuedAt"))

    # --- vocabulary
    mutate("bad-vocab-unsorted", ["AEE-VOCABULARY-SHAPE"],
           lambda s: ENV(s)["observationVocabulary"].__setitem__("labels", ["no_egress", "egress_captured"]))
    mutate("bad-vocab-duplicate", ["AEE-VOCABULARY-SHAPE"],
           lambda s: ENV(s)["observationVocabulary"].__setitem__("labels", ["egress_captured", "egress_captured", "no_egress"]))
    mutate("bad-vocab-supplementary", ["AEE-VOCABULARY-SHAPE"],
           lambda s: ENV(s)["observationVocabulary"].__setitem__("labels", ["egress_captured", "no_egress", "\U0001F600"]))
    mutate("bad-vocab-caught-not-subset", ["AEE-VOCABULARY-SHAPE"],
           lambda s: ENV(s)["observationVocabulary"].__setitem__("caught", ["egress_captured", "zzz"]))

    def vocab_digest_wrong(s):
        ENV(s)["observationVocabulary"]["digest"]["sha256"] = h("wrong")
    mutate("bad-vocab-digest", ["AEE-VOCABULARY-DIGEST-MISMATCH"], vocab_digest_wrong)

    def corpus_digest_wrong(s):
        st, _ = finalize(s)
        st["predicate"]["observationEnvironment"]["corpus"]["manifest"]["expectedPayloads"]["CO-EXFIL-1"] = [COMMIT_OTHER]
        return st
    mutate("bad-corpus-digest-edited-manifest", ["AEE-CORPUS-DIGEST-MISMATCH"], corpus_digest_wrong)

    # --- manifest
    def manifest_empty(s):
        m = ENV(s)["corpus"]["manifest"]
        m["classes"] = {"CO": []}
        m.pop("expectedPayloads")
        P(s)["coverage"] = {"assessedClasses": ["CO"], "outOfScope": {}, "routedElsewhere": {}}
        P(s)["attackResults"] = []
        P(s)["result"] = "pass"
        s["records"] = []
        ENV(s).pop("runEntropy")
    mutate("bad-manifest-empty-class", ["AEE-MANIFEST-EMPTY"], manifest_empty)
    mutate("bad-manifest-attack-two-classes", ["AEE-MANIFEST-ATTACK-MULTICLASS"],
           lambda s: ENV(s)["corpus"]["manifest"]["classes"].__setitem__("FS", ["FS-WRITE-1", "CO-EXFIL-1"]))
    mutate("bad-expected-payloads-unknown-attack", ["AEE-EXPECTED-PAYLOADS-SHAPE"],
           lambda s: ENV(s)["corpus"]["manifest"]["expectedPayloads"].__setitem__("XX-1", [COMMIT_CO]))
    mutate("bad-expected-payloads-unsorted", ["AEE-EXPECTED-PAYLOADS-SHAPE"],
           lambda s: ENV(s)["corpus"]["manifest"]["expectedPayloads"].__setitem__(
               "CO-EXFIL-1", sorted([COMMIT_CO, COMMIT_OTHER], reverse=True)))
    mutate("bad-expected-payloads-empty-array", ["AEE-EXPECTED-PAYLOADS-SHAPE"],
           lambda s: ENV(s)["corpus"]["manifest"]["expectedPayloads"].__setitem__("CO-EXFIL-1", []))

    # --- coverage
    mutate("bad-coverage-class-twice", ["AEE-COVERAGE-PARTITION"],
           lambda s: P(s)["coverage"]["outOfScope"].__setitem__("FS", "gap"))
    mutate("bad-coverage-class-missing", ["AEE-COVERAGE-PARTITION"],
           lambda s: P(s)["coverage"].__setitem__("assessedClasses", ["CO"]))
    mutate("bad-coverage-integrity-row-missing", ["AEE-COVERAGE-INTEGRITY"],
           lambda s: P(s).__setitem__("attackResults", P(s)["attackResults"][:1]))

    # --- rows
    def dup_row(s):
        rows = P(s)["attackResults"]
        rows.append(copy.deepcopy(rows[1]))
    mutate("bad-duplicate-attackid", ["AEE-ROW-DUPLICATE-ATTACK"], dup_row)
    mutate("bad-actuallayer-missing", ["AEE-ROW-ACTUALLAYER-MISSING"],
           lambda s: P(s)["attackResults"][0].pop("actualLayer"))
    mutate("bad-clean-actuallayer-not-none", ["AEE-ROW-CLEAN-LAYER-NOT-NONE"],
           lambda s: P(s)["attackResults"][1].__setitem__("actualLayer", "policy.egress_sinkhole"))
    mutate("bad-retired-intercept-refs", ["AEE-RETIRED-SPELLING"],
           lambda s: P(s)["attackResults"][1].__setitem__("interceptRefs", [1]))

    def artifact_out_of_range(s):
        P(s)["attackResults"][1]["basis"] = "artifact"
        P(s)["attackResults"][1]["observationRefs"] = [1, 7]
    mutate("bad-artifact-row-ref-out-of-range", ["AEE-ROW-REF-OUT-OF-RANGE"], artifact_out_of_range)
    mutate("bad-substrate-no-runentropy", ["AEE-RUNENTROPY-MISSING"],
           lambda s: ENV(s).pop("runEntropy") and None)

    # --- records / batchRoot
    def root_wrong(s):
        st, _ = finalize(s)
        st["predicate"]["batchRoot"] = h("not the root")
        return st
    mutate("bad-batchroot-mismatch", ["AEE-BATCHROOT-MISMATCH"], root_wrong)

    def root_missing(s):
        st, _ = finalize(s)
        del st["predicate"]["batchRoot"]
        return st
    mutate("bad-batchroot-missing", ["AEE-BATCHROOT-MISSING"], root_missing)

    def dup_record(s):
        st, _ = finalize(s)
        recs = st["predicate"]["observationRecords"]
        recs.append(copy.deepcopy(recs[1]))
        recompute_root(st)
        return st
    mutate("bad-duplicate-record", ["AEE-RECORD-DUPLICATE"], dup_record)

    def empty_sigs(s):
        st, _ = finalize(s)
        st["predicate"]["observationRecords"][1]["signatures"] = []
        return st
    mutate("bad-record-empty-signatures", ["AEE-RECORD-NO-SIGNATURES"], empty_sigs)

    def bad_b64(s):
        st, _ = finalize(s)
        st["predicate"]["observationRecords"][1]["payload"] = "%%%not-base64%%%"
        return st
    mutate("bad-record-payload-not-base64", ["AEE-RECORD-PAYLOAD-ENCODING"], bad_b64)

    # --- seal existence and universal partner
    def caught_only_no_seal(s):
        P(s)["attackResults"] = P(s)["attackResults"][:1]
        P(s)["coverage"] = {"assessedClasses": ["CO"], "outOfScope": {"FS": "gap"}, "routedElsewhere": {}}
        s["records"] = s["records"][:2]
    mutate("bad-caught-only-no-seal", ["AEE-SEAL-MISSING"], caught_only_no_seal)

    def only_seal_moat_down(s):
        s["records"][2]["aeeStillArmed"] = False
    mutate("bad-only-seal-moat-down", ["AEE-SEAL-MISSING", "AEE-RECORD-KIND-CONSTRAINT"], only_seal_moat_down,
           primary="AEE-SEAL-MISSING")

    def second_seal_moat_down(s):
        bad = copy.deepcopy(s["records"][2])
        bad["aeeStillArmed"] = False
        s["records"].append(bad)
    mutate("bad-second-seal-moat-down-unreferenced", ["AEE-RECORD-KIND-CONSTRAINT"], second_seal_moat_down)

    def seal_drop_unbounded(s):
        s["records"][2]["aeeDropCount"] = 1
    mutate("bad-seal-drop-without-bound", ["AEE-SEAL-MISSING", "AEE-RECORD-KIND-CONSTRAINT"], seal_drop_unbounded)

    def seal_posture_changed(s):
        s["records"][2]["aeePostureDigest"] = h("other posture")
    mutate("bad-seal-posture-changed", ["AEE-SEAL-MISSING", "AEE-RECORD-KIND-CONSTRAINT"], seal_posture_changed)

    def unrecognized_aee(s):
        s["records"][0]["aeeVersion"] = "1"
    mutate("bad-interception-unrecognized-aee-member",
           ["AEE-RECORD-KIND-CONSTRAINT", "AEE-REF-NOT-WELLFORMED"], unrecognized_aee)

    # --- aeeObservedSet
    def observed_set_wrong(s):
        s["records"][2]["aeeObservedSet"] = h("some other set")
    mutate("bad-observed-set-mismatch", ["AEE-OBSERVED-SET-MISMATCH"], observed_set_wrong)

    def interception_deleted(s):
        # seal was computed over the interception; then the producer drops the record and the row
        st, _ = finalize(s)
        p = st["predicate"]
        p["observationRecords"] = p["observationRecords"][1:]
        p["attackResults"] = [p["attackResults"][1]]
        p["attackResults"][0]["observationRefs"] = [0, 1]
        p["coverage"] = {"assessedClasses": ["FS"], "outOfScope": {"CO": "gap"}, "routedElsewhere": {}}
        p["result"] = "degraded"
        recompute_root(st)
        return st
    mutate("bad-interception-deleted-seal-commits", ["AEE-OBSERVED-SET-MISMATCH"], interception_deleted)

    # --- aeeObservedAttacks / aeeAssessedAttacks
    mutate("bad-observed-attack-without-caught-row", ["AEE-OBSERVED-ATTACK-NO-CAUGHT-ROW"],
           lambda s: s["records"][2].__setitem__("aeeObservedAttacks", ["CO-EXFIL-1", "FS-WRITE-1"]))
    mutate("bad-observed-attacks-unsorted", ["AEE-RECORD-KIND-CONSTRAINT"],
           lambda s: s["records"][2].__setitem__("aeeObservedAttacks", ["FS-WRITE-1", "CO-EXFIL-1"]))
    mutate("bad-assessed-not-subset", ["AEE-ASSESSED-NOT-SUBSET"],
           lambda s: s["records"][1].__setitem__("aeeAssessedAttacks", ["CO-EXFIL-1"]))

    # --- interception membership rules
    def clean_cites_interception(s):
        P(s)["attackResults"][1]["observationRefs"] = [0, 1, 2]
    mutate("bad-clean-row-cites-interception", ["AEE-CLEAN-ROW-CITES-INTERCEPTION"], clean_cites_interception)

    def unresolved_interception(s):
        s["records"].append({"aeeKind": "interception", "aeeMethod": "intercepted", "aeeRunBinding": AUTO,
                             "aeePayloadCommitment": [COMMIT_OTHER]})
    mutate("bad-interception-unresolved", ["AEE-INTERCEPTION-UNRESOLVED"], unresolved_interception)

    # --- attribution
    def pinned_no_entry(s):
        ENV(s)["corpus"]["manifest"].pop("expectedPayloads")
    mutate("bad-pinned-without-expectation", ["AEE-PINNED-NO-EXPECTATION"], pinned_no_entry)

    def pinned_mismatch(s):
        s["records"][0]["aeePayloadCommitment"] = [COMMIT_OTHER]
    mutate("bad-pinned-commitment-mismatch", ["AEE-PINNED-COMMITMENT-MISMATCH"], pinned_mismatch)

    def pinned_artifact_no_interception(s):
        P(s)["attackResults"][0]["basis"] = "artifact"
        P(s)["attackResults"][0]["observationRefs"] = []
        s["records"] = s["records"][1:]
        s["records"][1]["aeeObservedAttacks"] = []
        P(s)["attackResults"][1]["observationRefs"] = [0, 1]
    mutate("bad-pinned-artifact-no-interception", ["AEE-PINNED-NO-INTERCEPTION"], pinned_artifact_no_interception)

    mutate("bad-no-entry-attribution-missing", ["AEE-ATTRIBUTION-MUST-BE-PAIRED"],
           lambda s: P(s)["attackResults"][1].pop("attribution"))
    mutate("bad-no-entry-attribution-unknown", ["AEE-ATTRIBUTION-MUST-BE-PAIRED"],
           lambda s: P(s)["attackResults"][1].__setitem__("attribution", "window"))

    # --- substrate row coverage
    def method_cap(s):
        s["records"].append({"aeeKind": "examination", "aeeMethod": "reconstructed", "aeeRunBinding": AUTO})
        P(s)["attackResults"][1]["observationRefs"] = [1, 2, 3]
    mutate("bad-method-cap", ["AEE-METHOD-CAP"], method_cap)

    def interception_reconstructed_cap(s):
        s["records"][0]["aeeMethod"] = "reconstructed"
    mutate("bad-method-cap-interception-reconstructed", ["AEE-METHOD-CAP"], interception_reconstructed_cap)

    mutate("bad-clean-row-only-seal", ["AEE-CLASS-MISMATCH"],
           lambda s: P(s)["attackResults"][1].__setitem__("observationRefs", [2]))
    mutate("bad-substrate-row-no-refs", ["AEE-SUBSTRATE-ROW-NO-REFS"],
           lambda s: P(s)["attackResults"][1].__setitem__("observationRefs", []))

    def reconstructed_without_examination(s):
        P(s)["attackResults"][1]["method"] = "reconstructed"
        P(s)["result"] = "fail"
    mutate("bad-reconstructed-row-no-examination", ["AEE-CLASS-MISMATCH"], reconstructed_without_examination)

    def foreign_binding(s):
        st, binding = finalize(s)
        s2 = copy.deepcopy(s)
        ENV(s2)["runEntropy"]["digest"]["sha256"] = h("run-entropy-2")
        st2, _ = finalize(s2, binding_override=binding)  # records signed for run 1, statement claims run 2
        return st2
    mutate("bad-run-binding-splice", ["AEE-RUN-BINDING-MISMATCH", "AEE-SEAL-MISSING"], foreign_binding)

    def posture_member_added(s):
        st, binding = finalize(s)
        s2 = copy.deepcopy(s)
        ENV(s2)["networkPosture"]["note"] = "edited after arming"
        st2, _ = finalize(s2, binding_override=binding)
        return st2
    mutate("bad-posture-object-edited-after-arming", ["AEE-RUN-BINDING-MISMATCH"], posture_member_added)

    def narrowed_caught(s):
        st, binding = finalize(s)
        s2 = copy.deepcopy(s)
        ENV(s2)["observationVocabulary"]["labels"] = ["egress_captured", "no_egress", "zz_other"]
        st2, _ = finalize(s2, binding_override=binding)
        return st2
    mutate("bad-vocabulary-changed-after-arming", ["AEE-RUN-BINDING-MISMATCH"], narrowed_caught)

    def noncanonical_payload(s):
        s["raw_payloads"][0] = b'{ "aeeKind":"interception","aeeMethod":"intercepted"}'
    mutate("bad-noncanonical-payload", ["AEE-REF-NOT-WELLFORMED"], noncanonical_payload)

    def noncanonical_bound(s):
        st, binding = finalize(s)
        p = dict(s["records"][0])
        p["aeeRunBinding"] = binding
        s["raw_payloads"][0] = json.dumps(p, sort_keys=False).encode()
    mutate("bad-noncanonical-bound-interception", ["AEE-RECORD-KIND-CONSTRAINT", "AEE-REF-NOT-WELLFORMED"],
           noncanonical_bound)

    mutate("bad-payloadtype-not-plus-json", ["AEE-REF-NOT-WELLFORMED"],
           lambda s: s["ptypes"].__setitem__(1, "application/octet-stream"))
    mutate("bad-armedat-after-issuedat", ["AEE-RECORD-KIND-CONSTRAINT"],
           lambda s: s["records"][1].__setitem__("armedAt", "2026-06-23T16:08:08Z"))
    mutate("bad-armedat-missing", ["AEE-RECORD-KIND-CONSTRAINT"], lambda s: s["records"][1].pop("armedAt"))
    mutate("bad-armedat-offset", ["AEE-RECORD-KIND-CONSTRAINT"],
           lambda s: s["records"][1].__setitem__("armedAt", "2026-06-23T19:00:00+03:00"))
    mutate("bad-arming-posture-mismatch", ["AEE-RECORD-KIND-CONSTRAINT"],
           lambda s: s["records"][1].__setitem__("aeePostureDigest", h("x")))
    mutate("bad-arming-binding-version-1", ["AEE-BINDING-VERSION-UNSUPPORTED"],
           lambda s: s["records"][1].__setitem__("aeeBindingVersion", "1"))
    mutate("bad-chain-scope-without-seq", ["AEE-RECORD-KIND-CONSTRAINT"],
           lambda s: s["records"][1].__setitem__("aeeChainScope", ["subject"]))
    mutate("bad-chain-seq1-with-prev", ["AEE-RECORD-KIND-CONSTRAINT"],
           lambda s: s["records"][1].update({"aeeRunSeq": 1, "aeePrevRunBinding": h("p"), "aeeChainScope": ["subject"]}))
    mutate("bad-chain-unknown-token", ["AEE-RECORD-KIND-CONSTRAINT"],
           lambda s: s["records"][1].update({"aeeRunSeq": 1, "aeeChainScope": ["tenant"]}))
    mutate("bad-examination-intercepted", ["AEE-RECORD-KIND-CONSTRAINT"],
           lambda s: s["records"].append({"aeeKind": "examination", "aeeMethod": "intercepted", "aeeRunBinding": AUTO}))

    def only_moat_drop(s):
        s["records"].append({"aeeKind": "moat-drop", "aeeMethod": "intercepted", "aeeRunBinding": AUTO})
        P(s)["attackResults"][0]["observationRefs"] = [0]
        P(s)["attackResults"][1]["observationRefs"] = [3]
    mutate("bad-clean-row-only-moat-drop", ["AEE-REF-NONCOVERING-KIND"], only_moat_drop)

    def only_unknown_kind(s):
        s["records"].append({"aeeKind": "hardware-quote", "aeeMethod": "intercepted", "aeeRunBinding": AUTO})
        P(s)["attackResults"][1]["observationRefs"] = [3]
    mutate("bad-clean-row-only-unknown-kind", ["AEE-REF-UNKNOWN-KIND"], only_unknown_kind)

    def substrate_fail_closed(s):
        P(s)["attackResults"][1]["method"] = "inferred"
    mutate("bad-substrate-row-method-fail-closed", ["AEE-SUBSTRATE-ROW-FAIL-CLOSED"], substrate_fail_closed)

    def supplementary_member_name(s):
        s["records"][2]["\U0001F600note"] = "x"
    mutate("bad-seal-supplementary-member-name", ["AEE-SEAL-MISSING", "AEE-RECORD-KIND-CONSTRAINT"],
           supplementary_member_name)

    # simpler: drop count equal to 2^53 written directly (observed set placeholder replaced at finalize)
    def unsafe_int_seal2(s):
        s["records"][2]["aeeObservedSet"] = h("placeholder")  # fixed so raw bytes are stable
        st, binding = finalize(s)
        p = dict(s["records"][2])
        p["aeeRunBinding"] = binding
        p["aeePostureDigest"] = ENV(s)["networkPosture"]["digest"]["sha256"]
        p["aeeDropCount"] = 0
        txt = V.jcs(p).decode().replace('"aeeDropCount":0', '"aeeDropCount":9007199254740992')
        s["raw_payloads"][2] = txt.encode()
    mutate("bad-seal-unsafe-integer", ["AEE-SEAL-MISSING", "AEE-RECORD-KIND-CONSTRAINT"], unsafe_int_seal2)

    def seal_dup_member(s):
        s["records"][2]["aeeObservedSet"] = h("placeholder")
        st, binding = finalize(s)
        p = dict(s["records"][2])
        p["aeeRunBinding"] = binding
        p["aeePostureDigest"] = ENV(s)["networkPosture"]["digest"]["sha256"]
        txt = V.jcs(p).decode().replace('"aeeStillArmed":true', '"aeeStillArmed":false,"aeeStillArmed":true')
        s["raw_payloads"][2] = txt.encode()
    mutate("bad-seal-duplicate-member-in-payload", ["AEE-SEAL-MISSING"], seal_dup_member)


def main():
    os.makedirs(CASES, exist_ok=True)
    os.makedirs(KEYS, exist_ok=True)
    for f in os.listdir(CASES):
        os.remove(os.path.join(CASES, f))
    with open(os.path.join(KEYS, "good.json"), "w") as f:
        json.dump({"substrateObservationKeys": [{"keyid": "substrate-test", "publicKeyHex": PUB.hex()}]}, f)
    with open(os.path.join(KEYS, "wrong.json"), "w") as f:
        json.dump({"substrateObservationKeys": [{"keyid": "substrate-test", "publicKeyHex": WRONG_PUB.hex()}]}, f)
    positives()
    negatives()
    exp = {}
    for name, data, e in CASE_LIST:
        if name in exp:
            raise SystemExit("duplicate case name " + name)
        with open(os.path.join(CASES, name + ".json"), "wb") as f:
            f.write(data)
        exp[name] = e
    with open(os.path.join(HERE, "expectations.json"), "w") as f:
        json.dump(exp, f, indent=1, sort_keys=True)
    print("wrote %d cases" % len(exp))


if __name__ == "__main__":
    main()
