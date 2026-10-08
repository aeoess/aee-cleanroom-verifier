#!/usr/bin/env python3
"""Checks of the verifier's primitives against known values that do not come
from the verifier itself."""

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import aee_verify as V  # noqa: E402

fails = []


def check(name, got, want):
    if got != want:
        fails.append("%s: got %r want %r" % (name, got, want))


# ECMAScript Number serialization (RFC 8785 section 3.2.2.3 / ECMA-262 Number::toString)
for f, s in [(0.0, "0"), (-0.0, "0"), (1.0, "1"), (-1.5, "-1.5"), (0.1, "0.1"),
             (1e-7, "1e-7"), (0.000001, "0.000001"), (1e21, "1e+21"), (1e20, "100000000000000000000"),
             (123456789012345680000.0, "123456789012345680000"), (5e-324, "5e-324"),
             (1.7976931348623157e308, "1.7976931348623157e+308"), (0.002, "0.002"),
             (333333333.3333333, "333333333.3333333"), (1.5e-10, "1.5e-10")]:
    check("es_number(%r)" % f, V._es_number(f), s)

# JCS: UTF-16 code-unit member ordering (RFC 8785 section 3.2.3 example set)
obj = {"€": 1, "\r": 2, "דּ": 3, "1": 4, "\U0001F600": 5, "\u0080": 6, "ö": 7}
order = [k for k in sorted(obj, key=V.utf16_key)]
check("utf16 order", order, ["\r", "1", "\u0080", "ö", "€", "\U0001F600", "דּ"])
check("jcs escapes", V.jcs({"a": "\u0001\n\"\\/\u007f"}), b'{"a":"\\u0001\\n\\"\\\\/\x7f"}')
check("jcs literals", V.jcs([None, True, False, 1, 1.0, -0.0]), b"[null,true,false,1,1,0]")
try:
    V.jcs({"x": 2 ** 53})
    fails.append("jcs accepted 2^53")
except V.CanonError:
    pass
check("jcs 2^53-1", V.jcs([2 ** 53 - 1]), b"[9007199254740991]")

# DSSE PAE (DSSE protocol.md definition)
check("pae", V.pae("http://example.com/HelloWorld", b"hello world"),
      b"DSSEv1 29 http://example.com/HelloWorld 11 hello world")

# RFC 6962 tree shape: 3 leaves split 2+1, no duplication
H = lambda b: hashlib.sha256(b).digest()
l = [H(b"\x00" + bytes([i])) for i in range(3)]
check("mth3", V.merkle_root(l), H(b"\x01" + H(b"\x01" + l[0] + l[1]) + l[2]))
l5 = [H(b"\x00" + bytes([i])) for i in range(5)]
left = H(b"\x01" + H(b"\x01" + l5[0] + l5[1]) + H(b"\x01" + l5[2] + l5[3]))
check("mth5", V.merkle_root(l5), H(b"\x01" + left + l5[4]))
check("mth1", V.merkle_root(l[:1]), l[0])

# Ed25519: RFC 8032 section 7.1 TEST 1 (from memory) and cross-check with `cryptography` if present
sk = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
pk = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
sig = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555"
                    "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
check("ed25519 public", V.ed25519_public(sk), pk)
check("ed25519 sign", V.ed25519_sign(sk, b""), sig)
check("ed25519 verify", V.ed25519_verify(pk, b"", sig), True)
check("ed25519 verify tampered", V.ed25519_verify(pk, b"x", sig), False)
bad_s = sig[:32] + (int.from_bytes(sig[32:], "little") + V._Q).to_bytes(32, "little")
check("ed25519 rejects s>=L", V.ed25519_verify(pk, b"", bad_s), False)
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    for i in range(20):
        seed = hashlib.sha256(b"x%d" % i).digest()
        msg = hashlib.sha512(b"m%d" % i).digest()[: i * 3]
        k = Ed25519PrivateKey.from_private_bytes(seed)
        ref_sig = k.sign(msg)
        from cryptography.hazmat.primitives import serialization
        ref_pk = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        check("xcheck pk %d" % i, V.ed25519_public(seed), ref_pk)
        check("xcheck sig %d" % i, V.ed25519_sign(seed, msg), ref_sig)
        check("xcheck verify %d" % i, V.ed25519_verify(ref_pk, msg, ref_sig), True)
    print("ed25519 cross-checked against cryptography package")
except ImportError:
    print("cryptography not installed; ed25519 cross-check skipped")

# base64: standard and URL-safe accepted (DSSE)
check("b64 std", V.b64decode_dsse("+/8="), b"\xfb\xff")
check("b64 url", V.b64decode_dsse("-_8"), b"\xfb\xff")
check("b64 mixed", V.b64decode_dsse("+_8="), None)

# timestamp profile
check("ts Z", V.parse_timestamp("2026-06-23T16:08:07Z") is not None, True)
check("ts z", V.parse_timestamp("2026-06-23T16:08:07z"), None)
check("ts +05", V.parse_timestamp("2026-06-23T16:08:07+05:00"), None)
check("ts leap", V.parse_timestamp("2016-12-31T23:59:60Z") is not None, True)
check("ts 2024-02-29", V.parse_timestamp("2024-02-29T00:00:00Z") is not None, True)
check("ts 2100-02-29", V.parse_timestamp("2100-02-29T00:00:00Z"), None)

# strict parser corner cases
for bad, code in [(b'{"a":1,"a":2}', "AEE-JSON-DUPLICATE-MEMBER"), (b'{"a":"\\uD834x"}', "AEE-JSON-UNPAIRED-SURROGATE"),
                  (b'{"a":NaN}', "AEE-JSON-SYNTAX"), (b'{"a":01}', "AEE-JSON-SYNTAX"),
                  (b'{"a":"\\uFFFE"}', "AEE-JSON-NONCHARACTER"), (b'{"a":"\\x"}', "AEE-JSON-BAD-ESCAPE")]:
    try:
        V.parse_strict_bytes(bad)
        fails.append("parser accepted %r" % bad)
    except V.JsonError as e:
        check("parser code %r" % bad, e.code, code)
check("pair", V.parse_strict_bytes(b'"\\uD83D\\uDE00"'), "\U0001F600")
d128 = b"[" * 128 + b"]" * 128
check("depth 128 ok", isinstance(V.parse_strict_bytes(d128), list), True)
try:
    V.parse_strict_bytes(b"[" * 129 + b"]" * 129)
    fails.append("depth 129 accepted")
except V.JsonError as e:
    check("depth 129", e.code, "AEE-JSON-DEPTH")

for f in fails:
    print("FAIL", f)
print("primitives: %d failures" % len(fails))
sys.exit(1 if fails else 0)
