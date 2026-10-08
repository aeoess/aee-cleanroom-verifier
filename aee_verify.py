#!/usr/bin/env python3
"""Clean-room verifier for the Adversarial Execution Evidence (AEE) in-toto
predicate, v0.7 (spec file pinned at agent-evidence-vectors v0.12.1,
sha256 759d2383e5da36fa509dc335e6159a20b87641b25ebbadcf1676c55d75ffd8b0).

Usage:  python3 aee_verify.py <statement-file>      ("-" reads stdin)

Consumer key policy (optional): environment variable AEE_SUBSTRATE_KEYS names
a JSON file {"substrateObservationKeys": [{"keyid": ..., "publicKeyHex": ...}]}.

Output: diagnostics on stderr; the LAST line of stdout is one JSON object
  {"verdict": "accept"|"reject", "codes": [...], "primaryCode": ...,
   "result": <recomputed result or null>, "tiers": [...]}
Exit status: 0 accept (valid), 1 reject (invalid/malformed), 2 usage error.

Python 3 standard library only. Section references (§) point at headings of
the pinned spec file.
"""

import base64
import hashlib
import os
import re
import sys
from decimal import Decimal

PREDICATE_TYPE = "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
BINDING_VERSION = "2"
MAX_DEPTH = 128
SAFE_INT = 2 ** 53

RESULTS = ("fail", "degraded", "pass_indirect", "pass")  # ascending order
BASIS = ("substrate", "artifact")
METHOD = ("intercepted", "reconstructed")
ATTRIBUTION = ("pinned", "paired")
POSTURES = ("allowlist", "no_network", "sinkhole", "unsafe_bypass_egress")
COVERING_KINDS = ("interception", "arming", "sealed", "examination")
NONCOVERING_REGISTERED = ("moat-drop", "uncommitted-observation")
CHAIN_SCOPE_TOKENS = ("subject", "corpus", "networkPosture")
# Every reserved aee* payload member this document defines (§observationRecords).
KNOWN_AEE_MEMBERS = frozenset([
    "aeeRunBinding", "aeeKind", "aeeMethod", "aeePayloadCommitment",
    "aeePostureDigest", "aeeAssessedAttacks", "aeeBindingVersion",
    "aeeRunSeq", "aeePrevRunBinding", "aeeChainScope",
    "aeeStillArmed", "aeeDropCount", "aeeDropBound", "aeeObservedSet",
    "aeeObservedAttacks",
])

HEX64 = re.compile(r"[0-9a-f]{64}\Z")
TS_RE = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|\+00:00|-00:00)\Z")
NUM_RE = re.compile(r"-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?")


# ---------------------------------------------------------------------------
# Strict I-JSON parser (§Prerequisites)
# ---------------------------------------------------------------------------

class JsonError(Exception):
    def __init__(self, code, msg):
        Exception.__init__(self, msg)
        self.code = code
        self.msg = msg


_HEXCH = frozenset("0123456789abcdefABCDEF")
_SIMPLE_ESC = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f",
               "n": "\n", "r": "\r", "t": "\t"}


def _is_nonchar(cp):
    return 0xFDD0 <= cp <= 0xFDEF or (cp & 0xFFFE) == 0xFFFE


class _Parser(object):
    def __init__(self, text):
        self.s = text
        self.i = 0
        self.n = len(text)

    def err(self, code, msg):
        raise JsonError(code, "%s at offset %d" % (msg, self.i))

    def ws(self):
        s, n = self.s, self.n
        while self.i < n and s[self.i] in " \t\n\r":
            self.i += 1

    def parse(self):
        self.ws()
        v = self.value(0)
        self.ws()
        if self.i != self.n:
            self.err("AEE-JSON-SYNTAX", "trailing content")
        return v

    def value(self, depth):
        self.ws()
        if self.i >= self.n:
            self.err("AEE-JSON-SYNTAX", "unexpected end of input")
        c = self.s[self.i]
        if c == "{":
            return self.obj(depth + 1)
        if c == "[":
            return self.arr(depth + 1)
        if c == '"':
            return self.string()
        if self.s.startswith("true", self.i):
            self.i += 4
            return True
        if self.s.startswith("false", self.i):
            self.i += 5
            return False
        if self.s.startswith("null", self.i):
            self.i += 4
            return None
        m = NUM_RE.match(self.s, self.i)
        if m and m.end() > self.i:
            tok = m.group(0)
            self.i = m.end()
            if m.group(1) is None and m.group(2) is None:
                return int(tok)
            return float(tok)  # may be inf on overflow; JCS rejects it
        self.err("AEE-JSON-SYNTAX", "unexpected character %r" % c)

    def obj(self, depth):
        if depth > MAX_DEPTH:
            self.err("AEE-JSON-DEPTH", "nesting depth exceeds %d" % MAX_DEPTH)
        self.i += 1
        d = {}
        self.ws()
        if self.i < self.n and self.s[self.i] == "}":
            self.i += 1
            return d
        while True:
            self.ws()
            if self.i >= self.n or self.s[self.i] != '"':
                self.err("AEE-JSON-SYNTAX", "expected member name")
            k = self.string()
            self.ws()
            if self.i >= self.n or self.s[self.i] != ":":
                self.err("AEE-JSON-SYNTAX", "expected ':'")
            self.i += 1
            v = self.value(depth)
            if k in d:
                self.err("AEE-JSON-DUPLICATE-MEMBER", "duplicate member %r" % k)
            d[k] = v
            self.ws()
            if self.i < self.n and self.s[self.i] == ",":
                self.i += 1
                continue
            if self.i < self.n and self.s[self.i] == "}":
                self.i += 1
                return d
            self.err("AEE-JSON-SYNTAX", "expected ',' or '}'")

    def arr(self, depth):
        if depth > MAX_DEPTH:
            self.err("AEE-JSON-DEPTH", "nesting depth exceeds %d" % MAX_DEPTH)
        self.i += 1
        out = []
        self.ws()
        if self.i < self.n and self.s[self.i] == "]":
            self.i += 1
            return out
        while True:
            out.append(self.value(depth))
            self.ws()
            if self.i < self.n and self.s[self.i] == ",":
                self.i += 1
                continue
            if self.i < self.n and self.s[self.i] == "]":
                self.i += 1
                return out
            self.err("AEE-JSON-SYNTAX", "expected ',' or ']'")

    def _hex4(self, j):
        h = self.s[j:j + 4]
        if len(h) != 4 or any(ch not in _HEXCH for ch in h):
            self.i = j
            self.err("AEE-JSON-BAD-ESCAPE", "\\u escape needs exactly four hex digits")
        return int(h, 16)

    def string(self):
        s, n = self.s, self.n
        i = self.i + 1
        out = []
        while True:
            if i >= n:
                self.i = i
                self.err("AEE-JSON-SYNTAX", "unterminated string")
            c = s[i]
            if c == '"':
                self.i = i + 1
                return "".join(out)
            if c == "\\":
                if i + 1 >= n:
                    self.i = i
                    self.err("AEE-JSON-SYNTAX", "unterminated escape")
                e = s[i + 1]
                if e in _SIMPLE_ESC:
                    out.append(_SIMPLE_ESC[e])
                    i += 2
                    continue
                if e != "u":
                    self.i = i
                    self.err("AEE-JSON-BAD-ESCAPE", "invalid escape \\%s" % e)
                cp = self._hex4(i + 2)
                i += 6
                if 0xD800 <= cp <= 0xDBFF:
                    if s.startswith("\\u", i):
                        lo = self._hex4(i + 2)
                        if 0xDC00 <= lo <= 0xDFFF:
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                            i += 6
                        else:
                            self.i = i
                            self.err("AEE-JSON-UNPAIRED-SURROGATE", "high surrogate not followed by low surrogate")
                    else:
                        self.i = i
                        self.err("AEE-JSON-UNPAIRED-SURROGATE", "unpaired high surrogate escape")
                elif 0xDC00 <= cp <= 0xDFFF:
                    self.i = i
                    self.err("AEE-JSON-UNPAIRED-SURROGATE", "unpaired low surrogate escape")
                if _is_nonchar(cp):
                    self.i = i
                    self.err("AEE-JSON-NONCHARACTER", "noncharacter U+%04X" % cp)
                out.append(chr(cp))
                continue
            o = ord(c)
            if o < 0x20:
                self.i = i
                self.err("AEE-JSON-CONTROL-CHAR", "raw control character in string")
            if _is_nonchar(o):
                self.i = i
                self.err("AEE-JSON-NONCHARACTER", "noncharacter U+%04X" % o)
            out.append(c)
            i += 1


def parse_strict_bytes(raw):
    """Raw-byte UTF-8 check first (§Prerequisites: applied before any decoded
    string is read), then strict parse. Raises JsonError."""
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as e:
        raise JsonError("AEE-JSON-INVALID-UTF8", "ill-formed UTF-8: %s" % e)
    return _Parser(text).parse()


# ---------------------------------------------------------------------------
# RFC 8785 JCS with the I-JSON safe-integer profile
# ---------------------------------------------------------------------------

class CanonError(Exception):
    pass


def _es_number(f):
    """ECMAScript Number::toString for a finite double (RFC 8785 §3.2.2.3)."""
    if f == 0:
        return "0"
    sign = "-" if f < 0 else ""
    r = repr(abs(f))  # shortest round-trip digits
    if "e" in r:
        mant, exp = r.split("e")
        exp = int(exp)
    else:
        mant, exp = r, 0
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    digits = ip + fp
    n = len(ip) + exp
    stripped = digits.lstrip("0")
    n -= len(digits) - len(stripped)
    digits = stripped.rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        es = ("+" if e >= 0 else "-") + str(abs(e))
        out = digits + "e" + es if k == 1 else digits[0] + "." + digits[1:] + "e" + es
    return sign + out


def _jcs_str(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def utf16_key(s):
    return s.encode("utf-16-be", "surrogatepass")


def _jcs(v, parts):
    if v is None:
        parts.append("null")
    elif v is True:
        parts.append("true")
    elif v is False:
        parts.append("false")
    elif isinstance(v, int):
        if abs(v) >= SAFE_INT:
            raise CanonError("integer magnitude at or above 2^53")
        parts.append(str(v))
    elif isinstance(v, float):
        if v != v or v in (float("inf"), float("-inf")):
            raise CanonError("number not representable as a finite double")
        if v.is_integer() and abs(v) >= SAFE_INT:
            raise CanonError("integer magnitude at or above 2^53")
        parts.append(_es_number(v))
    elif isinstance(v, str):
        parts.append(_jcs_str(v))
    elif isinstance(v, list):
        parts.append("[")
        for idx, x in enumerate(v):
            if idx:
                parts.append(",")
            _jcs(x, parts)
        parts.append("]")
    elif isinstance(v, dict):
        parts.append("{")
        for idx, k in enumerate(sorted(v.keys(), key=utf16_key)):
            if idx:
                parts.append(",")
            parts.append(_jcs_str(k))
            parts.append(":")
            _jcs(v[k], parts)
        parts.append("}")
    else:
        raise CanonError("unsupported type")


def jcs(v):
    parts = []
    _jcs(v, parts)
    return "".join(parts).encode("utf-8")


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


# ---------------------------------------------------------------------------
# DSSE, RFC 6962, base64
# ---------------------------------------------------------------------------

def pae(payload_type, body):
    t = payload_type.encode("utf-8")
    return b"DSSEv1 " + str(len(t)).encode() + b" " + t + b" " + str(len(body)).encode() + b" " + body


def leaf_hash(pae_bytes):
    return hashlib.sha256(b"\x00" + pae_bytes).digest()


def merkle_root(leaves):
    """RFC 6962 MTH over already-hashed leaves (recursive split, no padding)."""
    n = len(leaves)
    if n == 1:
        return leaves[0]
    k = 1
    while k * 2 < n:
        k *= 2
    return hashlib.sha256(b"\x01" + merkle_root(leaves[:k]) + merkle_root(leaves[k:])).digest()


_B64_STD = re.compile(r"[A-Za-z0-9+/]*={0,2}\Z")
_B64_URL = re.compile(r"[A-Za-z0-9_-]*={0,2}\Z")


def b64decode_dsse(s):
    """DSSE: standard or URL-safe base64 (verifiers MUST accept either)."""
    if not isinstance(s, str):
        return None
    try:
        if _B64_STD.match(s) and len(s) % 4 == 0:
            return base64.b64decode(s, validate=True)
        if _B64_URL.match(s):
            body = s.rstrip("=")
            if len(body) % 4 == 1:
                return None
            if "=" in s and len(s) % 4 != 0:
                return None
            body = body + "=" * (-len(body) % 4)
            return base64.b64decode(body.replace("-", "+").replace("_", "/"), validate=True)
    except (ValueError, base64.binascii.Error):
        return None
    return None


# ---------------------------------------------------------------------------
# Ed25519 verification (RFC 8032 §5.1.7), pure Python, for the evidence tier
# ---------------------------------------------------------------------------

_P = 2 ** 255 - 19
_Q = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _pt_add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    A = (y1 - x1) * (y2 - x2) % _P
    B = (y1 + x1) * (y2 + x2) % _P
    C = 2 * t1 * t2 * _D % _P
    Dd = 2 * z1 * z2 % _P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _pt_mul(s, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _pt_add(q, p)
        p = _pt_add(p, p)
        s >>= 1
    return q


def _pt_equal(a, b):
    x1, y1, z1, _ = a
    x2, y2, z2, _ = b
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _pt_compress(p):
    x, y, z, _ = p
    zi = pow(z, _P - 2, _P)
    x, y = x * zi % _P, y * zi % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _pt_decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def ed25519_verify(public, msg, sig):
    if len(public) != 32 or len(sig) != 64:
        return False
    A = _pt_decompress(public)
    if A is None:
        return False
    R = _pt_decompress(sig[:32])
    if R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _Q:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + public + msg).digest(), "little") % _Q
    return _pt_equal(_pt_mul(s, _G), _pt_add(R, _pt_mul(h, A)))


def _sha512_int(b):
    return int.from_bytes(hashlib.sha512(b).digest(), "little")


def ed25519_public(secret):
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return _pt_compress(_pt_mul(a, _G))


def ed25519_sign(secret, msg):
    """Used only by the test generator."""
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    A = _pt_compress(_pt_mul(a, _G))
    r = _sha512_int(h[32:] + msg) % _Q
    R = _pt_compress(_pt_mul(r, _G))
    k = _sha512_int(R + A + msg) % _Q
    s = (r + k * a) % _Q
    return R + int.to_bytes(s, 32, "little")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool) or (
        isinstance(v, float) and v.is_integer())


def is_strict_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def is_hex64(v):
    return isinstance(v, str) and HEX64.match(v) is not None


def sorted_unique_utf16(arr):
    """Ascending by UTF-16 code unit, duplicate-free (strictly increasing)."""
    keys = [utf16_key(x) for x in arr]
    return all(keys[i] < keys[i + 1] for i in range(len(keys) - 1))


def bmp_only(s):
    return all(ord(c) <= 0xFFFF for c in s)


def member_names_bmp(v):
    if isinstance(v, dict):
        for k, x in v.items():
            if not bmp_only(k) or not member_names_bmp(x):
                return False
    elif isinstance(v, list):
        return all(member_names_bmp(x) for x in v)
    return True


def parse_timestamp(v):
    """§issuedAt profile: RFC 3339, uppercase T, zone Z / +00:00 / -00:00.
    Returns a comparable key or None."""
    if not isinstance(v, str):
        return None
    m = TS_RE.match(v)
    if not m:
        return None
    y, mo, d, hh, mi, ss = (int(m.group(i)) for i in range(1, 7))
    if not 1 <= mo <= 12:
        return None
    leap = (y % 4 == 0 and y % 100 != 0) or y % 400 == 0
    mdays = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1]
    if not 1 <= d <= mdays or hh > 23 or mi > 59 or ss > 60:
        return None
    if ss == 60 and not (hh == 23 and mi == 59):
        return None  # leap second only at the end of a UTC day
    frac = Decimal("0" + m.group(7)) if m.group(7) else Decimal(0)
    return (y, mo, d, hh, mi, ss, frac)


def sha256_of(obj):
    """The `digest.sha256` value of a descriptor-shaped object, or None."""
    if not isinstance(obj, dict):
        return None
    d = obj.get("digest")
    if not isinstance(d, dict):
        return None
    return d.get("sha256")


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------

class Stop(Exception):
    pass


class Record(object):
    __slots__ = ("idx", "ptype", "body", "pae", "leaf", "obj", "kind",
                 "general_ok", "general_problems", "bound", "kind_ok",
                 "kind_problems", "version_bad", "sigs")


class Verifier(object):
    def __init__(self, raw, keys=None):
        self.raw = raw
        self.keys = keys  # None (no policy) or list of 32-byte public keys
        self.codes = []
        self.notes = []
        self.result = None
        self.tiers = []

    # -- reporting --------------------------------------------------------
    def fail(self, code, detail):
        if code not in self.codes:
            self.codes.append(code)
        self.notes.append("%s: %s" % (code, detail))

    def stop(self, code, detail):
        self.fail(code, detail)
        raise Stop()

    # -- entry ------------------------------------------------------------
    def run(self):
        try:
            self._run()
        except Stop:
            pass
        return not self.codes

    def _run(self):
        try:
            top = parse_strict_bytes(self.raw)
        except JsonError as e:
            self.stop(e.code, e.msg)
        if not isinstance(top, dict):
            self.stop("AEE-STATEMENT-SHAPE", "statement is not a JSON object")
        if "_type" not in top and "payloadType" in top and "payload" in top:
            top = self._unwrap_envelope(top)
        self.st = top
        self.check_statement()

    def _unwrap_envelope(self, env):
        # Extension: a DSSE-enveloped Statement is unwrapped; the byte rules of
        # §Prerequisites are re-applied to the inner payload bytes.
        if env.get("payloadType") != "application/vnd.in-toto+json":
            self.stop("AEE-ENVELOPE-SHAPE", "enclosing envelope payloadType is not application/vnd.in-toto+json")
        sigs = env.get("signatures")
        if not isinstance(sigs, list):
            self.stop("AEE-ENVELOPE-SHAPE", "enclosing envelope has no signatures array")
        body = b64decode_dsse(env.get("payload"))
        if body is None:
            self.stop("AEE-ENVELOPE-SHAPE", "enclosing envelope payload is not base64")
        try:
            inner = parse_strict_bytes(body)
        except JsonError as e:
            self.stop(e.code, "in enveloped statement: " + e.msg)
        if not isinstance(inner, dict):
            self.stop("AEE-STATEMENT-SHAPE", "enveloped statement is not a JSON object")
        self.notes.append("info: unwrapped DSSE envelope; envelope signature not evaluated (no envelope key policy)")
        return inner

    # -- step 1: statement well-formedness ----------------------------------
    def check_statement(self):
        st = self.st
        if st.get("_type") != STATEMENT_TYPE:
            self.fail("AEE-STATEMENT-TYPE", "_type is not %s" % STATEMENT_TYPE)
        if st.get("predicateType") != PREDICATE_TYPE:
            self.stop("AEE-PREDICATE-TYPE", "predicateType is not %s" % PREDICATE_TYPE)
        subj = st.get("subject")
        if not isinstance(subj, list) or len(subj) != 1:
            self.fail("AEE-SUBJECT-COUNT", "subject must contain exactly one entry")
            subj0 = subj[0] if isinstance(subj, list) and subj else None
        else:
            subj0 = subj[0]
        if not isinstance(subj0, dict) or not is_hex64(sha256_of(subj0)):
            self.fail("AEE-DIGEST-FORMAT", "subject[0].digest.sha256 missing or not lowercase 64-hex")
        pred = st.get("predicate")
        if not isinstance(pred, dict):
            self.stop("AEE-PREDICATE-SHAPE", "predicate missing or not an object")
        self.pred = pred
        self.subject_sha = sha256_of(subj0) if isinstance(subj0, dict) else None

        for old in ("does_not_assert", "interceptRecords"):
            if old in pred:
                self.fail("AEE-RETIRED-SPELLING", "retired member %r is rejected (no alias)" % old)

        res = pred.get("result")
        if not isinstance(res, str) or res not in RESULTS:
            self.fail("AEE-RESULT-VALUE", "result missing or not one of %s" % (RESULTS,))
        self.issued = parse_timestamp(pred.get("issuedAt"))
        if self.issued is None:
            self.fail("AEE-ISSUEDAT-PROFILE", "issuedAt absent, not RFC 3339, or outside the timestamp profile")
        if "doesNotAssert" in pred:
            dna = pred["doesNotAssert"]
            if not isinstance(dna, list) or not all(isinstance(x, str) for x in dna):
                self.fail("AEE-PREDICATE-SHAPE", "doesNotAssert must be an array of strings")

        rows = pred.get("attackResults")
        if not isinstance(rows, list):
            self.stop("AEE-PREDICATE-SHAPE", "attackResults missing or not an array")
        if not all(isinstance(r, dict) for r in rows):
            self.stop("AEE-ROW-SHAPE", "attackResults entries must be objects")
        self.rows = rows
        self.has_substrate = any(r.get("basis") == "substrate" for r in rows)

        self.check_environment()
        self.check_coverage()
        self.check_records_structure()
        self.check_rows_structure()
        self.derive_binding()
        self.analyse_records()
        self.check_coverage_validity()
        self.recompute_result()
        self.check_digest_integrity()
        if not self.codes:
            self.derive_tiers()

    def check_environment(self):
        env = self.pred.get("observationEnvironment")
        if not isinstance(env, dict):
            self.stop("AEE-ENVIRONMENT-SHAPE", "observationEnvironment missing or not an object")
        for name in ("substrate", "corpus", "catchPolicy", "networkPosture", "observationVocabulary"):
            if not isinstance(env.get(name), dict):
                self.stop("AEE-ENVIRONMENT-SHAPE", "observationEnvironment.%s missing or not an object" % name)
        for name in ("substrate", "corpus", "catchPolicy", "networkPosture"):
            if not is_hex64(sha256_of(env[name])):
                self.fail("AEE-DIGEST-FORMAT", "%s.digest.sha256 missing or not lowercase 64-hex" % name)
        self.env = env

        # runEntropy (§Run binding, §observationEnvironment)
        if "runEntropy" in env:
            if not is_hex64(sha256_of(env["runEntropy"])):
                self.fail("AEE-DIGEST-FORMAT", "runEntropy.digest.sha256 missing or not lowercase 64-hex")
        elif self.has_substrate:
            self.fail("AEE-RUNENTROPY-MISSING", "runEntropy is required when any row carries basis: substrate")

        # corpus manifest
        corpus = env["corpus"]
        manifest = corpus.get("manifest")
        if not isinstance(manifest, dict):
            self.stop("AEE-MANIFEST-SHAPE", "corpus.manifest missing or not an object")
        classes = manifest.get("classes")
        if not isinstance(classes, dict):
            self.stop("AEE-MANIFEST-SHAPE", "corpus.manifest.classes missing or not an object")
        self.classes = {}
        owner = {}
        for cls, ids in classes.items():
            if not isinstance(ids, list) or not all(isinstance(x, str) for x in ids):
                self.stop("AEE-MANIFEST-SHAPE", "manifest class %r must map to an array of strings" % cls)
            self.classes[cls] = ids
            for a in ids:
                if a in owner and owner[a] != cls:
                    self.fail("AEE-MANIFEST-ATTACK-MULTICLASS", "attackId %r appears under more than one class" % a)
                owner.setdefault(a, cls)
        self.manifest_ids = set(owner)
        if not self.manifest_ids:
            self.fail("AEE-MANIFEST-EMPTY", "manifest declares zero attack identifiers")
        self.expected = {}
        if "expectedPayloads" in manifest:
            ep = manifest["expectedPayloads"]
            if not isinstance(ep, dict):
                self.fail("AEE-EXPECTED-PAYLOADS-SHAPE", "expectedPayloads must be an object")
            else:
                for a, vals in ep.items():
                    ok = True
                    if a not in self.manifest_ids:
                        self.fail("AEE-EXPECTED-PAYLOADS-SHAPE", "expectedPayloads key %r is not a declared attackId" % a)
                        ok = False
                    if (not isinstance(vals, list) or not vals
                            or not all(is_hex64(x) for x in vals)
                            or not sorted_unique_utf16(vals)):
                        self.fail("AEE-EXPECTED-PAYLOADS-SHAPE",
                                  "expectedPayloads[%r] must be a non-empty, sorted, duplicate-free array of lowercase 64-hex" % a)
                        ok = False
                    if ok:
                        self.expected[a] = set(vals)
        self.manifest = manifest

        # networkPosture
        np = env["networkPosture"]
        if not isinstance(np.get("posture"), str) or np.get("posture") not in POSTURES:
            self.fail("AEE-POSTURE-VOCAB", "networkPosture.posture absent, not a string, or unregistered")
        self.posture_pin = sha256_of(np)

        # observationVocabulary
        voc = env["observationVocabulary"]
        labels, caught = voc.get("labels"), voc.get("caught")
        ok = True
        for nm, arr in (("labels", labels), ("caught", caught)):
            if not isinstance(arr, list) or not all(isinstance(x, str) for x in arr):
                self.fail("AEE-VOCABULARY-SHAPE", "observationVocabulary.%s must be an array of strings" % nm)
                ok = False
                continue
            if not all(bmp_only(x) for x in arr):
                self.fail("AEE-VOCABULARY-SHAPE", "observationVocabulary.%s carries a supplementary-plane entry" % nm)
                ok = False
            if not sorted_unique_utf16(arr):
                self.fail("AEE-VOCABULARY-SHAPE", "observationVocabulary.%s not sorted by UTF-16 code unit or has duplicates" % nm)
                ok = False
        if ok and not set(caught) <= set(labels):
            self.fail("AEE-VOCABULARY-SHAPE", "observationVocabulary.caught is not a subset of labels")
        if not ok:
            raise Stop()
        self.labels = set(labels)
        self.caught = set(caught)
        self.voc = voc

    def check_coverage(self):
        cov = self.pred.get("coverage")
        if not isinstance(cov, dict):
            self.stop("AEE-COVERAGE-SHAPE", "coverage missing or not an object")
        ac = cov.get("assessedClasses")
        oos = cov.get("outOfScope")
        rel = cov.get("routedElsewhere")
        if not isinstance(ac, list) or not all(isinstance(x, str) for x in ac):
            self.stop("AEE-COVERAGE-SHAPE", "coverage.assessedClasses must be an array of strings")
        for nm, mp in (("outOfScope", oos), ("routedElsewhere", rel)):
            if not isinstance(mp, dict) or not all(isinstance(x, str) for x in mp.values()):
                self.stop("AEE-COVERAGE-SHAPE", "coverage.%s must be an object mapping class to reason string" % nm)
        self.assessed = list(ac)
        self.gap_nonempty = bool(oos) or bool(rel)
        sets = [set(ac), set(oos), set(rel)]
        for cls in set().union(*sets):
            n = sum(1 for s in sets if cls in s)
            if n > 1:
                self.fail("AEE-COVERAGE-PARTITION", "class %r appears in more than one coverage set" % cls)
            if cls not in self.classes:
                self.fail("AEE-COVERAGE-PARTITION", "coverage names class %r the manifest does not declare" % cls)
        for cls in self.classes:
            if not any(cls in s for s in sets):
                self.fail("AEE-COVERAGE-PARTITION", "manifest class %r appears in no coverage set" % cls)

    def check_records_structure(self):
        pred = self.pred
        recs = pred.get("observationRecords")
        self.recs_present = "observationRecords" in pred
        if recs is None and not self.recs_present:
            recs = []
        if not isinstance(recs, list):
            self.stop("AEE-RECORD-SHAPE", "observationRecords must be an array")
        self.records = []
        for i, e in enumerate(recs):
            if not isinstance(e, dict):
                self.stop("AEE-RECORD-SHAPE", "observationRecords[%d] is not an object" % i)
            pt = e.get("payloadType")
            if not isinstance(pt, str):
                self.stop("AEE-RECORD-SHAPE", "observationRecords[%d].payloadType missing or not a string" % i)
            if not isinstance(e.get("payload"), str):
                self.stop("AEE-RECORD-SHAPE", "observationRecords[%d].payload missing or not a string" % i)
            body = b64decode_dsse(e["payload"])
            if body is None:
                self.stop("AEE-RECORD-PAYLOAD-ENCODING", "observationRecords[%d].payload is not base64" % i)
            sigs = e.get("signatures")
            if not isinstance(sigs, list) or not sigs:
                self.fail("AEE-RECORD-NO-SIGNATURES", "observationRecords[%d].signatures must carry at least one entry" % i)
                sigs = sigs if isinstance(sigs, list) else []
            for s in sigs:
                if not isinstance(s, dict) or not isinstance(s.get("sig"), str) or (
                        "keyid" in s and not isinstance(s["keyid"], str)):
                    self.fail("AEE-RECORD-SHAPE", "observationRecords[%d] has a malformed signature entry" % i)
            r = Record()
            r.idx, r.ptype, r.body = i, pt, body
            r.pae = pae(pt, body)
            r.leaf = leaf_hash(r.pae)
            r.sigs = [s for s in sigs if isinstance(s, dict) and isinstance(s.get("sig"), str)]
            self.records.append(r)
        seen = {}
        for r in self.records:
            if r.leaf in seen:
                self.fail("AEE-RECORD-DUPLICATE", "observationRecords[%d] duplicates [%d]" % (r.idx, seen[r.leaf]))
            seen.setdefault(r.leaf, r.idx)
        # batchRoot (§batchRoot)
        br_present = "batchRoot" in pred
        if self.records:
            if not br_present:
                self.fail("AEE-BATCHROOT-MISSING", "batchRoot is required when observationRecords is non-empty")
            else:
                root = merkle_root([r.leaf for r in self.records]).hex()
                if pred["batchRoot"] != root:
                    self.fail("AEE-BATCHROOT-MISMATCH", "batchRoot does not recompute over observationRecords")
        elif br_present:
            self.fail("AEE-BATCHROOT-MISMATCH", "batchRoot present but there are no records to root")

    def check_rows_structure(self):
        seen = set()
        n = len(self.records)
        for i, r in enumerate(self.rows):
            if "interceptRefs" in r:
                self.fail("AEE-RETIRED-SPELLING", "row %d carries retired member 'interceptRefs'" % i)
            a = r.get("attackId")
            if not isinstance(a, str):
                self.fail("AEE-ROW-SHAPE", "row %d attackId missing or not a string" % i)
            else:
                if a not in self.manifest_ids:
                    self.fail("AEE-ROW-ATTACK-NOT-IN-MANIFEST", "row %d attackId %r not in manifest" % (i, a))
                if a in seen:
                    self.fail("AEE-ROW-DUPLICATE-ATTACK", "attackId %r appears on more than one row" % a)
                seen.add(a)
            if "actualLayer" not in r:
                self.fail("AEE-ROW-ACTUALLAYER-MISSING", "row %d has no actualLayer" % i)
            elif not isinstance(r["actualLayer"], str):
                self.fail("AEE-ROW-SHAPE", "row %d actualLayer is not a string" % i)
            elif self.is_clean(r) and r["actualLayer"] != "none":
                self.fail("AEE-ROW-CLEAN-LAYER-NOT-NONE", "clean row %d must carry actualLayer 'none'" % i)
            if "observationRefs" in r:
                refs = r["observationRefs"]
                if not isinstance(refs, list) or not all(is_strict_int(x) for x in refs):
                    self.fail("AEE-ROW-REFS-SHAPE", "row %d observationRefs must be an array of integer indexes" % i)
                elif not all(0 <= x < n for x in refs):
                    self.fail("AEE-ROW-REF-OUT-OF-RANGE", "row %d observationRefs has an index out of range" % i)
        # coverage integrity (§attackResults)
        expect = set()
        for cls in self.assessed:
            expect.update(self.classes.get(cls, []))
        got = set(r.get("attackId") for r in self.rows if isinstance(r.get("attackId"), str))
        if got != expect:
            self.fail("AEE-COVERAGE-INTEGRITY",
                      "row attackIds do not equal the manifest attackIds of assessedClasses (missing %s, extra %s)"
                      % (sorted(expect - got), sorted(got - expect)))

    # -- row classification ---------------------------------------------
    def label_ok(self, r):
        return isinstance(r.get("containmentObserved"), str) and r["containmentObserved"] in self.labels

    def is_caught(self, r):
        return self.label_ok(r) and r["containmentObserved"] in self.caught

    def is_clean(self, r):
        return self.label_ok(r) and r["containmentObserved"] not in self.caught

    def refs(self, r):
        v = r.get("observationRefs")
        if isinstance(v, list) and all(is_strict_int(x) and 0 <= x < len(self.records) for x in v):
            return v
        return []

    # -- run binding (§Run binding) ---------------------------------------
    def derive_binding(self):
        self.binding = None
        if not self.has_substrate:
            return
        env = self.env
        vals = {
            "catchPolicy": sha256_of(env["catchPolicy"]),
            "corpus": sha256_of(env["corpus"]),
            "observationVocabulary": sha256_of(env["observationVocabulary"]),
            "runEntropy": sha256_of(env.get("runEntropy")),
            "subject": self.subject_sha,
            "substrate": sha256_of(env["substrate"]),
        }
        if not all(is_hex64(vals[k]) for k in ("catchPolicy", "corpus", "runEntropy", "subject", "substrate")):
            self.fail("AEE-BINDING-UNDERIVABLE", "run binding inputs are missing or malformed")
            return
        if not isinstance(vals["observationVocabulary"], str):
            self.fail("AEE-BINDING-UNDERIVABLE", "observationVocabulary.digest.sha256 missing or not a string")
            return
        try:
            vals["networkPosture"] = sha256_hex(jcs(env["networkPosture"]))
        except CanonError as e:
            self.fail("AEE-BINDING-UNDERIVABLE", "networkPosture object cannot be canonicalized: %s" % e)
            return
        vals["aeeBindingVersion"] = BINDING_VERSION
        self.binding = sha256_hex(jcs(vals))

    # -- per-record analysis (§observationRecords) -----------------------
    def analyse_records(self):
        for r in self.records:
            r.obj, r.kind = None, None
            r.general_problems = []
            r.kind_problems = []
            r.version_bad = False
            try:
                obj = parse_strict_bytes(r.body)
            except JsonError as e:
                obj = None
                r.general_problems.append("payload is not strict I-JSON (%s)" % e.code)
            if obj is not None and not isinstance(obj, dict):
                r.general_problems.append("payload is not a JSON object")
                obj = None
            r.obj = obj
            if obj is not None and isinstance(obj.get("aeeKind"), str):
                r.kind = obj["aeeKind"]
            if obj is not None:
                try:
                    if jcs(obj) != r.body:
                        r.general_problems.append("payload bytes are not RFC 8785 canonical")
                except CanonError as e:
                    r.general_problems.append("payload violates the I-JSON safe-integer profile (%s)" % e)
                if not member_names_bmp(obj):
                    r.general_problems.append("payload carries a supplementary-plane member name")
                if not isinstance(obj.get("aeeRunBinding"), str):
                    r.general_problems.append("aeeRunBinding missing or not a string")
                if not isinstance(obj.get("aeeKind"), str):
                    r.general_problems.append("aeeKind missing or not a string")
                if obj.get("aeeMethod") not in METHOD:
                    r.general_problems.append("aeeMethod missing or not intercepted/reconstructed")
                for k in obj:
                    if k.startswith("aee") and k not in KNOWN_AEE_MEMBERS:
                        r.general_problems.append("unrecognized reserved member %r" % k)
            if not r.ptype.endswith("+json"):
                r.general_problems.append("payloadType does not end in +json")
            r.general_ok = not r.general_problems
            r.bound = (self.binding is not None and obj is not None
                       and obj.get("aeeRunBinding") == self.binding)
        # second pass: kind constraints (the seal's recompute reads every record's kind)
        for r in self.records:
            if r.obj is not None and r.kind in COVERING_KINDS:
                r.kind_problems = self.kind_constraints(r)
            r.kind_ok = r.general_ok and not r.kind_problems

    def kind_constraints(self, r):
        o, k, p = r.obj, r.kind, []
        if k == "interception":
            pc = o.get("aeePayloadCommitment")
            if (not isinstance(pc, list) or not pc or not all(is_hex64(x) for x in pc)
                    or not sorted_unique_utf16(pc)):
                p.append("aeePayloadCommitment must be a non-empty, sorted, duplicate-free array of lowercase 64-hex")
        elif k == "arming":
            if o.get("aeeMethod") != "intercepted":
                p.append("arming aeeMethod must be intercepted")
            if "aeeBindingVersion" in o and o["aeeBindingVersion"] != BINDING_VERSION:
                r.version_bad = True
                p.append("aeeBindingVersion %r is not implemented" % (o["aeeBindingVersion"],))
            at = parse_timestamp(o.get("armedAt"))
            if at is None:
                p.append("armedAt missing or outside the timestamp profile")
            elif self.issued is not None and at > self.issued:
                p.append("armedAt is later than issuedAt")
            if o.get("aeePostureDigest") != self.posture_pin:
                p.append("aeePostureDigest does not equal the pinned networkPosture digest")
            aa = o.get("aeeAssessedAttacks")
            if (not isinstance(aa, list) or not all(isinstance(x, str) for x in aa)
                    or not sorted_unique_utf16(aa) or not all(x in self.manifest_ids for x in aa)):
                p.append("aeeAssessedAttacks must be a sorted, duplicate-free array of manifest attackIds")
            p.extend(self.chain_constraints(o))
        elif k == "sealed":
            if o.get("aeeMethod") != "intercepted":
                p.append("sealed aeeMethod must be intercepted")
            still = o.get("aeeStillArmed")
            if not isinstance(still, bool):
                p.append("aeeStillArmed missing or not a boolean")
            elif still is not True:
                p.append("aeeStillArmed is false (vantage did not stay armed)")
            dc = o.get("aeeDropCount")
            db = o.get("aeeDropBound")
            if not is_int(dc):
                p.append("aeeDropCount missing or not an integer")
            if "aeeDropBound" in o and not is_int(db):
                p.append("aeeDropBound is not an integer")
            if is_int(dc) and dc != 0 and not ("aeeDropBound" in o and is_int(db) and dc <= db):
                p.append("aeeDropCount is non-zero and exceeds any declared aeeDropBound")
            if o.get("aeePostureDigest") != self.posture_pin:
                p.append("aeePostureDigest does not equal the pinned networkPosture digest")
            os_ = o.get("aeeObservedSet")
            if not is_hex64(os_):
                p.append("aeeObservedSet missing or not lowercase 64-hex")
            elif os_ != self.observed_set():
                p.append("aeeObservedSet does not equal the recompute over carried records")
            oa = o.get("aeeObservedAttacks")
            if (not isinstance(oa, list) or not all(isinstance(x, str) for x in oa)
                    or not sorted_unique_utf16(oa) or not all(x in self.manifest_ids for x in oa)):
                p.append("aeeObservedAttacks must be a sorted, duplicate-free array of manifest attackIds")
        elif k == "examination":
            if o.get("aeeMethod") != "reconstructed":
                p.append("examination aeeMethod must be reconstructed")
        return p

    def chain_constraints(self, o):
        p = []
        has_seq = "aeeRunSeq" in o
        if not has_seq:
            for m in ("aeePrevRunBinding", "aeeChainScope"):
                if m in o:
                    p.append("%s present without aeeRunSeq" % m)
            return p
        seq = o["aeeRunSeq"]
        if not is_int(seq) or seq < 1 or abs(seq) >= SAFE_INT:
            p.append("aeeRunSeq must be a positive safe-range integer")
            seq = None
        if "aeePrevRunBinding" in o:
            if not is_hex64(o["aeePrevRunBinding"]):
                p.append("aeePrevRunBinding is not lowercase 64-hex")
            if seq == 1:
                p.append("aeePrevRunBinding present although aeeRunSeq is 1")
        elif seq is not None and seq != 1:
            p.append("aeePrevRunBinding absent although aeeRunSeq is not 1")
        cs = o.get("aeeChainScope")
        if "aeeChainScope" not in o:
            p.append("aeeChainScope required when aeeRunSeq is present")
        elif (not isinstance(cs, list) or not all(isinstance(x, str) for x in cs)
              or not all(x in CHAIN_SCOPE_TOKENS for x in cs) or not sorted_unique_utf16(cs)):
            p.append("aeeChainScope must be a sorted, duplicate-free array of registered tokens")
        return p

    _observed_cache = None

    def observed_set(self):
        """§aeeObservedSet: JCS of the sorted, duplicate-free array of hex leaf
        hashes of every carried interception and examination record."""
        if self._observed_cache is None:
            leaves = sorted(set(r.leaf.hex() for r in self.records
                                if r.kind in ("interception", "examination")))
            self._observed_cache = sha256_hex(jcs(leaves))
        return self._observed_cache

    def covers(self, r, kind):
        return r.kind == kind and r.general_ok and r.bound and r.kind_ok

    # -- step 2: coverage validity ----------------------------------------
    def check_coverage_validity(self):
        recs = self.records
        # Existence of a valid, bound seal (stated first so it can be primary).
        if self.has_substrate and not any(self.covers(r, "sealed") for r in recs):
            self.fail("AEE-SEAL-MISSING",
                      "statement carries a basis: substrate row but no sealed record that satisfies its kind and binds to this run")

        # Universal partner: every bound record of a covering kind satisfies its kind.
        for r in recs:
            if r.bound and r.kind in COVERING_KINDS and not r.kind_ok:
                if r.version_bad:
                    self.fail("AEE-BINDING-VERSION-UNSUPPORTED",
                              "record %d declares an unimplemented aeeBindingVersion" % r.idx)
                self.fail("AEE-RECORD-KIND-CONSTRAINT",
                          "record %d (%s) violates its kind: %s" % (r.idx, r.kind, "; ".join(r.general_problems + r.kind_problems)))

        # aeeObservedSet equality on every carried sealed record.
        for r in recs:
            if r.kind == "sealed" and "aeeObservedSet" in r.obj:
                if r.obj["aeeObservedSet"] != self.observed_set():
                    self.fail("AEE-OBSERVED-SET-MISMATCH",
                              "record %d aeeObservedSet does not equal the recompute over carried records" % r.idx)
            if r.kind == "sealed" and isinstance(r.obj.get("aeeObservedAttacks"), list):
                for a in r.obj["aeeObservedAttacks"]:
                    if not any(row.get("attackId") == a and self.is_caught(row) for row in self.rows):
                        self.fail("AEE-OBSERVED-ATTACK-NO-CAUGHT-ROW",
                                  "seal %d names attack %r but no caught row carries it" % (r.idx, a))
            if r.kind == "arming" and isinstance(r.obj.get("aeeAssessedAttacks"), list):
                need = set()
                for cls in self.assessed:
                    need.update(self.classes.get(cls, []))
                if not need <= set(x for x in r.obj["aeeAssessedAttacks"] if isinstance(x, str)):
                    self.fail("AEE-ASSESSED-NOT-SUBSET",
                              "assessed attack set is not a subset of arming record %d aeeAssessedAttacks" % r.idx)

        # Interception records: clean rows must not cite them; every one is resolved by a caught row.
        resolved = set()
        for i, row in enumerate(self.rows):
            rf = self.refs(row)
            if self.is_caught(row):
                resolved.update(rf)
            if self.is_clean(row) and any(recs[x].kind == "interception" for x in rf):
                self.fail("AEE-CLEAN-ROW-CITES-INTERCEPTION", "clean row %d resolves an interception record" % i)
        for r in recs:
            if r.kind == "interception" and r.idx not in resolved:
                self.fail("AEE-INTERCEPTION-UNRESOLVED",
                          "interception record %d is resolved by no caught row" % r.idx)

        # Attribution (§Coverage validity, last bullet).
        for i, row in enumerate(self.rows):
            a = row.get("attackId")
            has_entry = isinstance(a, str) and a in self.expected
            att = row.get("attribution")
            if att == "pinned":
                ints = [recs[x] for x in self.refs(row) if recs[x].kind == "interception"]
                if not ints:
                    self.fail("AEE-PINNED-NO-INTERCEPTION", "pinned row %d resolves no interception record" % i)
                if not has_entry:
                    self.fail("AEE-PINNED-NO-EXPECTATION", "pinned row %d attackId has no expectedPayloads entry" % i)
                else:
                    for rec in ints:
                        pc = rec.obj.get("aeePayloadCommitment")
                        vals = set(x for x in pc if isinstance(x, str)) if isinstance(pc, list) else set()
                        if not vals & self.expected[a]:
                            self.fail("AEE-PINNED-COMMITMENT-MISMATCH",
                                      "pinned row %d: interception %d carries no expected commitment" % (i, rec.idx))
            elif not has_entry and att != "paired":
                self.fail("AEE-ATTRIBUTION-MUST-BE-PAIRED",
                          "row %d attackId has no expectedPayloads entry and must declare paired" % i)

        # Per basis: substrate row requirements.
        for i, row in enumerate(self.rows):
            if row.get("basis") != "substrate":
                continue
            raw_refs = row.get("observationRefs")
            if not isinstance(raw_refs, list) or not raw_refs:
                self.fail("AEE-SUBSTRATE-ROW-NO-REFS", "substrate row %d has empty or missing observationRefs" % i)
                continue
            rf = self.refs(row)
            if len(rf) != len(raw_refs):
                continue  # already reported as out of range / malformed
            method = row.get("method")
            if not self.label_ok(row) or method not in METHOD:
                self.fail("AEE-SUBSTRATE-ROW-FAIL-CLOSED",
                          "substrate row %d is fail-closed on containmentObserved or method and cannot class-match" % i)
                continue
            for x in rf:
                rec = recs[x]
                if not rec.general_ok:
                    self.fail("AEE-REF-NOT-WELLFORMED",
                              "substrate row %d references record %d that is not a well-formed covering payload: %s"
                              % (i, x, "; ".join(rec.general_problems)))
                elif not rec.bound:
                    self.fail("AEE-RUN-BINDING-MISMATCH",
                              "substrate row %d references record %d whose aeeRunBinding differs from the derived binding" % (i, x))
            refd = [recs[x] for x in rf]
            if method == "reconstructed":
                ok = any(self.covers(r, "examination") for r in refd)
                need = "examination"
            elif self.is_caught(row):
                ok = any(self.covers(r, "interception") for r in refd)
                need = "interception"
            else:
                armings = [r for r in refd if r.kind == "arming"]
                has_arm = any(self.covers(r, "arming") for r in armings)
                has_seal = any(self.covers(r, "sealed") and all(
                    r.obj.get("aeePostureDigest") == a.obj.get("aeePostureDigest") for a in armings)
                    for r in refd)
                ok = has_arm and has_seal
                need = "arming and sealed"
            if not ok:
                kinds = set(r.kind for r in refd)
                if kinds and kinds <= set(NONCOVERING_REGISTERED):
                    self.fail("AEE-REF-NONCOVERING-KIND",
                              "substrate row %d resolves only %s records, which cover nothing" % (i, sorted(kinds)))
                elif kinds and all(k not in COVERING_KINDS and k not in NONCOVERING_REGISTERED for k in kinds):
                    self.fail("AEE-REF-UNKNOWN-KIND",
                              "substrate row %d resolves only records of unrecognized kind" % i)
                else:
                    self.fail("AEE-CLASS-MISMATCH",
                              "substrate row %d does not reference a covering %s record" % (i, need))
            # method cap: weakest aeeMethod across covering-kind references
            covering = [r for r in refd if r.kind in COVERING_KINDS and r.obj is not None]
            if method == "intercepted" and any(r.obj.get("aeeMethod") == "reconstructed" for r in covering):
                self.fail("AEE-METHOD-CAP", "substrate row %d claims intercepted above a reconstructed covering record" % i)

    # -- step 3: result recompute ----------------------------------------
    def recompute_result(self):
        c1 = c3 = False
        for row in self.rows:
            if (not self.label_ok(row) or self.is_caught(row)
                    or row.get("basis") not in BASIS or row.get("method") not in METHOD
                    or row.get("attribution") not in ATTRIBUTION):
                c1 = True
            elif self.is_clean(row) and (row["basis"] != "substrate" or row["method"] != "intercepted"):
                c3 = True
        contributions = ["fail" if c1 else "pass",
                         "degraded" if self.gap_nonempty else "pass",
                         "pass_indirect" if c3 else "pass"]
        self.result = min(contributions, key=RESULTS.index)
        carried = self.pred.get("result")
        if carried in RESULTS and carried != self.result:
            self.fail("AEE-RESULT-MISMATCH", "carried result %r but recompute gives %r" % (carried, self.result))

    # -- step 4: digest integrity ----------------------------------------
    def check_digest_integrity(self):
        try:
            md = sha256_hex(jcs(self.manifest))
        except CanonError as e:
            self.fail("AEE-MANIFEST-CANONICALIZATION", "corpus.manifest cannot be canonicalized: %s" % e)
        else:
            if sha256_of(self.env["corpus"]) != md:
                self.fail("AEE-CORPUS-DIGEST-MISMATCH", "corpus.digest.sha256 does not equal JCS digest of the manifest")
        vd = sha256_hex(jcs({"caught": sorted(self.caught, key=utf16_key),
                             "labels": sorted(self.labels, key=utf16_key)}))
        if sha256_of(self.voc) != vd:
            self.fail("AEE-VOCABULARY-DIGEST-MISMATCH", "observationVocabulary.digest.sha256 does not equal the recompute")

    # -- stage two: evidence tier ------------------------------------------
    def record_verifies(self, r):
        if not self.keys:
            return False
        msg = r.pae
        for s in r.sigs:
            sig = b64decode_dsse(s["sig"])
            if sig is None:
                continue
            for k in self.keys:
                if ed25519_verify(k, msg, sig):
                    return True
        return False

    def derive_tiers(self):
        tiers = []
        for row in self.rows:
            if row.get("basis") != "substrate":
                tiers.append("declared")
                continue
            covering = [self.records[x] for x in self.refs(row) if self.records[x].kind in COVERING_KINDS]
            ok = bool(self.keys) and bool(covering) and all(self.record_verifies(r) for r in covering)
            tiers.append("attested" if ok else "unattested")
        self.tiers = tiers

    def primary(self):
        if not self.codes:
            return None
        if "AEE-SEAL-MISSING" in self.codes:
            return "AEE-SEAL-MISSING"
        return self.codes[0]


def load_keys():
    path = os.environ.get("AEE_SUBSTRATE_KEYS")
    if not path:
        return None
    try:
        with open(path, "rb") as f:
            doc = parse_strict_bytes(f.read())
    except (OSError, JsonError) as e:
        sys.stderr.write("warning: AEE_SUBSTRATE_KEYS unreadable (%s); no substrate key is pinned\n" % e)
        return None
    keys = []
    entries = doc.get("substrateObservationKeys") if isinstance(doc, dict) else None
    for ent in entries if isinstance(entries, list) else []:
        hx = ent.get("publicKeyHex") if isinstance(ent, dict) else None
        if isinstance(hx, str) and re.match(r"[0-9a-fA-F]{64}\Z", hx):
            keys.append(bytes.fromhex(hx))
    return keys


def emit(obj):
    import json
    sys.stdout.write(json.dumps(obj, separators=(",", ":"), ensure_ascii=True) + "\n")
    sys.stdout.flush()


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: aee_verify.py <statement-file | ->\n")
        emit({"verdict": "reject", "codes": ["AEE-USAGE"], "primaryCode": "AEE-USAGE", "result": None, "tiers": []})
        return 2
    try:
        if argv[1] == "-":
            raw = sys.stdin.buffer.read()
        else:
            with open(argv[1], "rb") as f:
                raw = f.read()
    except OSError as e:
        sys.stderr.write("cannot read input: %s\n" % e)
        emit({"verdict": "reject", "codes": ["AEE-INPUT-UNREADABLE"], "primaryCode": "AEE-INPUT-UNREADABLE",
              "result": None, "tiers": []})
        return 2
    v = Verifier(raw, load_keys())
    try:
        ok = v.run()
    except Exception as e:  # fail closed on any defect in this verifier
        sys.stderr.write("internal error: %r\n" % (e,))
        emit({"verdict": "reject", "codes": ["AEE-INTERNAL-ERROR"], "primaryCode": "AEE-INTERNAL-ERROR",
              "result": None, "tiers": []})
        return 1
    for n in v.notes:
        sys.stderr.write(n + "\n")
    if ok:
        emit({"verdict": "accept", "codes": [], "result": v.result, "tiers": v.tiers})
        return 0
    emit({"verdict": "reject", "codes": v.codes, "primaryCode": v.primary(), "result": None, "tiers": []})
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
