# AEE v0.7 clean-room verifier

An independent verifier for the in-toto predicate "Adversarial Execution
Evidence" (`https://in-toto.io/attestation/adversarial-execution-evidence/v0.7`),
built only from the spec file pinned at agent-evidence-vectors tag v0.12.1
(`spec/adversarial-execution-evidence.md`, SHA-256
`759d2383e5da36fa509dc335e6159a20b87641b25ebbadcf1676c55d75ffd8b0`) and the
"What the suite compares" section of the 0.12.1 PyPI README. See BUILD-LOG.md
for provenance and AMBIGUITIES.md for every reading the text left open.

## Run

```
python3 aee_verify.py <statement.json>
# or
./run.sh <statement.json>
# with a consumer key policy for the evidence tier
AEE_SUBSTRATE_KEYS=/path/to/keys.json python3 aee_verify.py <statement.json>
```

`-` as the path reads the statement from stdin. The key file has the shape
`{"substrateObservationKeys": [{"keyid": "...", "publicKeyHex": "<32-byte Ed25519 key, hex>"}]}`.

Runtime: Python 3 standard library only. Developed and tested on CPython
3.13.16 on Linux. No third-party dependency at runtime. Ed25519 is implemented
in pure Python (RFC 8032) because the standard library has none.

## Output contract

Diagnostics go to stderr. The last line of stdout is exactly one JSON object
on one line:

```
{"verdict":"accept","codes":[],"result":"pass","tiers":["attested"]}
{"verdict":"reject","codes":["AEE-SEAL-MISSING",...],"primaryCode":"AEE-SEAL-MISSING","result":null,"tiers":[]}
```

Exit status: `0` valid (accept), `1` invalid or malformed (reject, also used
on any internal error, fail-closed), `2` usage error or unreadable input.
`result` is the recomputed result token. `tiers` holds one evidence tier per
`attackResults` row in row order (`attested`, `unattested`, `declared`) and is
derived only for valid statements. Codes are this build's own vocabulary,
because the spec defines no condition vocabulary.

## What it checks

Stage one, byte-pure (all four steps are consumption preconditions, and any
failure rejects):

1. Well-formedness. Strict I-JSON over the raw bytes before decoding: valid
   UTF-8 (no overlong forms, no CESU-8 surrogates), duplicate members at any
   depth, `\u` escapes of exactly four hex digits, paired surrogate escapes,
   no raw control characters, no noncharacters in names or values, nesting
   depth at most 128. Statement shape (`_type`, `predicateType` exactly v0.7,
   exactly one subject), lowercase 64-hex `sha256` on subject, substrate,
   catchPolicy, corpus, networkPosture and runEntropy, `runEntropy` required
   with any `basis: substrate` row, closed `networkPosture.posture`
   vocabulary, observation vocabulary arrays (sorted by UTF-16 code unit,
   duplicate-free, BMP-only, `caught` a subset of `labels`), manifest rules
   (one class per attackId, at least one attackId, `expectedPayloads` keys,
   ordering and hex), coverage as a partition of manifest classes, row rules
   (attackId in manifest and unique, `actualLayer` required and `none` on clean
   rows, `observationRefs` in range everywhere), coverage integrity at attack
   granularity, `issuedAt` timestamp profile, retired spellings rejected,
   record envelope shape (base64 payload, at least one signature), duplicate
   records, `batchRoot` RFC 6962 recompute, and run-binding derivability
   (binding version 2 over the canonical `networkPosture` object).
2. Coverage validity. Per `basis: substrate` row: non-empty references,
   class match (interception for caught intercepted rows, examination for
   reconstructed rows, arming plus a covering sealed record for clean
   intercepted rows), every referenced payload canonical RFC 8785 `+json` with
   the reserved members and the derived `aeeRunBinding`, and the `method` cap.
   Statement-wide: clean rows cite no interception, every interception is
   resolved by a caught row, a valid bound `sealed` record exists, every bound
   record of a covering kind satisfies its kind (for arming the `armedAt`
   profile and ordering, posture, `aeeAssessedAttacks`, binding version and
   chain members, for sealed the armed flag, drop count and bound, posture,
   `aeeObservedSet` and `aeeObservedAttacks`, for interception
   `aeePayloadCommitment`, for examination the reconstructed method), `aeeObservedSet` recompute, `aeeObservedAttacks` caught-row
   obligation, `aeeAssessedAttacks` subset rule, `attribution: pinned` checks
   against `expectedPayloads`, and `paired` where no expectation exists.
   Unrecognized `aee*` payload members make a record cover nothing.
   `moat-drop` and `uncommitted-observation` cover nothing and are reported
   under their own condition when they are all a row cites.
3. `result` recompute as the minimum of the three conditions, compared with
   the carried `result`.
4. Digest integrity: `corpus.digest` over the JCS of the whole manifest and
   the vocabulary digest over `{"caught", "labels"}`.

Stage two, trust-relative: the per-row evidence tier. A substrate row is
`attested` only when every covering record it references carries a signature
that verifies (Ed25519 over DSSE PAE) under a key from `AEE_SUBSTRATE_KEYS`.
With no key policy every substrate row is `unattested`. The tier never moves
`result` or validity.

## Tests

```
python3 tests/gen_cases.py     # regenerate tests/cases and tests/expectations.json
python3 tests/run_tests.py     # exit 0 when every check passes
```

`run_tests.py` runs `tests/test_primitives.py` (JCS number and ordering
values, PAE, RFC 6962 tree shape, Ed25519 RFC 8032 test 1 and a
cross-check against the `cryptography` package when it is installed, base64,
timestamps, parser corner cases) and then every case in `tests/cases` twice,
with and without the key policy, checking exit status, verdict, result, tiers
and that the expected codes are present.

## Limits

- Codes are this build's vocabulary. A harness that grades by a registry of
  condition identifiers will not match them. The clean-room rules forbade
  reading that registry.
- The enclosing envelope signature of a DSSE-wrapped statement is not
  evaluated, because the key-policy channel names only substrate observation
  keys. Unwrapping a DSSE envelope is an extension, not a spec requirement.
- Consumer policy obligations (corpus and substrate anchors, demanded
  classes, pinned-attribution demands, key validity windows, `runEntropy`
  reuse, chain gap and fork analysis across attestations) are outside a
  single-statement verifier and are not implemented.
- Readings chosen where the text is open are listed in AMBIGUITIES.md. Each
  is untested against the official vectors, by design of the study.
- Pure-Python Ed25519 is not constant time. That does not matter for
  verification with public keys, but the signing helper exists only for the
  test generator.
