# Ambiguities and the readings chosen

Section names refer to headings of the pinned spec
(`spec/adversarial-execution-evidence.md`). "README" means the "What the
suite compares" section of the agent-evidence-vectors 0.12.1 PyPI README.
The rule applied throughout was the most literal reading of the text, without
guessing at hidden test expectations.

## Output and invocation

1. **Verdict tokens and exit status** (README). The README says the verdict is
   read from the exit status and gives the JSON shape, but names no verdict
   tokens and no exit values. Chosen: `"accept"` with exit 0, `"reject"` with
   exit 1, exit 2 for usage errors and unreadable input. The spec defines no
   exit codes.
2. **Codes** (README, §Coverage validity "This document defines no condition
   vocabulary"). The README compares codes against a manifest registry that
   the clean-room rules put out of reach. Chosen: an own `AEE-*` vocabulary.
   Codes are reported as a set of every detected violation.
3. **`primaryCode`** (README, §Coverage validity paragraph on the existence
   requirement). Chosen: the first detected code, except that the unmet seal
   existence requirement (`AEE-SEAL-MISSING`) is primary whenever it holds, as
   the spec asks.
4. **`result` and `tiers` on reject** (README). Chosen: `result: null` and
   `tiers: []`, because §Evidence tier says "Given a valid attestation" and an
   invalid attestation's `result` "MUST NOT be consumed".
5. **Input form** (README `<cmd> <vector-file>`). Chosen: the file is an
   in-toto Statement. As an extension, a top-level DSSE envelope with
   `payloadType` `application/vnd.in-toto+json` is unwrapped and the byte
   rules are re-applied to its payload. The envelope signature is not
   evaluated (no envelope key policy exists in the key channel).
6. **Key file problems.** An unset or empty `AEE_SUBSTRATE_KEYS`, or an
   unreadable file, means no pinned substrate key, so every substrate row is
   `unattested` (§Evidence tier no-TOFU rule). Malformed key entries are
   skipped.

## Prerequisites and parsing

7. **Scope of the lowercase-hex digest requirement** (§Prerequisites, Run
   binding paragraph: "Separately, ... MUST each carry ... a
   substrate-row-carrying statement violating this ... is malformed"). The MUST
   is unconditional while the stated consequence names substrate statements.
   Chosen: enforced on every statement for `subject[0]`, `substrate`,
   `catchPolicy`, `corpus` and `networkPosture`, and for `runEntropy` whenever
   it is present.
8. **Safe-integer profile reach** (§Prerequisites "on canonicalized content").
   Chosen: enforced wherever this verifier canonicalizes: record payloads
   (violation makes the record cover nothing), the manifest and the
   `networkPosture` object (violation makes the statement malformed). Numbers
   elsewhere in the statement are not range-checked, since RFC 7493's number
   rule is a SHOULD and the spec's MUST is scoped to canonicalized content.
   "Integer" is judged by value: any number with an integral value of
   magnitude 2^53 or more is rejected, including exponent forms, and
   non-finite numbers are rejected on the same terms.
9. **UTF-8 byte-order mark.** Not mentioned. Chosen: rejected as a syntax
   error under the strict reading of I-JSON.
10. **Duplicate members compared after escape decoding** (§Prerequisites).
    `"a"` and `"a"` are the same member name and count as a duplicate.
11. **Retired spellings** (§Fields `doesNotAssert`, Changelog 0.6
    `interceptRecords`/`interceptRefs`). The in-toto parsing rules say unknown
    fields are ignored, but the spec says the old spellings are "rejected".
    Chosen: their presence makes the statement malformed.
12. **`doesNotAssert` type** (§Fields, "array of strings, optional"). Chosen:
    when present it must be an array of strings.

## observationEnvironment, coverage, rows

13. **`corpus.name` and `corpus.uri`** (§observationEnvironment). Listed as
    members but read by no gate. Chosen: not required.
14. **Repeated attackId inside one class array, repeated class inside
    `assessedClasses`** (§observationEnvironment, §coverage). Only cross-class
    repetition and membership in more than one of the three coverage sets are
    named as malformed. Chosen: in-array repetition is tolerated (set
    semantics).
15. **Clean row with `actualLayer` other than `none`** (§actualLayer "the
    producer MUST emit the literal string none"). Chosen: invalid.
16. **"A row whose attackId carries no such entry MUST declare `paired`"**
    (§Coverage validity, last bullet). Chosen literally: on a row whose
    attackId has no `expectedPayloads` entry, any `attribution` other than
    `paired`, including a missing or out-of-vocabulary value, makes the
    statement invalid. A missing or unknown `attribution` on a row that does
    have an entry is fail-closed (`result` `fail`) and otherwise valid.
17. **Tier of a row whose `basis` is missing or out of vocabulary** (§Evidence
    tier defines tiers for `artifact` and `substrate` only). Chosen:
    `declared`, the bottom tier, matching "sits at the bottom of both
    orderings".

## observationRecords

18. **What counts as "an interception record"** for the clean-row rule, the
    unresolved-interception rule and the `pinned` rules (§Coverage validity
    "whose payload aeeKind is interception"). Chosen: any carried record whose
    payload strictly parses as a JSON object with `aeeKind` equal to
    `interception`, regardless of canonicality or run binding.
19. **Which records the seal and arming statement rules read**
    (§`aeeObservedSet`, §`aeeObservedAttacks`, §`aeeAssessedAttacks`). The
    text says "every carried sealed record" for the observed set and speaks of
    "this array" for the other two. Chosen: all three rules apply to every
    carried record of that kind on which the member is present, bound or not.
    A missing or mistyped member is handled through the kind constraints of
    bound records.
20. **`aeeObservedSet` recompute set** (§`aeeObservedSet`). Chosen: every
    carried record whose payload `aeeKind` is `interception` or
    `examination`, regardless of binding. Leaf hashes are deduplicated, sorted,
    and the JCS of the array of lowercase hex strings is hashed.
21. **"Satisfies every constraint of its kind"** (§Coverage validity, universal
    partner). Chosen: includes the general covering constraints (canonical
    RFC 8785 payload, `+json` media type, reserved members well-typed, BMP-only
    member names, no unrecognized `aee*` member) as well as the kind-specific
    ones.
22. **Sealed kind constraints** (§observationRecords "covers no clean row
    unless ...", and the universal-partner example of "a sealed record
    reporting its moat down"). Chosen: `aeeStillArmed` true, drop count zero
    or within a declared bound, and `aeePostureDigest` equal to the pinned
    digest are kind constraints, so they also drive the existence requirement
    and the universal partner. Equality with the `aeePostureDigest` of every
    resolved arming record is checked only for row coverage, because the text
    says which arming records apply on a row-free check "is not settled".
23. **Unrecognized `aee*` members** (§observationRecords precedent note
    "a colliding or unrecognized aee* member can only weaken coverage, the
    record covering nothing"). Chosen: a top-level payload member starting
    with `aee` that this document never defines (for example `aeeVersion`)
    makes the record cover nothing. A member the document defines for another
    kind is treated as recognized, with kind-specific constraints read on
    their declared kind. The three chain members are an exception: their
    syntax is checked in the reserved-member walk on every record, as the
    chain section specifies. Nested members are producer territory.
    Review of 8f61306 corrected the former arming-only chain check.
24. **`aeeBindingVersion` value type** (§Run binding). The binding object uses
    the string `"2"`. Chosen: only the string `"2"` is the implemented
    version, so an integer `2` is an unimplemented version.
25. **`aeeDropCount` sign** (§observationRecords "an integer counting").
    Chosen: integer type checked, sign not checked.
26. **Duplicate records** (§batchRoot "Two byte-identical entries" and "a
    record's canonical identity is its leaf hash"). Chosen: two records with
    the same leaf hash are duplicates.
27. **Base64** (DSSE: standard or URL-safe, verifiers MUST accept either).
    Chosen: standard alphabet with correct padding, or URL-safe alphabet with
    padding optional. A payload that is not decodable makes the statement
    malformed, because its leaf and `batchRoot` cannot be computed.
28. **`+json` suffix** (§observationRecords). Chosen: case-sensitive suffix
    match on `payloadType`.
29. **`batchRoot` comparison and presence** (§batchRoot). Chosen: exact string
    match against the lowercase hex recompute. A `batchRoot` carried with an
    empty or absent record array does not recompute and is invalid.
30. **Method cap set** (§Coverage validity, §moat-drop). Chosen: referenced
    records of the four covering kinds. Unrecognized kinds and the two
    registered non-covering kinds are excluded.
31. **Records referenced from a substrate row** (§Coverage validity "every
    referenced payload parses ..."). Chosen: applies to every referenced
    record, including unrecognized and non-covering kinds, which must still be
    canonical, `+json`, carry the three reserved members and bind to the run.

## Stage two

32. **Evidence tier record set and signature rule** (§Evidence tier "every
    covering record's signature verifies"). Chosen: covering records are the
    referenced records of the four covering kinds. A record verifies when any
    one of its signatures verifies under any pinned key. `keyid` is treated as
    an unauthenticated hint and not used to restrict keys. Signature algorithm
    Ed25519, from the spec's policy example (`ed25519-public-key-bytes`).
    After review: signatures on every carried record are evaluated, including
    the noncovering kinds (`moat-drop`, `uncommitted-observation`), because the
    spec asks for verification on the same terms as every carried record. Only
    covering records enter a row's tier. A failed noncovering signature does
    not lower a covering row's tier and does not invalidate the statement. With
    no pinned key, verification is unavailable and substrate rows stay
    `unattested`.

## Timestamps

33. **Leap seconds and calendar validity** (§issuedAt, RFC 3339). Chosen:
    calendar dates are validated (including leap years). Second `60` is
    accepted only at `23:59:60` on the last day of a month (RFC 3339 section
    5.7). This was tightened after review: `3621fad` through `8372071` also
    accepted it mid month. Whether a leap second was actually announced for
    that month is not checked, because no announcement table is carried.
    Fractional seconds of any length are allowed and compared numerically.

34. **Integer-valued refs written as floats** (row `observationRefs` and other
    ref arrays). Corrected after review of 8f61306: references are judged by
    numeric value. Integral numbers such as 0.0 and 0e0 are accepted when in
    range and converted to integer indexes for lookup. Fractions, booleans,
    strings and out-of-range values are rejected. The prior integer-token
    restriction added a requirement absent from the spec.

## Descriptors

35. **Recognized ResourceDescriptor fields** (§Fields, `subject`,
    `substrate`, `catchPolicy`, framework ResourceDescriptor and ResourceURI).
    Chosen, after review: when present, `name`, `uri`, `downloadLocation` and
    `mediaType` must be strings, `annotations` an object with any values, and
    `content` valid base64 (standard or URL-safe). `uri` and
    `downloadLocation` must follow RFC 3986 generic syntax with lowercase
    scheme and authority, as the framework states ("MUST be case normalized
    as per section 6.2.2.1 of RFC 3986"). This follows the framework's
    explicit authority-wide wording, including userinfo and hex letters in
    authority percent encodings. Percent-encoding hex case is unrestricted
    in path, query and fragment. The cited RFC describes normalization
    differently, including uppercase percent-encoding hex digits and
    preservation of other case-sensitive components. This inherited wording
    ambiguity is retained explicitly. Values are rejected, not rewritten.
    Unknown fields are ignored.
    Failures use this build's code `AEE-DESCRIPTOR-SHAPE`. `3621fad` through
    `8372071` did not check these fields.
