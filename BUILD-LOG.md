# Build log

Builder: Claude (Anthropic) via a Claude Code general-purpose subagent. A
coding agent wrote this build (code, tests and documents). No human edited the
code.

Times are UTC from the build host clock. The task brief said "today is
7 October" (2026). The host clock read 2026-10-08T00:10Z at the start, which is
the evening of 7 October in US time zones.

Work directory:
`/tmp/claude-0/-home-claude/d06a6d3b-c9eb-5feb-af7b-a0f5ea7fcbf2/scratchpad/emse-aee-build`
(git repository, no remote, never pushed).

## Tools

- Claude Code tools: Bash, Read, Write, Edit.
- curl 8.5.0, sha256sum (GNU coreutils), git 2.43.0.
- CPython 3.13.16 (standard library only for the verifier).
- Python package `cryptography` 50.0.1, already installed on the host, used
  only inside `tests/test_primitives.py` to cross-check the pure-Python
  Ed25519 implementation. The verifier does not import it.

## Chronology

### 2026-10-08T00:10Z. Pinned spec

- Downloaded
  `https://raw.githubusercontent.com/probityai/agent-evidence-vectors/v0.12.1/spec/predicates/adversarial-execution-evidence.md`
  with curl into `spec/adversarial-execution-evidence.md`.
- SHA-256 `759d2383e5da36fa509dc335e6159a20b87641b25ebbadcf1676c55d75ffd8b0`.
  Hash check against the expected value: **MATCH**. Only then was the file
  read.
- Read the whole spec (2322 lines, 22235 words) in full with the Read tool,
  lines 1 to 2323.

### 00:12Z. PyPI README, "What the suite compares" only

- `https://pypi.org/project/agent-evidence-vectors/0.12.1/` downloaded with
  curl to a separate directory outside the repo
  (`scratchpad/dl-pypi/pypi.html`, SHA-256
  `32ed63159c77e21ee19ca1b9aa3213ccf0218eb59539560b132a8e68ef0e18ea`). It was
  a 3038-byte JavaScript challenge stub with no README content. A heading
  scan found nothing.
- `https://pypi.org/pypi/agent-evidence-vectors/0.12.1/json` (the PyPI JSON
  API for the same release, whose `info.description` is the same README)
  downloaded to `scratchpad/dl-pypi/pypi-0.12.1.json`, SHA-256
  `86c515baf564750813480980d67ff08b1751c13872e86ed4491acfaf7ee8084f`.
- To avoid reading anything else, a Python one-liner printed only the
  Markdown heading lines of the description, then printed only the lines of
  the section `### What the suite compares` (description lines 425 to 515).
  Nothing else of the README was printed or read.
- Seen only as heading names in that scan, and **not read**: "Run the suite
  against your verifier", "What the suite judges", "The failure-code
  contract" (parent of the target section), "The registry", "Indeterminate
  vectors", "Conformance vectors", "Condition ids", "On independence", and
  others. These sections, which plausibly describe or list test cases and the
  condition-code registry, were skipped.
- The target section itself names a few vector identifiers in passing
  (`ok-024`, `bad-817`, `ok-055`, `bad-986`) and scripts in the repository
  (`packaging/run_vectors.py`, `scripts/external-rail-gate.py`,
  `scripts/observed-code-closure-gate.py`, `cmd/aee-verify`). Their content
  was not available or opened. The identifiers were not used for anything.
- Learned from the section: argv `<cmd> <vector-file>`, verdict from the exit
  status, last stdout line a one-line JSON object
  `{"verdict", "codes", "result", "tiers"}` plus optional `primaryCode`, key
  policy path in `AEE_SUBSTRATE_KEYS` with shape
  `{"substrateObservationKeys": [{"keyid", "publicKeyHex"}]}`, codes compared
  as a set intersecting a declared set, accept vectors compared on `result`,
  and each vector run with and without the key variable.

### 00:13Z to 00:15Z. Referenced public standards

Downloaded with curl into `scratchpad/dl-std/` (outside the repo):

| URL | SHA-256 | Read? |
| --- | --- | --- |
| https://raw.githubusercontent.com/secure-systems-lab/dsse/master/envelope.md | 3a8e7370671354cf3d3417c818a44dcda02cbc57dce6f4b6a75a84c41c483074 | yes, whole |
| https://raw.githubusercontent.com/secure-systems-lab/dsse/master/protocol.md | 6c0d965475162230f9f461acf634b4d4b409eab1a1839d31a9c24c76b3676253 | lines 1 to 120 (PAE, base64) |
| https://raw.githubusercontent.com/in-toto/attestation/main/spec/v1/statement.md | cbe684a18b812b8b613d9202eb43b2ea24477f91a2ad6ca5be935185a455ebea | yes, whole |
| https://raw.githubusercontent.com/in-toto/attestation/main/spec/v1/field_types.md | 7c14b278a5d14191b7284bac3b05565b91940ca619fedd5f08f3a3498e9a37aa | yes, whole (Timestamp) |
| https://raw.githubusercontent.com/in-toto/attestation/main/spec/v1/README.md | 2c1b2b94b23a10783f7c3a7f69e092f1dd704f1bb9b54e0c36174612ec5653c3 | only the "Parsing rules" section via grep |
| https://raw.githubusercontent.com/in-toto/attestation/main/spec/v1/resource_descriptor.md | bee71bedd6a957771233cbbe6494144157b865992e53cc91d607a8e02a34c58a | downloaded, not read |
| https://raw.githubusercontent.com/in-toto/attestation/main/spec/v1/digest_set.md | 0b1889fdea7f6d623b41555632aedf04ee4398cf02a32002060608c75ebb038e | downloaded, not read |

These are the framework documents the spec cites (Statement v1, DSSE,
Timestamp field type, parsing rules). None is under `spec/predicates/`, and
none is in-toto/attestation PR #570 or its discussion.

Attempts that failed, with no content obtained:

- `https://www.rfc-editor.org/rfc/rfc8032.txt`, `https://www.ietf.org/rfc/rfc8032.txt`,
  `https://datatracker.ietf.org/doc/html/rfc8032`: the network proxy answered
  403 to CONNECT (host policy).
- `https://raw.githubusercontent.com/ietf-tools/rfc-txt/main/rfc8032.txt`:
  HTTP 404 body (`404: Not Found`, 14 bytes, SHA-256
  `d5558cd419c8d46bdc958064cb97f963d1ea793866414c025906ec15033512ed`).

Consequence: RFC 8785 (JCS), RFC 7493 (I-JSON), RFC 3339, RFC 6962, RFC 4648
and RFC 8032 were implemented from the model's own knowledge of these
standards, without consulting their text in this session. The JCS number
formatting and UTF-16 ordering, the PAE definition, the RFC 6962 split, and
Ed25519 (RFC 8032 section 7.1 test 1, recalled from memory, plus 20 random
cross-checks against the `cryptography` package) are checked in
`tests/test_primitives.py`.

### 00:16Z onward. Build

- `git init`, first commit of the pinned spec.
- Wrote `aee_verify.py` (strict I-JSON parser, JCS, PAE, RFC 6962, pure-Python
  Ed25519, the four byte-pure validity steps, result recompute, digest
  integrity, evidence tier, one-line JSON output).
- Wrote `tests/gen_cases.py` (generates 118 own statements from the spec text:
  21 accept, 97 reject), `tests/run_tests.py`, `tests/test_primitives.py`.
- Bugs found and fixed while testing: a test-sentinel object lost identity
  under `deepcopy` (generator), mutators returning popped values (generator),
  and the seal's observed-set recompute running before later records had
  been parsed (verifier, fixed by a two-pass record analysis). The verifier's
  `main` was also made fail-closed on any unexpected exception.
- Wrote README.md, AMBIGUITIES.md (33 readings) and this log.

## Clean-room statement

I did not access any forbidden source. Specifically:

- Nothing else from probityai/agent-evidence-vectors or any probityai
  repository was cloned, browsed or downloaded: no test vectors, fixtures,
  examples, MANIFEST, changelog, CHANGELOG, release notes, issues or PRs. The
  only file fetched from that repository is the pinned spec.
- in-toto/attestation PR #570 and its discussion were not opened.
- No existing verifier for this predicate was searched for or read. No web
  search was used at all.
- `agent-evidence-vectors` was not pip-installed, and its wheel and sdist
  were neither downloaded nor read. The PyPI JSON metadata file lists release
  file URLs, and none was fetched.
- Of the PyPI README, only the "What the suite compares" section was read
  (see above for the exact procedure and what was skipped).

Closest approaches to a violation, recorded for the study:

1. The PyPI JSON metadata file contains the entire README, including the
   sections on vectors and condition ids. It sits on disk outside the repo.
   Only heading lines and the target section were ever printed.
2. The heading scan exposed section titles that describe vectors and a code
   registry. Their bodies were not read.
3. The target section names four vector identifiers and several repository
   scripts in passing. None was looked up.
4. The pinned spec itself mentions that two other implementations exist and
   that one author reported a finding during review. No implementation
   content appears in the spec, and none was sought.

## Addendum after review (2026-10-07)

Model: all 91 assistant entries in the build agent's session log record `claude-opus-5-5`. The agent was a fresh Claude Code general-purpose subagent whose first message was the build assignment. Its starting context also held an injected copy of the account owner's general memory (about 26,000 characters of profile, preferences and a project note index, including a one-line entry naming the study organizer and his corpus), with no AEE test statements, changelog or verifier code. The log also records one proxy status check (`$HTTPS_PROXY/__agentproxy/status`), which the URL extraction below misses.

Every URL that appears in the agent's tool calls, extracted mechanically from the transcript (including URLs that only appeared as strings in code, such as type URIs and an example URI):

- `http://example.com/HelloWorld`
- `https://datatracker.ietf.org/doc/html/rfc8032`
- `https://in-toto.io/Statement/v1`
- `https://in-toto.io/attestation/adversarial-execution-evidence/v0.7`
- `https://pypi.org/project/agent-evidence-vectors/0.12.1/`
- `https://pypi.org/pypi/agent-evidence-vectors/0.12.1/json`
- `https://raw.githubusercontent.com/ietf-tools/rfc-txt/main/rfc8032.txt`
- `https://raw.githubusercontent.com/in-toto/attestation/main/spec/v1/README.md`
- `https://raw.githubusercontent.com/in-toto/attestation/main/spec/v1/digest_set.md`
- `https://raw.githubusercontent.com/in-toto/attestation/main/spec/v1/field_types.md`
- `https://raw.githubusercontent.com/in-toto/attestation/main/spec/v1/resource_descriptor.md`
- `https://raw.githubusercontent.com/in-toto/attestation/main/spec/v1/statement.md`
- `https://raw.githubusercontent.com/probityai/agent-evidence-vectors/v0.12.1/spec/predicates/adversarial-execution-evidence.md`
- `https://raw.githubusercontent.com/secure-systems-lab/dsse/master/envelope.md`
- `https://raw.githubusercontent.com/secure-systems-lab/dsse/master/protocol.md`
- `https://www.ietf.org/rfc/rfc8032.txt`
- `https://www.rfc-editor.org/rfc/rfc8032.txt`

This list comes from the transcript, not from this log's own narrative. It shows no access to the study's test set, changelog, code registry or other verifiers.

## Second addendum (2026-10-08)

Codex (OpenAI) reviewed `8372071` against the spec, built a separate
comparison verifier in TypeScript after reading this code, and compared
both on 386 statements in 772 paired runs. It found three defects and
supplied patches with regression tests: recognized descriptor fields and
URIs were unchecked, a mid month `23:59:60` was accepted, and signatures on
noncovering records were never evaluated. The account owner's main Claude
session reproduced each regression failing on `8372071` and passing with
its patch, applied all four patches and updated these documents. The
remaining output differences between the two verifiers are the readings in
AMBIGUITIES 23, 25, 32 (`keyid`) and 34. The comparison verifier is internal
and not independent evidence. Codex opened no AEE test set, changelog, code
registry or other AEE verifier. The DSSE protocol page it fetched included a
generic example and test vector section, which it stopped using and did not
use for inputs.
