# Executed verification

Builder environment on 2026-11-01: CPython 3.11.15, Windows 10.0.26300,
standard library only. These results describe the builder's local runs; a
workflow definition alone does not prove a Linux or remote CI run passed.

```console
python -m unittest discover -s tests -v
```

Result: **48 tests passed, zero failures/errors/skips**. The suite uses real
temporary ZIP files, checks unchanged original bytes and no extraction, and
launches CLI scripts by basename with the project root as the working directory.
Subprocesses have timeouts and pipe ownership uses context managers.

Coverage includes:

- same-size and different-size tampering, stale/missing hashes or sizes,
  missing/unlisted members, explicit self-row classification, and counts;
- quoted comma paths, UTF-8 names, empty files, SHA-256/384/512, and directories;
- duplicate names/rows, raw NUL truncation, traversal/drive/backslash paths,
  file/directory conflicts, nested or multiple RECORD members;
- deprecated signatures, special files, encrypted/unsupported compression,
  malformed CSV/UTF-8, sizes, and canonical base64 syntax;
- CRC and local-name disagreement, complete stored/deflate byte reads,
  understated ZIP sizes, late invalid entries discarding partial evidence;
- byte/member/row/path/ratio ceilings and equality boundaries, central-count
  deception, data descriptors, deterministic results;
- CLI JSON/exit semantics, neutral argument errors, and an actual closed stdout
  pipe for both `--help` and an error report (no traceback or exit 120).
- explicit URL/URI, UNC, mixed-slash UNC, and Windows device spelling rejection
  before filesystem access: mocked `os.open` must remain uncalled, while local,
  `pathlib`, absolute, relative, and Windows drive paths still reach it.

## Documented commands

The root `checks.json` is a list of `{args, exit}` cases. The builder executed
all six through subprocesses with captured output and a 20-second timeout:

| Command arguments after `python` | Expected / actual exit |
| --- | --- |
| `examples/make_samples.py` | 0 / 0 |
| `wheel_record_verify.py examples/generated/valid.whl` | 0 / 0 |
| `wheel_record_verify.py examples/generated/tampered.whl` | 1 / 1 |
| `wheel_record_verify.py examples/generated/missing.whl` | 1 / 1 |
| `wheel_record_verify.py examples/generated/signature.whl` | 2 / 2 |
| `wheel_record_verify.py --help` | 0 / 0 |

Generated samples are ignored. Their creation is an explicit helper action;
verification itself only reads. The sample-generator test generates fixtures
in two separate temporary directories and checks identical bytes and all four
expected verification outcomes.

## Test-first evidence

The initial API-presence test was executed before `wheel_record_verify.py`
existed and failed with `Missing required wheel verifier API` (one assertion
failure). The initial full suite also recorded the expected missing-module
setup error. Both logs were retained outside the released source directory.

An initial implementation using size-capped ZIP member reads failed two newly
added regressions: stored and deflated members with understated size/CRC claims
could hide a suffix and produce an incorrect clean result. After independent,
complete raw-stream reads and CRC checks were implemented, both tests passed
in the full suite. The first test run also exposed Windows' fixture-construction
backslash normalization; the test now mutates the raw ZIP member spelling.
The sample-generator presence test also failed before that helper was written.

An additional test failed before ZIP64 extra-field rejection was added, ensuring
the documented non-ZIP64 profile is enforced even without sentinel size fields.

The path-guard regression was executed before its implementation: 12 nonlocal
spelling subcases failed with `INPUT_UNREADABLE` instead of `INPUT_NOT_LOCAL`;
the positive local/drive test already passed. After the guard was added, all
rejections assert `os.open` was not called. No real network path was accessed.
The lexical guard does not certify local mounts, mapped drives, or symlink
backing storage.

Final builder results were 48 tests and six example commands passing. These
fixtures do not establish performance on large production artifacts, complete
wheel specification conformance, package trust, or any reproduced third-party
defect. Release integration and independent reviews may add further evidence.

Quality review additionally found a ZIP comment profile edge: stdlib's index
can mistake EOCD signature bytes inside a comment for the end record. The tool
already refused that sample without a partial result. One added regression
first failed because the code was generic ARCHIVE_INVALID. The preflight now
explicitly rejects this unsupported comment dialect as ZIP_PROFILE_UNSUPPORTED,
while ordinary comments remain accepted. The full suite then passed **49 tests,
zero skips**; RED/GREEN evidence is retained in the enclosing batch. This is a
documented bounded profile restriction, not arbitrary ZIP comment support.
The subsequent independent raw-assembler review also exercised a comment that
looks like a complete fake end record. That ambiguous unsupported layout is
refused with ARCHIVE_INVALID/2 rather than ZIP_PROFILE_UNSUPPORTED/2. The scope
wording and same regression method now explicitly cover this distinction;
neither result reports clean or partial counts.

A separate seeded mutation smoke run (`random.Random(815)`, 1,000 archives with
one to three byte mutations) completed without an uncaught API exception or
input modification: 971 invalid results and 29 clean results. This is a bounded
robustness smoke check, not a correctness oracle for arbitrary ZIP mutations;
changes to out-of-scope metadata can remain clean.
