# Research and design rationale

Primary pages inspected on 2026-11-01; observations below are not third-party
defect reproductions or claims of adoption.

## Observed facts

- The [PyPA wheel format](https://packaging.python.org/en/latest/specifications/binary-distribution-format/)
  defines wheel as ZIP and describes RECORD file hashes, with RECORD itself
  excepted. This provides a concrete artifact consistency contract.
- [PEP 815](https://peps.python.org/pep-0815/) is Final and deprecates the two
  in-wheel signature members. It points provenance users toward index-hosted
  attestations. Consequently this tool explicitly rejects those members rather
  than implying it verified signatures.
- [Jacobian issue 1233](https://github.com/morluto/jacobian/issues/1233) is a
  historical reporter claim about hashing recorded claims instead of measuring
  installed bytes. It was created 2026-08-11 and closed 2026-08-14; the page marks
  it closed as not planned. The issue was not reproduced here. Its installed
  environment/runtime scope is different from this tool's wheel artifact scope.
- [PyPA wheel](https://github.com/pypa/wheel) documents conversion, unpacking,
  repacking and tag manipulation. It is an established alternative when those
  workflows are the user's goal.

## Inference and original contribution

There is a useful, smaller task between reading manifest metadata and installing
a package: compare the complete local ZIP member bytes to RECORD, and report
coverage separately from matching hashes. That usefulness is a design inference,
not proof of demand, users, or superiority over established tools.

The implementation is original Python standard-library code. Tests construct
synthetic archives and mutate their bytes; no third-party implementation or
large source snippet was copied. In particular, complete stored/deflate reads
are bounded independently from declared uncompressed sizes. Otherwise a ZIP
reader that clips output to the declared size can hide a suffix. The regression
suite demonstrates this concern on local fixtures, not a vulnerability finding
against another project.

The deliberate choices are fixed neutral diagnostics, explicit unsupported
results, finite resource ceilings, zero archive extraction, and no package
execution. Missing self row is a coverage finding; a malformed self row is
invalid structure. Strict ZIP/profile restrictions are our operational scope,
not a claim that all rejected archives violate the entire wheel specification.

## Fair alternatives and boundaries

Use PyPA wheel for its broader wheel manipulation workflow. Use a trusted
expected artifact digest or appropriate attestation verification for origin
questions; RECORD alone is mutable with the package. Use separate metadata
validation and installation tests for package validity and compatibility.
Use environment-specific controls to measure installed or executed code.

This tool does not compare against a registry, install into a sandbox, inspect
Python syntax, validate METADATA/WHEEL, check dependency resolution, verify
signatures, or certify security. It does not establish whether the historical
Jacobian report still applies. Synthetic demonstrations prove the selected
local behavior only. No real-world usage or performance result is claimed.
