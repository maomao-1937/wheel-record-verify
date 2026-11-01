# wheel-record-verify

[![tests](https://github.com/maomao-1937/wheel-record-verify/actions/workflows/tests.yml/badge.svg)](https://github.com/maomao-1937/wheel-record-verify/actions/workflows/tests.yml)

Compare the actual file bytes in a local wheel ZIP with its `RECORD` manifest,
without extracting, installing, or importing a package. Reports contain counts
and fixed issue codes, with file and row indices instead of member names.

**A clean result establishes bounded RECORD consistency only.** An author can
change both the files and their RECORD hashes. This tool does not establish
authenticity, provenance, signatures, safety, installability, metadata validity,
or the state of an installed Python environment.

## Run from source

Python 3.11+ and its standard library are the only requirements. No install step,
dependencies, configuration file, network access, or credentials are required.
Download the repository, open a terminal in its directory, and run:

```console
python wheel_record_verify.py path/to/package.whl
python wheel_record_verify.py --help
```

The path is an explicitly named local regular file; the extension and wheel
filename convention are not validated. A lexical guard runs before filesystem
access: after converting backslashes to slashes for checking, it rejects `//`
prefixes (UNC and Windows device spellings), any `://`, and URI schemes other
than a single-letter Windows drive. Rejections return `INPUT_NOT_LOCAL`, exit 2.
Ordinary relative/absolute paths, Windows drive paths, and `pathlib` paths are
accepted. This spelling check cannot certify the backing storage of a local
mount, mapped drive, or symlink. The archive is opened read-only and
snapshotted into bounded memory. No package code is executed. The CLI emits one
JSON object to stdout, except human-readable `--help`. Argument and input errors
are neutral and never repeat supplied paths or values.

| Exit | Meaning |
| --- | --- |
| 0 | Every covered non-RECORD file matched its declared supported digest and size; coverage is complete. |
| 1 | Coverage, missing required digest/size, or actual digest/size findings. |
| 2 | Invalid, ambiguous, unsupported, resource-limited, unreadable input, invalid arguments, or failed output. No partial clean report. |

## Reproducible examples

This **separate helper writes** four deterministic demo ZIPs under the ignored
`examples/generated/` directory. They are synthetic fixtures, not distributed
packages and not evidence about third-party products.

```console
python examples/make_samples.py
python wheel_record_verify.py examples/generated/valid.whl
python wheel_record_verify.py examples/generated/tampered.whl
python wheel_record_verify.py examples/generated/missing.whl
python wheel_record_verify.py examples/generated/signature.whl
```

Expected exits are `0, 0, 1, 1, 2`, respectively. The tampered demo changes file
bytes without changing RECORD. Its single issue is:

```json
{"code":"HASH_MISMATCH","file_index":1,"row_index":1}
```

The valid demo reports:

```json
{"exit_code":0,"issues":[],"schema_version":1,"scope":"record-consistency","status":"clean","summary":{"covered_files":4,"directories":0,"files":4,"findings":0,"hashed_bytes":115,"missing_files":0,"read_bytes":375,"rows":4,"unlisted_files":0,"verified_bytes":115,"verified_files":3}}
```

`file_index` is one-based central-directory **regular file** order; directories
do not consume an index. `row_index` is one-based CSV row order. These references
allow a caller who already has the artifact to locate a finding without copying
names, file contents, or digests into logs. This is output minimization, not
anonymity: counts and positions still reveal structural information.

`files` includes RECORD, while `hashed_bytes` counts all non-RECORD file bytes
hashed, including unlisted files. `verified_files`/`verified_bytes` count only
non-RECORD files whose declared digest **and** size match. `read_bytes` also
includes RECORD. `covered_files` is the file/row intersection;
`missing_files` counts rows without a file; `unlisted_files` counts files without
a row, including RECORD when its self row is absent. Invalid reports have
`summary: null` and a fixed diagnostic; partial findings are discarded.

## Supported profile and bounds

The tool reads exactly one root `*.dist-info/RECORD` regular member. Other wheel
metadata is not interpreted. CSV must be UTF-8, have exactly three columns per
row, unique safe paths, and canonical decimal sizes (`0` or a nonzero first
digit, at most 19 digits). Supported digests are lowercase `sha256`, `sha384`,
and `sha512`, with canonical URL-safe, unpadded base64 of the correct length.
Quoted commas, UTF-8 names, empty files, and zero-length directory markers are
supported. Paths are compared exactly, without case folding or Unicode
normalization; nothing is extracted to a filesystem.

Missing self row: exit 1 (`SELF_ROW_MISSING`). Duplicate self row: exit 2
(`DUPLICATE_ROW`). A present self row must have both other fields empty,
otherwise exit 2 (`SELF_ROW_INVALID`). Missing digest/size on another file is a
finding; malformed nonempty values are invalid input. Rows naming directories
are invalid, while directory markers themselves need no coverage rows.

ZIP support is deliberately limited to stored/deflated, single-disk, non-ZIP64
archives with matching local/central headers and contiguous member records.
Ordinary 32-bit data descriptors, including optional signatures, and ZIP
comments without embedded EOCD signature bytes (`50 4b 05 06`) are supported.
Comments containing those bytes are unsupported (exit 2) because the stdlib
ZIP index can misidentify them. Identifiable embedded signatures produce
`ZIP_PROFILE_UNSUPPORTED`; ambiguous fake end-record layouts can produce
`ARCHIVE_INVALID`. Neither is a clean result or a complete ZIP validity judgment.
Preambles, padding between members, appended material,
split archives, ZIP64 metadata, special/encrypted entries, unsupported flags,
compression methods, or algorithms are rejected. Actual streams are decompressed
in bounded chunks, checked for a complete deflate stream, CRC, and actual size;
understated header sizes cannot truncate the evidence read.

Unsafe/ambiguous names include absolute or drive-prefixed paths, backslashes,
empty/dot/dot-dot segments, NUL/raw-truncated spellings, duplicate names, and
file/directory or file/ancestor conflicts. Non-ASCII ZIP names must use the
UTF-8 flag. Nested dist-info RECORD members are rejected. Deprecated
`RECORD.jws` / `RECORD.p7s` signature members cause explicit exit 2; no signature
verification is attempted. See [PEP 815](https://peps.python.org/pep-0815/).

Default ceilings, enforced before or during reads:

| Resource | Maximum |
| --- | --- |
| Archive bytes | 32 MiB |
| ZIP members, including directory markers | 2,048 |
| Actual or declared bytes per member | 16 MiB |
| Actual or declared decompressed total | 64 MiB |
| Decompressed/compressed member ratio | 200, using `max(1, compressed_bytes)` |
| RECORD bytes / CSV rows | 1 MiB / 4,096 |
| UTF-8 path bytes | 1,024 |
| Digest field / size field characters | 128 / 30 (size syntax is limited to 19 digits) |

Central records are counted before constructing the ZIP object index. Size and
ratio limits apply to both metadata claims and complete streams. The CLI uses
these fixed defaults; trusted API callers can provide different positive integer
`Limits` ceilings. There is no promise to process large production ML wheels
under these defaults. Unreadable or unsupported inputs are not reported clean.

## Python API and tests

```python
from wheel_record_verify import Limits, verify_wheel

report = verify_wheel("package.whl", limits=Limits(max_archive_bytes=8 * 1024 * 1024))
print(report["exit_code"])
```

The API returns a JSON-safe dictionary for archive/input failures. Invalid
programmer-supplied limits raise `ValueError` or `TypeError`; API callers handle
their own report output. Reports are deterministic for unchanged bytes and
limits. The input is neither modified nor extracted. Verification describes
the captured archive bytes, not a later installation or concurrent filesystem
state.

```console
python -m unittest discover -s tests -v
```

Builder verification: CPython 3.11.15 on Windows, 48 tests and six example
commands passed. Cross-platform CI is defined separately; this local run alone
does not establish Linux behavior. [TESTING.md](TESTING.md) records the executed
checks and development regression evidence. [RESEARCH.md](RESEARCH.md) separates
the source observations, design inference, and alternatives. MIT license.

## 中文说明

这个工具直接读取本地 wheel ZIP 中的真实文件字节，核对 RECORD 声明的哈希、大小和
清单覆盖情况。只读，不解压、不安装、不导入包，不访问网络。需要 Python 3.11+，
仅使用标准库，无额外依赖或配置。文件访问前先拒绝显式 URL、UNC 和 Windows 设备
前缀等非本地路径写法，返回 `INPUT_NOT_LOCAL` / `2`；普通相对、绝对、盘符及
`pathlib` 路径可以使用。这个词法检查不能证明本地挂载、映射盘或符号链接背后的
存储位置。下载源码后，在仓库目录运行：

```console
python wheel_record_verify.py 本地文件.whl
python examples/make_samples.py
python wheel_record_verify.py examples/generated/tampered.whl
python -m unittest discover -s tests -v
```

示例生成器会明确写入 `examples/generated/` 下的四个演示文件；校验器自身不写入
或改动被检查的压缩包。正常输出为 JSON，不回显包内路径、文件内容或哈希，只给出
固定问题代码、文件序号和 CSV 行号。文件序号按 ZIP 中央目录中的普通文件顺序计数，
目录不占号。结构信息仍可能由计数或位置推断，因此这不是匿名化保证。

退出码：`0` 表示本工具范围内的 RECORD 一致；`1` 表示缺文件、未列出文件、缺少
必要字段、大小或哈希不符等发现；`2` 表示输入无效、不支持、超出资源上限、读取或
输出失败。缺少 RECORD 自身行归为 `1`；重复自身行或自身行的哈希/大小非空归为 `2`。
遇到无效输入时丢弃部分计数，不给出“部分验证通过”的结论。

支持 stored/deflate、UTF-8 CSV、sha256/sha384/sha512、带引号的逗号路径、空文件和
无内容的目录标记。不支持 ZIP64、加密、特殊文件、其他压缩/哈希方法和旧签名文件；
也拒绝路径穿越、重名、NUL 截断及含糊的目录结构。默认限制：压缩包 32 MiB、
2,048 个成员、单成员 16 MiB、解压总量 64 MiB、压缩比 200、RECORD 1 MiB、
4,096 行、路径 1,024 个 UTF-8 字节。英文表格列出完整限制和所选 ZIP 范围。

**通过只证明这个有界检查范围内的字节与清单一致。** 修改者可以同时修改内容和
清单；本工具不能证明来源可信、无恶意代码、签名有效、可安装、wheel 元数据合规，
也不检查已安装环境或运行时实际加载的代码。当前构建者实际验证环境为 Windows /
CPython 3.11.15，48 个测试及 6 条示例命令通过；其他平台以对应实际 CI 结果为准。
