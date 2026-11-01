#!/usr/bin/env python3
"""Bounded, read-only comparison of wheel member bytes with RECORD declarations.

No package is extracted, imported, installed, or certified. Public reports use
fixed codes and one-based file/row indices, never supplied member names.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import csv
from dataclasses import dataclass, fields
import hashlib
import io
import json
import ntpath
import os
import re
import stat
import struct
import sys
import zipfile
import zlib


@dataclass(frozen=True)
class Limits:
    """Positive integer resource ceilings for trusted API configuration."""

    max_archive_bytes: int = 32 * 1024 * 1024
    max_members: int = 2048
    max_member_bytes: int = 16 * 1024 * 1024
    max_total_bytes: int = 64 * 1024 * 1024
    max_ratio: int = 200
    max_record_bytes: int = 1024 * 1024
    max_rows: int = 4096
    max_path_bytes: int = 1024

    def __post_init__(self):
        for field in fields(self):
            value = getattr(self, field.name)
            if type(value) is not int or value <= 0:
                raise ValueError("limits require positive integers")


class _Invalid(Exception):
    def __init__(self, code, **indices):
        self.issue = {"code": code, **indices}


def _fail(code, **indices):
    raise _Invalid(code, **indices)


def _path_valid(name, directory=False):
    if not name or "\x00" in name or "\\" in name or ntpath.splitdrive(name)[0]:
        return False
    if any(0xD800 <= ord(char) <= 0xDFFF for char in name):
        return False
    if directory:
        if not name.endswith("/"):
            return False
        name = name[:-1]
    return all(part not in ("", ".", "..") for part in name.split("/"))


def _extra_profile(extra):
    position = 0
    while position < len(extra):
        if position + 4 > len(extra):
            _fail("ARCHIVE_INVALID")
        kind, size = struct.unpack_from("<HH", extra, position)
        if kind == 1:
            _fail("ZIP_PROFILE_UNSUPPORTED")
        position += 4 + size
        if position > len(extra):
            _fail("ARCHIVE_INVALID")


def _preflight(blob, limits):
    """Bound central entries before zipfile constructs its object index.

    This selected ZIP profile has one disk, no ZIP64, no prepended/trailing
    material, and a central directory immediately before the end record.
    ZIP comments without embedded EOCD signatures are supported.
    Parsing here only establishes resource bounds;
    zipfile subsequently validates and reads each member.
    """
    end = -1
    start = max(0, len(blob) - 65557)
    candidate = blob.rfind(b"PK\x05\x06", start)
    while candidate >= start:
        if candidate + 22 <= len(blob):
            comment = struct.unpack_from("<H", blob, candidate + 20)[0]
            if candidate + 22 + comment == len(blob):
                end = candidate
                break
        candidate = blob.rfind(b"PK\x05\x06", start, candidate)
    if end < 0:
        _fail("ARCHIVE_INVALID")
    # stdlib ZipFile indexes using the last signature even within a comment.
    # Keep this bounded dialect explicit instead of implying arbitrary comments.
    if b"PK\x05\x06" in blob[end + 22:]:
        _fail("ZIP_PROFILE_UNSUPPORTED")
    disk, central_disk, on_disk, count, size, offset = struct.unpack_from("<4H2I", blob, end + 4)
    if disk or central_disk or on_disk != count:
        _fail("ZIP_PROFILE_UNSUPPORTED")
    if count == 65535 or size == 0xFFFFFFFF or offset == 0xFFFFFFFF:
        _fail("ZIP_PROFILE_UNSUPPORTED")
    if count > limits.max_members:
        _fail("LIMIT_EXCEEDED")
    if offset + size != end or offset > len(blob):
        _fail("ARCHIVE_INVALID")
    position, actual = offset, 0
    while position < end:
        if position + 46 > end or blob[position:position + 4] != b"PK\x01\x02":
            _fail("ARCHIVE_INVALID")
        name_length, extra_length, comment_length, member_disk = struct.unpack_from(
            "<4H", blob, position + 28)
        if member_disk:
            _fail("ZIP_PROFILE_UNSUPPORTED")
        if name_length > limits.max_path_bytes:
            _fail("LIMIT_EXCEEDED")
        flags = struct.unpack_from("<H", blob, position + 8)[0]
        raw_name = blob[position + 46:position + 46 + name_length]
        if any(char >= 128 for char in raw_name) and not flags & 0x800:
            _fail("MEMBER_PATH_INVALID")
        extra_start = position + 46 + name_length
        _extra_profile(blob[extra_start:extra_start + extra_length])
        actual += 1
        if actual > limits.max_members:
            _fail("LIMIT_EXCEEDED")
        position += 46 + name_length + extra_length + comment_length
    if position != end or actual != count:
        _fail("ARCHIVE_INVALID")
    return offset


def _index(wheel, limits):
    infos = wheel.infolist()
    names, files, directories, records = {}, {}, set(), []
    claimed_total = 0
    for info in infos:
        name = info.filename
        directory = info.is_dir()
        if info.orig_filename != name or not _path_valid(name, directory):
            _fail("MEMBER_PATH_INVALID")
        if len(name.encode("utf-8")) > limits.max_path_bytes:
            _fail("LIMIT_EXCEEDED")
        if name in names:
            _fail("DUPLICATE_MEMBER")
        names[name] = info
        if info.flag_bits & (1 | 64):
            _fail("ENCRYPTION_UNSUPPORTED")
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            _fail("COMPRESSION_UNSUPPORTED")
        mode = info.external_attr >> 16 if info.create_system == 3 else 0
        kind = stat.S_IFMT(mode)
        if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
            _fail("MEMBER_TYPE_UNSUPPORTED")
        if (kind == stat.S_IFDIR and not directory) or (kind == stat.S_IFREG and directory):
            _fail("MEMBER_TYPE_UNSUPPORTED")
        if directory and info.file_size:
            _fail("DIRECTORY_INVALID")
        if info.file_size > limits.max_member_bytes:
            _fail("LIMIT_EXCEEDED")
        claimed_total += info.file_size
        if claimed_total > limits.max_total_bytes:
            _fail("LIMIT_EXCEEDED")
        if info.file_size > limits.max_ratio * max(1, info.compress_size):
            _fail("LIMIT_EXCEEDED")
        parts = name.rstrip("/").split("/")
        if len(parts) >= 2 and parts[-2].endswith(".dist-info"):
            if parts[-1] in ("RECORD.jws", "RECORD.p7s"):
                _fail("SIGNATURE_UNSUPPORTED")
            if parts[-1] == "RECORD":
                if len(parts) != 2 or directory:
                    _fail("RECORD_STRUCTURE")
                records.append(name)
        if directory:
            directories.add(name[:-1])
        else:
            files[name] = len(files) + 1
    if len(records) != 1:
        _fail("RECORD_STRUCTURE")
    if set(files) & directories:
        _fail("MEMBER_CONFLICT")
    for name in names:
        parts = name.rstrip("/").split("/")
        if any("/".join(parts[:i]) in files for i in range(1, len(parts))):
            _fail("MEMBER_CONFLICT")
    return names, files, directories, records[0]


def _layout(blob, infos, central_start):
    """Check every local header and establish disjoint compressed byte ranges."""
    ordered = sorted(infos, key=lambda info: info.header_offset)
    if not ordered or ordered[0].header_offset != 0:
        _fail("ZIP_PROFILE_UNSUPPORTED")
    spans = {}
    for index, info in enumerate(ordered):
        offset = info.header_offset
        following = ordered[index + 1].header_offset if index + 1 < len(ordered) else central_start
        if offset < 0 or offset + 30 > following or blob[offset:offset + 4] != b"PK\x03\x04":
            _fail("ARCHIVE_INVALID")
        version, flags, method, _, _, crc, compressed, size, name_len, extra_len = struct.unpack_from(
            "<5H3I2H", blob, offset + 4)
        if compressed == 0xFFFFFFFF or size == 0xFFFFFFFF or version > 20:
            _fail("ZIP_PROFILE_UNSUPPORTED")
        if flags != info.flag_bits or method != info.compress_type:
            _fail("ARCHIVE_INVALID")
        if flags & ~(0x800 | 8 | 6):
            _fail("ZIP_PROFILE_UNSUPPORTED")
        start = offset + 30 + name_len + extra_len
        end = start + info.compress_size
        if start > following or end > following:
            _fail("ARCHIVE_INVALID")
        raw_name = blob[offset + 30:offset + 30 + name_len]
        _extra_profile(blob[offset + 30 + name_len:start])
        try:
            name = raw_name.decode("utf-8" if flags & 0x800 else "ascii")
        except UnicodeError:
            _fail("ARCHIVE_INVALID")
        if name != info.filename:
            _fail("ARCHIVE_INVALID")
        expected = (info.CRC, info.compress_size, info.file_size)
        if flags & 8:
            if any(value not in (0, actual) for value, actual in zip((crc, compressed, size), expected)):
                _fail("ARCHIVE_INVALID")
            descriptor = blob[end:following]
            if len(descriptor) == 16 and descriptor[:4] == b"PK\x07\x08":
                descriptor = descriptor[4:]
            if len(descriptor) != 12 or struct.unpack("<3I", descriptor) != expected:
                _fail("ARCHIVE_INVALID")
        elif (crc, compressed, size) != expected or end != following:
            _fail("ARCHIVE_INVALID")
        spans[info.filename] = (start, end)
    return spans


def _read(blob, span, info, limits, budget, algorithm=None, collect=False):
    """Read the complete raw stored/deflate stream, not ZipExtFile's size cap."""
    length = 0
    chunks = []
    hasher = hashlib.new(algorithm) if algorithm else None
    crc = 0
    decoder = zlib.decompressobj(-15) if info.compress_type == zipfile.ZIP_DEFLATED else None
    position, end = span
    pending = b""
    while position < end or pending:
        if not pending:
            pending = blob[position:min(position + 65536, end)]
            position += len(pending)
        if decoder:
            chunk = decoder.decompress(pending, 65536)
            pending = decoder.unconsumed_tail
            if decoder.unused_data or (decoder.eof and position != end):
                _fail("ARCHIVE_INVALID")
        else:
            chunk, pending = pending, b""
        length += len(chunk)
        budget[0] += len(chunk)
        if length > limits.max_member_bytes or budget[0] > limits.max_total_bytes:
            _fail("LIMIT_EXCEEDED")
        if length > limits.max_ratio * max(1, info.compress_size):
            _fail("LIMIT_EXCEEDED")
        if collect:
            if length > limits.max_record_bytes:
                _fail("LIMIT_EXCEEDED")
            chunks.append(chunk)
        if hasher:
            hasher.update(chunk)
        crc = zlib.crc32(chunk, crc)
    if decoder and not decoder.eof:
        _fail("ARCHIVE_INVALID")
    if length != info.file_size or crc != info.CRC:
        _fail("ARCHIVE_INVALID")
    return length, hasher.digest() if hasher else None, b"".join(chunks)


def _parse_record(data, record_name, directories, limits):
    try:
        text = data.decode("utf-8")
        reader = csv.reader(io.StringIO(text, newline=""), strict=True)
        rows = {}
        for row_index, row in enumerate(reader, 1):
            if row_index > limits.max_rows:
                _fail("LIMIT_EXCEEDED")
            if len(row) != 3:
                _fail("RECORD_INVALID", row_index=row_index)
            path, digest, size = row
            if len(path.encode("utf-8")) > limits.max_path_bytes or len(digest) > 128 or len(size) > 30:
                _fail("LIMIT_EXCEEDED", row_index=row_index)
            if path.endswith("/") or path in directories:
                _fail("DIRECTORY_ROW", row_index=row_index)
            if not _path_valid(path):
                _fail("ROW_PATH_INVALID", row_index=row_index)
            if path in rows:
                _fail("DUPLICATE_ROW", row_index=row_index)
            if path == record_name:
                if digest or size:
                    _fail("SELF_ROW_INVALID", row_index=row_index)
                rows[path] = (row_index, None, None, None)
                continue
            number = None
            if size:
                if not re.fullmatch(r"0|[1-9][0-9]{0,18}", size):
                    _fail("SIZE_INVALID", row_index=row_index)
                number = int(size)
            algorithm, expected = None, None
            if digest:
                if "=" not in digest:
                    _fail("DIGEST_INVALID", row_index=row_index)
                algorithm, encoded = digest.split("=", 1)
                if algorithm not in ("sha256", "sha384", "sha512"):
                    if algorithm.lower() in ("sha256", "sha384", "sha512"):
                        _fail("DIGEST_INVALID", row_index=row_index)
                    _fail("ALGORITHM_UNSUPPORTED", row_index=row_index)
                if not re.fullmatch(r"[A-Za-z0-9_-]+", encoded):
                    _fail("DIGEST_INVALID", row_index=row_index)
                try:
                    expected = base64.b64decode(encoded + "=" * (-len(encoded) % 4),
                                                altchars=b"-_", validate=True)
                except (ValueError, binascii.Error):
                    _fail("DIGEST_INVALID", row_index=row_index)
                canonical = base64.urlsafe_b64encode(expected).rstrip(b"=").decode("ascii")
                if len(expected) != hashlib.new(algorithm).digest_size or encoded != canonical:
                    _fail("DIGEST_INVALID", row_index=row_index)
            rows[path] = (row_index, algorithm, expected, number)
        return rows
    except (UnicodeError, csv.Error):
        _fail("RECORD_INVALID")


def _report(code, issues, summary=None):
    return {"schema_version": 1, "scope": "record-consistency", "exit_code": code,
            "status": ("clean", "findings", "invalid")[code],
            "summary": summary, "issues": issues}


def verify_wheel(path: str | os.PathLike, *, limits: Limits | None = None) -> dict:
    """Return JSON-safe evidence. No archive names/values appear in the report.

    Exit 0: consistency checked; 1: coverage/digest/size findings; 2: invalid,
    unsupported, resource-limited or unreadable input. Invalid reports discard
    partial counts/findings. Indices are one-based archive *file* and CSV row
    ordinals; directory markers have no file index.
    """
    limits = limits if limits is not None else Limits()
    if not isinstance(limits, Limits):
        raise TypeError("limits must be Limits")
    try:
        path = os.fspath(path)
        if not isinstance(path, str):
            _fail("INPUT_NOT_LOCAL")
        spelling = path.replace("\\", "/")
        scheme = re.match(r"([A-Za-z][A-Za-z0-9+.-]*):", spelling)
        if (spelling.startswith("//") or "://" in spelling
                or (scheme is not None and len(scheme.group(1)) != 1)):
            _fail("INPUT_NOT_LOCAL")
        # Open once; read at most the archive ceiling plus the overflow sentinel.
        # Regular local files only: no device or FIFO reads.
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
        with os.fdopen(descriptor, "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                _fail("INPUT_UNREADABLE")
            if os.fstat(source.fileno()).st_size > limits.max_archive_bytes:
                _fail("LIMIT_EXCEEDED")
            blob = source.read(limits.max_archive_bytes + 1)
        if len(blob) > limits.max_archive_bytes:
            _fail("LIMIT_EXCEEDED")
        central_start = _preflight(blob, limits)
        with zipfile.ZipFile(io.BytesIO(blob), "r") as wheel:
            names, files, directories, record_name = _index(wheel, limits)
            spans = _layout(blob, wheel.infolist(), central_start)
            budget = [0]
            if names[record_name].file_size > limits.max_record_bytes:
                _fail("LIMIT_EXCEEDED")
            _, _, record = _read(blob, spans[record_name], names[record_name], limits, budget, collect=True)
            rows = _parse_record(record, record_name, directories, limits)
            issues = []
            def finding(code, **indices):
                issues.append({"code": code, **indices})
            if record_name not in rows:
                finding("SELF_ROW_MISSING", file_index=files[record_name])
            for name, (row_index, algorithm, expected, size) in rows.items():
                if name == record_name:
                    continue
                if name not in files:
                    finding("MISSING_FILE", row_index=row_index)
                if algorithm is None:
                    finding("DIGEST_MISSING", row_index=row_index)
                if size is None:
                    finding("SIZE_MISSING", row_index=row_index)
            hashed_bytes = verified_bytes = verified_files = 0
            for name, info in names.items():
                if name == record_name:
                    continue
                if info.is_dir():
                    _read(blob, spans[name], info, limits, budget)
                    continue
                row = rows.get(name)
                algorithm = row[1] if row and row[1] else "sha256"
                size, actual_digest, _ = _read(blob, spans[name], info, limits, budget, algorithm)
                hashed_bytes += size
                if row is None:
                    finding("UNLISTED_FILE", file_index=files[name])
                    continue
                row_index, _, expected, expected_size = row
                if expected_size is not None and size != expected_size:
                    finding("SIZE_MISMATCH", file_index=files[name], row_index=row_index)
                if expected is not None and actual_digest != expected:
                    finding("HASH_MISMATCH", file_index=files[name], row_index=row_index)
                if expected is not None and actual_digest == expected and size == expected_size:
                    verified_files += 1
                    verified_bytes += size
            summary = {"files": len(files), "rows": len(rows), "directories": len(directories),
                       "covered_files": len(set(files) & set(rows)),
                       "missing_files": len(set(rows) - set(files)),
                       "unlisted_files": len(set(files) - set(rows)),
                       "hashed_bytes": hashed_bytes, "verified_bytes": verified_bytes,
                       "verified_files": verified_files, "read_bytes": budget[0],
                       "findings": len(issues)}
            return _report(1 if issues else 0, issues, summary)
    except _Invalid as error:
        return _report(2, [error.issue])
    except (OSError, ValueError, TypeError):
        return _report(2, [{"code": "INPUT_UNREADABLE"}])
    except (zipfile.BadZipFile, zipfile.LargeZipFile, NotImplementedError,
            RuntimeError, EOFError, UnicodeError, struct.error, zlib.error):
        return _report(2, [{"code": "ARCHIVE_INVALID"}])


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        _fail("ARGUMENT_INVALID")


def main(argv=None):
    parser = _Parser(description="Compare bounded wheel bytes with RECORD; no installation or trust certification.")
    parser.add_argument("wheel", help="local wheel ZIP to read")
    try:
        args = parser.parse_args(argv)
    except _Invalid as error:
        report = _report(2, [error.issue])
    else:
        report = verify_wheel(args.wheel)
    print(json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return report["exit_code"]


def _entry():
    try:
        try:
            code = main()
        except SystemExit as error:  # argparse help still needs an explicit flush.
            code = error.code
        sys.stdout.flush()
        return code
    except (BrokenPipeError, OSError):
        # Repoint the descriptor so interpreter shutdown cannot retry a broken
        # buffered flush and turn the intended code into exit 120.
        try:
            null_fd = os.open(os.devnull, os.O_WRONLY)
            try:
                os.dup2(null_fd, sys.stdout.fileno())
            finally:
                os.close(null_fd)
        except (OSError, ValueError):
            pass
        return 2


if __name__ == "__main__":
    raise SystemExit(_entry())
