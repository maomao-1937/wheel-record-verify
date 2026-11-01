"""Behavioral tests built before the verifier implementation."""
import base64
import csv
import hashlib
import importlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
RECORD = "demo-1.dist-info/RECORD"


def digest(data, algorithm="sha256"):
    return algorithm + "=" + base64.urlsafe_b64encode(
        hashlib.new(algorithm, data).digest()).rstrip(b"=").decode("ascii")


def manifest(rows):
    out = io.StringIO(newline="")
    csv.writer(out, lineterminator="\n").writerows(rows)
    return out.getvalue().encode("utf-8")


def archive(files=None, rows=None, extra=(), compression=zipfile.ZIP_STORED):
    files = {"demo/__init__.py": b"value = 1\n"} if files is None else files
    if rows is None:
        rows = [(name, digest(data), str(len(data))) for name, data in files.items()]
        rows.append((RECORD, "", ""))
    out = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(out, "w", compression=compression) as wheel:
            for name, data in [*files.items(), (RECORD, manifest(rows)), *extra]:
                wheel.writestr(name, data)
    return out.getvalue()


def mutate_headers(blob, offset, value, fmt="H"):
    data = bytearray(blob)
    local = data.index(b"PK\x03\x04")
    central = data.index(b"PK\x01\x02")
    # Different local/central offsets are passed as a tuple.
    a, b = offset
    struct.pack_into("<" + fmt, data, local + a, value)
    struct.pack_into("<" + fmt, data, central + b, value)
    return bytes(data)


class VerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = importlib.import_module("wheel_record_verify")

    def run_archive(self, data, **limits):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "private-name.whl"
            path.write_bytes(data)
            before = path.read_bytes()
            result = self.api.verify_wheel(path, **limits)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(list(Path(folder).iterdir()), [path])
            self.assertNotIn("private-name", json.dumps(result))
            return result

    def assert_code(self, blob, status, code, **limits):
        report = self.run_archive(blob, **limits)
        self.assertEqual(report["exit_code"], status, report)
        self.assertIn(code, [item["code"] for item in report["issues"]], report)
        return report

    def test_api_exists(self):
        self.assertTrue(callable(getattr(self.api, "verify_wheel", None)))

    def test_comment_profile_with_embedded_end_signature(self):
        base = archive()
        # Replace the zero EOCD comment length and append a bounded comment.
        ordinary = b"ordinary comment"
        accepted = base[:-2] + struct.pack("<H", len(ordinary)) + ordinary
        self.assertEqual(self.run_archive(accepted)["exit_code"], 0)
        embedded = b"comment PK\x05\x06 end"
        unsupported = base[:-2] + struct.pack("<H", len(embedded)) + embedded
        self.assert_code(unsupported, 2, "ZIP_PROFILE_UNSUPPORTED")
        ambiguous = b"PK\x05\x06" + b"\0" * 18
        unsupported = base[:-2] + struct.pack("<H", len(ambiguous)) + ambiguous
        self.assert_code(unsupported, 2, "ARCHIVE_INVALID")

    def test_valid_counts_and_no_raw_content(self):
        report = self.run_archive(archive())
        self.assertEqual(report["exit_code"], 0)
        self.assertEqual(report["summary"]["files"], 2)
        self.assertEqual(report["summary"]["rows"], 2)
        self.assertEqual(report["summary"]["hashed_bytes"], 10)
        self.assertEqual(report["summary"]["covered_files"], 2)
        self.assertEqual(report["summary"]["verified_files"], 1)
        self.assertEqual(report["summary"]["findings"], 0)
        encoded = json.dumps(report)
        for secret in ("demo/", "value =", "demo-1.dist-info", digest(b"value = 1\n")):
            self.assertNotIn(secret, encoded)

    def test_same_size_tamper(self):
        self.assert_code(archive(rows=[("demo/__init__.py", digest(b"value = 2\n"), "10"),
                                      (RECORD, "", "")]), 1, "HASH_MISMATCH")

    def test_different_size_tamper(self):
        self.assert_code(archive(rows=[("demo/__init__.py", digest(b"other"), "5"),
                                      (RECORD, "", "")]), 1, "SIZE_MISMATCH")

    def test_unlisted_file(self):
        self.assert_code(archive(rows=[(RECORD, "", "")]), 1, "UNLISTED_FILE")

    def test_missing_file(self):
        report = self.assert_code(archive(rows=[("absent.py", digest(b"x"), "1"),
                                               (RECORD, "", "")]), 1, "MISSING_FILE")
        self.assertNotIn("absent.py", json.dumps(report))

    def test_missing_self_row_is_finding(self):
        self.assert_code(archive(rows=[("demo/__init__.py", digest(b"value = 1\n"), "10")]),
                         1, "SELF_ROW_MISSING")

    def test_nonempty_self_fields_are_invalid(self):
        self.assert_code(archive(rows=[(RECORD, digest(b""), "0")]), 2, "SELF_ROW_INVALID")

    def test_empty_digest_and_size_are_findings(self):
        self.assert_code(archive(rows=[("demo/__init__.py", "", ""), (RECORD, "", "")]),
                         1, "DIGEST_MISSING")
        self.assert_code(archive(rows=[("demo/__init__.py", digest(b"value = 1\n"), ""),
                                      (RECORD, "", "")]), 1, "SIZE_MISSING")

    def test_quoted_comma_utf8_empty_and_sha_variants(self):
        files = {"pkg/a,b.py": b"", "pkg/中文.py": b"hello", "other": b"z"}
        rows = [(name, digest(data, algorithm), str(len(data)))
                for (name, data), algorithm in zip(files.items(), ("sha256", "sha384", "sha512"))]
        rows.append((RECORD, "", ""))
        self.assertEqual(self.run_archive(archive(files, rows))["exit_code"], 0)

    def test_directories_need_no_rows(self):
        self.assertEqual(self.run_archive(archive(extra=[("demo/", b"")]))["exit_code"], 0)

    def test_directory_row_is_invalid(self):
        self.assert_code(archive(rows=[("demo/", digest(b""), "0"), (RECORD, "", "")],
                                 extra=[("demo/", b"")]), 2, "DIRECTORY_ROW")

    def test_directory_payload_is_invalid(self):
        self.assert_code(archive(extra=[("demo/", b"hidden")]), 2, "DIRECTORY_INVALID")

    def test_safe_path_policy(self):
        for name in ("../x", "/x", "a/./x", "a//x", "a/../x", "a\\x", "C:x", "C:/x"):
            with self.subTest(name=name):
                data = (archive(files={"a/x": b"x"}).replace(b"a/x", b"a\\x")
                        if name == "a\\x" else archive(files={name: b"x"}))
                self.assert_code(data, 2, "MEMBER_PATH_INVALID")

    def test_manifest_path_policy(self):
        self.assert_code(archive(rows=[("../secret", digest(b"x"), "1"), (RECORD, "", "")]),
                         2, "ROW_PATH_INVALID")

    def test_duplicate_names_and_rows(self):
        self.assert_code(archive(extra=[("demo/__init__.py", b"x")]), 2, "DUPLICATE_MEMBER")
        self.assert_code(archive(rows=[(RECORD, "", ""), (RECORD, "", "")]),
                         2, "DUPLICATE_ROW")

    def test_raw_nul_spelling_is_invalid(self):
        data = archive(files={"aXXXX": b"x"})
        # Equal-length mutation preserves ZIP offsets and exposes orig_filename truncation.
        data = data.replace(b"aXXXX", b"a\x00XXX")
        self.assert_code(data, 2, "MEMBER_PATH_INVALID")

    def test_file_directory_alias_and_file_ancestor_are_invalid(self):
        self.assert_code(archive(files={"pkg": b"x", "pkg/x": b"y"}), 2, "MEMBER_CONFLICT")
        self.assert_code(archive(files={"pkg": b"x"}, extra=[("pkg/", b"")]),
                         2, "MEMBER_CONFLICT")

    def test_root_record_selection(self):
        self.assert_code(archive(files={"nested/other.dist-info/RECORD": b""}),
                         2, "RECORD_STRUCTURE")
        self.assert_code(archive(extra=[("other.dist-info/RECORD", b"")]),
                         2, "RECORD_STRUCTURE")
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as wheel:
            wheel.writestr("file", b"x")
        self.assert_code(data.getvalue(), 2, "RECORD_STRUCTURE")

    def test_signature_members_are_unsupported(self):
        for suffix in ("jws", "p7s"):
            self.assert_code(archive(extra=[("demo-1.dist-info/RECORD." + suffix, b"sig")]),
                             2, "SIGNATURE_UNSUPPORTED")

    def test_special_file_modes(self):
        for mode in (stat.S_IFLNK, stat.S_IFIFO, stat.S_IFSOCK):
            info = zipfile.ZipInfo("special")
            info.create_system = 3
            info.external_attr = (mode | 0o644) << 16
            self.assert_code(archive(extra=[(info, b"target")]), 2, "MEMBER_TYPE_UNSUPPORTED")

    def test_encrypted_and_unsupported_compression(self):
        self.assert_code(mutate_headers(archive(), (6, 8), 1), 2, "ENCRYPTION_UNSUPPORTED")
        self.assert_code(mutate_headers(archive(), (8, 10), 12), 2, "COMPRESSION_UNSUPPORTED")

    def test_invalid_size_spellings(self):
        for value in ("01", "+1", "-1", "1.0", " 1", "١", "9" * 30):
            self.assert_code(archive(rows=[("demo/__init__.py", digest(b"x"), value),
                                          (RECORD, "", "")]), 2, "SIZE_INVALID")

    def test_invalid_digest_spellings(self):
        for value in ("sha256=abc", "sha256=" + "A" * 42 + "B", digest(b"x") + "=",
                      "sha256=" + "*" * 43, "SHA256=" + "A" * 43, "sha256"):
            self.assert_code(archive(rows=[("demo/__init__.py", value, "10"),
                                          (RECORD, "", "")]), 2, "DIGEST_INVALID")

    def test_unsupported_algorithm(self):
        self.assert_code(archive(rows=[("demo/__init__.py", "md5=abc", "10"),
                                      (RECORD, "", "")]), 2, "ALGORITHM_UNSUPPORTED")

    def test_bad_csv_and_utf8(self):
        for body in (b"a,b\n", b'"unterminated,b,c\n', b"\xff", b"a,b,c,d\n"):
            data = io.BytesIO()
            with zipfile.ZipFile(data, "w") as wheel:
                wheel.writestr(RECORD, body)
            self.assert_code(data.getvalue(), 2, "RECORD_INVALID")

    def test_crc_failure_is_neutral(self):
        data = bytearray(archive())
        at = data.index(b"value = 1\n")
        data[at] = ord("X")
        self.assert_code(bytes(data), 2, "ARCHIVE_INVALID")

    def test_local_name_disagreement_is_invalid(self):
        data = bytearray(archive())
        at = data.index(b"demo/__init__.py")
        data[at] = ord("X")
        self.assert_code(bytes(data), 2, "ARCHIVE_INVALID")

    def test_underreported_deflate_size_cannot_hide_member_suffix(self):
        data = archive(files={"demo/__init__.py": b"safehidden"},
                       rows=[("demo/__init__.py", digest(b"safe"), "4"), (RECORD, "", "")],
                       compression=zipfile.ZIP_DEFLATED)
        data = mutate_headers(data, (22, 24), 4, "I")
        data = mutate_headers(data, (14, 16), zlib.crc32(b"safe"), "I")
        self.assert_code(data, 2, "ARCHIVE_INVALID")

    def test_stored_size_disagreement_cannot_hide_member_suffix(self):
        data = archive(files={"demo/__init__.py": b"safehidden"},
                       rows=[("demo/__init__.py", digest(b"safe"), "4"), (RECORD, "", "")])
        data = mutate_headers(data, (22, 24), 4, "I")
        data = mutate_headers(data, (14, 16), zlib.crc32(b"safe"), "I")
        self.assert_code(data, 2, "ARCHIVE_INVALID")

    def test_deflate_and_ratio_bound(self):
        self.assertEqual(self.run_archive(archive(compression=zipfile.ZIP_DEFLATED))["exit_code"], 0)
        self.assert_code(archive(files={"large": b"0" * 5000}, compression=zipfile.ZIP_DEFLATED),
                         2, "LIMIT_EXCEEDED", limits=self.api.Limits(max_ratio=2))

    def test_resource_bounds(self):
        for limit in (self.api.Limits(max_archive_bytes=10), self.api.Limits(max_members=1),
                      self.api.Limits(max_member_bytes=5), self.api.Limits(max_total_bytes=10),
                      self.api.Limits(max_record_bytes=5), self.api.Limits(max_rows=1),
                      self.api.Limits(max_path_bytes=5)):
            with self.subTest(limit=limit):
                self.assert_code(archive(), 2, "LIMIT_EXCEEDED", limits=limit)

    def test_truncated_nonzip_and_missing_file(self):
        for data in (b"not a zip", archive()[:-5]):
            self.assert_code(data, 2, "ARCHIVE_INVALID")
        report = self.api.verify_wheel(ROOT / "does-not-exist-private.whl")
        self.assertEqual(report["exit_code"], 2)
        self.assertNotIn("private", json.dumps(report))

    def test_explicit_nonlocal_paths_are_rejected_before_open(self):
        for path in ("https://private.example/package.whl", "file:///private/package.whl",
                     "http:private-package", "smb:private-package", "custom+scheme:value",
                     "//private-server/share/package.whl", "\\\\private-server\\share\\package.whl",
                     "/\\private-server/share/package.whl", "\\/private-server/share/package.whl",
                     "\\\\?\\C:\\private\\package.whl", "\\\\.\\private-device",
                     "relative/https://private.example/package.whl"):
            with self.subTest(path=path), mock.patch.object(self.api.os, "open", side_effect=OSError) as opened:
                report = self.api.verify_wheel(path)
                self.assertEqual(report["exit_code"], 2)
                self.assertEqual(report["issues"], [{"code": "INPUT_NOT_LOCAL"}])
                self.assertIsNone(report["summary"])
                opened.assert_not_called()
                self.assertNotIn("private", json.dumps(report))

    def test_ordinary_local_and_drive_paths_reach_open(self):
        for path in ("package.whl", "folder/package.whl", "./package.whl", "/local/package.whl",
                     "C:/local/package.whl", "C:\\local\\package.whl", "C:package.whl",
                     Path("folder/package.whl")):
            with self.subTest(path=path), mock.patch.object(self.api.os, "open", side_effect=OSError) as opened:
                report = self.api.verify_wheel(path)
                self.assertEqual(report["issues"], [{"code": "INPUT_UNREADABLE"}])
                opened.assert_called_once()

    def test_invalid_limits_rejected(self):
        self.assertRaises(ValueError, self.api.Limits, max_rows=0)
        self.assertRaises(ValueError, self.api.Limits, max_rows=True)

    def test_limit_equality_is_accepted(self):
        data = archive()
        total = sum(item.file_size for item in zipfile.ZipFile(io.BytesIO(data)).infolist())
        record_size = len(manifest([("demo/__init__.py", digest(b"value = 1\n"), "10"),
                                    (RECORD, "", "")]))
        report = self.run_archive(data, limits=self.api.Limits(
            max_archive_bytes=len(data), max_members=2, max_total_bytes=total,
            max_record_bytes=record_size, max_rows=2))
        self.assertEqual(report["exit_code"], 0)

    def test_data_descriptor_archives_are_supported(self):
        class Unseekable(io.BytesIO):
            def seekable(self):
                return False
            def seek(self, *args):
                raise io.UnsupportedOperation("seek")
        out = Unseekable()
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as wheel:
            wheel.writestr("module", b"x")
            wheel.writestr(RECORD, manifest([("module", digest(b"x"), "1"), (RECORD, "", "")]))
        self.assertEqual(self.run_archive(out.getvalue())["exit_code"], 0)

    def test_zip64_extra_metadata_is_explicitly_unsupported(self):
        info = zipfile.ZipInfo("extra")
        info.extra = b"\x01\x00\x00\x00"
        self.assert_code(archive(extra=[(info, b"x")]), 2, "ZIP_PROFILE_UNSUPPORTED")

    def test_large_deflate_uses_complete_chunked_stream(self):
        # Repeated hash blocks give modest compression without the default ratio ceiling.
        data = b"".join(hashlib.sha256(str(i).encode()).digest() for i in range(10000))
        result = self.run_archive(archive(files={"module": data}, compression=zipfile.ZIP_DEFLATED))
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["summary"]["verified_bytes"], len(data))

    def test_invalid_late_member_discards_partial_counts(self):
        data = archive(extra=[("late", b"private-content")])
        data = data.replace(b"private-content", b"Xrivate-content")
        report = self.assert_code(data, 2, "ARCHIVE_INVALID")
        self.assertIsNone(report["summary"])
        self.assertEqual(len(report["issues"]), 1)

    def test_central_count_cannot_bypass_member_limit(self):
        data = bytearray(archive())
        end = data.rfind(b"PK\x05\x06")
        struct.pack_into("<HH", data, end + 8, 1, 1)
        self.assert_code(bytes(data), 2, "LIMIT_EXCEEDED", limits=self.api.Limits(max_members=1))

    def test_deterministic_results(self):
        data = archive()
        self.assertEqual(self.run_archive(data), self.run_archive(data))

    def test_sample_generator_is_deterministic_and_exercises_exit_codes(self):
        script = ROOT / "examples" / "make_samples.py"
        self.assertTrue(script.is_file(), "Missing documented deterministic fixture generator")
        spec = importlib.util.spec_from_file_location("sample_generator", script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            module.create_samples(Path(a))
            module.create_samples(Path(b))
            self.assertEqual({item.name for item in Path(a).iterdir()},
                             {"valid.whl", "tampered.whl", "missing.whl", "signature.whl"})
            for filename, code in (("valid.whl", 0), ("tampered.whl", 1),
                                   ("missing.whl", 1), ("signature.whl", 2)):
                first = (Path(a) / filename).read_bytes()
                self.assertEqual(first, (Path(b) / filename).read_bytes())
                self.assertEqual(self.run_archive(first)["exit_code"], code)

    def test_cli_exit_and_json(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input.whl"
            path.write_bytes(archive())
            result = subprocess.run([sys.executable, "wheel_record_verify.py", str(path)],
                                    cwd=ROOT, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["exit_code"], 0)
            self.assertEqual(result.stderr, b"")

    def test_cli_errors_do_not_echo_arguments(self):
        result = subprocess.run([sys.executable, "wheel_record_verify.py", "--private-token"],
                                cwd=ROOT, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b"private-token", result.stdout + result.stderr)
        self.assertNotIn(b"Traceback", result.stderr)

    def test_closed_stdout_including_help(self):
        for arguments in (["--help"], ["does-not-exist.whl"]):
            with subprocess.Popen([sys.executable, "wheel_record_verify.py", *arguments],
                                  cwd=ROOT, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE) as process:
                process.stdout.close()
                process.stdout = None
                _, error = process.communicate(timeout=20)
                self.assertEqual(process.returncode, 2, error)
                self.assertNotIn(b"Traceback", error)
                self.assertNotIn(b"Exception ignored", error)


class BaselineContract(unittest.TestCase):
    def test_verifier_api_is_present(self):
        spec = importlib.util.find_spec("wheel_record_verify")
        self.assertIsNotNone(spec, "Missing required wheel verifier API")


if __name__ == "__main__":
    unittest.main()
