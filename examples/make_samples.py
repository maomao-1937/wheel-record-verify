#!/usr/bin/env python3
"""Generate small deterministic demonstration archives, never real packages.

This helper explicitly writes four ignored files below examples/generated.
The verifier itself only reads its named input.
"""
import base64
import csv
import hashlib
import io
from pathlib import Path
import stat
import zipfile


RECORD = "demo-1.0.dist-info/RECORD"
FILES = {
    "demo/__init__.py": b"value = 1\n",
    "demo-1.0.dist-info/METADATA": b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n",
    "demo-1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
}


def _record():
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for name, content in FILES.items():
        value = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode("ascii")
        writer.writerow([name, "sha256=" + value, str(len(content))])
    writer.writerow([RECORD, "", ""])
    return output.getvalue().encode("utf-8")


def _archive(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as wheel:
        for name, content in files.items():
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            wheel.writestr(info, content)
    return output.getvalue()


def create_samples(destination):
    """Write only the four named demo archives in the supplied directory."""
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    valid = {**FILES, RECORD: _record()}
    variants = {
        "valid.whl": valid,
        "tampered.whl": {**valid, "demo/__init__.py": b"value = 2\n"},
        "missing.whl": {name: data for name, data in valid.items() if name != "demo/__init__.py"},
        "signature.whl": {**valid, "demo-1.0.dist-info/RECORD.jws": b"demonstration-only"},
    }
    for name, files in variants.items():
        (destination / name).write_bytes(_archive(files))


if __name__ == "__main__":
    create_samples(Path(__file__).resolve().parent / "generated")
    print("Generated four demonstration archives in examples/generated.")
