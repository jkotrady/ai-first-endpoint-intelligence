#!/usr/bin/env python3
"""Build a deterministic, uncompressed XP-friendly ZIP; no executables or OS media."""
from __future__ import annotations

import argparse
import hashlib
import io
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/legacy-intake"
PAYLOAD = ("README.txt", "run.cmd", "intake.vbs")


def build_archive() -> bytes:
    payload = {}
    for name in PAYLOAD:
        path = (SOURCE / name).resolve()
        if not path.is_relative_to(SOURCE.resolve()):
            raise ValueError("Payload symlink escapes source directory")
        text = path.read_text(encoding="ascii")
        payload[name] = text.replace("\r\n", "\n").replace("\n", "\r\n").encode("ascii")
    hashes = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\r\n" for name, data in payload.items())
    payload["SHA256SUMS.txt"] = hashes.encode("ascii")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        for name, data in payload.items():
            info = zipfile.ZipInfo("legacy-intake/" + name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 0
            info.external_attr = 0x20
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, data)
    return output.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="outputs/legacy-intake-v0.1.0.zip")
    args = parser.parse_args()
    try:
        target = Path(args.output)
        target = (ROOT / target).resolve() if not target.is_absolute() else target.resolve()
        if not target.is_relative_to(ROOT):
            raise ValueError("ZIP output must stay in the project")
        data = build_archive()
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data)
        print(f"bytes={len(data)} sha256={hashlib.sha256(data).hexdigest()}")
        return 0
    except (OSError, ValueError) as exc:
        print(f"Bundle failed: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
