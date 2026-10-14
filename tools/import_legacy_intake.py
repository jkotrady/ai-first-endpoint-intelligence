#!/usr/bin/env python3
"""Import untrusted XP/7 observations; never certify or modify a lab manifest.

Run on modern Python 3.10+. Exit 0: complete observation imported (review
required); 2: partial/inconsistent observation imported; 1: rejected input.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 262144
FIELDS = {
    "os": ("Caption", "Version", "BuildNumber", "ServicePackMajorVersion",
           "ServicePackMinorVersion", "ProductType", "TotalVisibleMemorySize",
           "FreePhysicalMemory", "Locale", "CurrentTimeZone"),
    "cpu": ("AddressWidth", "DataWidth", "Architecture"),
    "disk": ("DeviceID", "Size", "FreeSpace", "FileSystem"),
}
MAX_ROWS = {"os": 1, "cpu": 16, "disk": 26}
HEADERS = {"schema", "kit_version", "scope", "end"}


def inside_project(value: str) -> Path:
    path = Path(value)
    path = (ROOT / path).resolve() if not path.is_absolute() else path.resolve()
    if not path.is_relative_to(ROOT):
        raise ValueError("Input and output must stay inside this project")
    return path


def field_key(key: str) -> bool:
    parts = key.split(".")
    if len(parts) == 2:
        return parts[0] in FIELDS and parts[1] == "count"
    return (len(parts) == 3 and parts[0] in FIELDS
            and re.fullmatch(r"0|[1-9][0-9]?", parts[1]) is not None
            and int(parts[1]) < MAX_ROWS[parts[0]] and parts[2] in FIELDS[parts[0]])


def error_key(key: str) -> bool:
    suffix = key.removeprefix("error.")
    return (suffix == "connection" or suffix in FIELDS
            or any(suffix == f"{group}.{event}" for group in FIELDS
                   for event in ("limit", "enumeration", "empty"))
            or (field_key(suffix) and not suffix.endswith(".count")))


def parse_observations(blob: bytes) -> dict[str, str]:
    if not blob or len(blob) > MAX_BYTES:
        raise ValueError("Empty or oversized observation file")
    if blob.startswith((b"\xff\xfe", b"\xfe\xff")):
        encoding = "utf-16"
    else:
        encoding = "utf-8-sig"
    try:
        text = blob.decode(encoding)
    except UnicodeError as exc:
        raise ValueError("Expected UTF-16 with BOM or UTF-8") from exc
    if any(ord(c) < 32 and c not in "\r\n" for c in text):
        raise ValueError("Control characters in observation file")
    values = {}
    ended = False
    for line in text.splitlines():
        if not line:
            continue
        if ended or "=" not in line or len(line) > 1200:
            raise ValueError("Malformed record or content after end marker")
        key, value = line.split("=", 1)
        if key in values:
            raise ValueError(f"Duplicate observation key: {key}")
        if key not in HEADERS and not field_key(key) and not (key.startswith("error.") and error_key(key)):
            raise ValueError("Unexpected observation key")
        values[key] = value
        ended = key == "end"
    if (values.get("schema") != "legacy-intake-1" or values.get("kit_version") != "0.1.0"
            or values.get("scope") != "local_wmi_observations_only"):
        raise ValueError("Unsupported observation format/version/scope")
    if "end" in values and values["end"] not in {"complete", "partial"}:
        raise ValueError("Invalid end marker")
    return values


def summarize(blob: bytes, matrix: dict, expected_profile: str | None = None) -> dict:
    values = parse_observations(blob)
    issues = []
    if values.get("end") != "complete":
        issues.append("collection_partial_or_interrupted")
    for key in values:
        if key.startswith("error."):
            issues.append(key)

    def number(key: str, minimum: int = 0, maximum: int = 2**64 - 1) -> int | None:
        raw = values.get(key, "")
        if not re.fullmatch(r"-?[0-9]{1,20}", raw) or not minimum <= int(raw) <= maximum:
            issues.append("missing_or_invalid:" + key)
            return None
        return int(raw)

    counts = {}
    for group, limit in MAX_ROWS.items():
        count = number(group + ".count", 1, limit)
        counts[group] = count or 0
        for i in range(count or 0):
            for prop in FIELDS[group]:
                if not values.get(f"{group}.{i}.{prop}"):
                    issues.append(f"missing:{group}.{i}.{prop}")
        for key in values:
            if key.startswith(group + ".") and not key.endswith(".count"):
                if int(key.split(".")[1]) >= (count or 0):
                    issues.append("row_outside_declared_count:" + key)

    version = values.get("os.0.Version")
    family = None
    if version and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?", version):
        family = ".".join(version.split(".")[:3])
        if version.split(".")[2] != values.get("os.0.BuildNumber"):
            issues.append("version_build_number_mismatch")
    else:
        issues.append("missing_or_invalid:os.0.Version")
    sp_major = number("os.0.ServicePackMajorVersion", 0, 255)
    sp_minor = number("os.0.ServicePackMinorVersion", 0, 255)
    product_type = number("os.0.ProductType", 1, 3)
    total_kib = number("os.0.TotalVisibleMemorySize", 1)
    free_kib = number("os.0.FreePhysicalMemory")
    tz_minutes = number("os.0.CurrentTimeZone", -1440, 1440)
    if total_kib is not None and free_kib is not None and free_kib > total_kib:
        issues.append("free_memory_exceeds_total")
    address_widths, cpu_architectures = set(), set()
    for i in range(counts["cpu"]):
        address_widths.add(number(f"cpu.{i}.AddressWidth", 1, 64))
        number(f"cpu.{i}.DataWidth", 1, 64)
        cpu_architectures.add(number(f"cpu.{i}.Architecture", 0, 65535))
    architecture = None
    if address_widths == {32} and cpu_architectures <= {0, 9}:
        architecture = "x86"
    elif address_widths == {64} and cpu_architectures == {9}:
        architecture = "x64"
    else:
        issues.append("unknown_or_conflicting_os_architecture")
    disks = []
    for i in range(counts["disk"]):
        size = number(f"disk.{i}.Size", 1)
        free = number(f"disk.{i}.FreeSpace")
        if size is not None and free is not None and free > size:
            issues.append(f"disk.{i}.free_exceeds_size")
        drive = values.get(f"disk.{i}.DeviceID", "")
        if not re.fullmatch(r"[A-Z]:", drive):
            issues.append(f"disk.{i}.invalid_drive_letter")
        disks.append({"drive": drive, "size_bytes": size, "free_bytes": free,
                      "filesystem": values.get(f"disk.{i}.FileSystem")})
    candidates = []
    # Only suggest by kernel/SP/OS bitness. Caption is localized and not an
    # authoritative edition identifier; EVERY candidate needs human edition review.
    if not issues and product_type == 1 and sp_minor == 0:
        for profile in matrix["profiles"]:
            if (profile["id"] in {"W01", "W02", "W03"} and profile["build_family"] == family
                    and profile["architecture"] == architecture
                    and profile["version"] == f"SP{sp_major}"):
                candidates.append(profile["id"])
    return {
        "schema_version": 1,
        "record_type": "unverified_legacy_intake",
        "imported_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_sha256": hashlib.sha256(blob).hexdigest(),
        "collection_status": "partial" if issues else "complete_observations",
        "status": "needs_human_review",
        "matrix_id": matrix["matrix_id"],
        "expected_profile": expected_profile,
        "possible_profiles_by_version_sp_arch_only": candidates,
        "expected_profile_in_candidates": expected_profile in candidates if expected_profile else None,
        "edition_verification": "not_performed",
        "license_verification": "not_performed",
        "isolation_verification": "not_performed",
        "agent_runtime_verification": "not_performed",
        "patch_inventory_complete": False,
        "observed": {"caption": values.get("os.0.Caption"), "version": version,
                     "build_family": family, "service_pack_major": sp_major,
                     "service_pack_minor": sp_minor, "product_type": product_type,
                     "os_architecture_from_cpu_address_width": architecture,
                     "total_visible_memory_kib": total_kib, "free_physical_memory_kib": free_kib,
                     "locale": values.get("os.0.Locale"), "utc_offset_minutes": tz_minutes,
                     "fixed_disks": disks},
        "issues": sorted(set(issues)),
        "limits": ["Endpoint observations are untrusted and unsigned.",
                   "Candidate profile does not verify edition, license, patch baseline or agent support.",
                   "No VM, remote command, benchmark or Windows installation is performed by this importer.",
                   "This JSON is not a prepared image manifest; do not put it in lab/manifests."],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="Copied observations.txt inside the project")
    parser.add_argument("--profile", choices=("W01", "W02", "W03"))
    parser.add_argument("--report", help="New JSON output path inside the project")
    args = parser.parse_args()
    try:
        with inside_project(args.input).open("rb") as stream:
            blob = stream.read(MAX_BYTES + 1)
        matrix = json.loads((ROOT / "outputs/windows-matrix.json").read_text(encoding="utf-8"))
        report = summarize(blob, matrix, args.profile)
        encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        if args.report:
            target = inside_project(args.report)
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("x", encoding="utf-8") as stream:
                stream.write(encoded)
        # Keep untrusted endpoint values out of terminal output; inspect JSON as data.
        print(json.dumps({"status": report["status"], "collection_status": report["collection_status"],
                          "candidates": report["possible_profiles_by_version_sp_arch_only"],
                          "issues_count": len(report["issues"]), "report_written": bool(args.report)}))
        return 2 if report["issues"] else 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Intake import failed: {type(exc).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
