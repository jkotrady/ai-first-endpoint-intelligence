#!/usr/bin/env python3
"""Read-only lab inventory and manifest checks. Never starts or installs a VM.

Exit 0: configuration checks passed, not proof of runtime compatibility.
Exit 2: prerequisites missing. Exit 1: invalid input or invocation.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")


def project_path(value: str) -> Path:
    path = Path(value)
    path = (ROOT / path).resolve() if not path.is_absolute() else path.resolve()
    if not path.is_relative_to(ROOT):
        raise ValueError("All paths must remain inside the project, including symlink targets")
    return path


def load_json(path: Path) -> dict:
    if path.stat().st_size > 2_000_000:
        raise ValueError(f"JSON input too large: {path.name}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path.name}")
    return value


def validate_matrix(matrix: dict) -> list[dict]:
    if matrix.get("schema_version") != 1 or not matrix.get("matrix_id"):
        raise ValueError("Missing matrix ID or unsupported schema")
    profiles = matrix.get("profiles")
    if not isinstance(profiles, list) or not profiles:
        raise ValueError("Matrix needs profiles")
    seen = set()
    for profile in profiles:
        if not isinstance(profile, dict):
            raise ValueError("Profile must be an object")
        for key in ("id", "product_edition", "version", "build_family", "architecture"):
            if not isinstance(profile.get(key), str) or not profile[key].strip():
                raise ValueError(f"Missing profile field: {key}")
        if profile["id"] in seen:
            raise ValueError("Duplicate profile ID")
        seen.add(profile["id"])
        if type(profile.get("release_required")) is not bool:
            raise ValueError("release_required must be boolean")
    required = [p for p in profiles if p["release_required"]]
    if not required:
        raise ValueError("Matrix contains no required profiles")
    return required


def text_present(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def validate_manifest(profile: dict, manifest: dict) -> list[str]:
    issues = []
    if manifest.get("schema_version") != 1:
        issues.append("unsupported_manifest_schema")
    if manifest.get("template") is not False:
        issues.append("template_is_not_evidence")
    if manifest.get("profile_id") != profile["id"]:
        issues.append("profile_id_mismatch")
    if manifest.get("status") != "prepared":
        issues.append("image_not_prepared")
    for name in ("source", "os", "baseline", "virtualization", "approval"):
        if not isinstance(manifest.get(name), dict):
            issues.append(f"missing_section:{name}")
    if any(i.startswith("missing_section:") for i in issues):
        return issues
    source, os_info, baseline = (manifest[k] for k in ("source", "os", "baseline"))
    if source.get("product_edition") != profile["product_edition"]:
        issues.append("edition_mismatch")
    for key in ("version", "architecture", "build_family"):
        if os_info.get(key) != profile[key]:
            issues.append(f"os_mismatch:{key}")
    for key in ("provider", "media_channel", "download_or_media_reference", "license_evidence_reference"):
        if not text_present(source.get(key)):
            issues.append(f"missing_source:{key}")
    for key in ("verified_against_trusted_source", "dev_test_use_authorized", "virtualization_rights_verified"):
        if source.get(key) is not True:
            issues.append(f"unconfirmed_source:{key}")
    for label, value in (("media_sha256", source.get("media_sha256")), ("disk_image_sha256", baseline.get("disk_image_sha256"))):
        if not isinstance(value, str) or not SHA256.fullmatch(value):
            issues.append(f"invalid_digest:{label}")
    for key in ("image_id", "created_at_utc"):
        if not text_present(manifest.get(key)):
            issues.append(f"missing_image:{key}")
    for key in ("exact_build", "locale", "timezone"):
        if not text_present(os_info.get(key)):
            issues.append(f"missing_os:{key}")
    if os_info.get("patch_inventory_complete") is not True or not isinstance(os_info.get("kb_inventory"), list):
        issues.append("patch_inventory_incomplete")
    if profile["version"] in ("SP1", "SP3") and os_info.get("service_pack") != profile["version"]:
        issues.append("service_pack_mismatch")
    exact_build = os_info.get("exact_build")
    modern_windows = profile["build_family"].startswith("10.")
    if not isinstance(exact_build, str) or not re.fullmatch(r"\d+\.\d+\.\d+(?:\.\d+)?", exact_build):
        issues.append("invalid_exact_build")
    elif ".".join(exact_build.split(".")[:3]) != profile["build_family"]:
        issues.append("exact_build_family_mismatch")
    if modern_windows:
        ubr = os_info.get("ubr")
        if type(ubr) is not int or ubr < 0:
            issues.append("missing_or_invalid_ubr")
        elif exact_build != f"{profile['build_family']}.{ubr}":
            issues.append("exact_build_ubr_mismatch")
    for key in ("no_agent_identity", "no_production_secrets"):
        if baseline.get(key) is not True:
            issues.append(f"unsafe_baseline:{key}")
    for key in ("snapshot_restore_test", "network_isolation_test"):
        if baseline.get(key) != "passed":
            issues.append(f"unverified_baseline:{key}")
    if not text_present(baseline.get("snapshot_id")):
        issues.append("missing_snapshot_id")
    virt = manifest["virtualization"]
    for key in ("hypervisor_version", "machine_type_version", "firmware_version", "cpu_model_flags", "accelerator", "disk_controller", "network_adapter_driver"):
        if not text_present(virt.get(key)):
            issues.append(f"missing_virtualization:{key}")
    for key in ("vcpus", "ram_mib"):
        if type(virt.get(key)) is not int or virt[key] <= 0:
            issues.append(f"invalid_virtualization:{key}")
    if profile["product_edition"].startswith("Windows 11"):
        if type(virt.get("vcpus")) is not int or virt["vcpus"] < 2:
            issues.append("win11_vcpus_below_minimum")
        if type(virt.get("ram_mib")) is not int or virt["ram_mib"] < 4096:
            issues.append("win11_ram_below_minimum")
        if virt.get("secure_boot") is not True or not text_present(virt.get("vtpm_state_reference")):
            issues.append("win11_security_profile_missing")
    for key in ("operator", "verified_at_utc"):
        if not text_present(manifest["approval"].get(key)):
            issues.append(f"missing_review:{key}")
    expiry = source.get("evaluation_expiry_utc")
    if expiry is not None:
        try:
            stamp = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
            if stamp.tzinfo is None or stamp <= datetime.now(timezone.utc):
                issues.append("evaluation_expired_or_naive_time")
        except (AttributeError, TypeError, ValueError):
            issues.append("invalid_evaluation_expiry")
    return issues


def inspect_host() -> dict:
    qemu = shutil.which("qemu-system-x86_64")
    version = None
    if qemu:
        try:
            result = subprocess.run([qemu, "--version"], capture_output=True, text=True, timeout=5, check=True)
            version = result.stdout.splitlines()[0]
        except (OSError, subprocess.SubprocessError, IndexError):
            version = None
    mem = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            name, _, value = line.partition(":")
            if name in {"MemTotal", "MemAvailable"}:
                mem[name] = int(value.split()[0])
    except (OSError, ValueError, IndexError):
        pass
    disk = shutil.disk_usage(ROOT)
    return {"platform": platform.system(), "architecture": platform.machine(), "logical_cpus": os.cpu_count(),
            "memory_kib": mem, "free_disk_gib": round(disk.free / 2**30, 2),
            "qemu_version": version, "kvm_accessible": os.access("/dev/kvm", os.R_OK | os.W_OK),
            "scope": "current execution host only; no VM or benchmark started"}


def assess(matrix: dict, manifests: list[dict], host: dict) -> dict:
    profiles = validate_matrix(matrix)
    required_ids = {p["id"] for p in profiles}
    by_id = {}
    global_issues = []
    for manifest in manifests:
        ident = manifest.get("profile_id")
        if not isinstance(ident, str) or ident not in required_ids:
            global_issues.append("unknown_or_missing_manifest_profile")
            continue
        if ident in by_id:
            global_issues.append(f"duplicate_manifest:{ident}")
        by_id[ident] = manifest
    if host.get("platform") != "Linux" or host.get("architecture") not in {"x86_64", "AMD64"}:
        global_issues.append("host_outside_this_qemu_kvm_check")
    if not host.get("qemu_version"):
        global_issues.append("qemu_unavailable")
    if host.get("kvm_accessible") is not True:
        global_issues.append("kvm_unavailable_no_performance_validation")
    results = []
    for profile in profiles:
        issues = validate_manifest(profile, by_id[profile["id"]]) if profile["id"] in by_id else ["missing_image_manifest"]
        results.append({"profile_id": profile["id"], "configuration_checks": "blocked" if issues else "passed", "issues": issues})
    blocked = bool(global_issues) or any(r["issues"] for r in results)
    return {"schema_version": 1, "checked_at_utc": datetime.now(timezone.utc).isoformat(), "matrix_id": matrix["matrix_id"],
            "status": "blocked" if blocked else "configuration_checks_passed",
            "runtime_verification": "not_performed", "required_profiles": len(profiles),
            "global_issues": global_issues, "profiles": results, "host": host,
            "limitations": ["Declared license, media origin and isolation evidence still require human review.",
                            "This tool does not run the agent, verify signatures or prove Windows support.",
                            "No installer, purchase, VM start, network change or secret lookup is performed."]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", default="outputs/windows-matrix.json")
    parser.add_argument("--manifest-dir", default="work/lab/manifests")
    parser.add_argument("--report", help="Optional new JSON report inside this project; existing file is never overwritten")
    args = parser.parse_args()
    try:
        matrix_path = project_path(args.matrix)
        directory = project_path(args.manifest_dir)
        files = sorted(directory.glob("*.json")) if directory.is_dir() else []
        manifests = [load_json(project_path(str(p))) for p in files]
        report = assess(load_json(matrix_path), manifests, inspect_host())
        output = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        if args.report:
            target = project_path(args.report)
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("x", encoding="utf-8") as stream:
                stream.write(output)
        print(output, end="")
        return 2 if report["status"] == "blocked" else 0
    except (OSError, ValueError, TypeError) as exc:
        print(f"Preflight error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
