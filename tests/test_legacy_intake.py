import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


intake = module("legacy_intake", "import_legacy_intake.py")
bundle = module("legacy_bundle", "build_legacy_intake.py")


def fixture(**changes):
    """Invented observations for parser tests, never output from a Windows run."""
    values = {
        "schema": "legacy-intake-1", "kit_version": "0.1.0",
        "scope": "local_wmi_observations_only",
        "os.0.Caption": "Microsoft Windows XP Professional",
        "os.0.Version": "5.1.2600", "os.0.BuildNumber": "2600",
        "os.0.ServicePackMajorVersion": "3", "os.0.ServicePackMinorVersion": "0",
        "os.0.ProductType": "1", "os.0.TotalVisibleMemorySize": "1048576",
        "os.0.FreePhysicalMemory": "524288", "os.0.Locale": "0409",
        "os.0.CurrentTimeZone": "120", "os.count": "1",
        "cpu.0.AddressWidth": "32", "cpu.0.DataWidth": "64", "cpu.0.Architecture": "9",
        "cpu.count": "1", "disk.0.DeviceID": "C:", "disk.0.Size": "25769803776",
        "disk.0.FreeSpace": "12884901888", "disk.0.FileSystem": "NTFS", "disk.count": "1",
    }
    values.update(changes)
    values["end"] = "complete"
    return "\r\n".join(f"{k}={v}" for k, v in values.items()) + "\r\n"


class LegacyIntakeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix = json.loads((ROOT / "outputs/windows-matrix.json").read_text())

    def summarize(self, text=None, encoding="utf-16"):
        return intake.summarize((text or fixture()).encode(encoding), self.matrix, "W01")

    def test_x86_os_on_x64_cpu_is_only_unverified_candidate(self):
        r = self.summarize()
        self.assertEqual(r["possible_profiles_by_version_sp_arch_only"], ["W01"])
        self.assertEqual(r["status"], "needs_human_review")
        for key in ("edition_verification", "license_verification", "isolation_verification", "agent_runtime_verification"):
            self.assertEqual(r[key], "not_performed")
        self.assertFalse(r["patch_inventory_complete"])

    def test_windows7_x64_maps_only_to_w03(self):
        r = self.summarize(fixture(**{"os.0.Version": "6.1.7601", "os.0.BuildNumber": "7601",
                                     "os.0.ServicePackMajorVersion": "1", "cpu.0.AddressWidth": "64"}))
        self.assertEqual(r["possible_profiles_by_version_sp_arch_only"], ["W03"])
        self.assertFalse(r["expected_profile_in_candidates"])

    def test_wrong_service_pack_cannot_match(self):
        self.assertEqual(self.summarize(fixture(**{"os.0.ServicePackMajorVersion": "2"}))["possible_profiles_by_version_sp_arch_only"], [])

    def test_home_caption_never_confirms_professional_edition(self):
        r = self.summarize(fixture(**{"os.0.Caption": "Microsoft Windows XP Home Edition"}))
        self.assertEqual(r["edition_verification"], "not_performed")
        self.assertEqual(r["status"], "needs_human_review")

    def test_server_cannot_match_client(self):
        self.assertEqual(self.summarize(fixture(**{"os.0.ProductType": "3"}))["possible_profiles_by_version_sp_arch_only"], [])

    def test_localized_utf8_and_utf16_preserve_caption(self):
        for encoding in ("utf-8", "utf-8-sig", "utf-16", "utf-16-be"):
            text = fixture(**{"os.0.Caption": "Testovací systém 日本語"})
            raw = text.encode(encoding)
            if encoding == "utf-16-be":
                raw = b"\xfe\xff" + raw
            r = intake.summarize(raw, self.matrix)
            self.assertEqual(r["observed"]["caption"], "Testovací systém 日本語")

    def test_truncated_file_has_no_candidate(self):
        r = self.summarize(fixture().replace("end=complete\r\n", ""))
        self.assertEqual(r["collection_status"], "partial")
        self.assertEqual(r["possible_profiles_by_version_sp_arch_only"], [])

    def test_declared_error_cannot_be_hidden_by_complete(self):
        r = self.summarize(fixture(**{"error.cpu.0.AddressWidth": "null"}))
        self.assertEqual(r["collection_status"], "partial")
        self.assertEqual(r["possible_profiles_by_version_sp_arch_only"], [])

    def test_duplicate_unknown_control_and_post_end_records_rejected(self):
        for text in (fixture().replace("end=", "os.count=1\r\nend="),
                     fixture().replace("end=", "license.approved=true\r\nend="),
                     fixture().replace("Professional", "Pro\x1b[31m"),
                     fixture() + "os.count=1\r\n"):
            with self.subTest(text=text[-50:]), self.assertRaises(ValueError):
                self.summarize(text)

    def test_contradictory_numbers_or_build_have_no_candidate(self):
        for change in ({"os.0.FreePhysicalMemory": "99999999"}, {"os.0.BuildNumber": "7601"},
                       {"disk.0.FreeSpace": "-1"}, {"disk.0.Size": "1"}, {"cpu.count": "0"}):
            with self.subTest(change=change):
                r = self.summarize(fixture(**change))
                self.assertEqual(r["collection_status"], "partial")
                self.assertEqual(r["possible_profiles_by_version_sp_arch_only"], [])

    def test_oversized_and_invalid_encoding_rejected(self):
        for blob in (b"a" * (intake.MAX_BYTES + 1), b"\xff\xfe\x00", b"\xff"):
            with self.assertRaises(ValueError):
                intake.parse_observations(blob)

    def test_source_hash_matches_original_bytes(self):
        raw = fixture().encode("utf-16")
        self.assertEqual(intake.summarize(raw, self.matrix)["source_sha256"], hashlib.sha256(raw).hexdigest())

    def test_path_and_symlink_cannot_escape_project(self):
        with self.assertRaises(ValueError):
            intake.inside_project("../outside.txt")
        with tempfile.TemporaryDirectory(dir=ROOT / "work") as folder:
            link = Path(folder) / "outside"
            link.symlink_to(ROOT.parent)
            with self.assertRaises(ValueError):
                intake.inside_project(str(link / "outside.txt"))

    def test_cli_never_overwrites_existing_report(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "work") as folder:
            source = Path(folder) / "observations.txt"
            report = Path(folder) / "report.json"
            source.write_bytes(fixture().encode("utf-16"))
            report.write_text("keep me")
            r = subprocess.run([sys.executable, str(ROOT / "tools/import_legacy_intake.py"),
                                str(source), "--report", str(report)], capture_output=True)
            self.assertEqual(r.returncode, 1)
            self.assertEqual(report.read_text(), "keep me")

    def test_bundle_is_deterministic_crlf_and_hashes_verify(self):
        raw = bundle.build_archive()
        self.assertEqual(raw, bundle.build_archive())
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            self.assertEqual(set(archive.namelist()), {"legacy-intake/" + n for n in (*bundle.PAYLOAD, "SHA256SUMS.txt")})
            self.assertIsNone(archive.testzip())
            for entry in archive.infolist():
                self.assertEqual(entry.compress_type, zipfile.ZIP_STORED)
                data = archive.read(entry)
                data.decode("ascii")
                self.assertNotIn(b"\n", data.replace(b"\r\n", b""))
            for line in archive.read("legacy-intake/SHA256SUMS.txt").decode().splitlines():
                digest, name = line.split("  ")
                self.assertEqual(hashlib.sha256(archive.read("legacy-intake/" + name)).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
