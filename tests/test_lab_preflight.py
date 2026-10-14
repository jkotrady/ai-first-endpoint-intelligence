import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("lab_preflight", ROOT / "tools/lab_preflight.py")
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class LabPreflightTests(unittest.TestCase):
    def setUp(self):
        all_profiles = json.loads((ROOT / "outputs/windows-matrix.json").read_text())
        self.matrix = {"schema_version": 1, "matrix_id": "synthetic-test", "profiles": [all_profiles["profiles"][0]]}
        self.profile = self.matrix["profiles"][0]
        self.host = {"platform": "Linux", "architecture": "x86_64", "qemu_version": "test-fixture", "kvm_accessible": True}
        self.template = json.loads((ROOT / "outputs/lab-image-manifest.template.json").read_text())

    def prepared(self, profile=None):
        """Synthetic declarations exercise validation, never real license evidence."""
        profile = profile or self.profile
        item = copy.deepcopy(self.template)
        item.update(template=False, profile_id=profile["id"], status="prepared", image_id="synthetic-only", created_at_utc="2026-09-29T00:00:00Z")
        item["source"].update(provider="synthetic fixture", product_edition=profile["product_edition"], media_channel="fixture",
                              download_or_media_reference="synthetic://fixture", media_sha256="0" * 64,
                              verified_against_trusted_source=True, license_evidence_reference="synthetic-test-not-a-license",
                              dev_test_use_authorized=True, virtualization_rights_verified=True)
        item["os"].update(version=profile["version"], architecture=profile["architecture"], build_family=profile["build_family"],
                          exact_build=profile["build_family"] + (".1" if profile["build_family"].startswith("10.") else ""),
                          service_pack=profile["version"], ubr=1,
                          locale="en-US", timezone="UTC", patch_inventory_complete=True)
        item["baseline"].update(snapshot_id="fixture", disk_image_sha256="a" * 64, snapshot_restore_test="passed", network_isolation_test="passed")
        item["virtualization"].update({key: "synthetic" for key in ("hypervisor_version", "machine_type_version", "firmware_version", "cpu_model_flags", "accelerator", "disk_controller", "network_adapter_driver", "vtpm_state_reference")})
        item["virtualization"].update(vcpus=2, ram_mib=4096, secure_boot=True)
        item["approval"].update(operator="test-fixture", verified_at_utc="2026-09-29T00:00:00Z")
        return item

    def test_empty_template_never_passes(self):
        errors = lab.validate_manifest(self.profile, self.template)
        self.assertIn("template_is_not_evidence", errors)
        self.assertIn("unconfirmed_source:dev_test_use_authorized", errors)

    def test_missing_required_profile_blocks(self):
        report = lab.assess(self.matrix, [], self.host)
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["profiles"][0]["issues"], ["missing_image_manifest"])

    def test_duplicate_matrix_profile_is_invalid_input(self):
        self.matrix["profiles"].append(copy.deepcopy(self.profile))
        with self.assertRaises(ValueError):
            lab.validate_matrix(self.matrix)

    def test_truthy_strings_are_not_authorization(self):
        item = self.prepared()
        item["source"]["dev_test_use_authorized"] = "false"
        item["source"]["virtualization_rights_verified"] = 1
        errors = lab.validate_manifest(self.profile, item)
        self.assertIn("unconfirmed_source:dev_test_use_authorized", errors)
        self.assertIn("unconfirmed_source:virtualization_rights_verified", errors)

    def test_wrong_architecture_cannot_satisfy_profile(self):
        item = self.prepared()
        item["os"]["architecture"] = "x64"
        self.assertIn("os_mismatch:architecture", lab.validate_manifest(self.profile, item))

    def test_duplicate_manifests_block_even_when_valid(self):
        item = self.prepared()
        report = lab.assess(self.matrix, [item, copy.deepcopy(item)], self.host)
        self.assertEqual(report["status"], "blocked")
        self.assertIn("duplicate_manifest:W01", report["global_issues"])

    def test_qemu_alone_does_not_prove_kvm(self):
        self.host["kvm_accessible"] = False
        report = lab.assess(self.matrix, [self.prepared()], self.host)
        self.assertEqual(report["status"], "blocked")
        self.assertIn("kvm_unavailable_no_performance_validation", report["global_issues"])

    def test_config_success_never_claims_runtime_test(self):
        report = lab.assess(self.matrix, [self.prepared()], self.host)
        self.assertEqual(report["status"], "configuration_checks_passed")
        self.assertEqual(report["runtime_verification"], "not_performed")

    def test_expired_evaluation_blocks(self):
        item = self.prepared()
        item["source"]["evaluation_expiry_utc"] = "2000-01-01T00:00:00Z"
        self.assertIn("evaluation_expired_or_naive_time", lab.validate_manifest(self.profile, item))

    def test_wrong_service_pack_not_hidden_by_build_family(self):
        item = self.prepared()
        item["os"]["service_pack"] = "SP2"
        self.assertIn("service_pack_mismatch", lab.validate_manifest(self.profile, item))

    def test_path_cannot_escape_project(self):
        with self.assertRaises(ValueError):
            lab.project_path("../external-manifest.json")

    def test_windows11_requires_explicit_security_profile(self):
        profile = json.loads((ROOT / "outputs/windows-matrix.json").read_text())["profiles"][9]
        item = self.prepared(profile)
        item["virtualization"]["secure_boot"] = False
        self.assertIn("win11_security_profile_missing", lab.validate_manifest(profile, item))

    def test_unknown_profile_is_not_silently_ignored(self):
        item = self.prepared()
        item["profile_id"] = "UNKNOWN"
        report = lab.assess(self.matrix, [item], self.host)
        self.assertIn("unknown_or_missing_manifest_profile", report["global_issues"])
        self.assertEqual(report["status"], "blocked")

    def test_exact_build_cannot_hide_different_os_family(self):
        profiles = json.loads((ROOT / "outputs/windows-matrix.json").read_text())["profiles"]
        for profile in (profiles[0], profiles[9]):
            with self.subTest(profile=profile["id"]):
                item = self.prepared(profile)
                item["os"]["exact_build"] = "6.1.7601.17514"
                self.assertIn("exact_build_family_mismatch", lab.validate_manifest(profile, item))

    def test_modern_exact_build_must_match_ubr(self):
        profile = json.loads((ROOT / "outputs/windows-matrix.json").read_text())["profiles"][9]
        for value in (profile["build_family"], profile["build_family"] + ".99"):
            with self.subTest(exact_build=value):
                item = self.prepared(profile)
                item["os"]["exact_build"] = value
                self.assertIn("exact_build_ubr_mismatch", lab.validate_manifest(profile, item))

    def test_non_numeric_exact_build_is_rejected(self):
        item = self.prepared()
        item["os"]["exact_build"] = "unknown"
        self.assertIn("invalid_exact_build", lab.validate_manifest(self.profile, item))

    def test_windows11_under_minimum_cannot_pass(self):
        profile = json.loads((ROOT / "outputs/windows-matrix.json").read_text())["profiles"][9]
        for key, value, error in (("vcpus", 1, "win11_vcpus_below_minimum"),
                                  ("ram_mib", 4095, "win11_ram_below_minimum")):
            with self.subTest(resource=key):
                item = self.prepared(profile)
                item["virtualization"][key] = value
                self.assertIn(error, lab.validate_manifest(profile, item))

    def test_windows11_documented_cpu_ram_minimum_is_accepted(self):
        profile = json.loads((ROOT / "outputs/windows-matrix.json").read_text())["profiles"][9]
        self.assertEqual(lab.validate_manifest(profile, self.prepared(profile)), [])


if __name__ == "__main__":
    unittest.main()
