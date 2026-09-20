"""Adapter contracts derived from Cisco 2.1.0 ScanResult.to_dict, not a live scan."""

import copy
import json
import unittest

from skill_security import cisco


def scan_result(findings=None):
    """Representative real envelope including optional fields omitted upstream."""
    findings = [] if findings is None else findings
    return {
        "skill_name": "",  # Sparse skill metadata must not become a quality gate.
        "skill_path": "/staged/draft",
        "is_safe": True,
        "max_severity": "SAFE",
        "findings_count": len(findings),
        "findings": findings,
        "scan_duration_seconds": 0.2,
        "duration_ms": 200,
        "analyzers_used": list(cisco.CORE_ANALYZERS),
        "timestamp": "2026-09-19T00:00:00+00:00",
        "scan_metadata": {
            "policy_name": "strict",
            "policy_version": "1.0",
            "policy_preset_base": "strict",
            "policy_fingerprint_sha256": "a" * 64,
            "rule_contract": {"status": "passed", "schema_version": 2, "checked": 0, "invalid_findings": 0, "errors": []},
            "cel": {"mode": "shadow", "errors": [], "suppressed": 0, "projection_incomplete": 0},
        },
    }


def finding(rule_id="COMMAND_INJECTION", severity="HIGH"):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "title": "PRIVATE SENTINEL",
        "snippet": "PRIVATE SENTINEL",
        "description": "PRIVATE SENTINEL",
        "file_path": "/PRIVATE SENTINEL",
        "metadata": {"secret": "PRIVATE SENTINEL"},
    }


class CiscoAdapterTests(unittest.TestCase):
    def normalize(self, report, **changes):
        engine = {"version": cisco.VERSION, "source_sha": cisco.SOURCE_SHA, "expected_package_dir": "/staged/draft"}
        engine.update(changes)
        return cisco.normalize(report, package="community/draft", engine=engine)

    def assert_incomplete(self, report, code):
        result = self.normalize(report)
        self.assertEqual(result["status"], "incomplete")
        self.assertFalse(result["coverage"]["complete"])
        self.assertIn(code, result["errors"])
        return result

    def test_clean_real_envelope_without_optional_failures_or_analyzability(self):
        report = scan_result()
        before = copy.deepcopy(report)
        result = self.normalize(report)
        self.assertEqual(result["status"], "no-findings")
        self.assertEqual(result["errors"], [])
        self.assertTrue(result["coverage"]["package_path_bound"])
        self.assertTrue(result["coverage"]["complete"])
        self.assertEqual(report, before)

    def test_findings_not_is_safe_or_max_severity_drive_verdict_and_no_raw_text(self):
        result = self.normalize(scan_result([finding()]))
        self.assertEqual(result["status"], "findings")
        self.assertEqual(result["findings"], [{"rule_id": "COMMAND_INJECTION", "severity": "high"}])
        self.assertNotIn("PRIVATE SENTINEL", json.dumps(result))

    def test_no_metadata_maturity_gates_but_real_impersonation_remains(self):
        quality = [finding(rule, "INFO") for rule in cisco.METADATA_QUALITY_RULES]
        result = self.normalize(scan_result(quality))
        self.assertEqual(result["status"], "no-findings")
        self.assertEqual(result["coverage"]["metadata_warning_count"], 4)
        self.assertEqual(result["coverage"]["reported_findings"], 4)
        result = self.normalize(scan_result(quality + [finding("SOCIAL_ENG_ANTHROPIC_IMPERSONATION", "MEDIUM")]))
        self.assertEqual(result["status"], "findings")
        self.assertEqual(len(result["findings"]), 1)

    def test_missing_malformed_and_aggregate_reports_never_clean(self):
        for report in (None, [], {}, {"summary": {"total_skills_scanned": 0}, "results": []}):
            with self.subTest(report=report):
                self.assertEqual(self.normalize(report)["status"], "incomplete")
        report = scan_result()
        report["summary"] = {"skills_skipped": [{"reason": "PRIVATE SENTINEL"}]}
        result = self.assert_incomplete(report, "cisco.unexpected-report-envelope")
        self.assertNotIn("PRIVATE SENTINEL", json.dumps(result))

    def test_missing_failed_unknown_and_duplicate_analyzers(self):
        cases = [
            (["static_analyzer"], "cisco.missing-core-analyzer"),
            (list(cisco.CORE_ANALYZERS) + ["llm_analyzer"], "cisco.unexpected-analyzer"),
            (list(cisco.CORE_ANALYZERS) + ["bytecode"], "cisco.duplicate-analyzer"),
            ([{}], "cisco.invalid-analyzer-list"),
        ]
        for used, code in cases:
            with self.subTest(code=code):
                report = scan_result()
                report["analyzers_used"] = used
                self.assert_incomplete(report, code)
        report = scan_result([finding()])
        report["analyzers_failed"] = [{"analyzer": "bytecode", "error": "PRIVATE SENTINEL"}]
        result = self.assert_incomplete(report, "cisco.analyzer-failed")
        self.assertEqual(len(result["findings"]), 1)
        self.assertNotIn("PRIVATE SENTINEL", json.dumps(result))

    def test_counts_and_invalid_findings_fail_closed_without_echoing_input(self):
        for count in (True, -1, "0", None, 2):
            with self.subTest(count=count):
                report = scan_result()
                report["findings_count"] = count
                self.assertEqual(self.normalize(report)["status"], "incomplete")
        for bad in (None, {}, finding("PRIVATE SENTINEL\n"), finding(severity="SAFE"), finding(severity={})):
            with self.subTest(bad=bad):
                result = self.normalize(scan_result([bad]))
                self.assertEqual(result["status"], "incomplete")
                self.assertNotIn("PRIVATE SENTINEL", json.dumps(result))

    def test_rule_contract_cannot_be_missing_failed_or_type_confused(self):
        for contract in (None, {}, {"status": "failed"}, {"status": "passed", "schema_version": 2, "checked": 0, "invalid_findings": False, "errors": []}):
            with self.subTest(contract=contract):
                report = scan_result()
                report["scan_metadata"]["rule_contract"] = contract
                self.assertEqual(self.normalize(report)["status"], "incomplete")

    def test_policy_drift_invalid_fingerprint_and_malformed_engine_pins(self):
        for key, value in (("policy_name", "permissive"), ("policy_preset_base", "balanced"), ("policy_fingerprint_sha256", "PRIVATE SENTINEL")):
            with self.subTest(key=key):
                report = scan_result()
                report["scan_metadata"][key] = value
                self.assertEqual(self.normalize(report)["status"], "incomplete")
        for version in (None, [], "", "latest", "2.1.0 --extra-index-url=https://example.invalid", "2.1.0\n"):
            with self.subTest(version=version):
                result = self.normalize(scan_result(), version=version)
                self.assertEqual(result["status"], "incomplete")
                self.assertIn("cisco.invalid-version", result["errors"])
        for source_sha in (None, [], "main", "b" * 39, "z" * 40):
            with self.subTest(source_sha=source_sha):
                result = self.normalize(scan_result(), source_sha=source_sha)
                self.assertEqual(result["status"], "incomplete")
                self.assertIn("cisco.invalid-source-sha", result["errors"])

    def test_future_releases_pass_when_the_report_contract_remains_compatible(self):
        for version in ("2.1.1", "2.2.0", "3.0", "3.0.0", "3.1.0rc1", "3.1.0.dev2+gabcd"):
            with self.subTest(version=version):
                result = self.normalize(scan_result(), version=version, source_sha="b" * 40)
                self.assertEqual(result["status"], "no-findings")
                self.assertEqual(result["errors"], [])
                self.assertFalse(result["coverage"]["reported_version_checked"])
        report = scan_result()
        del report["scan_metadata"]["rule_contract"]
        result = self.normalize(report, version="3.0.0", source_sha="b" * 40)
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("cisco.missing-rule-contract", result["errors"])

    def test_optional_reported_version_is_checked_against_the_selected_release(self):
        result = self.normalize(scan_result(), version="3.0.0", reported_version="3.0.0", source_sha="b" * 40)
        self.assertEqual(result["status"], "no-findings")
        self.assertTrue(result["coverage"]["reported_version_checked"])
        for reported, code in (("2.1.0", "cisco.reported-version-mismatch"), ({}, "cisco.invalid-reported-version")):
            with self.subTest(reported=reported):
                result = self.normalize(scan_result(), version="3.0.0", reported_version=reported)
                self.assertEqual(result["status"], "incomplete")
                self.assertIn(code, result["errors"])
        report = scan_result()
        report["scanner_version"] = "3.0.0"
        result = self.normalize(report, version="3.0.0", source_sha="b" * 40)
        self.assertEqual(result["status"], "no-findings")
        self.assertTrue(result["coverage"]["reported_version_checked"])
        report["scanner_version"] = "2.1.0"
        result = self.normalize(report, version="3.0.0", reported_version="3.0.0")
        self.assertEqual(result["status"], "incomplete")
        self.assertIn("cisco.reported-version-mismatch", result["errors"])

    def test_shadow_projection_limits_are_visible_without_metadata_gate(self):
        report = scan_result()
        report["scan_metadata"]["cel"]["projection_incomplete"] = 1
        result = self.normalize(report)
        self.assertEqual(result["status"], "no-findings")
        self.assertEqual(result["coverage"]["cel_projection_incomplete"], 1)
        for key, value, code in (("mode", "enforce", "cisco.unexpected-cel-mode"), ("suppressed", 1, "cisco.unexpected-finding-suppression"), ("errors", [{"code": "PRIVATE SENTINEL"}], "cisco.cel-error")):
            with self.subTest(key=key):
                changed = copy.deepcopy(report)
                changed["scan_metadata"]["cel"][key] = value
                result = self.assert_incomplete(changed, code)
                self.assertNotIn("PRIVATE SENTINEL", json.dumps(result))

    def test_loader_rejection_and_unanalyzed_content_are_incomplete(self):
        report = scan_result([finding("SKILL_LOAD_REJECTED_LIMIT")])
        report["analyzers_used"] = ["skill_loader"]
        report["scan_metadata"]["loader"] = {"rejection_used": True, "content_scanned": False}
        self.assert_incomplete(report, "cisco.content-not-scanned")
        for rule in ("BYTECODE_ANALYSIS_UNAVAILABLE", "LOW_ANALYZABILITY", "UNANALYZABLE_BINARY"):
            with self.subTest(rule=rule):
                self.assert_incomplete(scan_result([finding(rule)]), "cisco.content-not-fully-analyzed")

    def test_network_evidence_and_explicit_errors_are_not_ignored(self):
        for key, value, code in (("llm_usage", {"tokens": 1}, "cisco.unexpected-network-analysis"), ("error", "PRIVATE SENTINEL", "cisco.report-error"), ("analyzers_failed", {}, "cisco.invalid-analyzer-failures")):
            with self.subTest(key=key):
                report = scan_result()
                report[key] = value
                self.assert_incomplete(report, code)
        report = scan_result()
        report["scan_metadata"]["adjudicator"] = {"considered": 1}
        self.assert_incomplete(report, "cisco.unexpected-network-analysis")

    def test_package_binding_handles_windows_and_rejects_stale_other_package(self):
        self.assertEqual(self.normalize(scan_result(), expected_package_dir="/staged/other")["status"], "incomplete")
        report = scan_result()
        report["skill_path"] = "C:\\Stage\\Draft"
        result = self.normalize(report, expected_package_dir="c:/stage/draft/")
        self.assertEqual(result["status"], "no-findings")
        self.assertTrue(result["coverage"]["package_path_bound"])
        self.assertEqual(self.normalize(report, expected_package_dir="draft")["status"], "incomplete")

    def test_command_is_argument_vector_with_local_options_only(self):
        argv = cisco.command("scanner executable", "-untrusted; directory", "report file.json")
        self.assertEqual(argv, ["scanner executable", "scan", "--lenient", "--policy", "strict", "--format", "json", "--output", "report file.json", "--", "-untrusted; directory"])
        for bad in ("", "x\x00y", None):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(ValueError, "cisco.invalid-command-argument"):
                    cisco.command("scanner", bad, "report.json")


if __name__ == "__main__":
    unittest.main()
