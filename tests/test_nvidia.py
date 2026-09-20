"""Contract fixtures for released SkillSpector CLI JSON (not graph state)."""

import copy
import json
import unittest

from skill_security.nvidia import command, normalize


ENGINE = {"version": "2.11.2", "revision": "69dcdfb74487d361ba4c811d088cfdea2ff3a9dc"}
PACKAGE = "universal/example"
# Keep the fixture independent of the adapter's analyzer allowlist.
ANALYZERS = (
    "artifact_integrity", "behavioral_ast", "behavioral_taint_tracking",
    "mcp_least_privilege", "mcp_rug_pull", "mcp_tool_poisoning", "meta_analyzer",
    "static_yara", "static_patterns_agent_snooping", "static_patterns_anti_refusal",
    "static_patterns_data_exfiltration", "static_patterns_deserialization",
    "static_patterns_excessive_agency", "static_patterns_harmful_content",
    "static_patterns_memory_poisoning", "static_patterns_output_handling",
    "static_patterns_privilege_escalation", "static_patterns_prompt_injection",
    "static_patterns_rogue_agent", "static_patterns_ssrf", "static_patterns_supply_chain",
    "static_patterns_system_prompt_leakage", "static_patterns_tool_misuse",
)


def successful_report():
    """A docs-only public report; unavailable semantic analyzers are omitted."""
    statuses = []
    for analyzer in ANALYZERS:
        not_applicable = analyzer in {
            "behavioral_ast", "behavioral_taint_tracking", "mcp_least_privilege", "meta_analyzer",
        }
        planned = 0 if not_applicable else 1
        statuses.append({
            "analyzer_id": analyzer,
            "status": "not_applicable" if not_applicable else "completed",
            "planned_work": planned, "completed": planned, "partial": 0,
            "skipped": 0, "failed": 0, "unaccounted": 0,
        })
    return {
        "skill": {"name": "unknown", "source": "/staging/secret-path", "scanned_at": "2026-09-19T12:00:00Z"},
        "risk_assessment": {"score": 0, "severity": "LOW", "recommendation": "SAFE", "max_issue_severity": "NONE"},
        "components": [{"path": "SKILL.md", "type": "markdown", "lines": 10, "executable": False, "size_bytes": 80}],
        "structured_summaries": [], "issues": [], "suppressed_count": 0, "suppressed": [],
        "metadata": {"has_executable_scripts": False, "skillspector_version": "2.11.2",
                     "llm_requested": False, "llm_available": False, "meta_analysis_applied": False,
                     "inference_usage": [], "filtering_mode": "heuristic"},
        "execution_successful": True,
        "analysis_completeness": {
            "total_components": 1, "scanned_components": 1, "coverage_percent": 100.0,
            "is_complete": True, "status": "complete", "execution_successful": True,
            "fully_inspected_files": 1, "partially_inspected_files": 0, "entirely_uninspected_files": 0,
            "ledger_exceptions": [], "scope_exclusions": [], "analyzer_statuses": statuses,
            "references": [], "limitations": [], "findings_before_filtering": 0, "findings_after_filtering": 0,
        },
    }


def finding():
    return {"id": "AST1", "finding_id": "f-1", "category": "dangerous_code", "pattern": "exec",
            "severity": "HIGH", "confidence": 0.9,
            "location": {"file": "private/path.py", "start_line": 1, "end_line": 1},
            "finding": "SECRET-MARKER", "explanation": "SECRET-MARKER", "remediation": "SECRET-MARKER",
            "code_snippet": "SECRET-MARKER", "intent": "unknown", "tags": [], "evidence": {},
            "match_fingerprint": "SECRET-MARKER", "occurrences": []}


class NvidiaAdapterTests(unittest.TestCase):
    def normalized(self, report):
        return normalize(report, package=PACKAGE, engine=ENGINE)

    def test_command_is_shell_free_single_package_static_scan(self):
        self.assertEqual(command("/tools path/skillspector", "/stage/$odd; name", "/tmp/report.json"), [
            "/tools path/skillspector", "scan", "/stage/$odd; name", "--no-llm",
            "--fail-on-incomplete", "--format", "json", "--output", "/tmp/report.json",
        ])

    def test_complete_docs_only_scan_is_no_findings_without_metadata_quality_gates(self):
        output = self.normalized(successful_report())
        self.assertEqual(output["status"], "no-findings")
        self.assertEqual(output["errors"], [])
        self.assertTrue(output["coverage"]["complete"])
        self.assertEqual(output["coverage"]["scanned_components"], 1)
        self.assertEqual(output["coverage"]["exclusion_count"], 0)
        self.assertEqual(output["engine"], "nvidia")
        self.assertEqual(output["package"], PACKAGE)

    def test_public_issues_are_retained_even_below_vendor_risk_threshold(self):
        report = successful_report()
        report["issues"] = [finding(), finding()]
        next(row for row in report["analysis_completeness"]["analyzer_statuses"]
             if row["analyzer_id"] == "meta_analyzer")["status"] = "disabled"
        report["risk_assessment"].update(score=25, recommendation="CAUTION")
        output = self.normalized(report)
        self.assertEqual(output["status"], "findings")
        self.assertEqual(output["findings"], [{"rule_id": "AST1", "severity": "high"}])
        serialized = json.dumps(output)
        for private in ("SECRET-MARKER", "private/path.py", "/staging/secret-path", "explanation", "risk_assessment"):
            self.assertNotIn(private, serialized)

    def test_internal_graph_fields_never_substitute_for_cli_json(self):
        output = self.normalized({"findings": [], "risk_score": 0, "filtered_findings": []})
        self.assertEqual(output["status"], "incomplete")
        self.assertIn("invalid_findings", output["errors"])
        self.assertIn("missing_completeness", output["errors"])

    def test_partial_analysis_preserves_valid_findings_and_removes_diagnostics(self):
        report = successful_report()
        report["issues"] = [finding()]
        report["analysis_completeness"].update(
            is_complete=False, status="partial", scanned_components=0, fully_inspected_files=0,
            partially_inspected_files=1, coverage_percent=0.0, limitations=["SECRET-MARKER"])
        output = self.normalized(report)
        self.assertEqual(output["status"], "incomplete")
        self.assertEqual(output["findings"], [{"rule_id": "AST1", "severity": "high"}])
        self.assertIn("analysis_incomplete", output["errors"])
        self.assertNotIn("SECRET-MARKER", json.dumps(output))

    def test_operational_failure_is_incomplete_even_with_zero_risk(self):
        report = successful_report()
        report["execution_successful"] = False
        report["analysis_completeness"].update(
            execution_successful=False, is_complete=False, status="failed",
            ledger_exceptions=[{"fatal": True, "reason_code": "read_error", "message": "SECRET-MARKER"}])
        output = self.normalized(report)
        self.assertEqual(output["status"], "incomplete")
        self.assertIn("execution_failed", output["errors"])
        self.assertFalse(output["coverage"]["execution_successful"])
        self.assertNotIn("SECRET-MARKER", json.dumps(output))

    def test_claimed_complete_does_not_hide_analyzer_failure(self):
        report = successful_report()
        report["analysis_completeness"]["analyzer_statuses"][0].update(status="failed", completed=0, failed=1)
        self.assertIn("analysis_incomplete", self.normalized(report)["errors"])

    def test_missing_static_analyzer_is_not_a_clean_dynamic_import_failure(self):
        report = successful_report()
        report["analysis_completeness"]["analyzer_statuses"].pop()
        self.assertIn("missing_analyzers", self.normalized(report)["errors"])

    def test_explicitly_disabled_model_analyzers_are_valid_static_mode(self):
        report = successful_report()
        for analyzer in ("semantic_developer_intent", "semantic_quality_policy", "semantic_security_discovery"):
            report["analysis_completeness"]["analyzer_statuses"].append({
                "analyzer_id": analyzer, "status": "disabled", "planned_work": 0,
                "completed": 0, "partial": 0, "skipped": 0, "failed": 0, "unaccounted": 0})
        self.assertEqual(self.normalized(report)["status"], "no-findings")

    def test_invalid_finding_cannot_be_silently_dropped_into_no_findings(self):
        for bad in ({"id": "https://secret.example/path", "severity": "HIGH"},
                    {"id": "P1", "severity": "SECRET-MARKER"}, {"rule_id": "P1", "severity": "HIGH"}, None):
            with self.subTest(bad=bad):
                report = successful_report()
                report["issues"] = [bad]
                output = self.normalized(report)
                self.assertEqual(output["status"], "incomplete")
                self.assertIn("invalid_finding", output["errors"])
                self.assertNotIn("SECRET-MARKER", json.dumps(output))

    def test_coverage_types_and_contradictions_fail_closed(self):
        for field, value in (("total_components", True), ("coverage_percent", float("nan")),
                             ("scanned_components", 2), ("coverage_percent", 50),
                             ("coverage_percent", 10 ** 400)):
            with self.subTest(field=field, value=value):
                report = successful_report()
                report["analysis_completeness"][field] = value
                output = self.normalized(report)
                self.assertIn("invalid_coverage", output["errors"])
                json.dumps(output, allow_nan=False)

    def test_malformed_analyzer_status_and_counts_do_not_raise_or_pass(self):
        for field, value in (("status", []), ("status", {}), ("completed", "1"),
                             ("planned_work", 5), ("completed", True)):
            with self.subTest(field=field, value=value):
                report = successful_report()
                report["analysis_completeness"]["analyzer_statuses"][0][field] = value
                self.assertEqual(self.normalized(report)["status"], "incomplete")

    def test_declared_directory_exclusion_is_incomplete_despite_vendor_complete(self):
        report = successful_report()
        report["analysis_completeness"]["scope_exclusions"] = [{
            "outcome": "out_of_scope", "path": "node_modules/SECRET-MARKER/",
            "phase": "discovery", "reason_code": "excluded_directory", "fatal": False,
            "message": "SECRET-MARKER"}]
        output = self.normalized(report)
        self.assertEqual(output["status"], "incomplete")
        self.assertEqual(output["errors"], ["excluded_input_scope"])
        self.assertEqual(output["findings"], [])
        self.assertFalse(output["coverage"]["complete"])
        self.assertTrue(output["coverage"]["execution_successful"])
        self.assertEqual(output["coverage"]["exclusion_count"], 1)
        self.assertNotIn("SECRET-MARKER", json.dumps(output))

    def test_any_declared_exclusion_retains_findings_and_reports_coverage_gap(self):
        report = successful_report()
        report["issues"] = [finding()]
        report["analysis_completeness"]["scope_exclusions"] = [{
            "reason_code": "future_vendor_scope_rule", "message": "SECRET-MARKER"}]
        output = self.normalized(report)
        self.assertEqual(output["status"], "incomplete")
        self.assertEqual(output["errors"], ["excluded_input_scope"])
        self.assertEqual(output["findings"], [{"rule_id": "AST1", "severity": "high"}])
        self.assertEqual(output["coverage"]["exclusion_count"], 1)
        self.assertNotIn("SECRET-MARKER", json.dumps(output))

    def test_oversized_finding_arrays_are_explicitly_incomplete(self):
        report = successful_report()
        report["issues"] = [finding()] * 10_001
        output = self.normalized(report)
        self.assertIn("report_limit_exceeded", output["errors"])
        self.assertEqual(len(output["findings"]), 1)

    def test_empty_scan_never_means_no_findings(self):
        report = successful_report()
        report["components"] = []
        self.assertIn("empty_scan", self.normalized(report)["errors"])

    def test_version_mismatch_llm_and_suppression_are_separate_coverage_errors(self):
        cases = (("version_mismatch", lambda r: r["metadata"].update(skillspector_version="2.11.1")),
                 ("unexpected_scan_mode", lambda r: r["metadata"].update(llm_requested=True)),
                 ("unexpected_suppression", lambda r: r.update(suppressed_count=1, suppressed=[finding()])))
        for error, mutate in cases:
            with self.subTest(error=error):
                report = successful_report()
                mutate(report)
                self.assertIn(error, self.normalized(report)["errors"])

    def test_new_version_same_public_contract_and_new_analyzers_are_accepted(self):
        report = successful_report()
        report["metadata"]["skillspector_version"] = "2.12.0"
        extra = copy.deepcopy(report["analysis_completeness"]["analyzer_statuses"][0])
        extra["analyzer_id"] = "future_detector"
        report["analysis_completeness"]["analyzer_statuses"].append(extra)
        output = normalize(report, package=PACKAGE, engine={"version": "v2.12.0"})
        self.assertEqual(output["status"], "no-findings")

    def test_normalization_does_not_mutate_input(self):
        report = successful_report()
        original = copy.deepcopy(report)
        self.normalized(report)
        self.assertEqual(report, original)

    def test_runner_package_binding_uses_public_skill_source_with_lexical_normalization(self):
        for source, expected in (("/staging/package/", "/staging/package"),
                                 ("C:\\Stage\\Package", "c:/stage/package/")):
            with self.subTest(source=source):
                report = successful_report()
                report["skill"]["source"] = source
                output = normalize(report, package=PACKAGE, engine={**ENGINE, "expected_package_dir": expected})
                self.assertEqual(output["status"], "no-findings")
                self.assertTrue(output["coverage"]["package_path_bound"])
                self.assertNotIn(source, json.dumps(output))

    def test_mismatched_or_missing_package_identity_is_never_attributed_as_clean(self):
        for skill in ({"source": "/other/package"}, {"source": "relative/package"}, {}, None):
            with self.subTest(skill=skill):
                report = successful_report()
                report["skill"] = skill
                output = normalize(report, package=PACKAGE, engine={**ENGINE, "expected_package_dir": "/staging/package"})
                self.assertEqual(output["status"], "incomplete")
                self.assertFalse(output["coverage"]["package_path_bound"])
                self.assertTrue({"package_path_mismatch", "invalid_package_path"}.intersection(output["errors"]))
                self.assertNotIn("/other/package", json.dumps(output))

    def test_invalid_expected_package_path_fails_closed(self):
        output = normalize(successful_report(), package=PACKAGE,
                           engine={**ENGINE, "expected_package_dir": "relative/package"})
        self.assertIn("invalid_expected_package_path", output["errors"])

    def test_non_object_report_is_incomplete(self):
        self.assertEqual(self.normalized(None)["errors"], ["invalid_report"])

    def test_full_file_coverage_retains_precise_ledger_gap_without_private_text(self):
        report = successful_report()
        report["analysis_completeness"]["ledger_exceptions"] = [
            {"reason_code": "reference_unresolved", "fatal": False, "path": "SECRET-MARKER"},
            {"reason_code": "SECRET-MARKER", "message": "SECRET-MARKER", "fatal": True},
        ]
        output = self.normalized(report)
        self.assertEqual(output["status"], "incomplete")
        self.assertEqual(output["coverage"]["coverage_percent"], 100)
        self.assertEqual(output["coverage"]["ledger_exception_count"], 2)
        self.assertEqual(output["coverage"]["ledger_fatal_count"], 1)
        self.assertEqual(output["coverage"]["ledger_reason_counts"], {"reference_unresolved": 1, "unknown": 1})
        self.assertIn("ledger_exceptions", output["coverage"]["incomplete_reasons"])
        self.assertNotIn("SECRET-MARKER", json.dumps(output))

    def test_unknown_analyzer_diagnostics_are_bounded_and_redacted(self):
        report = successful_report()
        row = dict(report["analysis_completeness"]["analyzer_statuses"][0])
        row.update(analyzer_id="SECRET-MARKER", status="SECRET-MARKER", reason_code="SECRET-MARKER")
        report["analysis_completeness"]["analyzer_statuses"].extend([row] * 100)
        output = self.normalized(report)
        self.assertEqual(output["status"], "incomplete")
        self.assertLessEqual(len(output["coverage"]["analyzer_details"]), 64)
        self.assertIn("analyzer_status", output["coverage"]["incomplete_reasons"])
        self.assertNotIn("SECRET-MARKER", json.dumps(output))

    def test_incomplete_work_is_distinct_from_completed_file_counts(self):
        report = successful_report()
        report["analysis_completeness"]["analyzer_statuses"][0].update(completed=0, skipped=1)
        output = self.normalized(report)
        self.assertEqual(output["coverage"]["coverage_percent"], 100)
        self.assertIn("analyzer_work_incomplete", output["coverage"]["incomplete_reasons"])
        self.assertEqual(output["status"], "incomplete")


if __name__ == "__main__":
    unittest.main()
