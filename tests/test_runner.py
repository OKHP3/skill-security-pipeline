"""Process, staging and aggregate failure boundaries; no vendor install needed."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from skill_security import runner


PACKAGE = "community/draft"


def normalized(name="cisco", status="no-findings", findings=None):
    return {"engine": name, "package": PACKAGE, "status": status,
            "findings": findings or [], "errors": ["synthetic-failure"] if status == "incomplete" else [],
            "coverage": {"complete": status != "incomplete"}}


class ReportAdapter:
    """Exercise supervision separately from the real adapters' contract tests."""

    def __init__(self, name):
        self.name = name
        self.observed_engine = None

    def command(self, executable, package_dir, output):
        return [executable, "scan", package_dir, "--output", output]

    def normalize(self, report, *, package, engine):
        self.observed_engine = engine
        if not isinstance(report, dict) or report.get("kind") != "synthetic-report":
            raise ValueError("PRIVATE-SENTINEL")
        result = normalized(self.name, report.get("status", "no-findings"), report.get("findings"))
        result["package"] = package
        return result


class ScanEngineTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.staged = self.work / "package"
        self.staged.mkdir()
        self.adapters = {name: ReportAdapter(name) for name in ("cisco", "nvidia")}
        patch = mock.patch.dict(runner.ADAPTERS, self.adapters, clear=True)
        patch.start()
        self.addCleanup(patch.stop)

    def scan(self, name="cisco"):
        return runner.scan_engine(name, self.work / "vendor-program", PACKAGE,
                                  self.staged, self.work, {"version": "2.1.0"})

    def process(self, name="cisco", *, content=None, code=0):
        def execute(argv, **kwargs):
            if content is not None:
                (self.work / f"{name}.json").write_text(content, encoding="utf-8")
            kwargs["stdout"].write(b"PRIVATE-SENTINEL\n::error::untrusted diagnostic\n")
            return subprocess.CompletedProcess(argv, code)
        return execute

    def test_missing_report_never_becomes_empty_success(self):
        with mock.patch.object(runner.subprocess, "run", side_effect=self.process()):
            result = self.scan()
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["errors"], ["missing-or-oversized-report"])

    def test_invalid_json_and_wrong_shape_are_sanitized_operational_failures(self):
        for content in ("{ PRIVATE-SENTINEL", "[]", "null", '{"error":"PRIVATE-SENTINEL"}'):
            with self.subTest(content=content):
                with mock.patch.object(runner.subprocess, "run", side_effect=self.process(content=content)):
                    result = self.scan()
                self.assertEqual(result["status"], "incomplete")
                self.assertEqual(result["errors"], ["invalid-scanner-report"])
                self.assertNotIn("PRIVATE-SENTINEL", json.dumps(result))

    def test_report_size_limit_is_checked_before_parsing(self):
        with mock.patch.object(runner, "MAX_REPORT", 16), mock.patch.object(
            runner.subprocess, "run", side_effect=self.process(content=" " * 17)
        ):
            result = self.scan()
        self.assertEqual(result["errors"], ["missing-or-oversized-report"])

    def test_nonzero_cisco_and_unexpected_nvidia_exit_fail_even_with_report(self):
        content = json.dumps({"kind": "synthetic-report", "status": "findings", "findings": [{"rule_id": "P1", "severity": "high"}]})
        for name, code in (("cisco", 1), ("cisco", 2), ("nvidia", 2), ("nvidia", -9)):
            with self.subTest(name=name, code=code):
                with mock.patch.object(runner.subprocess, "run", side_effect=self.process(name, content=content, code=code)):
                    result = self.scan(name)
                self.assertEqual(result["errors"], ["scanner-process-failed"])
                self.assertEqual(result["status"], "incomplete")

    def test_nvidia_findings_exit_is_valid_but_clean_report_contradiction_is_not(self):
        for status in ("findings", "no-findings"):
            with self.subTest(status=status):
                report = {"kind": "synthetic-report", "status": status}
                if status == "findings":
                    report["findings"] = [{"rule_id": "P1", "severity": "high"}]
                with mock.patch.object(runner.subprocess, "run", side_effect=self.process("nvidia", content=json.dumps(report), code=1)):
                    result = self.scan("nvidia")
                self.assertEqual(result["status"], "findings" if status == "findings" else "incomplete")
                if status == "no-findings":
                    self.assertEqual(result["errors"], ["exit-report-contradiction"])

    def test_timeout_and_missing_executable_return_safe_codes(self):
        for exception, code in ((subprocess.TimeoutExpired(["PRIVATE-SENTINEL"], 180, output="PRIVATE-SENTINEL"), "scanner-timeout"),
                                (FileNotFoundError("PRIVATE-SENTINEL"), "invalid-scanner-report")):
            with self.subTest(code=code):
                with mock.patch.object(runner.subprocess, "run", side_effect=exception):
                    result = self.scan()
                self.assertEqual(result["errors"], [code])
                self.assertEqual(result["status"], "incomplete")
                self.assertNotIn("PRIVATE-SENTINEL", json.dumps(result))

    def test_subprocess_has_no_credentials_user_home_or_python_import_injection(self):
        secrets = {key: "PRIVATE-SENTINEL" for key in (
            "GITHUB_TOKEN", "GH_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "VIRUSTOTAL_API_KEY",
            "SKILL_SCANNER_LLM_API_KEY", "AWS_SECRET_ACCESS_KEY", "PYTHONPATH", "PYTHONHOME", "GITHUB_ENV",
            "GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY", "BASH_ENV", "ENV", "HTTP_PROXY", "HTTPS_PROXY",
        )}
        secrets.update(HOME="PRIVATE-SENTINEL", USERPROFILE="PRIVATE-SENTINEL")
        report = json.dumps({"kind": "synthetic-report"})
        with mock.patch.dict(os.environ, secrets), mock.patch.object(
            runner.subprocess, "run", side_effect=self.process(content=report)
        ) as process:
            result = self.scan()
        self.assertEqual(result["status"], "no-findings")
        argv = process.call_args.args[0]
        options = process.call_args.kwargs
        env = options["env"]
        self.assertIsInstance(argv, list)
        self.assertFalse(options.get("shell", False))
        self.assertEqual(options["cwd"], self.work)
        self.assertEqual(options["timeout"], 180)
        self.assertIs(options["stdout"], options["stderr"])
        self.assertTrue(options["stdout"].closed)
        self.assertNotIn("PRIVATE-SENTINEL", json.dumps(env))
        self.assertEqual(env["HOME"], str(self.work))
        self.assertEqual(env["USERPROFILE"], str(self.work))
        self.assertEqual(env["PYTHONNOUSERSITE"], "1")
        self.assertEqual(self.adapters["cisco"].observed_engine["expected_package_dir"], str(self.staged))
        self.assertNotIn("PRIVATE-SENTINEL", json.dumps(result))


class PackageStagingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.env = os.environ.copy()
        self.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        self.git("init", "--quiet")
        self.git("config", "core.autocrlf", "false")

    def git(self, *args):
        return subprocess.run(["git", "-c", "core.hooksPath=" + str(self.root / ".no-hooks"),
                               "-c", "core.fsmonitor=false", "-c", "commit.gpgsign=false",
                               "-c", "user.name=Runner fixture", "-c", "user.email=runner@example.invalid", *args],
                              cwd=self.root, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              check=True, timeout=30).stdout

    def commit(self, files):
        for name, data in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.git("add", "--all")
        self.git("commit", "--quiet", "-m", "inert fixture")
        return self.git("rev-parse", "HEAD").decode().strip()

    def test_sparse_drafts_are_staged_from_git_without_rewriting_original_files(self):
        cases = (
            ({"SKILL.md": b"# Draft\nSummarize supplied notes.\n"}, False),
            ({"references/notes.md": b"A draft outlining a note summarization workflow.\n"}, True),
        )
        for number, (files, generated) in enumerate(cases):
            package = f"community/draft-{number}"
            with self.subTest(package=package):
                head = self.commit({f"{package}/{name}": data for name, data in files.items()})
                # Working-tree content is deliberately different from the pinned blob.
                (self.root / package / next(iter(files))).write_bytes(b"UNCOMMITTED CONTENT")
                seen = []

                def inspect(name, executable, selected, staged, work, pin):
                    self.assertEqual(selected, package)
                    self.assertTrue((staged / "SKILL.md").is_file())
                    for relative, original in files.items():
                        self.assertEqual((staged / relative).read_bytes(), original)
                    seen.append(name)
                    result = normalized(name)
                    result["package"] = package
                    return result

                with mock.patch.object(runner, "scan_engine", side_effect=inspect):
                    result = runner.scan_package(self.root, head, package, {"cisco": Path("cisco"), "nvidia": Path("nvidia")},
                                                 {"cisco": {}, "nvidia": {}})
                self.assertEqual(seen, ["cisco", "nvidia"])
                self.assertEqual(result["content"]["metadata_generated"], generated)
                self.assertEqual(result["content"]["files"], len(files))

    def test_staging_failure_accounts_for_both_unrun_engines(self):
        with mock.patch.object(runner, "stage", side_effect=ValueError("PRIVATE-SENTINEL")), mock.patch.object(runner, "scan_engine") as scan:
            result = runner.scan_package(self.root, "a" * 40, PACKAGE, {}, {})
        scan.assert_not_called()
        self.assertIsNone(result["content"])
        self.assertEqual({e["engine"] for e in result["engines"]}, {"cisco", "nvidia"})
        self.assertTrue(all(e["status"] == "incomplete" for e in result["engines"]))
        self.assertNotIn("PRIVATE-SENTINEL", json.dumps(result))


class AggregateTests(unittest.TestCase):
    def aggregate(self, engines):
        package = {"package": PACKAGE, "content": {"files": 1}, "engines": engines}
        plan = {"packages": [PACKAGE], "scope": "full", "inventory_count": 1, "deleted": []}
        with mock.patch.object(runner, "scan_package", return_value=package):
            return runner.run(Path("."), "a" * 40, plan, {"engines": {"cisco": {}, "nvidia": {}}}, {}, workers=1)

    def test_both_complete_no_blocking_findings_pass(self):
        result = self.aggregate([normalized(), normalized("nvidia")])
        self.assertTrue(result["complete"])
        self.assertEqual(result["completed_packages"], 1)
        self.assertEqual(result["decision"], "pass")

    def test_one_incomplete_engine_prevents_pass_even_with_high_findings(self):
        result = self.aggregate([normalized(status="findings", findings=[{"rule_id": "P1", "severity": "high"}]),
                                 normalized("nvidia", "incomplete")])
        self.assertFalse(result["complete"])
        self.assertEqual(result["completed_packages"], 0)
        self.assertEqual(result["decision"], "incomplete")
        self.assertEqual(result["high_or_critical_findings"], 1)

    def test_high_or_critical_requires_review_but_low_is_nonblocking(self):
        for severity, decision in (("critical", "review-required"), ("high", "review-required"), ("low", "pass")):
            with self.subTest(severity=severity):
                result = self.aggregate([normalized(status="findings", findings=[{"rule_id": "P1", "severity": severity}]), normalized("nvidia")])
                self.assertTrue(result["complete"])
                self.assertEqual(result["decision"], decision)
                self.assertEqual(result["high_or_critical_findings"], int(severity in {"high", "critical"}))

    def test_absent_engine_result_cannot_meet_expected_coverage(self):
        result = self.aggregate([normalized()])
        self.assertFalse(result["complete"])
        self.assertEqual(result["decision"], "incomplete")


if __name__ == "__main__":
    unittest.main()
