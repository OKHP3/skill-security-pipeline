"""Network-free boundaries for the public aggregate evidence snapshot."""
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.request import Request
import zipfile
import hashlib

from scripts import build_site_evidence as site
from test_vendors import pins_fixture

NOW = "2026-09-20T03:00:00+00:00"
SHA = "a" * 40
PIN = "b" * 40


def run_fixture():
    return {"id": 42, "run_attempt": 1, "repository": {"full_name": site.SOURCE, "id": 1},
            "head_repository": {"full_name": site.SOURCE, "id": 1}, "head_branch": "main",
            "head_sha": SHA, "path": site.WORKFLOW, "event": "workflow_dispatch",
            "status": "completed", "conclusion": "success", "pull_requests": [],
            "updated_at": NOW}


def fixture():
    pins = pins_fixture()
    plan = {"scope": "full", "source_commit": SHA, "inventory_count": 1, "packages": ["family/draft"]}
    engines = [{"engine": name, "package": "family/draft", "status": "no-findings", "findings": [],
                "errors": [], "coverage": {"complete": True}} for name in ("cisco", "nvidia")]
    report = {"schema": 1, "source_commit": SHA, "scope": "full", "inventory_count": 1,
              "expected_packages": 1, "completed_packages": 1, "complete": True,
              "high_or_critical_findings": 0, "decision": "pass", "toolchain": pins,
              "started_at": "2026-09-20T01:00:00+00:00", "finished_at": "2026-09-20T02:00:00+00:00",
              "packages": [{"package": "family/draft", "engines": engines}]}
    return report, plan, pins


def summarize(report=None, plan=None, pins=None, run=None, current=SHA):
    original = fixture()
    return site.summarize(report or original[0], plan or original[1], pins or original[2],
                          run or run_fixture(), f"uses: OKHP3/skillz-shield@{PIN}\n", current)


class SummaryTests(unittest.TestCase):
    def test_only_aggregate_allowlisted_fields_leave_the_report(self):
        report, plan, pins = fixture()
        report["packages"][0]["content"] = {"snippet": "private forbidden sentinel"}
        report["packages"][0]["engines"][0]["message"] = "private forbidden sentinel"
        result = summarize(report, plan, pins, current="c" * 40)
        self.assertEqual(result["decision"], "pass")
        self.assertFalse(result["sourceMatchesCurrent"])
        self.assertEqual(result["controlPin"], PIN)
        self.assertNotIn("sentinel", json.dumps(result))
        self.assertNotIn("family/draft", json.dumps(result))
        self.assertNotIn("wheel_url", json.dumps(result))

    def test_incomplete_report_preserves_findings_and_incompleteness(self):
        report, plan, pins = fixture()
        engine = report["packages"][0]["engines"][1]
        engine.update(status="incomplete", errors=["analysis_incomplete"], coverage={"complete": False},
                      findings=[{"severity": "high", "rule_id": "E4", "text": "do not publish"}])
        report.update(completed_packages=0, complete=False, decision="incomplete", high_or_critical_findings=1)
        result = summarize(report, plan, pins)
        self.assertEqual(result["completedPackages"], 0)
        self.assertEqual(result["highOrCriticalFindings"], 1)
        self.assertEqual(result["decision"], "incomplete")
        self.assertNotIn("do not publish", json.dumps(result))

    def test_false_clean_and_coverage_mismatches_are_rejected(self):
        for field, value in (("expected_packages", 2), ("inventory_count", 2), ("completed_packages", 0),
                             ("complete", False), ("high_or_critical_findings", 1), ("decision", "review-required")):
            with self.subTest(field=field):
                report, plan, pins = fixture()
                report[field] = value
                with self.assertRaises(ValueError):
                    summarize(report, plan, pins)

    def test_report_must_cover_the_exact_plan_packages(self):
        report, plan, pins = fixture()
        plan["packages"] = ["family/different"]
        with self.assertRaises(ValueError):
            summarize(report, plan, pins)

    def test_source_and_vendor_provenance_are_bound_to_the_run(self):
        for mutation in ("source", "vendor", "fingerprint"):
            report, plan, pins = fixture()
            if mutation == "source":
                report["source_commit"] = "c" * 40
            elif mutation == "vendor":
                pins["engines"]["nvidia"]["repository"] = "attacker/vendor"
            else:
                pins["fingerprint"] = "c" * 64
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                summarize(report, plan, pins)

    def test_pr_branch_fork_and_wrong_workflow_runs_are_not_trusted(self):
        mutations = [{"event": "pull_request"}, {"event": "pull_request_target"}, {"head_branch": "feature"},
                     {"path": ".github/workflows/other.yml"}, {"status": "in_progress"},
                     {"head_repository": {"full_name": "attacker/skillz", "id": 2}}, {"pull_requests": [{}]}]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                run = run_fixture() | mutation
                self.assertFalse(site.trusted_run(run))
                with self.assertRaises(ValueError):
                    summarize(run=run)

    def test_multiple_control_pins_are_not_a_known_identity(self):
        with self.assertRaises(ValueError):
            site.action_pin(f"uses: OKHP3/skillz-shield@{PIN}\nuses: OKHP3/skillz-shield@{SHA}\n")


class ArchiveTests(unittest.TestCase):
    def archive(self, entries):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            for name, content in entries:
                archive.writestr(name, content)
        return stream.getvalue()

    def test_only_exact_json_members_are_read_without_extraction(self):
        data = self.archive([("../../report.json", "malicious"), ("report.json", '{"schema":1}'),
                             ("diagnostics.txt", "private")])
        self.assertEqual(site.archive_json(data), {"report.json": {"schema": 1}})

    def test_duplicate_and_malformed_members_rejected(self):
        for entries in ([('report.json', '{}'), ('report.json', '{}')], [('report.json', '{bad')]):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                site.archive_json(self.archive(entries))

    def test_plan_only_artifact_cannot_become_a_scan(self):
        self.assertNotIn("report.json", site.archive_json(self.archive([("plan.json", '{}')])))

    def test_download_redirect_strips_credentials_and_rejects_other_hosts(self):
        redirect = site.ArtifactRedirect()
        request = Request("https://api.github.com/repos/OKHP3/skillz/actions/artifacts/1/zip",
                          headers={"Authorization": "Bearer secret"})
        target = redirect.redirect_request(request, None, 302, "", {},
                                           "https://productionresultssa1.blob.core.windows.net/artifact?sig=temporary")
        self.assertIsNone(target.get_header("Authorization"))
        with self.assertRaises(ValueError):
            redirect.redirect_request(request, None, 302, "", {}, "https://attacker.example/file")


class PublicationTests(unittest.TestCase):
    def test_failed_run_without_report_is_not_a_neutral_skip(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as zipped:
            zipped.writestr("plan.json", json.dumps(fixture()[1]))
        data = archive.getvalue()
        metadata = {"total_count": 1, "artifacts": [{"id": 9, "name": "skill-security-42-1",
            "expired": False, "size_in_bytes": len(data), "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
            "workflow_run": {"id": 42, "head_sha": SHA, "head_branch": "main", "repository_id": 1,
                             "head_repository_id": 1}}]}
        api = site.GitHub()
        with patch.object(api, "get", side_effect=[metadata, data]):
            self.assertEqual(api.report(run_fixture() | {"conclusion": "failure"}), (None, True))
        with patch.object(api, "get", side_effect=[metadata, data]):
            self.assertEqual(api.report(run_fixture()), (None, False))

    def test_saved_snapshot_strips_extra_fields_and_rebuilds_urls(self):
        previous = site.empty(NOW)
        previous.update(availability="available", scan=summarize(), secret="private sentinel")
        previous["scan"]["runId"] = 35482030046
        previous["scan"]["runUrl"] = "https://attacker.example/"
        previous["scan"]["packages"] = [{"private": "sentinel"}]
        previous["scan"]["engines"][0]["name"] = "untrusted name"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            path.write_text(json.dumps(previous), encoding="utf-8")
            result = site.saved_snapshot(path)
        self.assertEqual(result["scan"]["runUrl"], "https://github.com/OKHP3/skillz/actions/runs/35482030046")
        self.assertNotIn("sentinel", json.dumps(result))
        self.assertNotIn("attacker", json.dumps(result))
        self.assertNotIn("untrusted", json.dumps(result))

    def test_missing_live_evidence_is_unavailable(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(site, "collect", side_effect=OSError):
            result = site.build(Path(directory) / "result.json", None, False, NOW)
        self.assertEqual(result["availability"], "unavailable")
        self.assertIsNone(result["scan"])

    def test_failed_refresh_preserves_observation_date_and_marks_stale(self):
        previous = site.empty("2026-09-19T03:00:00+00:00")
        previous.update(availability="available", scan=summarize())
        with tempfile.TemporaryDirectory() as directory, patch.object(site, "collect", side_effect=OSError):
            path = Path(directory) / "snapshot.json"
            path.write_text(json.dumps(previous), encoding="utf-8")
            result = site.build(path, path, False, NOW)
        self.assertEqual(result["availability"], "stale")
        self.assertEqual(result["scan"]["observedAt"], previous["scan"]["observedAt"])
        self.assertEqual(result["checkedAt"], NOW)
        self.assertEqual(result["reason"], "refresh-unavailable")

    def test_offline_build_never_claims_a_fresh_check(self):
        previous = site.empty("2026-09-19T03:00:00+00:00")
        previous.update(availability="available", scan=summarize())
        with tempfile.TemporaryDirectory() as directory, patch.object(site, "collect") as collect:
            path = Path(directory) / "snapshot.json"
            path.write_text(json.dumps(previous), encoding="utf-8")
            result = site.build(path, path, True, NOW)
            collect.assert_not_called()
        self.assertEqual(result["availability"], "stale")
        self.assertEqual(result["checkedAt"], previous["checkedAt"])
        self.assertEqual(result["publishedAt"], NOW)

    def test_expired_artifact_is_unavailable_without_download(self):
        api = site.GitHub()
        with patch.object(api, "get", return_value={"total_count": 1, "artifacts": [{
            "name": "skill-security-42-1", "expired": True,
            "workflow_run": {"id": 42, "head_sha": SHA, "head_branch": "main",
                             "repository_id": 1, "head_repository_id": 1}}]}) as get:
            self.assertEqual(api.report(run_fixture()), (None, True))
            self.assertEqual(get.call_count, 1)

    def test_collection_continues_past_newer_plan_only_run(self):
        report, plan, pins = fixture()
        older = run_fixture()
        newer = older | {"id": 43}
        api = site.GitHub()
        def get(path):
            if path.endswith("/commits/main") or "/commits/v" in path:
                return {"sha": SHA}
            if path.endswith("/releases/latest"):
                return {"tag_name": "v1.0.2", "draft": False, "prerelease": False}
            if "/runs?" in path:
                return {"workflow_runs": [newer, older]}
            raise AssertionError(path)
        with patch.object(api, "get", side_effect=get), patch.object(api, "workflow", return_value=f"uses: OKHP3/skillz-shield@{PIN}"), \
                patch.object(api, "report", side_effect=lambda run: (None, False) if run["id"] == 43 else
                             ({"report.json": report, "plan.json": plan, "pins.json": pins}, False)):
            result = site.collect(api, NOW)
        self.assertEqual(result["scan"]["runId"], 42)
        self.assertEqual(result["availability"], "available")


if __name__ == "__main__":
    unittest.main()
