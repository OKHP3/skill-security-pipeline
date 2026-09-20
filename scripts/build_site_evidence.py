"""Publish aggregate evidence from trusted GitHub runs; never run a scanner.

The search is bounded to 200 completed runs, 200 artifacts, 8 MiB per archive,
and a five-minute collection budget. No archive files are extracted to disk.
An API failure leaves explicit stale evidence or an unavailable state, never a
passing verdict. --offline builds use a checked-in snapshot without credentials.
"""
from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.parse import quote, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from skill_security.vendors import _validate as validate_pins

SOURCE = "OKHP3/skillz"
CONTROL = "OKHP3/skillz-shield"
WORKFLOW = ".github/workflows/skill-security.yml"
SHA = re.compile(r"[a-f0-9]{40}\Z")
HEX = re.compile(r"[a-f0-9]{64}\Z")
MAX_ARCHIVE = 8 * 1024 * 1024
MAX_JSON = 8 * 1024 * 1024
MAX_RUNS = 200
MAX_PACKAGES = 10000
SEVERITIES = ("critical", "high", "medium", "low", "info")
NAMES = {"cisco": "Cisco Skill Scanner", "nvidia": "NVIDIA SkillSpector"}


def require(condition: bool, reason: str = "invalid-evidence") -> None:
    if not condition:
        raise ValueError(reason)


def timestamp(value: str) -> dt.datetime:
    require(isinstance(value, str) and len(value) <= 40)
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(parsed.tzinfo is not None)
    return parsed


def count(value: object) -> int:
    require(type(value) is int and 0 <= value <= 100000000)
    return value


def action_pin(workflow: str) -> str:
    pins = re.findall(r"uses:\s+OKHP3/(?:skillz-shield|skill-security-pipeline)@([a-f0-9]{40})(?=\s|$)", workflow)
    require(bool(pins) and len(set(pins)) == 1, "invalid-control-pin")
    return pins[0]


def trusted_run(run: dict) -> bool:
    return (isinstance(run, dict)
            and isinstance(run.get("repository"), dict) and isinstance(run.get("head_repository"), dict)
            and run.get("repository", {}).get("full_name") == SOURCE
            and run.get("head_repository", {}).get("full_name") == SOURCE
            and run.get("head_repository", {}).get("id") == run.get("repository", {}).get("id")
            and type(run.get("id")) is int and run["id"] > 0
            and type(run.get("run_attempt")) is int and run["run_attempt"] > 0
            and run.get("head_branch") == "main"
            and run.get("path") == WORKFLOW
            and isinstance(run.get("head_sha"), str) and bool(SHA.fullmatch(run["head_sha"]))
            and run.get("event") in {"push", "schedule", "workflow_dispatch"}
            and run.get("status") == "completed"
            and run.get("conclusion") in {"success", "failure"}
            and run.get("pull_requests") == [])


def summarize(report: dict, plan: dict, pins: dict, run: dict, workflow: str, current: str) -> dict:
    """Recompute counts instead of trusting a report's headline decision."""
    require(all(isinstance(value, dict) for value in (report, plan, pins)))
    require(trusted_run(run), "untrusted-run")
    require(report.get("schema") == 1 and report.get("scope") == plan.get("scope") == "full")
    require(report.get("source_commit") == plan.get("source_commit") == run["head_sha"], "source-mismatch")
    expected = count(report.get("expected_packages"))
    require(0 < expected <= MAX_PACKAGES and expected == count(report.get("inventory_count")))
    require(count(plan.get("inventory_count")) == expected, "coverage-mismatch")
    selected, packages = plan.get("packages"), report.get("packages")
    require(isinstance(selected, list) and len(selected) == expected)
    require(all(isinstance(p, str) and 0 < len(p) <= 1024 for p in selected))
    require(len(set(selected)) == expected and isinstance(packages, list) and len(packages) == expected)
    require(all(isinstance(p, dict) for p in packages))
    require([p.get("package") for p in packages] == selected, "coverage-mismatch")
    validate_pins(pins)
    require(report.get("toolchain") == pins, "pin-mismatch")
    totals = dict.fromkeys(SEVERITIES, 0)
    completed = 0
    for package in packages:
        engines = package.get("engines")
        require(isinstance(engines, list) and len(engines) == 2)
        require(all(isinstance(e, dict) for e in engines))
        require({e.get("engine") for e in engines} == set(NAMES))
        package_complete = True
        for engine in engines:
            require(engine.get("package") == package["package"])
            status = engine.get("status")
            require(status in {"incomplete", "findings", "no-findings"})
            findings, coverage, errors = engine.get("findings"), engine.get("coverage"), engine.get("errors")
            require(isinstance(findings, list) and isinstance(coverage, dict) and isinstance(errors, list))
            if status == "incomplete":
                package_complete = False
                require(coverage.get("complete") is False)
            else:
                require(coverage.get("complete") is True and not errors, "coverage-mismatch")
                require(bool(findings) == (status == "findings"))
            for finding in findings:
                require(isinstance(finding, dict) and finding.get("severity") in totals)
                totals[finding["severity"]] += 1
        completed += package_complete
    complete = completed == expected
    high = totals["critical"] + totals["high"]
    decision = "incomplete" if not complete else "review-required" if high else "pass"
    require(report.get("complete") is complete and count(report.get("completed_packages")) == completed,
            "coverage-mismatch")
    require(count(report.get("high_or_critical_findings")) == high and report.get("decision") == decision)
    observed = report.get("finished_at")
    require(timestamp(report.get("started_at")) <= timestamp(observed) <= timestamp(run["updated_at"]))
    pin = action_pin(workflow)
    return {
        "observedAt": observed, "sourceCommit": run["head_sha"], "sourceMatchesCurrent": run["head_sha"] == current,
        "runId": run["id"], "runUrl": f"https://github.com/{SOURCE}/actions/runs/{run['id']}",
        "scope": "full", "decision": decision, "complete": complete,
        "inventoryCount": expected, "expectedPackages": expected, "completedPackages": completed,
        "highOrCriticalFindings": high, "findingsBySeverity": totals,
        "controlPin": pin, "controlActionUrl": f"https://github.com/{CONTROL}/tree/{pin}",
        "toolchainFingerprint": pins["fingerprint"],
        "engines": [{"id": name, "name": NAMES[name], "repository": engine["repository"],
                     "version": engine["version"], "commit": engine["source_sha"],
                     "wheelSha256": engine["wheel_sha256"], "lockSha256": engine["lock_sha256"],
                     "projectSha256": engine["project_sha256"]}
                    for name, engine in sorted(pins["engines"].items())],
    }


def archive_json(data: bytes) -> dict:
    require(len(data) <= MAX_ARCHIVE, "artifact-too-large")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        require(len(entries) <= 16 and len({e.filename for e in entries}) == len(entries))
        result = {}
        for entry in entries:
            # Only these exact root filenames are ever opened; never extract.
            if entry.filename not in {"report.json", "plan.json", "pins.json"}:
                continue
            require(entry.file_size <= MAX_JSON and not entry.is_dir())
            require((entry.external_attr >> 16) & 0o170000 != 0o120000)
            with archive.open(entry) as stream:
                content = stream.read(MAX_JSON + 1)
            require(len(content) <= MAX_JSON)
            result[entry.filename] = json.loads(content)
        return result


class ArtifactRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        source, target = urlparse(request.full_url), urlparse(newurl)
        require(source.hostname == "api.github.com" and "/actions/artifacts/" in source.path)
        require(target.scheme == "https" and target.netloc == target.hostname
                and not target.fragment and (target.hostname.endswith(".blob.core.windows.net")
                or target.hostname.endswith(".actions.githubusercontent.com")), "untrusted-artifact-host")
        redirected = super().redirect_request(request, response, code, message, headers, newurl)
        if redirected is not None:
            redirected.remove_header("Authorization")
            redirected.remove_header("Proxy-authorization")
        return redirected


class GitHub:
    def __init__(self, token: str | None = None):
        self.token = token
        self.deadline = time.monotonic() + 300

    def get(self, path: str, binary: bool = False):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "collection-time-limit")
        require(path.startswith("repos/") and ".." not in path)
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "Skillz-Shield-evidence",
                   "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = Request("https://api.github.com/" + path, headers=headers)
        with build_opener(ArtifactRedirect()).open(request, timeout=min(30, remaining)) as response:
            data = response.read(MAX_ARCHIVE + 1)
        require(len(data) <= MAX_ARCHIVE, "response-too-large")
        return data if binary else json.loads(data)

    def workflow(self, sha: str) -> str:
        require(bool(SHA.fullmatch(sha)))
        content = self.get(f"repos/{SOURCE}/contents/{WORKFLOW}?ref={sha}")
        require(content.get("encoding") == "base64" and content.get("size", MAX_JSON) < 128000)
        return base64.b64decode(content["content"]).decode("utf-8")

    def report(self, run: dict) -> tuple[dict | None, bool]:
        """None/False means a genuine plan-only run, never a clean scan."""
        try:
            payload = self.get(f"repos/{SOURCE}/actions/runs/{run['id']}/artifacts?per_page=100")
            require(isinstance(payload, dict) and isinstance(payload.get("artifacts"), list))
            require(all(isinstance(a, dict) for a in payload["artifacts"]))
            require(payload.get("total_count", 101) <= 100)
            expected = f"skill-security-{run['id']}-{run['run_attempt']}"
            found = [a for a in payload["artifacts"] if a.get("name") == expected]
            if not found:
                return None, True
            require(len(found) == 1)
            artifact = found[0]
            provenance = artifact.get("workflow_run", {})
            require(provenance.get("id") == run["id"] and provenance.get("head_sha") == run["head_sha"]
                    and provenance.get("head_branch") == "main"
                    and provenance.get("repository_id") == run["repository"]["id"]
                    and provenance.get("head_repository_id") == run["repository"]["id"])
            require(artifact.get("expired") is False and count(artifact.get("size_in_bytes")) <= MAX_ARCHIVE)
            require(type(artifact.get("id")) is int and artifact["id"] > 0)
            data = self.get(f"repos/{SOURCE}/actions/artifacts/{artifact['id']}/zip", binary=True)
            require(artifact.get("digest") == "sha256:" + hashlib.sha256(data).hexdigest(), "artifact-digest-mismatch")
            files = archive_json(data)
            if "report.json" not in files:
                # A failed scan may leave only its plan and pins. Do not let an
                # older pass disguise that missing result as a neutral skip.
                return None, run["conclusion"] != "success"
            require(isinstance(files["report.json"], dict))
            if files["report.json"].get("scope") != "full":
                return None, False
            return files, False
        except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, zipfile.BadZipFile):
            return None, True


def empty(now: str) -> dict:
    return {"schemaVersion": 1, "publishedAt": now, "checkedAt": now,
            "availability": "unavailable", "reason": "no-verified-full-report",
            "source": {"repository": SOURCE, "branch": "main", "headCommit": None,
                       "workflowUrl": f"https://github.com/{SOURCE}/actions/workflows/skill-security.yml"},
            "control": {"repository": CONTROL, "version": None, "commit": None, "releaseUrl": None,
                        "consumerPin": None, "consumerActionUrl": None}, "scan": None}


def collect(api: GitHub, now: str) -> dict:
    result = empty(now)
    head = api.get(f"repos/{SOURCE}/commits/main")["sha"]
    require(isinstance(head, str) and bool(SHA.fullmatch(head)))
    result["source"]["headCommit"] = head
    pin = action_pin(api.workflow(head))
    result["control"].update(consumerPin=pin, consumerActionUrl=f"https://github.com/{CONTROL}/tree/{pin}")
    release = api.get(f"repos/{CONTROL}/releases/latest")
    tag = release.get("tag_name")
    require(isinstance(tag, str) and re.fullmatch(r"v\d+\.\d+\.\d+", tag)
            and release.get("draft") is False and release.get("prerelease") is False)
    released = api.get(f"repos/{CONTROL}/commits/{quote(tag, safe='')}")["sha"]
    require(isinstance(released, str) and bool(SHA.fullmatch(released)))
    result["control"].update(version=tag, commit=released, releaseUrl=f"https://github.com/{CONTROL}/releases/tag/{tag}")
    runs = []
    for page in (1, 2):
        response = api.get(f"repos/{SOURCE}/actions/workflows/skill-security.yml/runs?branch=main&status=completed&per_page=100&page={page}")
        require(isinstance(response.get("workflow_runs"), list) and len(response["workflow_runs"]) <= 100)
        runs.extend(r for r in response["workflow_runs"] if trusted_run(r))
        if len(response["workflow_runs"]) < 100:
            break
    runs.sort(key=lambda r: r["id"], reverse=True)
    missing_newer = False
    # Small parallel batches preserve newest-first selection without 200 downloads
    # after a report has already been found.
    with ThreadPoolExecutor(max_workers=4) as pool:
        for start in range(0, min(len(runs), MAX_RUNS), 4):
            batch = runs[start:start + 4]
            for run, (files, unavailable) in zip(batch, pool.map(api.report, batch)):
                missing_newer |= unavailable
                if files is None:
                    continue
                try:
                    scan = summarize(files["report.json"], files["plan.json"], files["pins.json"], run,
                                     api.workflow(run["head_sha"]), head)
                except (OSError, ValueError, KeyError, TypeError):
                    missing_newer = True
                    continue
                result["scan"] = scan
                old = timestamp(now) - timestamp(scan["observedAt"]) > dt.timedelta(days=8)
                result["availability"] = "stale" if old or missing_newer else "available"
                result["reason"] = "newer-evidence-unavailable" if missing_newer else "report-older-than-eight-days" if old else None
                return result
    return result


def saved_snapshot(path: Path) -> dict:
    """Reproject a reviewed snapshot onto the same public field allowlist."""
    require(path.is_file() and path.stat().st_size < 64000)
    saved = json.loads(path.read_text(encoding="utf-8"))
    require(saved.get("schemaVersion") == 1 and saved.get("source", {}).get("repository") == SOURCE)
    require(saved.get("availability") in {"available", "stale", "unavailable"})
    timestamp(saved["publishedAt"])
    timestamp(saved["checkedAt"])
    result = empty(saved["publishedAt"])
    reason = saved.get("reason")
    require(reason in {None, "no-verified-full-report", "newer-evidence-unavailable", "report-older-than-eight-days",
                       "refresh-unavailable", "offline-snapshot"})
    result.update(checkedAt=saved["checkedAt"], availability=saved["availability"], reason=reason)
    head = saved["source"].get("headCommit")
    require(head is None or isinstance(head, str) and bool(SHA.fullmatch(head)))
    result["source"]["headCommit"] = head
    control = saved.get("control", {})
    require(control.get("repository") == CONTROL)
    for field in ("commit", "consumerPin"):
        value = control.get(field)
        require(value is None or isinstance(value, str) and bool(SHA.fullmatch(value)))
        result["control"][field] = value
    version = control.get("version")
    require(version is None or isinstance(version, str) and bool(re.fullmatch(r"v\d+\.\d+\.\d+", version)))
    result["control"]["version"] = version
    if version:
        result["control"]["releaseUrl"] = f"https://github.com/{CONTROL}/releases/tag/{version}"
    if control.get("consumerPin"):
        result["control"]["consumerActionUrl"] = f"https://github.com/{CONTROL}/tree/{control['consumerPin']}"
    scan = saved.get("scan")
    if scan is None:
        require(saved["availability"] == "unavailable")
        return result
    require(isinstance(scan, dict) and scan.get("scope") == "full")
    timestamp(scan["observedAt"])
    clean = {"observedAt": scan["observedAt"], "scope": "full"}
    for field in ("sourceCommit", "controlPin"):
        require(isinstance(scan.get(field), str) and bool(SHA.fullmatch(scan[field])))
        clean[field] = scan[field]
    require(type(scan.get("runId")) is int and 0 < scan["runId"] < 10**15)
    clean["runId"] = scan["runId"]
    for field in ("inventoryCount", "expectedPackages", "completedPackages", "highOrCriticalFindings"):
        clean[field] = count(scan.get(field))
    require(0 < clean["expectedPackages"] == clean["inventoryCount"] <= MAX_PACKAGES
            and clean["completedPackages"] <= clean["expectedPackages"] and clean["runId"] > 0)
    totals = {key: count(scan.get("findingsBySeverity", {}).get(key)) for key in SEVERITIES}
    require(totals["critical"] + totals["high"] == clean["highOrCriticalFindings"])
    complete = clean["expectedPackages"] == clean["completedPackages"]
    decision = "incomplete" if not complete else "review-required" if clean["highOrCriticalFindings"] else "pass"
    require(scan.get("complete") is complete and scan.get("decision") == decision)
    clean.update(complete=complete, decision=decision, findingsBySeverity=totals,
                 sourceMatchesCurrent=clean["sourceCommit"] == head,
                 runUrl=f"https://github.com/{SOURCE}/actions/runs/{clean['runId']}",
                 controlActionUrl=f"https://github.com/{CONTROL}/tree/{clean['controlPin']}")
    require(isinstance(scan.get("toolchainFingerprint"), str) and bool(HEX.fullmatch(scan["toolchainFingerprint"])))
    clean["toolchainFingerprint"] = scan["toolchainFingerprint"]
    engines = scan.get("engines")
    require(isinstance(engines, list) and len(engines) == 2 and all(isinstance(e, dict) for e in engines))
    require({e.get("id") for e in engines} == set(NAMES))
    clean["engines"] = []
    for engine in engines:
        name = engine["id"]
        expected_repo = "cisco-ai-defense/skill-scanner" if name == "cisco" else "NVIDIA/SkillSpector"
        require(engine.get("repository") == expected_repo)
        require(isinstance(engine.get("version"), str) and bool(re.fullmatch(r"\d+\.\d+\.\d+", engine["version"])))
        item = {"id": name, "name": NAMES[name], "repository": expected_repo, "version": engine["version"]}
        for field, pattern in (("commit", SHA), ("wheelSha256", HEX), ("lockSha256", HEX), ("projectSha256", HEX)):
            require(isinstance(engine.get(field), str) and bool(pattern.fullmatch(engine[field])))
            item[field] = engine[field]
        clean["engines"].append(item)
    result["scan"] = clean
    return result


def build(output: Path, fallback: Path | None, offline: bool, now: str, api: GitHub | None = None) -> dict:
    if offline:
        result = saved_snapshot(fallback) if fallback else empty(now)
        # Never imply that an offline build checked current GitHub state.
        result["availability"] = "stale" if result.get("scan") else "unavailable"
        result["reason"] = "offline-snapshot"
        result["publishedAt"] = now
    else:
        try:
            result = collect(api or GitHub(os.environ.get("GH_TOKEN")), now)
            if result["scan"] is None:
                raise ValueError("no-verified-full-report")
        except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
            try:
                result = saved_snapshot(fallback) if fallback else empty(now)
            except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
                result = empty(now)
            result.update(publishedAt=now, checkedAt=now,
                          availability="stale" if result.get("scan") else "unavailable",
                          reason="refresh-unavailable")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("site/public/data/evidence.json"))
    parser.add_argument("--fallback", type=Path)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    result = build(args.output, args.fallback, args.offline, now)
    print(f"Public evidence: {result['availability']}; reason: {result['reason'] or 'verified-report'}")


if __name__ == "__main__":
    main()
