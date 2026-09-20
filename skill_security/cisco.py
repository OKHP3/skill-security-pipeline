"""Privacy-preserving adapter for compatible cisco-ai-skill-scanner reports.

Initial contract reviewed against 2.1.0 at upstream commit
a24df340ca6056a6446a239f4a7b114b11c6073a:
``skill_scanner/core/models.py`` (ScanResult.to_dict), ``core/scanner.py``,
``core/loader.py``, ``core/analyzer_factory.py`` and ``cli/cli.py``.
This module contains adapter code, not vendored scanner implementation.

The caller owns process success, fresh report creation, the engine/artifact pin,
isolated staging, package inventory and file-level coverage checks. A report
alone cannot prove those properties. ``engine['expected_package_dir']`` binds
the report to a staged directory when supplied. No report paths or free text
are copied into the normalized result.

Lenient loading fills missing name/description and tolerates malformed YAML;
it is independent of the strict *security* policy. No description, license,
naming or skill-maturity requirement is imposed here. Missing SKILL.md falls
back to immediate Markdown files upstream. NUL/invalid UTF-8, oversized or
symlink metadata can still block loading and require a recorded staging
adaptation by the caller; original content must remain available for scanning.
"""

from __future__ import annotations

import ntpath
import posixpath
import re


# Evidence/test defaults, not a runtime release allowlist. Compatible future
# releases are accepted; required coverage and report contracts still apply.
VERSION = "2.1.0"
SOURCE_SHA = "a24df340ca6056a6446a239f4a7b114b11c6073a"
CORE_ANALYZERS = ("static_analyzer", "bytecode", "pipeline", "correlation")
SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
# These checks inspect metadata format/length/presence only, not harmful behavior.
# Keep this exact, reviewed list: do not suppress all MANIFEST_* or SOCIAL_ENG_*.
METADATA_QUALITY_RULES = frozenset(
    {
        "MANIFEST_INVALID_NAME",
        "MANIFEST_DESCRIPTION_TOO_LONG",
        "SOCIAL_ENG_VAGUE_DESCRIPTION",
        "MANIFEST_MISSING_LICENSE",
    }
)
_INCOMPLETE_RULES = frozenset(
    {"SKILL_LOAD_REJECTED_LIMIT", "BYTECODE_ANALYSIS_UNAVAILABLE", "LOW_ANALYZABILITY", "UNANALYZABLE_BINARY"}
)
_RULE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SOURCE_SHA = re.compile(r"[0-9a-fA-F]{40}\Z")
_VERSION = re.compile(
    r"(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?"
    r"(?:\.post[0-9]+)?(?:\.dev[0-9]+)?(?:\+[a-z0-9]+(?:[._-][a-z0-9]+)*)?\Z",
    re.IGNORECASE,
)


def command(executable: str, package_dir: str, output: str) -> list[str]:
    """Build an argv list; never execute package code or request remote analyzers.

    No failure-on-findings flag: runner exit failure means an operational error;
    the JSON findings determine the security disposition independently.
    """
    for value in (executable, package_dir, output):
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ValueError("cisco.invalid-command-argument")
    return [executable, "scan", "--lenient", "--policy", "strict", "--format", "json", "--output", output, "--", package_dir]


def _count(value: object) -> bool:
    return type(value) is int and value >= 0


def _version(value: object) -> bool:
    return isinstance(value, str) and len(value) <= 128 and bool(_VERSION.fullmatch(value))


def _path_key(value: object) -> tuple[str, str] | None:
    """Compare scanner absolute paths lexically without following symlinks."""
    if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
        return None
    if ntpath.splitdrive(value)[0]:
        if not ntpath.isabs(value):
            return None
        return "windows", ntpath.normcase(ntpath.normpath(value))
    if value.startswith("/"):
        return "posix", posixpath.normpath(value)
    return None


def normalize(report: dict, *, package: str, engine: dict) -> dict:
    """Normalize the single-skill ``scan --format json`` envelope fail-closed.

    Optional engine keys: version, source_sha, expected_package_dir,
    reported_version. Supplied pins must be well formed, not equal to the initial
    release. A runner-observed reported_version or optional report.scanner_version
    must match engine.version when available. Cisco 2.1.0 emits no scanner version
    in its JSON; absence is valid and package installation remains caller-owned.
    Compatible future releases pass the same contract. Missing optional fields
    (notably analyzers_failed) are valid; required evidence that is absent or
    malformed yields ``incomplete`` rather than a clean result or an exception.
    Findings are retained even when the report is incomplete. Severity is lower
    case. Only finite safe codes and reviewed identities enter error/coverage
    fields; raw exceptions, snippets, titles, paths and arbitrary metadata do not.
    """
    errors: list[str] = []
    findings: list[dict[str, str]] = []
    coverage = {
        "report_shape": "single-skill",
        "expected_analyzers": list(CORE_ANALYZERS),
        "analyzers_used": [],
        "package_path_bound": False,
        "reported_version_checked": False,
        "reported_findings": None,
        "security_findings": 0,
        "metadata_warning_count": 0,
        "rule_contract": "unverified",
        "policy_fingerprint_sha256": None,
        "cel_projection_incomplete": None,
        "complete": False,
    }

    def error(code: str) -> None:
        if code not in errors:
            errors.append(code)

    def result() -> dict:
        coverage["security_findings"] = len(findings)
        coverage["complete"] = not errors
        return {
            "engine": "cisco",
            "package": package,
            "status": "incomplete" if errors else "findings" if findings else "no-findings",
            "findings": findings,
            "errors": errors,
            "coverage": coverage,
        }

    if not isinstance(engine, dict):
        error("cisco.invalid-engine-config")
        engine = {}
    if "version" in engine and not _version(engine["version"]):
        error("cisco.invalid-version")
    if "source_sha" in engine and (
        not isinstance(engine["source_sha"], str) or not _SOURCE_SHA.fullmatch(engine["source_sha"])
    ):
        error("cisco.invalid-source-sha")
    if not isinstance(report, dict):
        error("cisco.invalid-report")
        return result()
    for source, key in ((engine, "reported_version"), (report, "scanner_version")):
        if key not in source:
            continue
        reported_version = source[key]
        if not _version(reported_version):
            error("cisco.invalid-reported-version")
        elif not _version(engine.get("version")):
            error("cisco.unbound-reported-version")
        elif reported_version != engine["version"]:
            error("cisco.reported-version-mismatch")
        else:
            coverage["reported_version_checked"] = True
    if "results" in report or "summary" in report:
        error("cisco.unexpected-report-envelope")
    for key in ("error", "errors", "skills_skipped"):
        if key in report and report[key]:
            error("cisco.report-error")

    actual_path = _path_key(report.get("skill_path"))
    if actual_path is None:
        error("cisco.invalid-package-path")
    if "expected_package_dir" in engine:
        expected_path = _path_key(engine["expected_package_dir"])
        if expected_path is None:
            error("cisco.invalid-expected-package-path")
        elif actual_path != expected_path:
            error("cisco.package-path-mismatch")
        else:
            coverage["package_path_bound"] = True

    used = report.get("analyzers_used")
    if not isinstance(used, list) or any(not isinstance(item, str) for item in used):
        error("cisco.invalid-analyzer-list")
    else:
        coverage["analyzers_used"] = [name for name in CORE_ANALYZERS if name in used]
        if len(used) != len(set(used)):
            error("cisco.duplicate-analyzer")
        if set(CORE_ANALYZERS) - set(used):
            error("cisco.missing-core-analyzer")
        if set(used) - set(CORE_ANALYZERS):
            error("cisco.unexpected-analyzer")
    failed = report.get("analyzers_failed", [])
    if not isinstance(failed, list):
        error("cisco.invalid-analyzer-failures")
    elif failed:
        error("cisco.analyzer-failed")
    if report.get("llm_usage"):
        error("cisco.unexpected-network-analysis")

    raw_findings = report.get("findings")
    reported_count = report.get("findings_count")
    if not _count(reported_count):
        error("cisco.invalid-findings-count")
    else:
        coverage["reported_findings"] = reported_count
    if not isinstance(raw_findings, list):
        error("cisco.invalid-findings")
    else:
        if _count(reported_count) and reported_count != len(raw_findings):
            error("cisco.findings-count-mismatch")
        for finding in raw_findings:
            if not isinstance(finding, dict):
                error("cisco.invalid-finding")
                continue
            rule_id, severity = finding.get("rule_id"), finding.get("severity")
            if not isinstance(rule_id, str) or not _RULE_ID.fullmatch(rule_id):
                error("cisco.invalid-rule-id")
                continue
            if not isinstance(severity, str) or severity.lower() not in SEVERITIES:
                error("cisco.invalid-severity")
                continue
            if rule_id in METADATA_QUALITY_RULES:
                coverage["metadata_warning_count"] += 1
                continue
            findings.append({"rule_id": rule_id, "severity": severity.lower()})
            if rule_id in _INCOMPLETE_RULES:
                error("cisco.content-not-fully-analyzed")

    metadata = report.get("scan_metadata")
    if not isinstance(metadata, dict):
        error("cisco.invalid-scan-metadata")
        return result()
    if metadata.get("policy_name") != "strict" or metadata.get("policy_preset_base") != "strict":
        error("cisco.unexpected-policy")
    fingerprint = metadata.get("policy_fingerprint_sha256")
    if not isinstance(fingerprint, str) or not _SHA256.fullmatch(fingerprint):
        error("cisco.invalid-policy-fingerprint")
    else:
        coverage["policy_fingerprint_sha256"] = fingerprint

    contract = metadata.get("rule_contract")
    if not isinstance(contract, dict):
        error("cisco.missing-rule-contract")
    elif (
        contract.get("status") != "passed"
        or type(contract.get("schema_version")) is not int
        or contract["schema_version"] != 2
        or not _count(contract.get("checked"))
        or type(contract.get("invalid_findings")) is not int
        or contract["invalid_findings"] != 0
        or contract.get("errors") != []
    ):
        coverage["rule_contract"] = "failed"
        error("cisco.rule-contract-failed")
    else:
        coverage["rule_contract"] = "passed"

    cel = metadata.get("cel")
    if not isinstance(cel, dict):
        error("cisco.invalid-cel-telemetry")
    else:
        if cel.get("mode") != "shadow":
            error("cisco.unexpected-cel-mode")
        if cel.get("errors") != []:
            error("cisco.cel-error")
        if type(cel.get("suppressed")) is not int or cel["suppressed"] != 0:
            error("cisco.unexpected-finding-suppression")
        # Shadow projection gaps cannot remove findings. Record them without
        # turning incomplete descriptive metadata into a skill-quality gate.
        projection = cel.get("projection_incomplete")
        if not _count(projection):
            error("cisco.invalid-cel-telemetry")
        else:
            coverage["cel_projection_incomplete"] = projection

    if "loader" in metadata:
        loader = metadata["loader"]
        if not isinstance(loader, dict):
            error("cisco.invalid-loader-telemetry")
        elif loader.get("rejection_used") or loader.get("content_scanned") is False:
            error("cisco.content-not-scanned")
    if metadata.get("adjudicator"):
        error("cisco.unexpected-network-analysis")
    return result()
