"""Public JSON adapter for NVIDIA SkillSpector, without executing target code.

Verified against v2.11.2, commit 69dcdfb74487d361ba4c811d088cfdea2ff3a9dc:
https://github.com/NVIDIA/SkillSpector/blob/69dcdfb74487d361ba4c811d088cfdea2ff3a9dc/src/skillspector/nodes/report.py
https://github.com/NVIDIA/SkillSpector/blob/69dcdfb74487d361ba4c811d088cfdea2ff3a9dc/src/skillspector/inspection_ledger.py

Install the CLI only in its own tool environment (no MCP/development extras):
    uv tool install --python 3.13 \
      'skillspector @ git+https://github.com/NVIDIA/SkillSpector.git@69dcdfb74487d361ba4c811d088cfdea2ff3a9dc'
The caller owns installation, process deadlines, exit-code handling, and report
size limits. This module neither starts processes nor imports the vendor.

--no-llm needs no model credentials but is NOT a network-offline promise:
dependency checks can query api.osv.dev. v2.11.2 has no CLI offline switch;
SKILLSPECTOR_OSV_TIMEOUT defaults to a 30-second aggregate OSV budget and
SKILLSPECTOR_MAX_WORKFLOW_SECONDS defaults to 600 seconds per graph execution.
Fallback, parser/resource limits, or operational gaps remain incomplete evidence.
The process supervisor must enforce its own wall-clock limit and keep timeout,
missing/malformed JSON, and unexpected process exits distinct from findings.

Scan one staged package per invocation; --recursive only discovers immediate
children and caps scans at 32. Never use the vendor's risk score as a claim that
a package is safe. This adapter applies no author, quality, or maturity gate.
"""

from __future__ import annotations

import math
import re


_MAX_RECORDS = 10_000
_RULE_ID = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,79}\Z")
_VERSION = re.compile(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?\Z")
_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_COUNTS = (
    "total_components", "scanned_components", "fully_inspected_files",
    "partially_inspected_files", "entirely_uninspected_files",
)
_OPTIONAL_MODEL_ANALYZERS = {
    "meta_analyzer", "semantic_developer_intent",
    "semantic_quality_policy", "semantic_security_discovery",
}
# A failed dynamic analyzer import must not turn into a clean empty scan.
# New analyzers are accepted; removal of this baseline requires adapter review.
_REQUIRED_ANALYZERS = {
    "artifact_integrity", "behavioral_ast", "behavioral_taint_tracking",
    "mcp_least_privilege", "mcp_rug_pull", "mcp_tool_poisoning", "meta_analyzer",
    "static_yara",
    *("static_patterns_" + name for name in (
        "agent_snooping", "anti_refusal", "data_exfiltration", "deserialization",
        "excessive_agency", "harmful_content", "memory_poisoning",
        "output_handling", "privilege_escalation", "prompt_injection",
        "rogue_agent", "ssrf", "supply_chain", "system_prompt_leakage", "tool_misuse",
    )),
}


def command(executable: str, package_dir: str, output: str) -> list[str]:
    """Return argv for one package; the caller must use shell=False."""
    return [executable, "scan", package_dir, "--no-llm", "--fail-on-incomplete",
            "--format", "json", "--output", output]


def _count(value: object) -> bool:
    return type(value) is int and 0 <= value <= 1_000_000_000


def normalize(report: dict, *, package: str, engine: dict) -> dict:
    """Reduce released CLI JSON to safe findings and scan-coverage evidence.

    `engine` is trusted configuration; its optional `version` must match the
    reported build (a leading v is permitted). No supplied engine/report text
    is copied into output, except syntactically bounded public rule identifiers.
    `package` is the caller's catalog identity, never the report's source path.
    Valid findings survive an incomplete scan, but incomplete always wins status.
    """
    errors: set[str] = set()
    findings: set[tuple[str, str]] = set()
    coverage = {name: None for name in _COUNTS}
    coverage.update(complete=False, execution_successful=False,
                    coverage_percent=None, component_count=None,
                    analyzer_count=None, exclusion_count=None,
                    limitation_count=None)

    def result() -> dict:
        return {
            "engine": "nvidia", "package": package,
            "status": "incomplete" if errors else "findings" if findings else "no-findings",
            "findings": [{"rule_id": rule, "severity": severity}
                         for rule, severity in sorted(findings)],
            "errors": sorted(errors), "coverage": coverage,
        }

    if not isinstance(report, dict):
        errors.add("invalid_report")
        return result()

    issues = report.get("issues")
    if not isinstance(issues, list):
        errors.add("invalid_findings")
    else:
        if len(issues) > _MAX_RECORDS:
            errors.add("report_limit_exceeded")
        for issue in issues[:_MAX_RECORDS]:
            if not isinstance(issue, dict):
                errors.add("invalid_finding")
                continue
            rule, severity = issue.get("id"), issue.get("severity")
            if (not isinstance(rule, str) or not _RULE_ID.fullmatch(rule)
                    or not isinstance(severity, str)
                    or severity.lower() not in _SEVERITIES):
                errors.add("invalid_finding")
                continue
            findings.add((rule, severity.lower()))

    metadata = report.get("metadata")
    if not isinstance(metadata, dict):
        errors.add("invalid_metadata")
    else:
        version = metadata.get("skillspector_version")
        if not isinstance(version, str) or not _VERSION.fullmatch(version):
            errors.add("invalid_version")
        expected_version = engine.get("version")
        if expected_version is not None and (
            not isinstance(expected_version, str)
            or version != expected_version.removeprefix("v")
        ):
            errors.add("version_mismatch")
        if metadata.get("llm_requested") is not False:
            errors.add("unexpected_scan_mode")
        if metadata.get("meta_analysis_applied") is not False:
            errors.add("unexpected_scan_mode")
        if metadata.get("transitive_truncated"):
            errors.add("analysis_incomplete")

    if report.get("execution_successful") is not True:
        errors.add("execution_failed")
    suppressed = report.get("suppressed_count")
    if type(suppressed) is not int or suppressed != 0 or report.get("suppressed") != []:
        errors.add("unexpected_suppression")
    components = report.get("components")
    if not isinstance(components, list) or not all(isinstance(c, dict) for c in components[:_MAX_RECORDS]):
        errors.add("invalid_components")
    else:
        coverage["component_count"] = len(components)
        if len(components) > _MAX_RECORDS:
            errors.add("report_limit_exceeded")
        if not components:
            errors.add("empty_scan")

    completeness = report.get("analysis_completeness")
    if not isinstance(completeness, dict):
        errors.add("missing_completeness")
        return result()
    coverage["execution_successful"] = (
        report.get("execution_successful") is True
        and completeness.get("execution_successful") is True
    )
    if not coverage["execution_successful"]:
        errors.add("execution_failed")
    if completeness.get("is_complete") is not True or completeness.get("status") != "complete":
        errors.add("analysis_incomplete")

    for name in _COUNTS:
        if _count(completeness.get(name)):
            coverage[name] = completeness[name]
        else:
            errors.add("invalid_coverage")
    percent = completeness.get("coverage_percent")
    if (type(percent) in (int, float) and 0 <= percent <= 100 and math.isfinite(percent)):
        coverage["coverage_percent"] = percent
    else:
        errors.add("invalid_coverage")
    if all(coverage[name] is not None for name in _COUNTS):
        total, scanned, full, partial, uninspected = (coverage[name] for name in _COUNTS)
        if total == 0:
            errors.add("empty_scan")
        if scanned != full or full + partial + uninspected != total:
            errors.add("invalid_coverage")
        if partial or uninspected:
            errors.add("analysis_incomplete")
        if coverage["coverage_percent"] is not None and total:
            if abs(coverage["coverage_percent"] - round(full / total * 100, 1)) > 0.05:
                errors.add("invalid_coverage")

    for field, count_field in (("limitations", "limitation_count"),
                               ("scope_exclusions", "exclusion_count"),
                               ("ledger_exceptions", None)):
        rows = completeness.get(field)
        expected_type = str if field == "limitations" else dict
        if not isinstance(rows, list) or not all(isinstance(row, expected_type) for row in rows[:_MAX_RECORDS]):
            errors.add("invalid_coverage")
            continue
        if len(rows) > _MAX_RECORDS:
            errors.add("report_limit_exceeded")
        if count_field:
            coverage[count_field] = len(rows)
        if rows and field != "scope_exclusions":
            errors.add("analysis_incomplete")
        if field == "ledger_exceptions" and any(row.get("fatal") is True for row in rows[:_MAX_RECORDS]):
            errors.add("execution_failed")

    statuses = completeness.get("analyzer_statuses")
    if not isinstance(statuses, list):
        errors.add("invalid_analyzers")
    else:
        coverage["analyzer_count"] = len(statuses)
        if len(statuses) > _MAX_RECORDS:
            errors.add("report_limit_exceeded")
        seen: set[str] = set()
        for row in statuses[:_MAX_RECORDS]:
            if not isinstance(row, dict) or not isinstance(row.get("analyzer_id"), str):
                errors.add("invalid_analyzers")
                continue
            analyzer = row["analyzer_id"]
            if analyzer in seen:
                errors.add("invalid_analyzers")
            seen.add(analyzer)
            status = row.get("status")
            allowed_disabled = status == "disabled" and analyzer in _OPTIONAL_MODEL_ANALYZERS
            if (not isinstance(status, str)
                    or status not in {"completed", "not_applicable"} and not allowed_disabled):
                errors.add("analysis_incomplete")
            counters = (row.get(name) for name in
                        ("planned_work", "completed", "partial", "skipped", "failed", "unaccounted"))
            if not all(_count(value) for value in counters):
                errors.add("invalid_analyzers")
            else:
                if row["planned_work"] != sum(row[name] for name in
                                              ("completed", "partial", "skipped", "failed", "unaccounted")):
                    errors.add("invalid_analyzers")
                if any(row[name] for name in ("partial", "skipped", "failed", "unaccounted")):
                    errors.add("analysis_incomplete")
        if not _REQUIRED_ANALYZERS.issubset(seen):
            errors.add("missing_analyzers")

    # This means complete evidence for the requested static scan, not safe code.
    coverage["complete"] = not errors
    return result()
