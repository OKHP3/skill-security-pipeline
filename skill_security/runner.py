"""Bounded, credential-free subprocess supervision and sanitized evidence."""
import concurrent.futures
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import tempfile

from . import cisco, nvidia
from .staging import stage

ADAPTERS = {"cisco": cisco, "nvidia": nvidia}
MAX_REPORT = 16 * 1024 * 1024


def incomplete(engine: str, package: str, code: str) -> dict:
    return {"engine": engine, "package": package, "status": "incomplete",
            "findings": [], "errors": [code], "coverage": {"complete": False}}


def scan_engine(name: str, executable: Path, package: str, staged: Path, work: Path, pin: dict) -> dict:
    report_path = work / f"{name}.json"
    env = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "SSL_CERT_FILE", "SSL_CERT_DIR") if key in os.environ}
    env.update(HOME=str(work), USERPROFILE=str(work), TMPDIR=str(work), TEMP=str(work), TMP=str(work),
               LANG="C.UTF-8", PYTHONUTF8="1", PYTHONNOUSERSITE="1", DO_NOT_TRACK="1",
               SKILLSPECTOR_OSV_TIMEOUT="20", SKILLSPECTOR_MAX_WORKFLOW_SECONDS="150")
    try:
        # Submitted instructions and scanner diagnostics never become CI log commands.
        with (work / f"{name}.log").open("wb") as output:
            result = subprocess.run(ADAPTERS[name].command(str(executable), str(staged), str(report_path)),
                                    cwd=work, env=env, stdout=output, stderr=output, timeout=180, check=False)
        allowed = {0} if name == "cisco" else {0, 1}
        if result.returncode not in allowed:
            return incomplete(name, package, "scanner-process-failed")
        if not report_path.is_file() or report_path.is_symlink() or report_path.stat().st_size > MAX_REPORT:
            return incomplete(name, package, "missing-or-oversized-report")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        normalized = ADAPTERS[name].normalize(report, package=package, engine={**pin, "expected_package_dir": str(staged)})
        if result.returncode == 1 and normalized["status"] == "no-findings":
            return incomplete(name, package, "exit-report-contradiction")
        return normalized
    except subprocess.TimeoutExpired:
        return incomplete(name, package, "scanner-timeout")
    except (OSError, ValueError, KeyError, TypeError):
        return incomplete(name, package, "invalid-scanner-report")


def scan_package(root: Path, head: str, package: str, executables: dict, engines: dict) -> dict:
    with tempfile.TemporaryDirectory(prefix="skill-security-") as directory:
        work = Path(directory)
        try:
            content = stage(root, head, package, work / "package")
        except (ValueError, OSError, subprocess.SubprocessError):
            return {"package": package, "content": None,
                    "engines": [incomplete(name, package, "package-staging-failed") for name in ADAPTERS]}
        results = [scan_engine(name, executables[name], package, work / "package", work, engines[name]) for name in ADAPTERS]
        return {"package": package, "content": content, "engines": results}


def run(root: Path, head: str, plan: dict, pins: dict, executables: dict, workers: int = 4) -> dict:
    start = dt.datetime.now(dt.timezone.utc).isoformat()
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for result in pool.map(lambda package: scan_package(root, head, package, executables, pins["engines"]), plan["packages"]):
            results.append(result)
            if len(results) % 25 == 0 or len(results) == len(plan["packages"]):
                print(f"Security analysis returned for {len(results)}/{len(plan['packages'])} packages.", flush=True)
    engines = [engine for package in results for engine in package["engines"]]
    complete = len(results) == len(plan["packages"]) and len(engines) == 2 * len(results) and all(e["status"] != "incomplete" for e in engines)
    blocking = sum(f["severity"] in {"critical", "high"} for e in engines for f in e["findings"])
    return {"schema": 1, "source_commit": head, "started_at": start,
            "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "scope": plan["scope"],
            "inventory_count": plan["inventory_count"], "expected_packages": len(plan["packages"]),
            "completed_packages": sum(all(e["status"] != "incomplete" for e in p["engines"]) for p in results),
            "deleted_packages": plan["deleted"], "toolchain": pins, "complete": complete,
            "high_or_critical_findings": blocking,
            "decision": "incomplete" if not complete else "review-required" if blocking else "pass",
            "packages": results}
