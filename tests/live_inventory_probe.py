"""Diagnostic-only scan of two fixed, committed public Skillz packages.

This preserves known findings/incomplete decisions; it is not a passing security
gate. Submitted files are read by the runner, never imported or executed.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import subprocess

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from skill_security import discovery, runner


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    args = parser.parse_args()
    state, repository = args.state.resolve(), args.repository.resolve()
    pins = json.loads((state / "pins.json").read_text(encoding="utf-8"))
    head = subprocess.run(["git", "rev-parse", "--verify", "HEAD"], cwd=repository,
                          capture_output=True, text=True, check=True, timeout=30).stdout.strip()
    plan = discovery.plan(repository, None, head, full=True)
    packages = [".agents/skills/architecture-decision-records", ".agents/skills/catalog-integrity"]
    if not set(packages).issubset(plan["packages"]):
        raise ValueError("expected diagnostic package missing")
    plan.update(packages=packages, scope="changed")
    programs = {"cisco": "skill-scanner", "nvidia": "skillspector"}
    executables = {
        name: state / "vendors" / name / ".venv" / ("Scripts" if os.name == "nt" else "bin")
        / (program + (".exe" if os.name == "nt" else ""))
        for name, program in programs.items()
    }
    report = runner.run(repository, head, plan, pins, executables, workers=2)
    (state / "inventory-probe.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print("Diagnostic evidence recorded; inspect inventory-probe.json for the scan decision.")


if __name__ == "__main__":
    main()
