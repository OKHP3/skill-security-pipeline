"""CLI for the pinned action; only Python standard-library orchestration."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from skill_security import discovery, vendors


def write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def output(key: str, value: str) -> None:
    if "GITHUB_OUTPUT" in os.environ:
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            stream.write(f"{key}={value}\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("plan", "resolve", "install", "scan"))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--base", default="")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--full", action="store_true")
    args = parser.parse_args()
    state = args.state.resolve()
    state.mkdir(parents=True, exist_ok=True)
    if args.mode == "plan":
        base = args.base if args.base and set(args.base) != {"0"} else None
        value = discovery.plan(args.root, base, args.head, args.full)
        value["source_commit"] = discovery._revision(args.root, args.head)
        write(state / "plan.json", value)
        output("scan", str(bool(value["packages"])).lower())
        output("packages", str(len(value["packages"])))
        print(f"Selected {len(value['packages'])} skill packages; {len(value['deleted'])} removed.")
    elif args.mode == "resolve":
        pins = vendors.resolve()
        control = Path(__file__).parent
        files = sorted([control / "entrypoint.py", control / "action.yml", *control.glob("skill_security/*.py")])
        pins["controller_sha256"] = hashlib.sha256(b"".join(f.relative_to(control).as_posix().encode() + b"\0" + f.read_bytes() for f in files)).hexdigest()
        write(state / "pins.json", pins)
        output("fingerprint", hashlib.sha256((pins["fingerprint"] + pins["controller_sha256"]).encode()).hexdigest())
        # Weekly renewal also refreshes live vulnerability data without version changes.
        output("week", dt.date.today().strftime("%G-%V"))
        print("Resolved official vendor releases to immutable hashes.")
    elif args.mode == "install":
        pins = json.loads((state / "pins.json").read_text())
        vendors.materialize(pins, state / "vendors")
        installed = {}
        for name in vendors.VENDORS:
            directory = state / "vendors" / name
            environment = directory / ".venv"
            python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            commands = [
                ["uv", "export", "--quiet", "--frozen", "--no-dev", "--no-emit-project", "--no-editable", "--format", "requirements-txt", "--output-file", str(directory / "requirements.txt")],
                ["uv", "venv", "--python", "3.13", str(environment)],
                ["uv", "pip", "install", "--python", str(python), "--require-hashes", "-r", str(directory / "requirements.txt")],
                ["uv", "pip", "install", "--python", str(python), "--no-deps", "--require-hashes", "-r", str(directory / "wheel.txt")],
            ]
            for command in commands:
                subprocess.run(command, cwd=directory, check=True, timeout=600, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL if command[1] == "export" else None)
            distribution = "cisco-ai-skill-scanner" if name == "cisco" else "skillspector"
            version = subprocess.check_output([str(python), "-I", "-c", "import importlib.metadata,sys; print(importlib.metadata.version(sys.argv[1]))", distribution], text=True).strip()
            if version != pins["engines"][name]["version"]:
                raise ValueError("installed-version-mismatch")
            installed[name] = version
        write(state / "installed.json", installed)
        print("Installed both engines using verified wheels and vendor-locked dependencies.")
    else:
        from skill_security.runner import run
        plan = json.loads((state / "plan.json").read_text())
        pins = json.loads((state / "pins.json").read_text())
        programs = {"cisco": "skill-scanner", "nvidia": "skillspector"}
        executables = {name: state / "vendors" / name / ".venv" / ("Scripts" if os.name == "nt" else "bin") / (program + (".exe" if os.name == "nt" else "")) for name, program in programs.items()}
        report = run(args.root.resolve(), plan["source_commit"], plan, pins, executables)
        write(state / "report.json", report)
        output("complete", str(report["complete"]).lower())
        output("decision", report["decision"])
        summary = (f"Skill security: **{report['decision']}**\n\n"
                   f"Packages completed: {report['completed_packages']}/{report['expected_packages']}. "
                   f"High/critical findings: {report['high_or_critical_findings']}.\n\n"
                   "See the sanitized report artifact for package and rule identifiers. "
                   "This is security evidence, not a skill quality or safety certification.\n")
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
                stream.write(summary)
        print(summary)
        return 0 if report["decision"] == "pass" else 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, subprocess.SubprocessError):
        print("Security pipeline could not complete; no passing result was issued.", file=sys.stderr)
        sys.exit(2)
