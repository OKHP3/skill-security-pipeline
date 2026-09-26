"""Read-only public release audit; never install or execute downloaded content."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import gzip
import io
from pathlib import Path
import re
from urllib.parse import quote
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]


def version(value):
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        raise ValueError("not a stable three-part version")
    return tuple(map(int, match.groups()))


def fetch(url):
    with urlopen(Request(url, headers={"User-Agent": "Skillz-Shield-version-audit"}), timeout=30) as response:
        data = response.read(16 * 1024 * 1024 + 1)
    if len(data) > 16 * 1024 * 1024:
        raise ValueError("metadata size limit")
    if data.startswith(b"\x1f\x8b"):
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
            data = stream.read(16 * 1024 * 1024 + 1)
        if len(data) > 16 * 1024 * 1024:
            raise ValueError("expanded metadata size limit")
    return data.decode("utf-8")


def latest_release(repo):
    data = json.loads(fetch(f"https://api.github.com/repos/{repo}/releases/latest"))
    if data.get("draft") or data.get("prerelease"):
        raise ValueError("non-stable release")
    version(data["tag_name"])
    return data["tag_name"].removeprefix("v")


def status(current, latest):
    try:
        a, b = version(current), version(latest)
        return "update available" if a < b else "current" if a == b else "ahead of upstream stable"
    except ValueError:
        return "review floating or unknown version"


def npm_row(item):
    name, details = item
    url = "https://registry.npmjs.org/" + quote(name, safe="") + "/latest"
    row = {"technology": name, **details, "source": url}
    try:
        latest = json.loads(fetch(url))["version"]
        version(latest)
        row.update(latest=latest, status=status(details["current"], latest))
    except Exception as error:
        row.update(latest="unknown", status="lookup failed: " + type(error).__name__)
    return row


def collect(root=ROOT):
    package = json.loads((root / "site/package.json").read_text())
    direct = {**package["dependencies"], **package["devDependencies"]}
    lock = json.loads((root / "site/package-lock.json").read_text())
    packages = {}
    for path, info in lock["packages"].items():
        if not path:
            continue
        name = path.rsplit("node_modules/", 1)[1]
        key = (name, info["version"])
        packages[key] = {"current": info["version"], "scope": "direct npm" if name in direct else "transitive npm (includes optional platforms)", "location": path}
    with ThreadPoolExecutor(max_workers=8) as pool:
        rows = list(pool.map(npm_row, [(name, info) for (name, _), info in sorted(packages.items())]))
    for name, declared in direct.items():
        installed = lock["packages"].get("node_modules/" + name, {}).get("version")
        if installed != declared:
            rows.append(dict(technology=name, current=declared, latest=str(installed), scope="manifest consistency", location="site/package.json", source="site/package-lock.json", status="review manifest/lock mismatch"))

    def add(name, current, source, get_latest, scope, location):
        row = dict(technology=name, current=current, scope=scope, location=location, source=source)
        try:
            latest = get_latest()
            row.update(latest=latest, status=status(current, latest))
        except Exception as error:
            row.update(latest="unknown", status="lookup failed: " + type(error).__name__)
        rows.append(row)

    action = (root / "action.yml").read_text()
    site = (root / ".github/workflows/site.yml").read_text()
    replit = (root / ".replit").read_text()
    node_pin = re.search(r"node-version: ['\"]([^'\"]+)", site)[1]
    try:
        nodes = json.loads(fetch("https://nodejs.org/dist/index.json"))
        stable_nodes = [n for n in nodes if re.fullmatch(r"v\d+\.\d+\.\d+", n["version"])]
        node_latest = max(stable_nodes, key=lambda n: version(n["version"]))
        lts = max((n for n in stable_nodes if n["lts"]), key=lambda n: version(n["version"]))
    except Exception:
        node_latest = lts = {"version": "unknown", "npm": "unknown"}
        stable_nodes = []
    for name, current, latest, location in [
        ("Node.js (stable)", node_pin, node_latest["version"], ".github/workflows/site.yml"),
        ("Node.js (LTS adoption target)", node_pin, lts["version"], ".github/workflows/site.yml"),
        ("Node.js (Replit major)", re.search(r"nodejs-(\d+)", replit)[1], lts["version"], ".replit"),
    ]:
        add(name, current, "https://nodejs.org/dist/index.json", lambda v=latest: v, "runtime", location)
    bundled_npm = next((n["npm"] for n in stable_nodes if n["version"].removeprefix("v") == node_pin), "unknown")
    rows.append(npm_row(("npm", dict(current=bundled_npm, scope="bundled with CI Node; not separately pinned", location=".github/workflows/site.yml"))))
    def python_latest():
        values = re.findall(r"Python (3\.\d+\.\d+)(?![\w.])", fetch("https://www.python.org/downloads/"))
        return max(values, key=version)
    for name, current, location in [
        ("Python (scanner)", re.search(r"python-version: ['\"]([^'\"]+)", action)[1], "action.yml"),
        ("Python (Replit)", re.search(r"python-([\d.]+)", replit)[1], ".replit"),
    ]:
        add(name, current, "https://www.python.org/downloads/", python_latest, "runtime minor; patch floats", location)
    add("uv", re.search(r"version: '(\d+\.\d+\.\d+)'", action)[1], "https://github.com/astral-sh/uv/releases/latest", lambda: latest_release("astral-sh/uv"), "scanner installer", "action.yml")
    evidence = json.loads((root / "site/public/data/evidence.json").read_text())
    for engine in (evidence.get("scan") or {}).get("engines", []):
        repo = engine["repository"]
        if repo not in {"cisco-ai-defense/skill-scanner", "NVIDIA/SkillSpector"}:
            raise ValueError("unexpected engine repository")
        add(engine["name"], engine["version"], f"https://github.com/{repo}/releases/latest", lambda r=repo: latest_release(r), "historical scan only: " + evidence["scan"]["observedAt"], "site/public/data/evidence.json")
    for path in [root / "action.yml", *sorted((root / ".github/workflows").glob("*.yml"))]:
        for repo, pin, label in re.findall(r"uses: ([\w.-]+/[\w.-]+)@([a-f0-9]{40})\s+# (v[\d.]+)", path.read_text()):
            add(repo, label.removeprefix("v"), f"https://github.com/{repo}/releases/latest", lambda r=repo: latest_release(r), "GitHub Action; version label, immutable SHA " + pin, path.relative_to(root).as_posix())
    return rows


def markdown(report):
    def cell(value):
        return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    lines = ["# Technology release snapshot", "", "Checked: " + report["checkedAt"], "", "Declared/locked versions, not proof of a deployed environment. Scanner versions are historical. Action version labels are annotations; the full SHA is the executable identity. Latest means the publisher's stable release channel, not compatibility approval.", "", "| Technology | In place | Latest stable | Status | Scope / evidence |", "|---|---|---|---|---|"]
    for row in report["technologies"]:
        lines.append("| " + " | ".join(cell(v) for v in [row["technology"], row["current"], f'[{row["latest"]}]({row["source"]})', row["status"], row["scope"] + "; " + row["location"]]) + " |")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--check", action="store_true", help="Exit 1 for review candidates, 2 for failed metadata lookups")
    args = parser.parse_args()
    report = {"checkedAt": datetime.now(timezone.utc).isoformat(), "technologies": collect()}
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "technology-versions.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (args.output_dir / "technology-versions.md").write_text(markdown(report), encoding="utf-8")
    rows = report["technologies"]
    failed = sum(r["latest"] == "unknown" for r in rows)
    review = sum(r["status"] != "current" for r in rows)
    print(f"{len(rows)} observations; {review} need review; {failed} lookups unavailable")
    return 2 if failed else 1 if args.check and review else 0


if __name__ == "__main__":
    raise SystemExit(main())
