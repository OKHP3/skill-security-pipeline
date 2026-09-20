"""Resolve official stable releases to immutable source, wheel and dependency pins."""
import hashlib
import hmac
import json
import os
import re
from pathlib import Path
from urllib.parse import quote, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

VENDORS = {"cisco": "cisco-ai-defense/skill-scanner", "nvidia": "NVIDIA/SkillSpector"}
SHA = re.compile(r"^[a-f0-9]{40}$")
HEX = re.compile(r"^[a-f0-9]{64}$")
VERSION = re.compile(r"^v?(\d+\.\d+\.\d+)$")
MAX_DOWNLOAD = 64 * 1024 * 1024
HOSTS = {"api.github.com", "raw.githubusercontent.com", "pypi.org",
         "files.pythonhosted.org", "github.com", "release-assets.githubusercontent.com"}
ENGINE_FIELDS = {"repository", "version", "source_sha", "wheel_url", "wheel_sha256",
                 "lock_sha256", "project_sha256"}


def _url(url: str):
    if not isinstance(url, str) or any(ord(c) <= 32 or ord(c) == 127 for c in url) or "\\" in url:
        raise ValueError("unsafe-download-url")
    parsed = urlparse(url)
    if (parsed.scheme != "https" or parsed.hostname not in HOSTS
            or parsed.netloc != parsed.hostname or parsed.fragment):
        raise ValueError("untrusted-download-host")
    return parsed


class _SafeRedirect(HTTPRedirectHandler):
    """Only GitHub release assets may redirect; never forward credentials."""

    def redirect_request(self, request, response, code, message, headers, newurl):
        origin, destination = _url(request.full_url), _url(newurl)
        if (origin.hostname not in {"github.com", "release-assets.githubusercontent.com"}
                or destination.hostname != "release-assets.githubusercontent.com"):
            raise ValueError("untrusted-download-redirect")
        redirected = super().redirect_request(request, response, code, message, headers, newurl)
        if redirected is not None:
            redirected.remove_header("Authorization")
            redirected.remove_header("Proxy-authorization")
        return redirected


def fetch(url: str, *, token: str | None = None) -> bytes:
    host = _url(url).hostname
    headers = {"User-Agent": "OKHP3-skill-security-pipeline", "Accept": "application/vnd.github+json"}
    if token and host == "api.github.com":
        headers["Authorization"] = f"Bearer {token}"
    with build_opener(_SafeRedirect()).open(Request(url, headers=headers), timeout=60) as response:
        data = response.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise ValueError("download-size-limit")
    return data


def api(path: str) -> dict:
    return json.loads(fetch("https://api.github.com/" + path, token=os.environ.get("GH_TOKEN")))


def _cisco_wheel(filename: str, version: str) -> bool:
    if not isinstance(filename, str) or not filename.endswith(".whl"):
        return False
    parts = filename[:-4].split("-")
    if len(parts) != 5 or parts[:2] != ["cisco_ai_skill_scanner", version]:
        return False
    python_tags, abi_tags, platforms = (value.split(".") for value in parts[2:])
    return (all(re.fullmatch(r"[A-Za-z0-9_]+", tag) for tags in (python_tags, abi_tags, platforms) for tag in tags)
            and "cp313" in python_tags and bool({"none", "cp313"}.intersection(abi_tags))
            and any(re.fullmatch(r"manylinux[0-9_]*x86_64", platform) for platform in platforms))


def _wheel_url(name: str, engine: dict) -> None:
    url = _url(engine["wheel_url"])
    if url.query or url.params:
        raise ValueError("untrusted-wheel-url")
    version = engine["version"]
    if name == "nvidia":
        expected = {f"/NVIDIA/SkillSpector/releases/download/{tag}/skillspector-{version}-py3-none-any.whl"
                    for tag in (version, "v" + version)}
        valid = url.hostname == "github.com" and url.path in expected
    else:
        filename = url.path.rsplit("/", 1)[-1]
        valid = (url.hostname == "files.pythonhosted.org" and url.path.startswith("/packages/")
                 and re.fullmatch(r"/[A-Za-z0-9_./-]+", url.path) is not None
                 and ".." not in url.path.split("/") and _cisco_wheel(filename, version))
    if not valid:
        raise ValueError("untrusted-wheel-url")


def _validate(pins: dict) -> None:
    if (not isinstance(pins, dict) or type(pins.get("schema")) is not int or pins["schema"] != 1
            or not isinstance(pins.get("engines"), dict) or set(pins["engines"]) != set(VENDORS)):
        raise ValueError("invalid-vendor-pins")
    for name, engine in pins["engines"].items():
        if not isinstance(engine, dict) or set(engine) != ENGINE_FIELDS or not all(isinstance(v, str) for v in engine.values()):
            raise ValueError("invalid-engine-pins")
        if VENDORS[name] != engine["repository"] or not SHA.fullmatch(engine["source_sha"]):
            raise ValueError("untrusted-engine")
        if not re.fullmatch(r"\d+\.\d+\.\d+", engine["version"]):
            raise ValueError("unsupported-release")
        if any(not HEX.fullmatch(engine[key]) for key in ("wheel_sha256", "lock_sha256", "project_sha256")):
            raise ValueError("invalid-vendor-digest")
        _wheel_url(name, engine)
    actual = hashlib.sha256(json.dumps(pins["engines"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    fingerprint = pins.get("fingerprint")
    if not isinstance(fingerprint, str) or not HEX.fullmatch(fingerprint) or not hmac.compare_digest(actual, fingerprint):
        raise ValueError("vendor-fingerprint-mismatch")


def resolve() -> dict:
    engines = {}
    for name, repo in VENDORS.items():
        release = api(f"repos/{repo}/releases/latest")
        match = VERSION.fullmatch(release["tag_name"])
        if not match or release.get("draft") or release.get("prerelease"):
            raise ValueError("unsupported-release")
        version = match[1]
        commit = api(f"repos/{repo}/commits/{quote(release['tag_name'], safe='')}")["sha"]
        if not SHA.fullmatch(commit):
            raise ValueError("invalid-source-sha")
        source = f"https://raw.githubusercontent.com/{repo}/{commit}"
        lock = fetch(source + "/uv.lock")
        project = fetch(source + "/pyproject.toml")
        if name == "cisco":
            metadata = json.loads(fetch(f"https://pypi.org/pypi/cisco-ai-skill-scanner/{version}/json"))
            wheels = [f for f in metadata["urls"] if _cisco_wheel(f["filename"], version) and not f["yanked"]]
            if len(wheels) != 1:
                raise ValueError("cisco-wheel-unavailable")
            wheel_url, wheel_hash = wheels[0]["url"], wheels[0]["digests"]["sha256"]
        else:
            wheels = [f for f in release["assets"] if f["name"] == f"skillspector-{version}-py3-none-any.whl"]
            if len(wheels) != 1:
                raise ValueError("nvidia-wheel-unavailable")
            wheel_url = wheels[0]["browser_download_url"]
            wheel_hash = wheels[0].get("digest", "").removeprefix("sha256:")
        if not HEX.fullmatch(wheel_hash):
            raise ValueError("missing-wheel-digest")
        engines[name] = {"repository": repo, "version": version, "source_sha": commit,
                         "wheel_url": wheel_url, "wheel_sha256": wheel_hash,
                         "lock_sha256": hashlib.sha256(lock).hexdigest(),
                         "project_sha256": hashlib.sha256(project).hexdigest()}
    identity = json.dumps(engines, sort_keys=True, separators=(",", ":")).encode()
    pins = {"schema": 1, "engines": engines, "fingerprint": hashlib.sha256(identity).hexdigest()}
    _validate(pins)
    return pins


def _plain_path(path: Path) -> None:
    for candidate in (path, *path.parents):
        if candidate.is_symlink() or getattr(candidate, "is_junction", lambda: False)():
            raise ValueError("linked-vendor-destination")


def materialize(pins: dict, destination: Path) -> None:
    """Only fixed official repositories and hash-verified files can be installed."""
    _validate(pins)
    destination = Path(destination).absolute()
    _plain_path(destination)
    for name, engine in pins["engines"].items():
        target = destination / name
        _plain_path(target)
        target.mkdir(parents=True, exist_ok=True)
        prefix = f"https://raw.githubusercontent.com/{engine['repository']}/{engine['source_sha']}"
        for filename, hash_key in (("uv.lock", "lock_sha256"), ("pyproject.toml", "project_sha256")):
            data = fetch(prefix + "/" + filename)
            if hashlib.sha256(data).hexdigest() != engine[hash_key]:
                raise ValueError("vendor-file-digest-mismatch")
            _plain_path(target / filename)
            (target / filename).write_bytes(data)
        _plain_path(target / "wheel.txt")
        (target / "wheel.txt").write_text(f"{engine['wheel_url']} --hash=sha256:{engine['wheel_sha256']}\n", encoding="utf-8")
