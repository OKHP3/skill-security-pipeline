"""Read Git blobs, not working-tree links or submitted executable setup files."""
import hashlib
import re
import subprocess
import threading
from pathlib import Path, PurePosixPath

MAX_FILE = 10 * 1024 * 1024
MAX_PACKAGE = 64 * 1024 * 1024
MAX_FILES = 2048
MAX_PATH_BYTES = 4096
MAX_DEPTH = 64
GIT_TIMEOUT = 60
_HEAD = re.compile(r"[a-f0-9]{40}\Z")
_DEVICE = re.compile(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?\Z", re.IGNORECASE)


def git(root: Path, *args: str, limit: int = MAX_FILE) -> bytes:
    """Read bounded Git plumbing output without filters, hooks, or replacement refs."""
    with subprocess.Popen(["git", "--no-replace-objects", "-c", "core.fsmonitor=false",
                           "-C", str(root), *args], stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL) as process:
        expired = threading.Event()

        def terminate():
            expired.set()
            try:
                process.kill()
            except OSError:
                pass

        timer = threading.Timer(GIT_TIMEOUT, terminate)
        timer.daemon = True
        timer.start()
        try:
            data = process.stdout.read(limit + 1)
            if len(data) > limit:
                process.kill()
                raise ValueError("git-output-limit")
            code = process.wait()
            if expired.is_set():
                raise ValueError("git-read-timeout")
            if code:
                raise ValueError("git-read-failed")
            return data
        finally:
            timer.cancel()


def _safe_path(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise ValueError("unsafe-package-path")
    if len(value.encode("utf-8")) > MAX_PATH_BYTES or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("unsafe-file-path")
    parts = value.split("/")
    if (len(parts) > MAX_DEPTH or any(part in {"", ".", ".."} or part.casefold() == ".git"
                                   or part.endswith((" ", ".")) or _DEVICE.fullmatch(part)
                                   or len(part.encode("utf-8")) > 255 for part in parts)):
        raise ValueError("unsafe-file-path")
    return PurePosixPath(value)


def _plain_path(path: Path) -> None:
    for candidate in (path, *path.parents):
        if candidate.is_symlink() or getattr(candidate, "is_junction", lambda: False)():
            raise ValueError("linked-stage-destination")


def stage(root: Path, head: str, package: str, target: Path) -> dict:
    if not isinstance(head, str) or not _HEAD.fullmatch(head):
        raise ValueError("invalid-source-sha")
    package_path = _safe_path(package)
    if git(root, "cat-file", "-t", head, limit=32).strip() != b"commit":
        raise ValueError("source-is-not-commit")
    records = git(root, "ls-tree", "-r", "-z", "--long", head, "--", package,
                  limit=(MAX_PATH_BYTES + 96) * (MAX_FILES + 1)).split(b"\0")
    digest = hashlib.sha256()
    size = count = 0
    target = Path(target).absolute()
    _plain_path(target)
    target.mkdir(parents=True, exist_ok=False)
    for record in records:
        if not record:
            continue
        header, raw_path = record.split(b"\t", 1)
        mode, kind, oid, raw_size = header.decode("ascii").split()
        path = _safe_path(raw_path.decode("utf-8"))
        relative = path.relative_to(package_path)
        if mode not in {"100644", "100755"} or kind != "blob":
            raise ValueError("unsupported-link-or-submodule")
        if not relative.parts:
            raise ValueError("unsafe-file-path")
        count += 1
        size += int(raw_size)
        if count > MAX_FILES or int(raw_size) > MAX_FILE or size > MAX_PACKAGE:
            raise ValueError("package-resource-limit")
        data = git(root, "cat-file", "blob", oid, limit=int(raw_size))
        if len(data) != int(raw_size):
            raise ValueError("blob-size-mismatch")
        destination = target.joinpath(*relative.parts)
        if not destination.is_relative_to(target):
            raise ValueError("unsafe-file-path")
        _plain_path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        digest.update(str(relative).encode() + b"\0" + mode.encode() + b"\0" + data + b"\0")
    if not count:
        raise ValueError("empty-package")
    if (target / "SKILL.md").exists() and not (target / "SKILL.md").is_file():
        raise ValueError("metadata-path-conflict")
    generated = not (target / "SKILL.md").exists()
    if generated:
        # Compatibility input only. Original draft files remain unchanged and scanned.
        (target / "SKILL.md").write_text("---\nname: draft-package\ndescription: Draft skill package security scan.\n---\n# Draft package\nInspect all supporting files.\n", encoding="utf-8")
    return {"sha256": digest.hexdigest(), "files": count, "bytes": size, "metadata_generated": generated}
