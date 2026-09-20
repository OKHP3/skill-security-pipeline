"""Select skill packages from immutable Git trees, without reading package code."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import subprocess


# These surfaces never become distribution families merely by adding FAMILY.md.
_EXCLUDED_ROOTS = frozenset({
    "app", "apps", "artifacts", "build", "dist", "docs", "lib", "libs",
    "node_modules", "scripts", "skills", "src", "test", "tests", "tool",
    "tools", "vendor",
})
_SUPPORT_ROOTS = (".agents/skills", "skills")
# Markerless family-level support folders are not incomplete skill packages.
# A direct SKILL.md always overrides these exclusions.
_SUPPORT_CHILDREN = frozenset({
    "archive", "archives", "assets", "benchmarks", "context", "docs", "eval",
    "evals", "evaluations", "examples", "fixtures", "maturation", "node_modules",
    "promotion", "promotions", "references", "review", "reviews", "scripts",
    "test", "tests", "tools",
})
_CONTEXT_WORKSPACES = frozenset({
    "context-extraction/thread-extract-work",
    "glee-fully/organized-life",
})
_REGULAR_MODES = frozenset({"100644", "100755"})
_WINDOWS_DEVICE = re.compile(r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)", re.I)


@dataclass(frozen=True)
class _Entry:
    mode: str
    kind: str
    object_id: str


def _git(root: Path, *args: str, input: bytes | None = None) -> bytes:
    result = subprocess.run(
        ["git", *args], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, input=input,
    )
    if result.returncode:
        # Do not echo attacker-controlled revision names or terminal control bytes.
        raise ValueError("Unable to read the requested Git revision or tree")
    return result.stdout


def _revision(root: Path, ref: str) -> str:
    if not isinstance(ref, str) or not ref or "\0" in ref:
        raise ValueError("A nonempty Git revision is required")
    value = _git(root, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}")
    revision = value.decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision):
        raise ValueError("Git did not resolve the revision to one commit")
    return revision


def _tree(root: Path, revision: str) -> dict[str, _Entry]:
    entries = {}
    for record in _git(root, "ls-tree", "-r", "-z", "--full-tree", revision).split(b"\0"):
        if not record:
            continue
        metadata, path = record.split(b"\t", 1)
        mode, kind, object_id = metadata.decode("ascii").split()
        # Preserve every path byte until a selected package's safety check. An
        # unrelated application's unusual filename must not become a skill.
        entries[path.decode("utf-8", errors="surrogateescape")] = _Entry(mode, kind, object_id)
    return entries


def _safe_path(path: str) -> None:
    parts = path.split("/")
    if not path or "\\" in path or any(
        not part or part in {".", ".."} or ":" in part or part.endswith((" ", "."))
        or _WINDOWS_DEVICE.match(part)
        or any(ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in part)
        for part in parts
    ):
        raise ValueError("Unsafe or nonportable path in a skill package")


def _regular(path: str, entry: _Entry) -> None:
    _safe_path(path)
    if entry.kind != "blob" or entry.mode not in _REGULAR_MODES:
        raise ValueError("Symlinks and submodules are not supported in skill packages")


def _inside(path: str, directory: str) -> bool:
    return path.startswith(directory + "/")


def _small_blobs(root: Path, object_ids: set[str]) -> dict[str, str]:
    """Read bounded README blobs in batches; never use working-tree text."""
    if not object_ids:
        return {}
    request = ("\n".join(sorted(object_ids)) + "\n").encode("ascii")
    sizes = _git(root, "cat-file", "--batch-check", input=request)
    eligible = []
    for row in sizes.splitlines():
        object_id, kind, size = row.decode("ascii").split()
        if kind == "blob" and int(size) <= 16_384:
            eligible.append(object_id)
    if not eligible:
        return {}
    data = _git(root, "cat-file", "--batch", input=("\n".join(eligible) + "\n").encode("ascii"))
    result = {}
    offset = 0
    for expected in eligible:
        end = data.index(b"\n", offset)
        object_id, kind, size = data[offset:end].decode("ascii").split()
        if object_id != expected or kind != "blob":
            raise ValueError("Unexpected Git blob response")
        end_content = end + 1 + int(size)
        result[object_id] = data[end + 1:end_content].decode("utf-8", errors="replace")
        offset = end_content + 1
    return result


def _tombstone(text: str) -> bool:
    heading = re.match(
        r"^# (?:Skill moved|Skill consolidated|Specification workflow consolidated|Retired skill: [a-z0-9-]+)\s*(?:\n|$)",
        text, re.I,
    )
    canonical_link = re.search(r"\]\([^\n)]+/SKILL\.md(?:#[^)]*)?\)", text)
    prose = " ".join(text.casefold().split())
    locator = any(phrase in prose for phrase in (
        "not an installable skill", "contains no installable", "outside the active catalog",
    ))
    return bool(heading and canonical_link and locator)


def _inventory(root: Path, tree: dict[str, _Entry]) -> set[str]:
    families = set()
    for path, entry in tree.items():
        parts = path.split("/")
        if len(parts) != 2 or parts[1] != "FAMILY.md":
            continue
        family = parts[0]
        if family.startswith(".") or family.casefold() in _EXCLUDED_ROOTS:
            continue
        families.add(family)

    children: dict[str, list[str]] = {}
    for path, entry in tree.items():
        parts = path.split("/")
        if parts[0] in families:
            if len(parts) >= 3:
                children.setdefault("/".join(parts[:2]), []).append(path)
            elif len(parts) == 2 and entry.mode not in _REGULAR_MODES:
                # A symlink/gitlink at the direct-child package location has
                # no traversable tree; never silently treat it as an empty skill.
                children.setdefault(path, []).append(path)

    readmes = {
        tree[files[0]].object_id
        for directory, files in children.items()
        if files == [directory + "/README.md"] and tree[files[0]].mode in _REGULAR_MODES
    }
    contents = _small_blobs(root, readmes)
    packages = set()
    for directory, files in children.items():
        marker = directory + "/SKILL.md"
        if marker not in tree:
            if directory.split("/")[1].casefold() in _SUPPORT_CHILDREN or directory in _CONTEXT_WORKSPACES:
                continue
            if files == [directory + "/README.md"] and _tombstone(contents.get(tree[files[0]].object_id, "")):
                continue
        packages.add(directory)

    # The support/export surfaces require a marker. The outermost marker owns
    # embedded examples and fixtures, even when those contain another SKILL.md.
    candidates = {
        path.rsplit("/", 1)[0]
        for path in tree
        if path.endswith("/SKILL.md")
        and any(_inside(path.rsplit("/", 1)[0], prefix) for prefix in _SUPPORT_ROOTS)
    }
    for directory in sorted(candidates, key=lambda value: (value.count("/"), value)):
        if not any(directory == package or _inside(directory, package) for package in packages):
            packages.add(directory)

    # A link occupying a support package root has no marker to discover. Keep
    # this candidate so a changed/full scan rejects it rather than follows it.
    for path, entry in tree.items():
        if entry.mode not in _REGULAR_MODES and any(
            _inside(path, prefix) and "/" not in path[len(prefix) + 1:] for prefix in _SUPPORT_ROOTS
        ):
            packages.add(path)
    return packages


def _validate_selected(tree: dict[str, _Entry], packages: set[str]) -> None:
    for package in packages:
        _safe_path(package)
        parts = package.split("/")
        for length in range(1, len(parts) + 1):
            prefix = "/".join(parts[:length])
            if prefix in tree:
                _regular(prefix, tree[prefix])
        family_marker = parts[0] + "/FAMILY.md"
        if family_marker in tree and parts[0] not in _SUPPORT_ROOTS:
            _regular(family_marker, tree[family_marker])
    for path, entry in tree.items():
        if any(_inside(path, package) for package in packages):
            _regular(path, entry)


def plan(root: Path, base: str | None, head: str = "HEAD", full: bool = False) -> dict:
    """Return current packages to scan and package identities removed since base.

    Only committed trees participate; untracked and modified working files do not.
    ``base=None`` or ``full=True`` selects every current package. ``inventory_count``
    counts the head inventory; ``deleted`` contains base identities absent at head.
    A rename is a new package plus a deleted identity. Empty plans use scope
    ``none``, including repositories with no skill packages. No metadata, maturity,
    or schema validation is performed.

    Selected head package paths must be UTF-8 and portable to Windows/POSIX;
    symlinks and gitlinks fail closed. Unrelated pre-existing invalid packages do
    not break a no-impact plan, and removed unsafe content can be remediated.
    Regular executable files are never executed. Embedded fixture SKILL.md files
    belong to their outer package. Markerless family support folders and recognized
    README-only migration locators are excluded; other incomplete drafts remain.
    """
    root = Path(root)
    head_sha = _revision(root, head)
    head_tree = _tree(root, head_sha)
    head_packages = _inventory(root, head_tree)
    base_sha = _revision(root, base) if base is not None else None
    base_packages = _inventory(root, _tree(root, base_sha)) if base_sha is not None else set()
    deleted = base_packages - head_packages
    use_full = full or base_sha is None

    if use_full:
        selected = head_packages
    else:
        changed = _git(root, "diff", "--name-only", "--no-renames", "-z", base_sha, head_sha, "--")
        changed_paths = [path.decode("utf-8", errors="surrogateescape") for path in changed.split(b"\0") if path]
        selected = head_packages - base_packages
        selected.update(
            package for package in head_packages
            if any(path == package or _inside(path, package) for path in changed_paths)
        )

    _validate_selected(head_tree, selected)
    scope = ("full" if use_full else "changed") if selected or deleted else "none"
    return {
        "packages": sorted(selected),
        "deleted": sorted(deleted),
        "scope": scope,
        "inventory_count": len(head_packages),
    }
