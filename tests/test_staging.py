"""Exercise staging with temporary Git object databases, never submitted code."""

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from skill_security import staging


class StagingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "source"
        self.root.mkdir()
        self.git("init", "--quiet")

    def git(self, *arguments, data=None):
        environment = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        return subprocess.check_output(
            ["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
             "-c", "commit.gpgsign=false", "-C", str(self.root), *arguments],
            input=data, stderr=subprocess.DEVNULL, env=environment)

    def commit(self, files):
        """Create real blobs/index/tree/commit without checkout, hooks, or filters."""
        self.git("read-tree", "--empty")
        for path, mode, content in files:
            oid = self.git("hash-object", "-w", "--stdin", data=content).decode().strip()
            self.git("update-index", "--add", "--cacheinfo", f"{mode},{oid},{path}")
        tree = self.git("write-tree").decode().strip()
        return self.git("commit-tree", tree, "-m", "fixture").decode().strip()

    def test_stages_committed_bytes_and_preserves_malformed_draft_metadata(self):
        body = b"---\nname: [ unfinished\r\nSECRET TEXT\x00\xff"
        script = b"raise RuntimeError('must never execute')\n"
        head = self.commit([("family/draft/SKILL.md", "100644", body),
                            ("family/draft/scripts/task.py", "100755", script)])
        source = self.root / "family/draft"
        source.mkdir(parents=True)
        (source / "SKILL.md").write_bytes(b"UNCOMMITTED REPLACEMENT")
        target = self.base / "stage"
        result = staging.stage(self.root, head, "family/draft", target)
        self.assertEqual((target / "SKILL.md").read_bytes(), body)
        self.assertEqual((target / "scripts/task.py").read_bytes(), script)
        self.assertFalse(result["metadata_generated"])
        self.assertEqual(result["files"], 2)
        self.assertEqual(result["bytes"], len(body) + len(script))
        digest = hashlib.sha256(b"SKILL.md\0" + b"100644\0" + body + b"\0"
                                + b"scripts/task.py\0" + b"100755\0" + script + b"\0").hexdigest()
        self.assertEqual(result["sha256"], digest)

    def test_synthetic_metadata_is_separate_from_preserved_original_draft(self):
        content = b"draft without a manifest\r\n"
        head = self.commit([("family/draft/notes.txt", "100644", content)])
        target = self.base / "stage"
        result = staging.stage(self.root, head, "family/draft", target)
        self.assertTrue(result["metadata_generated"])
        self.assertEqual((target / "notes.txt").read_bytes(), content)
        self.assertIn("name: draft-package", (target / "SKILL.md").read_text())
        self.assertEqual(result["files"], 1)
        self.assertEqual(result["bytes"], len(content))
        self.assertFalse((self.root / "family/draft/SKILL.md").exists())

    def test_submitted_setup_filters_and_hooks_are_never_executed(self):
        marker = self.base / "EXECUTED"
        script = f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n".encode()
        head = self.commit([("family/draft/setup.py", "100755", script),
                            ("family/draft/.gitattributes", "100644", b"* filter=hostile\n"),
                            ("family/draft/pyproject.toml", "100644", b"[build-system]\nbuild-backend='setup'\n")])
        self.git("config", "filter.hostile.smudge", "this-program-must-never-run")
        self.git("config", "filter.hostile.required", "true")
        staging.stage(self.root, head, "family/draft", self.base / "stage")
        self.assertFalse(marker.exists())
        self.assertEqual((self.base / "stage/setup.py").read_bytes(), script)
        self.assertFalse((self.base / "stage/.git").exists())

    def test_git_symlink_blob_is_rejected_without_following_target(self):
        head = self.commit([("family/draft/link", "120000", b"../../private")])
        with self.assertRaisesRegex(ValueError, "unsupported-link-or-submodule"):
            staging.stage(self.root, head, "family/draft", self.base / "stage")

    def test_submodule_tree_entry_is_rejected(self):
        base = self.commit([("placeholder", "100644", b"base")])
        self.git("read-tree", "--empty")
        self.git("update-index", "--add", "--cacheinfo", f"160000,{base},family/draft/module")
        tree = self.git("write-tree").decode().strip()
        head = self.git("commit-tree", tree, "-m", "submodule fixture").decode().strip()
        with self.assertRaisesRegex(ValueError, "unsupported-link-or-submodule"):
            staging.stage(self.root, head, "family/draft", self.base / "stage")

    def test_head_must_be_an_immutable_commit_sha(self):
        for head in ("HEAD", "main", "--format=%(path)", "a" * 39):
            with self.subTest(head=head), patch.object(staging, "git") as git:
                with self.assertRaisesRegex(ValueError, "invalid-source-sha"):
                    staging.stage(self.root, head, "family/draft", self.base / "stage")
                git.assert_not_called()
        blob = self.git("hash-object", "-w", "--stdin", data=b"blob").decode().strip()
        with self.assertRaisesRegex(ValueError, "source-is-not-commit"):
            staging.stage(self.root, blob, "family/draft", self.base / "stage")

    def test_malicious_package_paths_are_rejected_before_git(self):
        for package in ("", ".", "/tmp/escape", "family/../outside", "family//draft", "family/./draft",
                        "family\\draft", "C:\\outside", "family/draft:stream", "family/.GIT/hooks",
                        "family/draft ", "family/CON", "family/draft\ncommand"):
            with self.subTest(package=package), patch.object(staging, "git") as git:
                with self.assertRaises(ValueError):
                    staging.stage(self.root, "a" * 40, package, self.base / "stage")
                git.assert_not_called()

    def test_per_file_total_and_count_limits_are_enforced(self):
        head = self.commit([("family/draft/a.txt", "100644", b"1234"),
                            ("family/draft/b.txt", "100644", b"5678")])
        for constant, value in (("MAX_FILE", 3), ("MAX_PACKAGE", 7), ("MAX_FILES", 1)):
            with self.subTest(constant=constant), patch.object(staging, constant, value):
                with self.assertRaisesRegex(ValueError, "package-resource-limit"):
                    staging.stage(self.root, head, "family/draft", self.base / constant)

    def test_empty_package_does_not_create_a_false_successful_scan(self):
        head = self.commit([("elsewhere/readme.txt", "100644", b"outside")])
        with self.assertRaisesRegex(ValueError, "empty-package"):
            staging.stage(self.root, head, "family/draft", self.base / "stage")

    def test_existing_destination_is_never_overwritten(self):
        head = self.commit([("family/draft/SKILL.md", "100644", b"source")])
        target = self.base / "stage"
        target.mkdir()
        (target / "SKILL.md").write_bytes(b"KEEP")
        with self.assertRaises(FileExistsError):
            staging.stage(self.root, head, "family/draft", target)
        self.assertEqual((target / "SKILL.md").read_bytes(), b"KEEP")

    def test_linked_destination_parent_is_rejected(self):
        head = self.commit([("family/draft/SKILL.md", "100644", b"source")])
        outside = self.base / "outside"
        outside.mkdir()
        link = self.base / "linked"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("Symlink creation is unavailable on this host")
        with self.assertRaisesRegex(ValueError, "linked-stage-destination"):
            staging.stage(self.root, head, "family/draft", link / "stage")
        self.assertEqual(list(outside.iterdir()), [])

    def test_replacement_refs_cannot_change_pinned_commit_content(self):
        original = self.commit([("family/draft/SKILL.md", "100644", b"original")])
        other = self.commit([("family/draft/SKILL.md", "100644", b"replaced")])
        self.git("replace", original, other)
        staging.stage(self.root, original, "family/draft", self.base / "stage")
        self.assertEqual((self.base / "stage/SKILL.md").read_bytes(), b"original")

    def test_git_read_output_limit_is_bounded(self):
        blob = self.git("hash-object", "-w", "--stdin", data=b"0123456789").decode().strip()
        with self.assertRaisesRegex(ValueError, "git-output-limit"):
            staging.git(self.root, "cat-file", "blob", blob, limit=5)


if __name__ == "__main__":
    unittest.main()
