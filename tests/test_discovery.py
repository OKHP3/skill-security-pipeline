from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from skill_security.discovery import plan


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git("init", "-q")
        self.git("config", "core.autocrlf", "false")
        self.git("config", "user.name", "Discovery fixture")
        self.git("config", "user.email", "discovery@example.invalid")
        self.git("commit", "-q", "--allow-empty", "-m", "empty baseline")

    def git(self, *args, input=None):
        return subprocess.run(
            ["git", *args], cwd=self.root, input=input, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=True,
        ).stdout

    def write(self, name, content="fixture\n"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def commit(self):
        self.git("add", "--all")
        self.git("commit", "-q", "--allow-empty", "-m", "fixture revision")
        return self.git("rev-parse", "HEAD").decode().strip()

    def package(self, directory="community/example"):
        self.write(directory.split("/")[0] + "/FAMILY.md")
        self.write(directory + "/SKILL.md", "---\nname: example\n---\n")

    def test_app_root_and_family_only_changes_have_no_scan_scope(self):
        self.package()
        base = self.commit()
        for name in ["README.md", "community/FAMILY.md", "artifacts/forge/app.tsx", "docs/notes.md"]:
            self.write(name, "changed\n")
        self.commit()
        self.assertEqual(plan(self.root, base), {
            "packages": [], "deleted": [], "scope": "none", "inventory_count": 1,
        })

    def test_app_markers_and_archived_skills_never_become_packages(self):
        base = self.commit()
        for root in ["app", "apps", "artifacts", "lib", "node_modules", "tool", "tools", "docs"]:
            self.write(root + "/FAMILY.md")
            self.write(root + "/example/SKILL.md")
        self.write("docs/archive/old/SKILL.md")
        self.commit()
        self.assertEqual(plan(self.root, base), {
            "packages": [], "deleted": [], "scope": "none", "inventory_count": 0,
        })

    def test_incomplete_skill_and_markerless_family_draft_are_in_scope(self):
        base = self.commit()
        self.write("community/FAMILY.md")
        self.write("community/incomplete/SKILL.md", "draft with no frontmatter")
        self.write("community/draft/references/notes.md")
        self.commit()
        self.assertEqual(plan(self.root, base)["packages"], ["community/draft", "community/incomplete"])

    def test_family_support_directories_are_excluded_unless_directly_marked(self):
        base = self.commit()
        self.write("community/FAMILY.md")
        for name in ["reviews", "review", "promotion", "evals", "context", "maturation", "scripts"]:
            self.write(f"community/{name}/notes.md")
            self.write(f"community/{name}/fixtures/example/SKILL.md")
        self.write("community/reviews/SKILL.md", "incomplete but explicit skill")
        self.write("community/draft/scripts/main.py", "print('draft')\n")
        self.write("context-extraction/FAMILY.md")
        self.write("context-extraction/thread-extract-work/history.json", "{}")
        self.write("glee-fully/FAMILY.md")
        self.write("glee-fully/organized-life/topic/context/threads/source.md")
        self.commit()
        self.assertEqual(plan(self.root, base)["packages"], ["community/draft", "community/reviews"])

    def test_support_directory_only_changes_have_no_scan_scope(self):
        self.package()
        self.write("community/reviews/report.md")
        base = self.commit()
        self.write("community/reviews/report.md", "updated review")
        self.commit()
        self.assertEqual(plan(self.root, base)["scope"], "none")

    def test_known_readme_only_tombstones_are_not_skills(self):
        base = self.commit()
        self.write("community/FAMILY.md")
        bodies = [
            "# Skill moved\n\nUse [current](../current/SKILL.md). This directory contains no installable `SKILL.md`.\n",
            "# Skill consolidated\n\nUse [current](../current/SKILL.md). It contains no installable `SKILL.md`.\n",
            "# Retired skill: old\n\nUse [current](../current/SKILL.md). This locator is not an installable skill.\n",
            "# Specification workflow consolidated\n\nUse [current](../current/SKILL.md). The original is outside the active catalog.\n",
        ]
        for i, body in enumerate(bodies):
            self.write(f"community/old-{i}/README.md", body)
        self.write("community/readme-draft/README.md", "# Proposed skill\nWrite a useful task contract next.")
        self.write("community/not-only-readme/README.md", bodies[0])
        self.write("community/not-only-readme/scripts/main.py")
        self.commit()
        self.assertEqual(plan(self.root, base)["packages"], ["community/not-only-readme", "community/readme-draft"])

    def test_tombstone_uses_committed_content_and_retirement_records_deletion(self):
        self.package()
        base = self.commit()
        (self.root / "community/example/SKILL.md").unlink()
        self.write("community/example/README.md", "# Skill moved\n\nUse [current](../current/SKILL.md). This is not an installable skill.\n")
        head = self.commit()
        self.write("community/example/README.md", "# Uncommitted draft\n")
        self.assertEqual(plan(self.root, base, head), {
            "packages": [], "deleted": ["community/example"], "scope": "changed", "inventory_count": 0,
        })

    def test_supporting_file_changes_select_owning_package(self):
        self.package("community/first")
        self.package("community/second")
        self.write("community/first/scripts/test helper.py")
        base = self.commit()
        self.write("community/first/scripts/test helper.py", "changed\n")
        self.commit()
        result = plan(self.root, base)
        self.assertEqual(result["packages"], ["community/first"])
        self.assertEqual(result["inventory_count"], 2)

    def test_new_family_is_discovered_without_a_family_allowlist(self):
        base = self.commit()
        self.package("future-family/new-skill")
        self.commit()
        self.assertEqual(plan(self.root, base)["packages"], ["future-family/new-skill"])

    def test_new_family_marker_admits_existing_draft_directory(self):
        self.write("future-family/draft/notes.md")
        base = self.commit()
        self.write("future-family/FAMILY.md")
        self.commit()
        self.assertEqual(plan(self.root, base)["packages"], ["future-family/draft"])

    def test_package_rename_and_deletion_use_both_trees(self):
        self.package("community/old")
        self.package("community/removed")
        base = self.commit()
        (self.root / "community/old").rename(self.root / "community/new")
        removed = (self.root / "community/removed").resolve()
        self.assertTrue(removed.is_relative_to(self.root.resolve()))
        shutil.rmtree(removed)
        self.commit()
        self.assertEqual(plan(self.root, base), {
            "packages": ["community/new"], "deleted": ["community/old", "community/removed"],
            "scope": "changed", "inventory_count": 1,
        })

    def test_deleted_supporting_file_still_selects_existing_package(self):
        self.package()
        self.write("community/example/references/old.md")
        base = self.commit()
        (self.root / "community/example/references/old.md").unlink()
        self.commit()
        self.assertEqual(plan(self.root, base)["packages"], ["community/example"])

    def test_support_and_export_markers_shadow_embedded_fixture_markers(self):
        base = self.commit()
        for prefix in [".agents/skills", "skills"]:
            self.write(prefix + "/outer/SKILL.md")
            self.write(prefix + "/outer/tests/fixture/SKILL.md")
            self.write(prefix + "/container/inner/SKILL.md")
            self.write(prefix + "/without-marker/notes.md")
        self.package()
        self.write("community/example/tests/fixture/SKILL.md")
        self.commit()
        self.assertEqual(plan(self.root, base)["packages"], [
            ".agents/skills/container/inner", ".agents/skills/outer", "community/example",
            "skills/container/inner", "skills/outer",
        ])

    def test_removed_support_marker_is_a_deleted_package(self):
        self.write(".agents/skills/local/SKILL.md")
        self.write(".agents/skills/local/references/retained.md")
        base = self.commit()
        (self.root / ".agents/skills/local/SKILL.md").unlink()
        self.commit()
        self.assertEqual(plan(self.root, base), {
            "packages": [], "deleted": [".agents/skills/local"], "scope": "changed", "inventory_count": 0,
        })

    def test_explicit_refs_ignore_untracked_and_modified_working_files(self):
        self.package("community/original")
        base = self.commit()
        self.write("community/original/SKILL.md", "committed change")
        head = self.commit()
        self.package("community/untracked")
        self.write("community/original/SKILL.md", "uncommitted change")
        self.assertEqual(plan(self.root, base, head)["packages"], ["community/original"])
        self.assertEqual(plan(self.root, base, base)["scope"], "none")
        self.assertEqual(plan(self.root, None, base)["inventory_count"], 1)

    def test_full_scan_selects_every_current_package(self):
        self.package("community/one")
        self.package("community/two")
        base = self.commit()
        self.assertEqual(plan(self.root, base, full=True), {
            "packages": ["community/one", "community/two"], "deleted": [],
            "scope": "full", "inventory_count": 2,
        })
        self.assertEqual(plan(self.root, None)["scope"], "full")

    def test_symlink_skill_and_supporting_paths_are_rejected_from_git_modes(self):
        for link_path in ["community/example/SKILL.md", "community/example/references/link", "community/linked", ".agents/skills/local/SKILL.md", ".agents/skills/local", "skills/local"]:
            with self.subTest(link_path=link_path):
                self.package()
                base = self.commit()
                blob = self.git("hash-object", "-w", "--stdin", input=b"../../outside\n").decode().strip()
                self.git("update-index", "--add", "--cacheinfo", "120000", blob, link_path)
                self.git("commit", "-q", "-m", "symlink fixture")
                head = self.git("rev-parse", "HEAD").decode().strip()
                with self.assertRaisesRegex(ValueError, "Symlinks"):
                    plan(self.root, base, head)
                # Restore only this temporary fixture repository's synthetic index.
                self.git("read-tree", base)
                self.git("commit", "-q", "-m", "restore fixture tree")

    def test_submodule_in_package_is_rejected_without_following_it(self):
        self.package()
        base = self.commit()
        self.git("update-index", "--add", "--cacheinfo", "160000", base, "community/example/vendor")
        self.git("commit", "-q", "-m", "gitlink fixture")
        with self.assertRaisesRegex(ValueError, "submodules"):
            plan(self.root, base)

    def test_unrelated_invalid_package_does_not_block_app_change_or_removal(self):
        self.package()
        self.commit()
        blob = self.git("hash-object", "-w", "--stdin", input=b"../outside\n").decode().strip()
        self.git("update-index", "--add", "--cacheinfo", "120000", blob, "community/linked")
        self.git("commit", "-q", "-m", "existing unsafe package")
        base = self.git("rev-parse", "HEAD").decode().strip()
        self.write("artifacts/app/main.py")
        self.git("add", "artifacts/app/main.py")
        self.git("commit", "-q", "-m", "app only")
        self.assertEqual(plan(self.root, base)["scope"], "none")
        with self.assertRaisesRegex(ValueError, "Symlinks"):
            plan(self.root, base, full=True)
        self.git("update-index", "--force-remove", "community/linked")
        self.git("commit", "-q", "-m", "remove unsafe link")
        self.assertEqual(plan(self.root, base)["deleted"], ["community/linked"])

    def test_invalid_revision_is_rejected(self):
        with self.assertRaises(ValueError):
            plan(self.root, None, "--help")


if __name__ == "__main__":
    unittest.main()
