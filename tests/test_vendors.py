"""Network-free tests of release provenance and vendor materialization."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from urllib.request import Request

from skill_security import vendors


LOCK = b'version = 1\n'
PROJECT = b'[project]\nname = "fixture"\n'
CISCO_WHEEL = "cisco_ai_skill_scanner-2.1.0-cp311.cp312.cp313.cp314-none-manylinux_2_17_x86_64.whl"
NVIDIA_WHEEL = "skillspector-2.11.2-py3-none-any.whl"


def repin(pins):
    pins["fingerprint"] = hashlib.sha256(json.dumps(
        pins["engines"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return pins


def pins_fixture():
    engines = {}
    for name, repo in vendors.VENDORS.items():
        engines[name] = {
            "repository": repo, "version": "2.1.0" if name == "cisco" else "2.11.2",
            "source_sha": ("a" if name == "cisco" else "b") * 40,
            "wheel_url": ("https://files.pythonhosted.org/packages/aa/bb/" + CISCO_WHEEL
                          if name == "cisco" else
                          "https://github.com/NVIDIA/SkillSpector/releases/download/v2.11.2/" + NVIDIA_WHEEL),
            "wheel_sha256": "c" * 64,
            "lock_sha256": hashlib.sha256(LOCK).hexdigest(),
            "project_sha256": hashlib.sha256(PROJECT).hexdigest(),
        }
    return repin({"schema": 1, "engines": engines})


def source_fetch(url, **kwargs):
    if url.endswith("/uv.lock"):
        return LOCK
    if url.endswith("/pyproject.toml"):
        return PROJECT
    if url == "https://pypi.org/pypi/cisco-ai-skill-scanner/2.1.0/json":
        return json.dumps({"urls": [{"filename": CISCO_WHEEL, "yanked": False,
                           "url": pins_fixture()["engines"]["cisco"]["wheel_url"],
                           "digests": {"sha256": "c" * 64}}]}).encode()
    raise AssertionError("Unexpected fixture URL")


def api_fixture(path):
    for name, engine in pins_fixture()["engines"].items():
        prefix = "repos/" + engine["repository"]
        if path == prefix + "/releases/latest":
            return {"tag_name": "v" + engine["version"], "draft": False, "prerelease": False,
                    "assets": [{"name": NVIDIA_WHEEL,
                                "browser_download_url": engine["wheel_url"],
                                "digest": "sha256:" + engine["wheel_sha256"]}]}
        if path == prefix + "/commits/v" + engine["version"]:
            return {"sha": engine["source_sha"]}
    raise AssertionError("Unexpected fixture API path")


class VendorTests(unittest.TestCase):
    def test_resolve_pins_stable_release_sha_wheel_and_exact_source_bytes(self):
        with patch.object(vendors, "api", side_effect=api_fixture), patch.object(vendors, "fetch", side_effect=source_fetch) as fetch:
            pins = vendors.resolve()
        self.assertEqual(pins, pins_fixture())
        source_urls = [call.args[0] for call in fetch.call_args_list if "raw.githubusercontent.com" in call.args[0]]
        self.assertEqual(len(source_urls), 4)
        self.assertTrue(all("/main/" not in url and "/v2." not in url for url in source_urls))

    def test_actual_multi_python_cisco_tag_is_accepted_but_wrong_platform_is_not(self):
        self.assertTrue(vendors._cisco_wheel(CISCO_WHEEL, "2.1.0"))
        self.assertTrue(vendors._cisco_wheel("cisco_ai_skill_scanner-2.1.0-cp313-cp313-manylinux2014_x86_64.whl", "2.1.0"))
        for filename in (CISCO_WHEEL.replace("cp313.", ""), CISCO_WHEEL.replace("x86_64", "aarch64"),
                         CISCO_WHEEL.replace("none", "cp312"), CISCO_WHEEL.replace("2.1.0", "2.0.0")):
            with self.subTest(filename=filename):
                self.assertFalse(vendors._cisco_wheel(filename, "2.1.0"))

    def test_unstable_malicious_or_unhashed_releases_are_rejected(self):
        for override in ({"tag_name": "../../main"}, {"draft": True}, {"prerelease": True}):
            def changed(path):
                data = api_fixture(path)
                if path.endswith("/releases/latest"):
                    data.update(override)
                return data
            with self.subTest(override=override), patch.object(vendors, "api", side_effect=changed), patch.object(vendors, "fetch", side_effect=source_fetch):
                with self.assertRaisesRegex(ValueError, "unsupported-release"):
                    vendors.resolve()
        def missing_digest(path):
            data = api_fixture(path)
            if "NVIDIA/" in path and path.endswith("/releases/latest"):
                data["assets"][0].pop("digest")
            return data
        with patch.object(vendors, "api", side_effect=missing_digest), patch.object(vendors, "fetch", side_effect=source_fetch):
            with self.assertRaisesRegex(ValueError, "missing-wheel-digest"):
                vendors.resolve()

    def test_resolve_rejects_nonimmutable_commit_response(self):
        def changed(path):
            data = api_fixture(path)
            if "/commits/" in path:
                data["sha"] = "main"
            return data
        with patch.object(vendors, "api", side_effect=changed), patch.object(vendors, "fetch", side_effect=source_fetch):
            with self.assertRaisesRegex(ValueError, "invalid-source-sha"):
                vendors.resolve()

    def test_fetch_rejects_insecure_or_ambiguous_urls_before_network(self):
        for url in ("http://api.github.com/repos/example", "https://api.github.com.evil.invalid/x",
                    "https://token@api.github.com/x", "https://api.github.com:444/x",
                    "https://api.github.com/x#fragment", "https://api.github.com/x\nINJECT",
                    "file:///etc/passwd", "https://github.com\\evil.invalid/x"):
            with self.subTest(url=url), patch.object(vendors, "build_opener") as opener:
                with self.assertRaises(ValueError):
                    vendors.fetch(url, token="secret")
                opener.assert_not_called()

    def test_authentication_is_only_sent_to_github_api(self):
        for url, authorized in (("https://api.github.com/repos/example", True),
                                ("https://github.com/NVIDIA/SkillSpector/releases/download/v2.11.2/x.whl", False)):
            opener = MagicMock()
            opener.open.return_value.__enter__.return_value.read.return_value = b"{}"
            with self.subTest(url=url), patch.object(vendors, "build_opener", return_value=opener):
                self.assertEqual(vendors.fetch(url, token="secret"), b"{}")
            request = opener.open.call_args.args[0]
            self.assertEqual(request.get_header("Authorization"), "Bearer secret" if authorized else None)
            self.assertEqual(opener.open.call_args.kwargs["timeout"], 60)

    def test_release_asset_redirect_is_validated_and_strips_auth(self):
        request = Request("https://github.com/NVIDIA/SkillSpector/releases/download/v2.11.2/x.whl",
                          headers={"Authorization": "Bearer secret"})
        handler = vendors._SafeRedirect()
        redirected = handler.redirect_request(request, None, 302, "Found", {},
                                               "https://release-assets.githubusercontent.com/asset?signature=test")
        self.assertIsNone(redirected.get_header("Authorization"))
        for url in ("http://release-assets.githubusercontent.com/asset", "https://evil.invalid/asset",
                    "https://raw.githubusercontent.com/other/repo/main/setup.py"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                handler.redirect_request(request, None, 302, "Found", {}, url)
        with self.assertRaises(ValueError):
            handler.redirect_request(Request("https://api.github.com/repos/example", headers={"Authorization": "Bearer secret"}),
                                     None, 302, "Found", {}, "https://release-assets.githubusercontent.com/asset")

    def test_fetch_enforces_bounded_reads(self):
        opener = MagicMock()
        response = opener.open.return_value.__enter__.return_value
        response.read.return_value = b"x" * 17
        with patch.object(vendors, "build_opener", return_value=opener), patch.object(vendors, "MAX_DOWNLOAD", 16):
            with self.assertRaisesRegex(ValueError, "download-size-limit"):
                vendors.fetch("https://pypi.org/pypi/example/json")
        response.read.assert_called_once_with(17)

    def test_materialize_writes_only_hash_verified_source_and_hashed_requirement(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(vendors, "fetch", side_effect=source_fetch):
            root = Path(temporary) / "vendors"
            pins = pins_fixture()
            vendors.materialize(pins, root)
            for name, engine in pins["engines"].items():
                self.assertEqual((root / name / "uv.lock").read_bytes(), LOCK)
                self.assertEqual((root / name / "pyproject.toml").read_bytes(), PROJECT)
                self.assertEqual((root / name / "wheel.txt").read_text(),
                                 engine["wheel_url"] + " --hash=sha256:" + engine["wheel_sha256"] + "\n")

    def test_materialize_revalidates_pins_even_with_recomputed_fingerprint(self):
        attacks = (("repository", "attacker/SkillSpector"), ("source_sha", "main"),
                   ("wheel_url", "https://github.com/attacker/repo/releases/download/v2.11.2/" + NVIDIA_WHEEL),
                   ("wheel_url", "https://github.com/NVIDIA/SkillSpector/releases/download/v2.11.2/" + NVIDIA_WHEEL + "\nmalicious-package"),
                   ("wheel_sha256", "c" * 64 + "\n--extra-index-url https://evil.invalid"),
                   ("version", "2.11.2\n"), ("lock_sha256", "not-a-hash"))
        for field, value in attacks:
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as temporary:
                pins = pins_fixture()
                pins["engines"]["nvidia"][field] = value
                repin(pins)
                with patch.object(vendors, "fetch") as fetch, self.assertRaises(ValueError):
                    vendors.materialize(pins, Path(temporary) / "vendors")
                fetch.assert_not_called()

    def test_missing_engine_and_fingerprint_mismatch_fail_before_download(self):
        for mutate in (lambda pins: pins["engines"].pop("nvidia"),
                       lambda pins: pins.update(fingerprint="0" * 64)):
            pins = pins_fixture()
            mutate(pins)
            with tempfile.TemporaryDirectory() as temporary, patch.object(vendors, "fetch") as fetch:
                with self.assertRaises(ValueError):
                    vendors.materialize(pins, Path(temporary) / "vendors")
                fetch.assert_not_called()

    def test_source_digest_mismatch_is_not_materialized(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(vendors, "fetch", return_value=b"tampered"):
            root = Path(temporary) / "vendors"
            with self.assertRaisesRegex(ValueError, "vendor-file-digest-mismatch"):
                vendors.materialize(pins_fixture(), root)
            self.assertFalse((root / "cisco" / "uv.lock").exists())

    def test_linked_destination_does_not_overwrite_external_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "outside"
            outside.mkdir()
            link = root / "vendors"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except OSError:
                self.skipTest("Symlink creation is unavailable on this host")
            with patch.object(vendors, "fetch") as fetch, self.assertRaisesRegex(ValueError, "linked-vendor-destination"):
                vendors.materialize(pins_fixture(), link)
            fetch.assert_not_called()
            self.assertEqual(list(outside.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
