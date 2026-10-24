#!/usr/bin/env python3
"""Regression tests for install.sh and tools/validate.py.

Each test builds a throwaway copy of the repo layout (the real tools and
installer, a few fixture skills) in a temp folder and runs it there, so the
real Skills/ tree is never touched.

Usage:
  python3 -m unittest discover -s tools -p 'test_*.py'
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

try:
    import yaml  # noqa: F401  # type: ignore

    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

REPO = Path(__file__).resolve().parent.parent
TIER2 = "> **Tier 2 - methodology skill.** No rule ships with this skill yet.\n"


def skill_text(name: str, description: str = "Detect an example threat. Use when testing.", extra_fm: str = "", body: str = "") -> str:
    return f'---\nname: {name}\ndescription: "{description}"\n{extra_fm}---\n\n# {name}\n\n{TIER2}\n{body}'


class Sandbox:
    """A temp repo with the real tools and installer and fixture skills."""

    def __init__(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "repo"
        (self.root / "tools").mkdir(parents=True)
        for f in ("_common.py", "validate.py", "sync_rules.py"):
            shutil.copy(REPO / "tools" / f, self.root / "tools" / f)
        shutil.copy(REPO / "install.sh", self.root / "install.sh")
        self.target = Path(self.tmp.name) / "target"
        self.skills: list[str] = []

    def add(self, category: str, name: str, text: str | None = None, pair: bool = True) -> Path:
        d = self.root / "Skills" / category / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "SKILL.md").write_text(text if text is not None else skill_text(name), encoding="utf-8")
        if pair:
            self.skills.append(name)
        return d

    def remove(self, category: str, name: str) -> None:
        shutil.rmtree(self.root / "Skills" / category / name)
        self.skills.remove(name)

    def write_pairs(self) -> None:
        pairs = [{"red": f"red-{n}", "blue": n} for n in self.skills]
        (self.root / "tools" / "pairs.json").write_text(json.dumps({"pairs": pairs}), encoding="utf-8")

    def validate(self, *args: str) -> subprocess.CompletedProcess:
        self.write_pairs()
        return self.tool("validate.py", *args)

    def tool(self, script: str, *args: str) -> subprocess.CompletedProcess:
        # The interpreter running the tests, so HAVE_YAML describes the validator too.
        return subprocess.run([sys.executable, f"tools/{script}", *args], cwd=self.root, capture_output=True, text=True)

    def install(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(self.root / "install.sh"), *args], cwd=self.root, capture_output=True, text=True)

    def close(self) -> None:
        self.tmp.cleanup()


class SandboxTest(unittest.TestCase):
    def setUp(self) -> None:
        self.sb = Sandbox()
        self.addCleanup(self.sb.close)
        self.sb.add("web", "detect-one")
        self.sb.add("cloud", "detect-two")


class InstallerTests(SandboxTest):
    def test_option_without_value_is_a_clear_error(self) -> None:
        for opt in ("--target", "--category", "--tier"):
            with self.subTest(opt=opt):
                r = self.sb.install(opt)
                self.assertEqual(r.returncode, 1, r.stderr)
                self.assertIn(f"{opt} needs a value", r.stderr)
                self.assertNotIn("unbound variable", r.stderr)

    def test_option_followed_by_another_option_is_not_taken_as_its_value(self) -> None:
        for nxt in ("--dry-run", "-h"):
            with self.subTest(nxt=nxt):
                r = self.sb.install("--target", nxt)
                self.assertEqual(r.returncode, 1, r.stderr)
                self.assertIn("--target needs a value", r.stderr)
                self.assertFalse((self.sb.root / nxt).exists())

    def test_install_update_and_uninstall(self) -> None:
        t = str(self.sb.target)
        r = self.sb.install("--target", t)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Installed 2, updated 0", r.stdout)
        r = self.sb.install("--target", t)
        self.assertIn("Installed 0, updated 2", r.stdout)
        r = self.sb.install("--target", t, "--uninstall")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(list(self.sb.target.iterdir()), [])

    def test_update_removes_skills_no_longer_in_the_repo(self) -> None:
        t = str(self.sb.target)
        self.sb.install("--target", t)
        self.sb.remove("cloud", "detect-two")
        r = self.sb.install("--target", t)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse((self.sb.target / "detect-two").exists(), r.stdout)
        self.assertTrue((self.sb.target / "detect-one" / "SKILL.md").exists())
        self.assertIn("removed 1", r.stdout)

    def test_update_of_one_category_still_removes_stale_skills_but_keeps_others(self) -> None:
        t = str(self.sb.target)
        self.sb.install("--target", t)
        self.sb.remove("web", "detect-one")
        self.sb.add("cloud", "detect-three")
        r = self.sb.install("--target", t, "--category", "cloud")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse((self.sb.target / "detect-one").exists(), r.stdout)
        self.assertTrue((self.sb.target / "detect-two").exists())
        self.assertTrue((self.sb.target / "detect-three").exists())

    def test_stale_removal_never_touches_folders_without_the_marker(self) -> None:
        t = str(self.sb.target)
        self.sb.install("--target", t)
        own = self.sb.target / "my-own-skill"
        own.mkdir()
        (own / "SKILL.md").write_text("mine", encoding="utf-8")
        r = self.sb.install("--target", t)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((own / "SKILL.md").exists())

    def test_a_renamed_copy_of_an_installed_skill_is_never_removed(self) -> None:
        t = str(self.sb.target)
        self.sb.install("--target", t)
        copy = self.sb.target / "my-detect-one"
        shutil.copytree(self.sb.target / "detect-one", copy)
        r = self.sb.install("--target", t, "--category", "web")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((copy / "SKILL.md").exists(), r.stdout)
        self.assertIn("removed 0", r.stdout)

    def test_a_marker_from_an_older_installer_is_never_removed(self) -> None:
        old = self.sb.target / "detect-gone"
        old.mkdir(parents=True)
        (old / "SKILL.md").write_text("old", encoding="utf-8")
        (old / ".umbra-blue").write_text("web\n", encoding="utf-8")
        r = self.sb.install("--target", str(self.sb.target))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((old / "SKILL.md").exists(), r.stdout)

    def test_dry_run_reports_stale_skills_without_removing_them(self) -> None:
        t = str(self.sb.target)
        self.sb.install("--target", t)
        self.sb.remove("cloud", "detect-two")
        r = self.sb.install("--target", t, "--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("would remove", r.stdout)
        self.assertTrue((self.sb.target / "detect-two").exists())


class ValidatorTests(SandboxTest):
    def assertFails(self, needle: str, *args: str) -> None:
        r = self.sb.validate(*args)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn(needle, r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_clean_fixture_passes(self) -> None:
        r = self.sb.validate()
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_extra_frontmatter_key(self) -> None:
        self.sb.add("web", "detect-one", skill_text("detect-one", extra_fm="license: MIT\n"))
        self.assertFails("frontmatter key")

    def test_angle_brackets_in_description(self) -> None:
        self.sb.add("web", "detect-one", skill_text("detect-one", description="Detect <script> tags. Use when testing."))
        self.assertFails("angle brackets")

    def test_reserved_word_in_name(self) -> None:
        self.sb.add("web", "claude-helper", skill_text("claude-helper"))
        self.assertFails("reserved word")

    def test_empty_description_value(self) -> None:
        text = "---\nname: detect-one\ndescription:\n---\n\n" + TIER2
        self.sb.add("web", "detect-one", text)
        self.assertFails("empty description")

    @unittest.skipUnless(HAVE_YAML, "the fallback parser does not reject malformed YAML")
    def test_malformed_yaml_frontmatter_is_reported_not_a_crash(self) -> None:
        text = '---\nname: detect-one\ndescription: "unterminated\n---\n\n' + TIER2
        self.sb.add("web", "detect-one", text)
        self.assertFails("malformed frontmatter")

    def test_duplicate_skill_name_across_categories(self) -> None:
        self.sb.add("cloud", "detect-one", pair=False)
        self.assertFails("more than one category")

    def test_skill_folder_without_skill_md(self) -> None:
        (self.sb.root / "Skills" / "web" / "detect-empty").mkdir()
        self.assertFails("has no SKILL.md")

    def test_dot_entries_in_a_category_are_not_skill_folders(self) -> None:
        (self.sb.root / "Skills" / "web" / ".DS_Store").write_text("x", encoding="utf-8")
        (self.sb.root / "Skills" / "web" / ".hidden").mkdir()
        r = self.sb.validate()
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_skill_md_at_the_wrong_depth(self) -> None:
        d = self.sb.root / "Skills" / "web" / "detect-one" / "nested"
        d.mkdir()
        (d / "SKILL.md").write_text(skill_text("nested"), encoding="utf-8")
        self.assertFails("not at Skills/<category>/<skill>/SKILL.md")

    def test_dash_in_a_bundled_file(self) -> None:
        (self.sb.root / "Skills" / "web" / "detect-one" / "notes.md").write_text("a \u2014 b\n", encoding="utf-8")
        self.assertFails("notes.md: contains an em-dash or en-dash")

    def test_broken_relative_link_without_dot_prefix(self) -> None:
        self.sb.add("web", "detect-one", skill_text("detect-one", body="See [notes](references/missing.md).\n"))
        self.assertFails("broken relative link references/missing.md")

    def test_relative_link_that_leaves_the_repo(self) -> None:
        outside = self.sb.root.parent / "outside.md"
        outside.write_text("x", encoding="utf-8")
        self.sb.add("web", "detect-one", skill_text("detect-one", body="See [x](../../../../outside.md).\n"))
        self.assertFails("points outside the repository")

    def test_links_that_are_urls_or_anchors_are_not_checked(self) -> None:
        body = "[a](https://example.com/x) [b](#tldr) [c](mailto:someone)\n"
        self.sb.add("web", "detect-one", skill_text("detect-one", body=body))
        r = self.sb.validate()
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_duplicate_rule_file_name_in_sigma_pack(self) -> None:
        pack = self.sb.root.parent / "pack"
        (pack / "a").mkdir(parents=True)
        (pack / "b").mkdir()
        (pack / "a" / "rule.yml").write_text("title: A\n", encoding="utf-8")
        (pack / "b" / "rule.yml").write_text("title: B\n", encoding="utf-8")
        self.assertFails("rule.yml appears more than once", "--sigma-pack", str(pack))

    def test_sync_rules_reads_the_same_rule_files_as_the_validator(self) -> None:
        pack = self.sb.root.parent / "pack"
        pack.mkdir()
        (pack / "rule.yaml").write_text("title: New\n", encoding="utf-8")
        body = "```yaml\n# rule.yaml (canonical copy: https://umbrasec.dev/tools/sigma-pack/)\ntitle: Old\n```\n"
        text = skill_text("detect-one", body=body).replace(TIER2, "")
        self.sb.add("web", "detect-one", text)
        self.assertFails("differs from sigma-pack", "--sigma-pack", str(pack))
        r = self.sb.tool("sync_rules.py", "--sigma-pack", str(pack))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        r = self.sb.validate("--sigma-pack", str(pack))
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
