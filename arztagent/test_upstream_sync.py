"""Tests for upstream_sync.py: classification, image tags and the merge flow on throwaway repos.

Run: python3 -m unittest discover -s arztagent -p 'test_*.py'
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import upstream_sync as sync


class ClassifyTest(unittest.TestCase):
    def test_security_word(self):
        result = sync.classify("Bind refresh tokens to their client (#1781)", "", ["README.md"])
        self.assertTrue(result["security"])

    def test_fix_in_auth_path(self):
        result = sync.classify("Fix update used ts dyn client device code", "",
                               ["src/service/src/oidc/grant_types/device_code.rs"])
        self.assertTrue(result["security"])
        self.assertTrue(result["auth"])

    def test_fix_naming_mfa(self):
        self.assertTrue(sync.classify("Fix: admin-based MFA deletion for user", "", [])["security"])

    def test_feature_in_auth_path_is_only_auth(self):
        result = sync.classify("feat: configurable name order", "", ["src/data/src/entity/users.rs"])
        self.assertFalse(result["security"])
        self.assertTrue(result["auth"])

    def test_unrelated_fix(self):
        result = sync.classify("Fix: make the updated svelte linter happy", "", ["frontend/x.svelte"])
        self.assertFalse(result["security"])

    def test_upstream_pr_number(self):
        self.assertEqual(sync.upstream_pr("Fix: race (#1807)"), 1807)
        self.assertIsNone(sync.upstream_pr("no number"))


class ImageTagTest(unittest.TestCase):
    TAGS = ["0.37.1-aa1", "0.37.1-aa6", "0.37.2-aa1", "latest", "0.37.10-aa2", "0.37.1"]

    def test_next_for_known_version(self):
        self.assertEqual(sync.next_tag("0.37.1", self.TAGS), "0.37.1-aa7")

    def test_next_for_new_version(self):
        self.assertEqual(sync.next_tag("0.38.0", self.TAGS), "0.38.0-aa1")

    def test_latest_compares_numbers(self):
        self.assertEqual(sync.latest_tag(self.TAGS), "0.37.10-aa2")
        self.assertIsNone(sync.latest_tag(["latest"]))


class PrBodyTest(unittest.TestCase):
    def test_lists_security_commits_and_conflicts(self):
        plan = {
            "upstream": "a" * 40, "upstream_version": "0.37.2", "fork_version": "0.37.1",
            "commits": [
                {"sha": "b" * 40, "subject": "Fix: race | x (#1)", "pr": 1, "security": True,
                 "auth": True, "reasons": ["Stichworte: race"]},
                {"sha": "c" * 40, "subject": "feat: y", "pr": None, "security": False,
                 "auth": True, "reasons": []},
            ],
            "advisories": [], "conflicts": ["src/a.rs"], "notes": "kept both checks",
        }
        body = sync.pr_body(plan, "https://run")
        self.assertIn("**1 sicherheitsrelevant**", body)
        self.assertIn("Fix: race \\| x", body)
        self.assertIn("ändert Auth-Code", body)
        self.assertIn("`src/a.rs`", body)
        self.assertIn("kept both checks", body)


def run(cwd, *args):
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


class MergeFlowTest(unittest.TestCase):
    """fork and upstream diverge from a common base; merge, resolve, finish, verify."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name) / "repo"
        self.repo.mkdir()
        self.cwd = os.getcwd()
        run(self.repo, "git", "init", "-q", "-b", "main")
        run(self.repo, "git", "config", "user.email", "t@example.org")
        run(self.repo, "git", "config", "user.name", "t")
        (self.repo / "Cargo.toml").write_text('[workspace.package]\nversion = "0.1.0"\n')
        (self.repo / "auth.rs").write_text("check_a();\n")
        run(self.repo, "git", "add", "-A")
        run(self.repo, "git", "commit", "-qm", "base")
        run(self.repo, "git", "checkout", "-qb", "upstream")
        os.chdir(self.repo)
        self.plan = str(Path(self.tmp.name) / "plan.json")

    def tearDown(self):
        os.chdir(self.cwd)
        self.tmp.cleanup()

    def commit(self, branch, path, text, message):
        run(self.repo, "git", "checkout", "-q", branch)
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        run(self.repo, "git", "add", "-A")
        run(self.repo, "git", "commit", "-qm", message)

    def make_plan(self):
        sync.main(["--plan", self.plan, "plan", "--base", "main", "--upstream", "upstream", "--repo", ""])
        return sync.load(self.plan)

    def test_clean_merge(self):
        self.commit("upstream", "other.rs", "x\n", "Fix: session race (#2)")
        self.commit("main", "fork.rs", "y\n", "fork change")
        plan = self.make_plan()
        self.assertEqual(len(plan["commits"]), 1)
        self.assertTrue(plan["commits"][0]["security"])
        self.assertEqual(sync.main(["--plan", self.plan, "merge"]), 0)
        sync.verify_bundle_head(plan, "HEAD")

    def test_conflict_then_finish(self):
        self.commit("upstream", "auth.rs", "check_a();\ncheck_upstream();\n", "Fix: token check")
        self.commit("main", "auth.rs", "check_a();\ncheck_fork();\n", "fork hardening")
        plan = self.make_plan()
        self.assertEqual(sync.main(["--plan", self.plan, "merge"]), sync.CONFLICT_EXIT)
        self.assertEqual(sync.load(self.plan)["conflicts"], ["auth.rs"])
        self.assertEqual(sync.main(["--plan", self.plan, "finish"]), 1)  # markers still there
        (self.repo / "auth.rs").write_text("check_a();\ncheck_fork();\ncheck_upstream();\n")
        (self.repo / "SYNC_NOTES.md").write_text("kept both checks")
        self.assertEqual(sync.main(["--plan", self.plan, "finish"]), 0)
        sync.verify_bundle_head(plan, "HEAD")
        self.assertEqual(sync.load(self.plan)["notes"], "kept both checks")
        self.assertFalse((self.repo / "SYNC_NOTES.md").exists())

    def test_extra_commit_is_rejected(self):
        self.commit("upstream", "other.rs", "x\n", "feat: x")
        plan = self.make_plan()
        sync.main(["--plan", self.plan, "merge"])
        self.commit(plan["branch"], "sneaky.rs", "z\n", "extra")
        with self.assertRaises(RuntimeError):
            sync.verify_bundle_head(plan, "HEAD")

    def test_workflow_change_is_refused(self):
        self.commit("upstream", ".github/workflows/x.yaml", "on: push\n", "ci")
        self.make_plan()
        self.assertEqual(sync.main(["--plan", self.plan, "merge"]), 4)
        self.assertEqual(sync.load(self.plan)["forbidden"], [".github/workflows/x.yaml"])


if __name__ == "__main__":
    unittest.main()
