"""Exercise publisher trust boundaries with local Git remotes and forged artifacts."""

import argparse
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import copilot_findings as findings
import upstream_sync as sync


def run(cwd, *args):
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


class PublishBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.origin = self.root / "origin.git"
        self.upstream = self.root / "upstream.git"
        run(self.root, "git", "init", "--bare", "-q", str(self.origin))
        run(self.root, "git", "init", "--bare", "-q", str(self.upstream))
        run(self.repo, "git", "init", "-q", "-b", "main")
        run(self.repo, "git", "config", "user.email", "test@example.org")
        run(self.repo, "git", "config", "user.name", "test")
        (self.repo / ".github/workflows").mkdir(parents=True)
        (self.repo / ".github/workflows/test.yaml").write_text("name: test\n")
        (self.repo / "Cargo.toml").write_text('[workspace.package]\nversion = "0.1.0"\n')
        (self.repo / "auth.rs").write_text("safe();\n")
        run(self.repo, "git", "add", ".")
        run(self.repo, "git", "commit", "-qm", "base")
        self.base = run(self.repo, "git", "rev-parse", "HEAD")
        run(self.repo, "git", "remote", "add", "origin", str(self.origin))
        run(self.repo, "git", "remote", "add", "upstream", str(self.upstream))
        run(self.repo, "git", "push", "-q", "-u", "origin", "main")
        run(self.repo, "git", "checkout", "-qb", "upstream-work")
        (self.repo / "upstream.rs").write_text("upstream();\n")
        run(self.repo, "git", "add", ".")
        run(self.repo, "git", "commit", "-qm", "upstream fix")
        self.upstream_sha = run(self.repo, "git", "rev-parse", "HEAD")
        run(self.repo, "git", "push", "-q", "upstream", "HEAD:refs/heads/main")
        self.branch = f"upstream-sync/{self.upstream_sha[:12]}"
        run(self.repo, "git", "checkout", "-qb", self.branch, "main")
        run(self.repo, "git", "merge", "--no-ff", "-qm", "merge", "upstream-work")
        self.merge = run(self.repo, "git", "rev-parse", "HEAD")
        self.cwd = os.getcwd()
        os.chdir(self.repo)

    def tearDown(self):
        os.chdir(self.cwd)
        self.tmp.cleanup()

    def remote_ref(self, ref):
        return run(self.repo, "git", "--git-dir", str(self.origin), "rev-parse", ref)

    def sync_plan(self, **changes):
        plan = {"base": self.base, "upstream": self.upstream_sha, "branch": self.branch,
                "commits": [], "advisories": [], "conflicts": [], "superseded": [],
                "fork_version": "0.1.0", "upstream_version": "0.1.0"}
        plan.update(changes)
        path = self.root / "plan.json"
        path.write_text(json.dumps(plan))
        return path

    def sync_bundle(self, head=None):
        if head:
            run(self.repo, "git", "update-ref", f"refs/heads/{self.branch}", head)
        # An attacker can put both a legitimate-looking branch and a main ref in a bundle.
        run(self.repo, "git", "update-ref", "refs/heads/main", head or self.merge)
        path = self.root / "sync.bundle"
        run(self.repo, "git", "bundle", "create", str(path), "refs/heads/main",
            f"refs/heads/{self.branch}", f"^{self.base}")
        return path

    def publish_sync(self, plan, bundle):
        args = argparse.Namespace(plan=str(plan), bundle=str(bundle), repo="owner/repo",
                                  base_branch="main", run_url="run")
        calls = []

        def api(method, path, payload=None):
            calls.append((method, path, payload))
            return {"number": 17} if method == "POST" and path.endswith("/pulls") else []

        with patch.object(sync, "api", side_effect=api), \
             patch.object(sync, "open_sync_pulls", return_value=[]), \
             patch.object(sync, "recent_advisories", return_value=[]):
            result = sync.cmd_publish(args)
        return result, calls

    def test_sync_artifact_cannot_force_push_main(self):
        with self.assertRaises(RuntimeError):
            self.publish_sync(self.sync_plan(branch="main"), self.sync_bundle())
        self.assertEqual(self.remote_ref("refs/heads/main"), self.base)

    def test_sync_artifact_cannot_choose_merge_parents(self):
        tree = run(self.repo, "git", "rev-parse", f"{self.base}^{{tree}}")
        forged_base = run(self.repo, "git", "commit-tree", tree, "-p", self.base, "-m", "forged base")
        merge_tree = run(self.repo, "git", "rev-parse", f"{self.merge}^{{tree}}")
        forged_merge = run(self.repo, "git", "commit-tree", merge_tree, "-p", forged_base,
                           "-p", self.upstream_sha, "-m", "forged merge")
        with self.assertRaises(RuntimeError):
            self.publish_sync(self.sync_plan(base=forged_base), self.sync_bundle(forged_merge))
        self.assertEqual(self.remote_ref("refs/heads/main"), self.base)

    def test_sync_ignores_artifact_superseded_pull_numbers(self):
        result, calls = self.publish_sync(self.sync_plan(superseded=[314]), self.sync_bundle())
        self.assertEqual(result, 0)
        self.assertEqual(self.remote_ref(f"refs/heads/{self.branch}"), self.merge)
        self.assertFalse(any("/314" in path for _, path, _ in calls))

    def test_sync_rejects_outdated_main(self):
        tree = run(self.repo, "git", "rev-parse", f"{self.base}^{{tree}}")
        advanced = run(self.repo, "git", "commit-tree", tree, "-p", self.base, "-m", "new main")
        run(self.repo, "git", "push", "-q", "origin", f"{advanced}:refs/heads/main")
        with self.assertRaises(RuntimeError):
            self.publish_sync(self.sync_plan(), self.sync_bundle())
        self.assertEqual(self.remote_ref("refs/heads/main"), advanced)

    def test_sync_rejects_outdated_upstream(self):
        tree = run(self.repo, "git", "rev-parse", f"{self.upstream_sha}^{{tree}}")
        advanced = run(self.repo, "git", "commit-tree", tree, "-p", self.upstream_sha, "-m", "new upstream")
        run(self.repo, "git", "push", "-q", "upstream", f"{advanced}:refs/heads/main")
        with self.assertRaises(RuntimeError):
            self.publish_sync(self.sync_plan(), self.sync_bundle())
        self.assertEqual(self.remote_ref("refs/heads/main"), self.base)

    def test_sync_does_not_overwrite_existing_branch(self):
        tree = run(self.repo, "git", "rev-parse", f"{self.base}^{{tree}}")
        other = run(self.repo, "git", "commit-tree", tree, "-p", self.base, "-m", "other work")
        run(self.repo, "git", "push", "-q", "origin", f"{other}:refs/heads/{self.branch}")
        with self.assertRaises(RuntimeError):
            self.publish_sync(self.sync_plan(), self.sync_bundle())
        self.assertEqual(self.remote_ref(f"refs/heads/{self.branch}"), other)

    def test_sync_cannot_move_a_workflow_out_of_github(self):
        (self.repo / "docs").mkdir()
        run(self.repo, "git", "mv", ".github/workflows/test.yaml", "docs/test.yaml")
        run(self.repo, "git", "commit", "--amend", "--no-edit", "-q")
        head = run(self.repo, "git", "rev-parse", "HEAD")
        with self.assertRaises(RuntimeError):
            sync.verify_bundle_head(self.base, self.upstream_sha, head)

    def test_superseded_sync_pulls_are_limited_to_this_repo_and_main(self):
        def pull(number, repo, branch, base="main"):
            return {"number": number, "head": {"repo": {"full_name": repo}, "ref": branch},
                    "base": {"ref": base}}

        pulls = [pull(1, "owner/repo", "upstream-sync/0123456789ab"),
                 pull(2, "other/repo", "upstream-sync/0123456789ab"),
                 pull(3, "owner/repo", "upstream-sync/0123456789ab", "other"),
                 pull(4, "owner/repo", "upstream-sync/not-a-sha")]
        with patch.object(sync, "api", return_value=pulls):
            self.assertEqual([p["number"] for p in sync.open_sync_pulls("owner/repo")], [1])

    def finding_artifacts(self, branch="copilot-autofix/alert-3", severity="low", number=3):
        out = self.root / "finding"
        out.mkdir(exist_ok=True)
        alert = {"number": number, "state": "open", "tool": {"name": "CodeQL"},
                 "html_url": f"https://example.invalid/{number}",
                 "rule": {"id": "rust/test", "security_severity_level": severity},
                 "most_recent_instance": {"location": {"path": "auth.rs", "start_line": 1}}}
        (out / "alert.json").write_text(json.dumps({"alert": alert, "branch": branch,
                                                    "base": self.base, "autofix": {}}))
        return out, alert

    def publish_finding(self, out, trusted_alert):
        args = argparse.Namespace(out=str(out), repo="owner/repo", run_url="run", alert=3)
        calls = []

        def api(method, path, payload=None):
            calls.append((method, path, payload))
            if method == "GET" and path.endswith("/code-scanning/alerts/3"):
                return trusted_alert
            return {"number": 17}

        with patch.object(findings, "api", side_effect=api):
            result = findings.cmd_publish(args)
        return result, calls

    def test_finding_artifact_cannot_force_push_main(self):
        out, alert = self.finding_artifacts(branch="main")
        (out / "verdict.json").write_text(json.dumps({"decision": "accept", "summary": "fix"}))
        run(self.repo, "git", "bundle", "create", str(out / "fix.bundle"), "HEAD", f"^{self.base}")
        with self.assertRaises(RuntimeError):
            self.publish_finding(out, alert)
        self.assertEqual(self.remote_ref("refs/heads/main"), self.base)

    def test_finding_uses_fresh_severity_before_dismissal(self):
        out, alert = self.finding_artifacts(severity="low")
        trusted_alert = {**alert, "rule": {**alert["rule"], "security_severity_level": "high"}}
        (out / "verdict.json").write_text(json.dumps({"decision": "dismiss", "summary": "test",
                                                      "dismissed_reason": "false positive"}))
        _, calls = self.publish_finding(out, trusted_alert)
        self.assertFalse(any(method == "PATCH" and "/code-scanning/alerts/" in path
                             for method, path, _ in calls))
        self.assertTrue(any(method == "POST" and path.endswith("/issues") for method, path, _ in calls))

    def test_finding_with_unknown_severity_needs_human_review(self):
        out, alert = self.finding_artifacts(severity=None)
        (out / "verdict.json").write_text(json.dumps({"decision": "dismiss", "summary": "test",
                                                      "dismissed_reason": "false positive"}))
        _, calls = self.publish_finding(out, alert)
        self.assertFalse(any(method == "PATCH" and "/code-scanning/alerts/" in path
                             for method, path, _ in calls))
        self.assertTrue(any(method == "POST" and path.endswith("/issues") for method, path, _ in calls))

    def test_finding_can_publish_a_verified_fix(self):
        out, alert = self.finding_artifacts()
        (out / "verdict.json").write_text(json.dumps({"decision": "accept", "summary": "fix"}))
        run(self.repo, "git", "checkout", "-qb", "finding-work", self.base)
        (self.repo / "auth.rs").write_text("safer();\n")
        run(self.repo, "git", "add", "auth.rs")
        run(self.repo, "git", "commit", "-qm", "fix")
        head = run(self.repo, "git", "rev-parse", "HEAD")
        run(self.repo, "git", "push", "-q", "origin", f"{self.base}:refs/heads/copilot-autofix/alert-3")
        run(self.repo, "git", "bundle", "create", str(out / "fix.bundle"), "HEAD", f"^{self.base}")
        result, calls = self.publish_finding(out, alert)
        self.assertEqual(result, 0)
        self.assertEqual(self.remote_ref("refs/heads/copilot-autofix/alert-3"), head)
        self.assertEqual(self.remote_ref("refs/heads/main"), self.base)
        self.assertTrue(any(method == "POST" and path.endswith("/pulls") for method, path, _ in calls))

    def test_finding_rejects_outdated_main(self):
        out, alert = self.finding_artifacts()
        (out / "verdict.json").write_text(json.dumps({"decision": "dismiss", "summary": "test",
                                                      "dismissed_reason": "false positive"}))
        tree = run(self.repo, "git", "rev-parse", f"{self.base}^{{tree}}")
        advanced = run(self.repo, "git", "commit-tree", tree, "-p", self.base, "-m", "new main")
        run(self.repo, "git", "push", "-q", "origin", f"{advanced}:refs/heads/main")
        with self.assertRaises(RuntimeError):
            self.publish_finding(out, alert)
        self.assertEqual(self.remote_ref("refs/heads/main"), advanced)

    def test_finding_does_not_overwrite_existing_branch(self):
        out, alert = self.finding_artifacts()
        (out / "verdict.json").write_text(json.dumps({"decision": "accept", "summary": "fix"}))
        run(self.repo, "git", "checkout", "-qb", "finding-work", self.base)
        (self.repo / "auth.rs").write_text("safer();\n")
        run(self.repo, "git", "add", "auth.rs")
        run(self.repo, "git", "commit", "-qm", "fix")
        run(self.repo, "git", "bundle", "create", str(out / "fix.bundle"), "HEAD", f"^{self.base}")
        tree = run(self.repo, "git", "rev-parse", f"{self.base}^{{tree}}")
        other = run(self.repo, "git", "commit-tree", tree, "-p", self.base, "-m", "other work")
        branch = "refs/heads/copilot-autofix/alert-3"
        run(self.repo, "git", "push", "-q", "origin", f"{other}:{branch}")
        with self.assertRaises(RuntimeError):
            self.publish_finding(out, alert)
        self.assertEqual(self.remote_ref(branch), other)

    def test_finding_artifact_cannot_choose_another_alert(self):
        out, alert = self.finding_artifacts(number=4)
        (out / "verdict.json").write_text(json.dumps({"decision": "dismiss", "summary": "test",
                                                      "dismissed_reason": "false positive"}))
        with self.assertRaises(RuntimeError):
            self.publish_finding(out, {**alert, "number": 3})

    def test_fix_cannot_move_a_workflow_out_of_github(self):
        run(self.repo, "git", "checkout", "-qb", "fix-work", self.base)
        (self.repo / "docs").mkdir()
        run(self.repo, "git", "mv", ".github/workflows/test.yaml", "docs/test.yaml")
        run(self.repo, "git", "commit", "-qm", "move workflow")
        head = run(self.repo, "git", "rev-parse", "HEAD")
        with self.assertRaises(RuntimeError):
            findings.verify_fix(self.base, head)


if __name__ == "__main__":
    unittest.main()
