"""Tests for copilot_findings.py: selection, verdict checks, fix verification and publishing."""

import argparse
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import copilot_findings as cf


def alert(number, level, tool="CodeQL", path="src/a.rs"):
    return {"number": number, "tool": {"name": tool}, "html_url": f"https://x/{number}",
            "rule": {"id": f"rust/rule-{number}", "security_severity_level": level, "description": "Bad"},
            "most_recent_instance": {"location": {"path": path, "start_line": 3}}}


class SelectTest(unittest.TestCase):
    def test_worst_first_codeql_only_skips_handled(self):
        alerts = [alert(1, "low"), alert(2, "critical"), alert(3, "high", tool="zizmor"),
                  alert(4, "high"), alert(5, "medium")]
        chosen = cf.select(alerts, skip={4}, limit=2)
        self.assertEqual([a["number"] for a in chosen], [2, 5])

    def test_handled_from_prs_and_issues(self):
        pulls = [{"head": {"ref": "copilot-autofix/alert-7"}}, {"head": {"ref": "feature"}}]
        issues = [{"title": "Security-Entscheidung: Code-Scanning-Alert #9 (rust/x)"}]
        with patch.object(cf, "api", side_effect=[pulls, issues]):
            self.assertEqual(cf.handled("o/r"), {7, 9})


class VerdictTest(unittest.TestCase):
    def write(self, data):
        path = Path(tempfile.mkdtemp()) / cf.VERDICT
        path.write_text(json.dumps(data))
        return path

    def test_valid(self):
        verdict = cf.load_verdict(self.write({"decision": "accept", "summary": "ok"}))
        self.assertEqual(verdict["decision"], "accept")

    def test_invalid(self):
        for data in ({"decision": "maybe", "summary": "x"}, {"decision": "dismiss", "summary": "x"},
                     {"decision": "accept", "summary": " "}):
            with self.assertRaises(ValueError):
                cf.load_verdict(self.write(data))


def run(cwd, *args):
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


class GitTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        self.cwd = os.getcwd()
        run(self.repo, "git", "init", "-q", "-b", "main")
        run(self.repo, "git", "config", "user.email", "t@example.org")
        run(self.repo, "git", "config", "user.name", "t")
        (self.repo / "a.rs").write_text("x\n")
        run(self.repo, "git", "add", "-A")
        run(self.repo, "git", "commit", "-qm", "base")
        self.base = run(self.repo, "git", "rev-parse", "HEAD")
        os.chdir(self.repo)

    def tearDown(self):
        os.chdir(self.cwd)
        self.tmp.cleanup()

    def commit(self, path, text):
        (self.repo / path).parent.mkdir(parents=True, exist_ok=True)
        (self.repo / path).write_text(text)
        run(self.repo, "git", "add", "-A")
        run(self.repo, "git", "commit", "-qm", "fix")
        return run(self.repo, "git", "rev-parse", "HEAD")

    def test_fix_on_main(self):
        head = self.commit("a.rs", "y\n")
        self.assertEqual(cf.verify_fix(self.base, head), ["a.rs"])

    def test_workflow_change_refused(self):
        head = self.commit(".github/workflows/x.yaml", "on: push\n")
        with self.assertRaises(RuntimeError):
            cf.verify_fix(self.base, head)

    def test_unrelated_history_refused(self):
        run(self.repo, "git", "checkout", "-q", "--orphan", "other")
        head = self.commit("b.rs", "z\n")
        with self.assertRaises(RuntimeError):
            cf.verify_fix(self.base, head)


class PublishTest(unittest.TestCase):
    def publish(self, level, verdict):
        out = Path(tempfile.mkdtemp())
        (out / "alert.json").write_text(json.dumps({"alert": alert(3, level), "branch": "copilot-autofix/alert-3",
                                                    "base": "0" * 40, "autofix": {"status": "success"}}))
        (out / "verdict.json").write_text(json.dumps(verdict))
        calls = []
        with patch.object(cf, "api", side_effect=lambda *a: calls.append(a)):
            cf.cmd_publish(argparse.Namespace(out=str(out), repo="o/r", run_url="u"))
        return calls

    def test_dismiss_medium(self):
        calls = self.publish("medium", {"decision": "dismiss", "dismissed_reason": "false positive",
                                        "summary": "nur Testcode"})
        patch_call = [c for c in calls if c[0] == "PATCH"][0]
        self.assertEqual(patch_call[2]["state"], "dismissed")
        self.assertTrue(patch_call[2]["dismissed_comment"].startswith("Security-Agent:"))

    def test_dismiss_high_asks_a_human(self):
        calls = self.publish("high", {"decision": "dismiss", "dismissed_reason": "won't fix", "summary": "s"})
        self.assertFalse([c for c in calls if c[0] == "PATCH"])
        issue = [c for c in calls if c[0] == "POST" and c[1].endswith("/issues")][0]
        self.assertIn(cf.LABEL_DECISION, issue[2]["labels"])
        self.assertIn("#3", issue[2]["title"])

    def test_body_names_decision(self):
        record = {"alert": alert(3, "high"), "autofix": {"description": "Copilot sagt"}}
        text = cf.body(record, {"decision": "improve", "summary": "s", "tests": "cargo test ok"}, ["a.rs"], "u")
        self.assertIn("verbessert", text)
        self.assertIn("Copilot sagt", text)


if __name__ == "__main__":
    unittest.main()
