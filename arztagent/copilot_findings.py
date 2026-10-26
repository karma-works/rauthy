#!/usr/bin/env python3
"""Check GitHub code scanning findings and their Copilot Autofix, then fix, improve or reject.

Used by .github/workflows/copilot_findings.yaml; see arztagent/SECURITY-AGENT.md.

  plan       open CodeQL alerts not handled yet (no open PR, no open decision issue), worst
             first, at most --max; writes the matrix for the workflow
  autofix    asks Copilot Autofix for one alert and commits it to copilot-autofix/alert-<n>
             (API only, no repository code runs); without an autofix the branch is plain main
  finalize   after Claude: commits its edits, checks the verdict file, writes a git bundle
  publish    verdict fix/improve/own-fix: push, open the PR, dispatch CI;
             dismiss: dismiss the alert (low/medium) or ask a human in an issue (high/critical);
             unsure: issue

The verdict (FINDING_VERDICT.json, written by Claude) has
  {"decision": "accept" | "improve" | "own-fix" | "dismiss" | "unsure",
   "dismissed_reason": "false positive" | "won't fix" | "used in tests",   (dismiss only)
   "summary": "...", "tests": "..."}
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from upstream_sync import CI_WORKFLOWS, FORBIDDEN_PATHS, api, git, write_output

TOOLS = ("CodeQL",)
BRANCH_PREFIX = "copilot-autofix/alert-"
LABEL_AUTOFIX = "copilot-autofix"
LABEL_SECURITY = "security"
LABEL_DECISION = "security-decision"
SEVERITY_ORDER = ("critical", "high", "medium", "low", "error", "warning", "note", "none")
AUTO_DISMISS = ("medium", "low", "warning", "note", "none")
DECISIONS = ("accept", "improve", "own-fix", "dismiss", "unsure")
DISMISS_REASONS = ("false positive", "won't fix", "used in tests")
VERDICT = "FINDING_VERDICT.json"


def severity(alert: dict[str, Any]) -> str:
    rule = alert.get("rule") or {}
    return (rule.get("security_severity_level") or rule.get("severity") or "none").lower()


def location(alert: dict[str, Any]) -> str:
    loc = (alert.get("most_recent_instance") or {}).get("location") or {}
    return f"{loc.get('path', '?')}:{loc.get('start_line', '?')}"


def handled(repo: str) -> set[int]:
    """Alerts with an open autofix PR or an open decision issue."""
    numbers = set()
    for pull in api("GET", f"repos/{repo}/pulls?state=open&per_page=100") or []:
        ref = pull["head"]["ref"]
        if ref.startswith(BRANCH_PREFIX) and ref[len(BRANCH_PREFIX):].isdigit():
            numbers.add(int(ref[len(BRANCH_PREFIX):]))
    for issue in api("GET", f"repos/{repo}/issues?state=open&labels={LABEL_DECISION}&per_page=100") or []:
        title = issue.get("title", "")
        if "#" in title and "pull_request" not in issue:
            digits = title.split("#", 1)[1].split()[0].rstrip(":")
            if digits.isdigit():
                numbers.add(int(digits))
    return numbers


def select(alerts: list[dict[str, Any]], skip: set[int], limit: int) -> list[dict[str, Any]]:
    candidates = [a for a in alerts if a["tool"]["name"] in TOOLS and a["number"] not in skip]
    candidates.sort(key=lambda a: (SEVERITY_ORDER.index(severity(a)) if severity(a) in SEVERITY_ORDER
                                   else len(SEVERITY_ORDER), a["number"]))
    return candidates[:limit]


def cmd_plan(args: argparse.Namespace) -> int:
    alerts = api("GET", f"repos/{args.repo}/code-scanning/alerts?state=open&ref=refs/heads/main&per_page=100") or []
    chosen = select(alerts, handled(args.repo), args.max)
    matrix = [{"alert": a["number"], "rule": a["rule"]["id"], "severity": severity(a),
               "location": location(a)} for a in chosen]
    print(f"{len(alerts)} open alerts, {len(matrix)} to check: {json.dumps(matrix)}")
    write_output(matrix=json.dumps(matrix), count=len(matrix))
    return 0


def cmd_autofix(args: argparse.Namespace) -> int:
    """Copilot Autofix for one alert, committed to its branch; alert.json for the next jobs."""
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    alert = api("GET", f"repos/{args.repo}/code-scanning/alerts/{args.alert}")
    branch = f"{BRANCH_PREFIX}{args.alert}"
    main_sha = api("GET", f"repos/{args.repo}/git/ref/heads/main")["object"]["sha"]
    try:
        api("POST", f"repos/{args.repo}/git/refs", {"ref": f"refs/heads/{branch}", "sha": main_sha})
    except RuntimeError:
        api("PATCH", f"repos/{args.repo}/git/refs/heads/{branch}", {"sha": main_sha, "force": True})
    autofix = _request_autofix(args.repo, args.alert, args.wait)
    commit = None
    if autofix.get("status") == "success":
        try:
            commit = api("POST", f"repos/{args.repo}/code-scanning/alerts/{args.alert}/autofix/commits", {
                "target_ref": f"refs/heads/{branch}",
                "message": f"Copilot Autofix for code scanning alert #{args.alert}"})
        except RuntimeError as error:  # e.g. a fix in .github/ the workflow token may not commit
            autofix = {**autofix, "status": "commit-failed", "error": str(error)[:300]}
    record = {"alert": alert, "branch": branch, "base": main_sha, "autofix": autofix,
              "autofix_commit": (commit or {}).get("sha")}
    (out / "alert.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(f"alert #{args.alert}: autofix {autofix.get('status')}, branch {branch}")
    write_output(branch=branch)
    return 0


def _request_autofix(repo: str, number: int, wait: int) -> dict[str, Any]:
    path = f"repos/{repo}/code-scanning/alerts/{number}/autofix"
    try:
        status = api("POST", path) or {}
    except RuntimeError as error:  # not supported for this alert or language
        return {"status": "unavailable", "description": str(error)[:300]}
    deadline = time.monotonic() + wait
    while status.get("status") == "pending" and time.monotonic() < deadline:
        time.sleep(10)
        status = api("GET", path) or {}
    return status


def load_verdict(path: Path) -> dict[str, Any]:
    verdict = json.loads(path.read_text(encoding="utf-8"))
    if verdict.get("decision") not in DECISIONS:
        raise ValueError(f"unknown decision {verdict.get('decision')!r}")
    if verdict["decision"] == "dismiss" and verdict.get("dismissed_reason") not in DISMISS_REASONS:
        raise ValueError("dismiss needs dismissed_reason " + " | ".join(DISMISS_REASONS))
    if not str(verdict.get("summary", "")).strip():
        raise ValueError("verdict needs a summary")
    return verdict


def cmd_finalize(args: argparse.Namespace) -> int:
    out = Path(args.out)
    verdict_file = Path(VERDICT)
    try:
        verdict = load_verdict(verdict_file)
    except (OSError, ValueError) as error:
        print(f"no valid verdict ({error}); treating as unsure", file=sys.stderr)
        verdict = {"decision": "unsure", "summary": f"Kein gültiges Urteil des Agenten: {error}"}
    verdict_file.unlink(missing_ok=True)
    record = json.loads((out / "alert.json").read_text(encoding="utf-8"))
    git("add", "-u")
    if git("diff", "--cached", "--name-only"):
        git("commit", "-q", "-m", f"Fix code scanning alert #{record['alert']['number']} "
            f"({record['alert']['rule']['id']})\n\n{verdict['summary'][:1500]}")
    (out / "verdict.json").write_text(json.dumps(verdict, indent=2, ensure_ascii=False), encoding="utf-8")
    git("bundle", "create", str(out / "fix.bundle"), f"{record['base']}..HEAD", check=False)
    print(f"verdict: {verdict['decision']}")
    return 0


def verify_fix(base: str, head: str) -> list[str]:
    """Files the fix changes; raises unless it builds on main and avoids paths the token may not push."""
    if subprocess.run(["git", "merge-base", "--is-ancestor", base, head]).returncode != 0:
        raise RuntimeError(f"{head} does not build on main {base}")
    changed = git("diff", "--name-only", base, head).splitlines()
    forbidden = [f for f in changed if f.startswith(FORBIDDEN_PATHS)]
    if forbidden:
        raise RuntimeError("fix touches " + ", ".join(forbidden))
    return changed


def body(record: dict[str, Any], verdict: dict[str, Any], files: list[str], run_url: str) -> str:
    alert = record["alert"]
    rule = alert["rule"]
    autofix = record.get("autofix") or {}
    used = {"accept": "Copilot-Autofix unverändert übernommen",
            "improve": "Copilot-Autofix übernommen und vom Agenten verbessert",
            "own-fix": "Copilot-Autofix verworfen, eigener Fix des Agenten"}.get(verdict["decision"], verdict["decision"])
    lines = [
        f"Code-Scanning-Alert [#{alert['number']}]({alert['html_url']}): **{rule.get('description') or rule['id']}** "
        f"(`{rule['id']}`, Schwere {severity(alert)}) in `{location(alert)}`.",
        "",
        f"**Entscheidung:** {used}.",
        "",
        "## Bewertung des Agenten",
        "",
        verdict["summary"].strip(),
        "",
    ]
    if autofix.get("description"):
        lines += ["<details><summary>Beschreibung von Copilot Autofix</summary>", "",
                  autofix["description"].strip(), "", "</details>", ""]
    lines += ["## Geänderte Dateien", ""] + [f"- `{f}`" for f in files] + [""]
    if verdict.get("tests"):
        lines += ["## Geprüft", "", verdict["tests"].strip(), ""]
    lines += ["Ein Mensch prüft und mergt. Nach dem Merge baut `ArztAgent image` ein neues Image "
              "(Label `security`).", "", f"Lauf: {run_url}"]
    return "\n".join(lines)


def cmd_publish(args: argparse.Namespace) -> int:
    out = Path(args.out)
    record = json.loads((out / "alert.json").read_text(encoding="utf-8"))
    verdict = json.loads((out / "verdict.json").read_text(encoding="utf-8"))
    alert, branch, number = record["alert"], record["branch"], record["alert"]["number"]
    decision = verdict["decision"]
    if decision in ("accept", "improve", "own-fix"):
        git("fetch", "-q", str(out / "fix.bundle"), f"HEAD:refs/fix/{number}")
        head = git("rev-parse", f"refs/fix/{number}")
        try:
            files = verify_fix(record["base"], head)
        except RuntimeError as error:
            return _issue(args, record, verdict, f"Fix nicht automatisch veröffentlichbar: {error}")
        if not files:
            return _issue(args, record, verdict, "Das Urteil verlangt einen Fix, aber es gibt keine Änderung.")
        git("push", "-q", "--force", "origin", f"{head}:refs/heads/{branch}")
        title = f"[Security] {alert['rule'].get('description') or alert['rule']['id']} (Alert #{number})"
        pull = api("POST", f"repos/{args.repo}/pulls", {
            "title": title[:200], "head": branch, "base": "main",
            "body": body(record, verdict, files, args.run_url), "maintainer_can_modify": True})
        api("POST", f"repos/{args.repo}/issues/{pull['number']}/labels",
            {"labels": [LABEL_SECURITY, LABEL_AUTOFIX]})
        for workflow in CI_WORKFLOWS:
            try:
                api("POST", f"repos/{args.repo}/actions/workflows/{workflow}/dispatches", {"ref": branch})
            except RuntimeError as error:
                print(f"warning: could not dispatch {workflow}: {error}", file=sys.stderr)
        print(f"PR #{pull['number']} for alert #{number}")
        return 0
    _delete_branch(args.repo, branch)
    if decision == "dismiss" and severity(alert) in AUTO_DISMISS:
        api("PATCH", f"repos/{args.repo}/code-scanning/alerts/{number}", {
            "state": "dismissed", "dismissed_reason": verdict["dismissed_reason"],
            "dismissed_comment": ("Security-Agent: " + verdict["summary"])[:280]})
        print(f"alert #{number} dismissed ({verdict['dismissed_reason']})")
        return 0
    reason = ("Vorschlag: verwerfen; Schwere zu hoch für ein automatisches Verwerfen"
              if decision == "dismiss" else "Der Agent ist unsicher")
    return _issue(args, record, verdict, reason)


def _delete_branch(repo: str, branch: str) -> None:
    try:
        api("DELETE", f"repos/{repo}/git/refs/heads/{branch}")
    except RuntimeError:
        pass


def _issue(args: argparse.Namespace, record: dict[str, Any], verdict: dict[str, Any], reason: str) -> int:
    alert = record["alert"]
    text = "\n".join([
        f"{reason}.",
        "",
        f"Alert [#{alert['number']}]({alert['html_url']}): `{alert['rule']['id']}`, Schwere {severity(alert)}, "
        f"`{location(alert)}`. Copilot Autofix: {(record.get('autofix') or {}).get('status', '?')}.",
        "",
        f"**Urteil des Agenten:** {verdict['decision']}"
        + (f" ({verdict['dismissed_reason']})" if verdict.get("dismissed_reason") else ""),
        "",
        verdict["summary"].strip(),
        "",
        "Bitte entscheiden: Alert im Code Scanning mit Begründung verwerfen, oder das Issue "
        "schließen, damit der Agent beim nächsten Lauf neu prüft.",
        "",
        f"Lauf: {args.run_url}",
    ])
    api("POST", f"repos/{args.repo}/issues", {
        "title": f"Security-Entscheidung: Code-Scanning-Alert #{alert['number']} ({alert['rule']['id']})",
        "body": text, "labels": [LABEL_DECISION, LABEL_SECURITY]})
    print(f"issue opened for alert #{alert['number']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    import os

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan")
    plan.add_argument("--max", type=int, default=5)
    autofix = sub.add_parser("autofix")
    autofix.add_argument("--alert", type=int, required=True)
    autofix.add_argument("--wait", type=int, default=600)
    autofix.add_argument("--out", required=True)
    finalize = sub.add_parser("finalize")
    finalize.add_argument("--out", required=True)
    publish = sub.add_parser("publish")
    publish.add_argument("--out", required=True)
    publish.add_argument("--run-url", default="")
    args = parser.parse_args(argv)
    return {"plan": cmd_plan, "autofix": cmd_autofix, "finalize": cmd_finalize,
            "publish": cmd_publish}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
