#!/usr/bin/env python3
"""Bring upstream (sebadob/rauthy) changes, above all security fixes, into this fork.

Used by .github/workflows/upstream_sync.yaml; see arztagent/SECURITY-AGENT.md.

  plan       new upstream commits, security classification, open sync PR; writes plan.json
  merge      merge the upstream head into the fork head; exit 3 leaves conflicts for an agent
  finish     check that no conflict is left and create the merge commit
  publish    push a verified merge bundle, open the PR, dispatch CI (no upstream code runs here)
  conflict   open or update the issue for conflicts nobody resolved
  image-tag  next ArztAgent image tag (<version>-aa<n>) from GHCR, or the latest one

Only the standard library; Python 3.11+.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tomllib
from datetime import date
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

UPSTREAM = "sebadob/rauthy"
IMAGE = "karma-works/rauthy"
LABEL_SYNC = "upstream-sync"
LABEL_SECURITY = "security"
LABEL_CONFLICT = "upstream-sync-conflict"
BRANCH_PREFIX = "upstream-sync/"
# Workflows the sync dispatches on its branch: PRs opened with the workflow token start no runs.
CI_WORKFLOWS = ("code_style.yaml", "tests.yaml", "security_scan.yaml")
CONFLICT_EXIT = 3

# Words in an upstream commit message that point to a security fix on their own.
SECURITY_WORDS = re.compile(
    r"\b(security|vulnerab\w*|cve-\d{4}-\d+|ghsa(-\w{4}){3}|rustsec-\d{4}-\d+|xss|csrf|ssrf|"
    r"injection|bypass\w*|race|timing|leak\w*|dos|denial of service|open redirect|privilege\w*|"
    r"escalat\w*|sanitiz\w*|escaping|harden\w*|brute.?force|replay|single.use|bind|binds|"
    r"invalidat\w*|revo[ck]\w*|unauthori[sz]ed|forgery|forged)\b",
    re.IGNORECASE,
)
# A fix ("Fix: ...") counts when it names one of these or touches SECURITY_PATHS.
AUTH_WORDS = re.compile(
    r"\b(mfa|webauthn|passkey\w*|session\w*|token\w*|auth\w*|login|password\w*|pkce|jwt|"
    r"cookie\w*|api.?key\w*|scope\w*|permission\w*|access)\b",
    re.IGNORECASE,
)
FIX = re.compile(r"^\s*(fix|bugfix|hotfix)\b", re.IGNORECASE)
# Paths where any change touches authentication, sessions or tokens.
SECURITY_PATHS = (
    "src/service/src/oidc/",
    "src/api/src/oidc",
    "src/middlewares/",
    "src/jwt/",
    "src/service/src/login_delay",
    "src/service/src/token_set",
    "src/data/src/entity/sessions",
    "src/data/src/entity/refresh_token",
    "src/data/src/entity/users",
    "src/data/src/entity/mfa",
    "src/data/src/entity/webauthn",
    "src/data/src/entity/passkey",
    "src/data/src/entity/api_keys",
    "src/data/src/entity/clients",
    "src/data/src/entity/devices",
    "src/data/src/entity/magic_link",
    "src/data/src/entity/auth_code",
    "src/data/src/entity/pam",
    "vendor/",
)
FORBIDDEN_PATHS = (".github/",)  # the workflow token cannot push workflow changes
ADVISORY_DAYS = 180


# --- helpers ---------------------------------------------------------------------------------


def git(*args: str, check: bool = True) -> str:
    result = subprocess.run(["git", *args], capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def api(method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
    url = path if path.startswith("https://") else f"https://api.github.com/{path.lstrip('/')}"
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"{method} {url}: {error.code} {error.read()[:300]!r}") from error
    return json.loads(body) if body else None


def write_output(**values: Any) -> None:
    target = os.environ.get("GITHUB_OUTPUT")
    lines = "".join(f"{key}={value}\n" for key, value in values.items())
    if target:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(lines)
    else:
        sys.stdout.write(lines)


def load(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def save(path: str, data: dict[str, Any]) -> None:
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


# --- classification --------------------------------------------------------------------------


def classify(subject: str, body: str, files: list[str]) -> dict[str, Any]:
    """Whether an upstream commit is a security fix, and whether it changes auth code at all.

    Security: a security word in the message, or a fix that names or touches auth code. Other
    changes to auth paths (features, release preparation) are only marked as auth changes.
    """
    reasons = []
    words = sorted({m.group(0).lower() for m in SECURITY_WORDS.finditer(f"{subject}\n{body}")})
    if words:
        reasons.append("Stichworte: " + ", ".join(words))
    paths = sorted({f for f in files if f.startswith(SECURITY_PATHS)})
    is_fix = bool(FIX.match(subject))
    if is_fix and AUTH_WORDS.search(subject):
        reasons.append("Fix an Anmeldung/Token: " + AUTH_WORDS.search(subject).group(0))
    if is_fix and paths:
        shown = ", ".join(paths[:3]) + (f" (+{len(paths) - 3})" if len(paths) > 3 else "")
        reasons.append("Fix in Auth-Code: " + shown)
    return {"security": bool(reasons), "auth": bool(paths), "reasons": reasons}


def upstream_pr(subject: str) -> int | None:
    match = re.search(r"\(#(\d+)\)\s*$", subject)
    return int(match.group(1)) if match else None


def new_commits(base: str, upstream: str) -> list[dict[str, Any]]:
    log = git("log", "--reverse", "--no-merges", "--format=%H%x1f%s%x1f%b%x1e", f"{base}..{upstream}")
    commits = []
    for record in filter(None, (r.strip() for r in log.split("\x1e"))):
        sha, subject, body = (record.split("\x1f") + ["", ""])[:3]
        files = git("diff-tree", "--no-commit-id", "--name-only", "-r", sha).splitlines()
        commits.append({"sha": sha, "subject": subject, "pr": upstream_pr(subject),
                        "files": files, **classify(subject, body, files)})
    return commits


def recent_advisories() -> list[dict[str, Any]]:
    """Published GitHub advisories of the upstream repository from the last ADVISORY_DAYS."""
    try:
        advisories = api("GET", f"repos/{UPSTREAM}/security-advisories?state=published&per_page=50")
    except RuntimeError as error:
        print(f"warning: upstream advisories not readable: {error}", file=sys.stderr)
        return []
    out = []
    for item in advisories or []:
        published = (item.get("published_at") or "")[:10]
        if published and _days_ago(published) <= ADVISORY_DAYS:
            patched = sorted({v.get("patched_versions") or "?" for v in item.get("vulnerabilities") or []})
            out.append({"id": item["ghsa_id"], "severity": item.get("severity") or "?",
                        "summary": item.get("summary") or "", "published": published,
                        "patched": ", ".join(patched), "url": item.get("html_url") or ""})
    return out


def _days_ago(day: str) -> int:
    return (date.today() - date.fromisoformat(day)).days


def open_sync_pulls(repo: str) -> list[dict[str, Any]]:
    pulls = api("GET", f"repos/{repo}/pulls?state=open&per_page=100") or []
    return [p for p in pulls if p["head"]["ref"].startswith(BRANCH_PREFIX)]


# --- commands --------------------------------------------------------------------------------


def cmd_plan(args: argparse.Namespace) -> int:
    base_sha = git("rev-parse", args.base)
    upstream_sha = git("rev-parse", args.upstream)
    branch = BRANCH_PREFIX + upstream_sha[:12]
    commits = new_commits(base_sha, upstream_sha)
    advisories = recent_advisories()
    existing = open_sync_pulls(args.repo) if args.repo else []
    up_to_date = any(p["head"]["ref"] == branch for p in existing)
    plan = {
        "base": base_sha, "upstream": upstream_sha, "branch": branch,
        "upstream_version": _version_at(upstream_sha), "fork_version": _version_at(base_sha),
        "commits": commits, "advisories": advisories,
        "superseded": [p["number"] for p in existing if p["head"]["ref"] != branch],
        "conflicts": [], "notes": "",
    }
    save(args.plan, plan)
    security = any(c["security"] for c in commits)
    act = bool(commits) and not up_to_date
    print(f"{len(commits)} new upstream commits, security={security}, open PR for head={up_to_date}")
    for commit in commits:
        mark = "SECURITY" if commit["security"] else "        "
        print(f"  {mark} {commit['sha'][:10]} {commit['subject']}")
    write_output(act=str(act).lower(), security=str(security).lower(),
                 upstream_sha=upstream_sha, branch=branch, count=len(commits))
    return 0


def _version_at(ref: str) -> str:
    try:
        manifest = tomllib.loads(git("show", f"{ref}:Cargo.toml"))
    except (RuntimeError, tomllib.TOMLDecodeError):
        return "?"
    return manifest.get("workspace", {}).get("package", {}).get("version") or manifest.get(
        "package", {}).get("version", "?")


def cmd_merge(args: argparse.Namespace) -> int:
    plan = load(args.plan)
    git("checkout", "-q", "-B", plan["branch"], plan["base"])
    forbidden = _forbidden(plan["base"], plan["upstream"])
    if forbidden:
        plan["forbidden"] = forbidden
        save(args.plan, plan)
        print("upstream changes paths the sync may not push: " + ", ".join(forbidden), file=sys.stderr)
        return 4
    result = subprocess.run(
        ["git", "merge", "--no-ff", "--no-commit", plan["upstream"]], capture_output=True, text=True)
    conflicts = git("diff", "--name-only", "--diff-filter=U").splitlines()
    plan["conflicts"] = conflicts
    save(args.plan, plan)
    if result.returncode != 0 and not conflicts:
        print(result.stdout + result.stderr, file=sys.stderr)
        return 1
    if conflicts:
        print(f"{len(conflicts)} conflicts: " + ", ".join(conflicts))
        write_output(conflicts=len(conflicts))
        return CONFLICT_EXIT
    _commit(plan)
    write_output(conflicts=0)
    return 0


def _forbidden(base: str, upstream: str) -> list[str]:
    merge_base = git("merge-base", base, upstream)
    changed = git("diff", "--name-only", merge_base, upstream).splitlines()
    return [f for f in changed if f.startswith(FORBIDDEN_PATHS)]


def _commit(plan: dict[str, Any]) -> None:
    upstream = plan["upstream"][:12]
    count = len(plan["commits"])
    lines = [f"Merge upstream {UPSTREAM}@{upstream} ({count} commits)", ""]
    lines += [f"- {c['subject']}" for c in plan["commits"]]
    if plan["conflicts"]:
        lines += ["", "Conflicts resolved by the sync agent:"] + [f"- {f}" for f in plan["conflicts"]]
    git("commit", "-q", "--no-edit", "-m", "\n".join(lines))


def cmd_finish(args: argparse.Namespace) -> int:
    plan = load(args.plan)
    if not git("rev-parse", "-q", "--verify", "MERGE_HEAD", check=False):
        print("the merge state is gone; the agent must not commit or abort the merge", file=sys.stderr)
        return 1
    markers = [f for f in plan["conflicts"] if Path(f).is_file() and _has_markers(Path(f))]
    if markers:
        print("conflict markers left in: " + ", ".join(markers), file=sys.stderr)
        return 1
    notes = Path(args.notes)
    if notes.is_file():
        plan["notes"] = notes.read_text(encoding="utf-8")[:20000]
        notes.unlink()
    # Only tracked files: build output of the agent's checks must not end up in the merge.
    git("add", "-u")
    unmerged = git("diff", "--name-only", "--diff-filter=U").splitlines()
    if unmerged:
        print("still unmerged: " + ", ".join(unmerged), file=sys.stderr)
        return 1
    save(args.plan, plan)
    _commit(plan)
    return 0


def _has_markers(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return False
    return bool(re.search(r"^(<{7}|={7}|>{7})( |$)", text, re.MULTILINE))


def verify_bundle_head(plan: dict[str, Any], head: str) -> None:
    """The pushed commit must be exactly one merge of the planned fork and upstream heads."""
    parents = git("rev-list", "--parents", "-n", "1", head).split()[1:]
    if parents != [plan["base"], plan["upstream"]]:
        raise RuntimeError(f"unexpected parents {parents} for {head}")
    changed = git("diff", "--name-only", plan["base"], head).splitlines()
    forbidden = [f for f in changed if f.startswith(FORBIDDEN_PATHS)]
    if forbidden:
        raise RuntimeError("merge changes forbidden paths: " + ", ".join(forbidden))


def pr_body(plan: dict[str, Any], run_url: str) -> str:
    commits = plan["commits"]
    security = [c for c in commits if c["security"]]
    other = [c for c in commits if not c["security"]]
    lines = [
        f"Automatischer Upstream-Sync bis [{UPSTREAM}@{plan['upstream'][:12]}]"
        f"(https://github.com/{UPSTREAM}/commit/{plan['upstream']}) "
        f"(Upstream-Version {plan['upstream_version']}, Fork {plan['fork_version']}).",
        "",
        f"{len(commits)} neue Upstream-Commits, davon **{len(security)} sicherheitsrelevant**.",
        "",
    ]
    if security:
        lines += ["## Sicherheitsrelevant", "", "| Commit | Titel | Grund |", "|---|---|---|"]
        lines += [_row(c, with_reason=True) for c in security] + [""]
    if other:
        lines += ["## Weitere Commits", "", "| Commit | Titel |", "|---|---|"]
        lines += [_row(c) for c in other] + [""]
    if plan["advisories"]:
        lines += [f"## Upstream-Advisories (letzte {ADVISORY_DAYS} Tage)", "",
                  "| Advisory | Schwere | Behoben in | Zusammenfassung |", "|---|---|---|---|"]
        lines += [f"| [{a['id']}]({a['url']}) | {a['severity']} | {a['patched']} | {_cell(a['summary'])} |"
                  for a in plan["advisories"]] + [""]
    lines += ["## Konflikte", ""]
    if plan["conflicts"]:
        lines += ["**Ein Agent hat diese Konflikte aufgelöst. Bitte jede Datei im Diff genau lesen:**", ""]
        lines += [f"- `{f}`" for f in plan["conflicts"]] + [""]
        if plan.get("notes"):
            lines += ["<details><summary>Notizen des Agenten</summary>", "", plan["notes"].strip(),
                      "", "</details>", ""]
    else:
        lines += ["Keine; der Merge lief ohne Eingriff.", ""]
    lines += [
        "## Vor dem Merge",
        "",
        "- [ ] `Check Code Style`, `Tests` und `Security scan` sind grün",
        "- [ ] Sicherheitsrelevante Commits gelesen; Fork-Härtungen (force_mfa, Passkeys, "
        "Wiederherstellungscodes) sind erhalten",
        "- [ ] Migrationen: keine doppelte oder umnummerierte Version",
        "",
        "Nach dem Merge baut `ArztAgent image` das Image automatisch; ArztAgent öffnet danach "
        "selbst den PR für `ops/rauthy/IMAGE`.",
        "",
        f"Lauf: {run_url}",
    ]
    return "\n".join(lines)


def _row(commit: dict[str, Any], with_reason: bool = False) -> str:
    sha = commit["sha"]
    link = f"[`{sha[:10]}`](https://github.com/{UPSTREAM}/commit/{sha})"
    title = _cell(commit["subject"])
    if commit.get("auth") and not with_reason:
        title += " – *ändert Auth-Code*"
    if commit["pr"]:
        title += f" ([{UPSTREAM}#{commit['pr']}](https://github.com/{UPSTREAM}/pull/{commit['pr']}))"
    return f"| {link} | {title} | {_cell('; '.join(commit['reasons']))} |" if with_reason else f"| {link} | {title} |"


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def cmd_publish(args: argparse.Namespace) -> int:
    plan = load(args.plan)
    git("fetch", "-q", args.bundle, f"{plan['branch']}:refs/sync/head")
    head = git("rev-parse", "refs/sync/head")
    verify_bundle_head(plan, head)
    git("push", "-q", "--force", "origin", f"{head}:refs/heads/{plan['branch']}")
    security = any(c["security"] for c in plan["commits"])
    title = f"Upstream-Sync: {UPSTREAM}@{plan['upstream'][:12]}"
    if security:
        title = "[Security] " + title
    body = pr_body(plan, args.run_url)
    existing = [p for p in open_sync_pulls(args.repo) if p["head"]["ref"] == plan["branch"]]
    if existing:
        number = existing[0]["number"]
        api("PATCH", f"repos/{args.repo}/pulls/{number}", {"title": title, "body": body})
    else:
        number = api("POST", f"repos/{args.repo}/pulls", {
            "title": title, "body": body, "head": plan["branch"], "base": args.base_branch,
            "maintainer_can_modify": True})["number"]
    labels = [LABEL_SYNC] + ([LABEL_SECURITY] if security else [])
    api("POST", f"repos/{args.repo}/issues/{number}/labels", {"labels": labels})
    for old in plan["superseded"]:
        api("POST", f"repos/{args.repo}/issues/{old}/comments",
            {"body": f"Ersetzt durch #{number} (neuerer Upstream-Stand)."})
        api("PATCH", f"repos/{args.repo}/pulls/{old}", {"state": "closed"})
    for workflow in CI_WORKFLOWS:
        try:
            api("POST", f"repos/{args.repo}/actions/workflows/{workflow}/dispatches",
                {"ref": plan["branch"]})
        except RuntimeError as error:
            print(f"warning: could not dispatch {workflow}: {error}", file=sys.stderr)
    _close_conflict_issue(args.repo, number)
    print(f"PR #{number}: {title}")
    write_output(pr=number)
    return 0


def _conflict_issue(repo: str) -> dict[str, Any] | None:
    issues = api("GET", f"repos/{repo}/issues?state=open&labels={LABEL_CONFLICT}&per_page=10") or []
    return next((i for i in issues if "pull_request" not in i), None)


def _close_conflict_issue(repo: str, number: int) -> None:
    issue = _conflict_issue(repo)
    if issue:
        api("POST", f"repos/{repo}/issues/{issue['number']}/comments", {"body": f"Erledigt mit #{number}."})
        api("PATCH", f"repos/{repo}/issues/{issue['number']}", {"state": "closed", "state_reason": "completed"})


def cmd_conflict(args: argparse.Namespace) -> int:
    plan = load(args.plan)
    files = plan.get("forbidden") or plan["conflicts"]
    why = ("Upstream ändert Workflows, die der Sync nicht pushen darf" if plan.get("forbidden")
           else "Der Merge hat Konflikte, die kein Agent aufgelöst hat")
    security = [c for c in plan["commits"] if c["security"]]
    body = "\n".join([
        f"{why} ({args.reason}).",
        "",
        f"Upstream-Stand: {UPSTREAM}@{plan['upstream'][:12]}, {len(plan['commits'])} neue Commits, "
        f"davon {len(security)} sicherheitsrelevant:",
        "",
        *[f"- {c['subject']}" for c in security],
        "",
        "Betroffene Dateien:",
        "",
        *[f"- `{f}`" for f in files],
        "",
        "**Was zu tun ist:** In einer Claude-Code-Sitzung mit diesem Repo sagen: "
        f"„Löse den Upstream-Sync aus Issue #<diese Nummer>: `git merge {plan['upstream'][:12]}` "
        "von sebadob/rauthy in einen Branch von main, Fork-Härtungen und Upstream-Sicherheits"
        "korrekturen beide erhalten, `cargo fmt`, `cargo clippy`, Tests, dann PR.“",
        "",
        f"Lauf: {args.run_url}",
    ])
    title = f"Upstream-Sync braucht Hilfe: {UPSTREAM}@{plan['upstream'][:12]}"
    issue = _conflict_issue(args.repo)
    if issue:
        api("PATCH", f"repos/{args.repo}/issues/{issue['number']}", {"title": title, "body": body})
    else:
        labels = [LABEL_CONFLICT] + ([LABEL_SECURITY] if security else [])
        api("POST", f"repos/{args.repo}/issues", {"title": title, "body": body, "labels": labels})
    return 0


# --- image tags ------------------------------------------------------------------------------

TAG = re.compile(r"^(\d+\.\d+\.\d+)-aa(\d+)$")


def ghcr_tags(image: str = IMAGE) -> list[str]:
    """Tags of the public GHCR package, read with an anonymous pull token."""
    token = api("GET", f"https://ghcr.io/token?scope=repository:{image}:pull")["token"]
    request = urllib.request.Request(
        f"https://ghcr.io/v2/{image}/tags/list?n=1000", headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read()).get("tags") or []


def next_tag(version: str, tags: list[str]) -> str:
    numbers = [int(m.group(2)) for m in map(TAG.match, tags) if m and m.group(1) == version]
    return f"{version}-aa{max(numbers, default=0) + 1}"


def latest_tag(tags: list[str]) -> str | None:
    parsed = [(tuple(map(int, m.group(1).split("."))), int(m.group(2)), t)
              for t in tags if (m := TAG.match(t))]
    return max(parsed)[2] if parsed else None


def cmd_image_tag(args: argparse.Namespace) -> int:
    tags = ghcr_tags()
    tag = latest_tag(tags) if args.latest else next_tag(_version_at("HEAD"), tags)
    if not tag:
        print("no ArztAgent image tag found", file=sys.stderr)
        return 1
    print(tag)
    write_output(tag=tag)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--plan", default="plan.json")
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan")
    plan.add_argument("--base", default="origin/main")
    plan.add_argument("--upstream", default="upstream/main")
    plan.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    sub.add_parser("merge")
    finish = sub.add_parser("finish")
    finish.add_argument("--notes", default="SYNC_NOTES.md")
    publish = sub.add_parser("publish")
    publish.add_argument("--bundle", required=True)
    publish.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    publish.add_argument("--base-branch", default="main")
    publish.add_argument("--run-url", default="")
    conflict = sub.add_parser("conflict")
    conflict.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    conflict.add_argument("--reason", default="kein Agent konfiguriert")
    conflict.add_argument("--run-url", default="")
    image = sub.add_parser("image-tag")
    image.add_argument("--latest", action="store_true")
    args = parser.parse_args(argv)
    commands = {"plan": cmd_plan, "merge": cmd_merge, "finish": cmd_finish, "publish": cmd_publish,
                "conflict": cmd_conflict, "image-tag": cmd_image_tag}
    return commands[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
