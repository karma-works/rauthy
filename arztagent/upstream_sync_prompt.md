# Upstream sync: resolve the merge conflicts

You run unattended in CI inside the rauthy builder container (Rust 1.95.0, Node, `just`; UI and
WASM are already built). This repository is the ArztAgent fork of sebadob/rauthy. A
`git merge --no-commit` of the upstream head is in progress and has conflicts. Read `AGENTS.md`
first; the fork's own docs are in `arztagent/`.

## Goal

Resolve every conflict so that BOTH sides survive in full:

- the upstream changes, above all the security fixes marked below, and
- the fork's own changes: MFA hardening (`force_mfa`, MFA proof bound to the user, refresh
  enforces `force_mfa`, `amr` from the checked factor), passkey-only login, recovery codes,
  shared-device PIN login, mail resilience, ArztAgent extensions. Use
  `git log -p origin/main -- <file>` and `git log -p origin/main..upstream/main -- <file>` to
  see why each side changed a hunk. Never drop a check, a validation or a test from either side.

## Rules

- Do NOT commit, do NOT run `git merge --abort`, `git reset`, `git checkout <ref> -- <file>` on
  whole files or `git stash`. Edit the files; `git add` them when resolved.
- Change only what the merge needs: conflicted hunks, plus the smallest follow-up edits that
  make the merged code compile (e.g. a renamed function used in fork code). No refactors, no
  dependency upgrades beyond what the merged `Cargo.lock` needs, never anything in `.github/`.
- `Cargo.lock` / `frontend/package-lock.json`: start from upstream's version, then let cargo /
  npm add what the fork needs (`cargo check` without `--locked` once, then `--locked`;
  `npm install --package-lock-only` in `frontend/`). No `cargo update`; never upgrade a crate
  just to make it compile.
- Database migrations (`src/data/src/migration/`, `migrations/`): keep every migration of both
  sides, no duplicate or reused version numbers, never edit an already released migration.
- Generated archives (`assets/static_html/*.tar.gz`): take the fork's version.
- If you cannot resolve a hunk with confidence, keep both behaviours as strictly as possible
  (the stricter security check wins) and say so in the notes under "UNSICHER".

## Checks before you stop

Run and fix until green (they take a while; that is expected):

1. `cargo fmt --check`
2. `cargo clippy --locked -- -D warnings`
3. `cargo test --locked --lib` for the crates you touched (`-p rauthy-data`, `-p rauthy-service`,
   ...). Integration tests run later in CI.
4. If you touched `frontend/`: `cd frontend && npm run check && npm run format-check`.

## Notes for the reviewer

Write `SYNC_NOTES.md` in the repository root (it is moved into the PR description and not
committed), in German, short: per conflicted file one line with what you kept from each side;
which upstream security fixes are now fully in; results of the checks above (green/red and the
command); a section "UNSICHER" listing anything a human must look at, or "keine".
