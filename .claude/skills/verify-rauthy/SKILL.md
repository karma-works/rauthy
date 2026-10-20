---
name: verify-rauthy
description: >-
  Launch a disposable Rauthy (OIDC IdP) backend with seeded test data and drive it like a user:
  login page and account/admin UI via Playwright, OIDC and admin REST API via curl. Use to prove
  a change to login, OIDC flows, tokens, sessions or admin API/UI works in the running app, or
  when asked to verify, smoke test or "try it". Complements `just pre-pr-checks`, not a substitute.
---

# Verify Rauthy

Run from the repo root; `rv` = `.claude/skills/verify-rauthy/scripts/rv` (`rv help`). A run is
isolated by `RV_RUN` (state under `$RV_ROOT/$RV_RUN`, default `/tmp/rauthy-verify/default`) and
`RV_PORT` (default 8091; Hiqlite uses `+100`/`+200`), so it never collides with
`just test-hiqlite` (8081) or `just run` (8080). Export both for the whole session.

## Launch

`RV_RUN=<id> rv launch` runs `cargo build --locked` (first build ~10 min, `RV_SKIP_BUILD=1`
skips), then `target/debug/rauthy serve -c config-test.toml --test` with an **empty** Hiqlite dir
`instance/data`, so migrations, dev seed data and `bootstrap/*.json` apply fresh. Missing
`templates/html`/`static/v1` are extracted from `assets/static_html/` (= `just extract-ui-archive`);
after frontend changes run `just build-ui` first. It prints `READY at http://localhost:<port>` only
when `/auth/v1/ping` answers **and** the seeded admin gets a token (~10 s). No mail server is
started; email features need `just mailcrab-start` (Docker). Never use `just test-backend-stop`
or `just delete-hiqlite` here — they act on the shared `./data` and `.test_pid`.

## Doctor

`rv doctor` (read-only, run first whenever anything looks off): our pid alive, port owned by it,
`/ping`, issuer equals `http://localhost:<port>/auth/v1/`, version vs `Cargo.toml`, binary not
rebuilt after launch (stale code → `rv stop && rv launch`), seeded admin can get a token, stored
session valid. Do not drive an instance whose doctor fails or that your run did not start.

## Drive

- Browser: `rv browser pw-login.mjs <feature-id> [path] [email] [pw] [ok|denied]` logs in through
  the real login page (WASM PoW). Own scripts: `rv browser x.mjs` gets `RV_PLAYWRIGHT`,
  `RV_BASE_URL`, `RV_EVIDENCE`, `RV_ADMIN_*`; copy `pw-login.mjs` as a template.
- Admin API: `rv login [email] [pw]` (session → PoW → authorize → token, like the page), then
  `rv api GET /users` or `rv api POST /users '<json>'` (path under `/auth/v1`; status on stderr).
  Admin endpoints take this cookie + `x-csrf-token`; bearer tokens get 401.
- Public OIDC endpoints: plain `curl` against `http://localhost:<port>/auth/v1`.
- Seeds: admin `init_admin@localhost`/`123SuperSafe`; `alfred@batcave`/`123SuperSafe`;
  client `init_client` / `LjERi0WSEz1E9OY9KFJaMjlwV1Uf3nuIuOUnJnoJQNm2i7YMjTDMy4PbAKnYRgFy`.
- Handles: textbox `E-Mail`, label `Password`, `form` → button `Login` (locale pinned `en-US`).
- Recipes with exact commands and expected output: [features/README.md](features/README.md). Read
  the index and the matching feature file before driving; cover every entry point it lists.

## Evidence

Write to `$RV_ROOT/$RV_RUN/evidence/<feature-id>/` (`rv env` prints it); it survives cleanup.

- Real user path only: login page, or the public/admin API the UI calls. No DB edits, no
  dev-only endpoints as proof of a production path.
- Capture action and result: before/after screenshot + ARIA snapshot, `browser.log` statuses,
  `rv api … 2>&1 | tee <evidence>/<step>.txt`.
- Verify side effects with a second read (GET after POST, 404 after DELETE, introspect a token).
- Copy relevant server lines from `$RV_ROOT/$RV_RUN/instance/rauthy.log` into
  `<evidence>/server.log` before cleanup, which deletes the log.
- Report unreachable paths with the attempted command and unmet precondition; never report a
  skipped entry point as verified through another one.

## Cleanup

`rv cleanup` stops only the pid this run recorded (never `pkill rauthy`) and deletes `instance/`
and `session.json`; evidence stays. Run it after failed attempts too. `rv stop` keeps the DB.
Extracted `static/` and `templates/html/` are gitignored build inputs and stay.

## Helpers (`scripts/`, executable; needs bash, curl, jq, python3, node + Playwright)

- `rv` — `launch | doctor | login | api | browser | stop | cleanup | env`.
- `rv_login.py` — stdlib PoW solver + PKCE login used by `rv login`.
- `pw-login.mjs` — browser login, writes `01-login`/`02-after` `.png` + `.aria.txt` and
  `browser.log`; exit 0 only if the expectation (`ok`/`denied`) holds.

When a route, label or seed changes, update the matching `features/*.md` in the same PR.
