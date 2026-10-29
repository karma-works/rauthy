# Rauthy — Code Map for Agents & Contributors

> This is an index of code locations. Update it before committing major code-layout changes.
> Wrap Markdown at 100 characters; keep this index within 80 lines.

## AI-assisted contributions and PRs

AI-assisted and agent-authored contributions are welcome. They follow the same code, security,
testing, and review standards as other contributions; there is no separate AI-specific local
approval or Draft PR requirement. Contributors are responsible for understanding and validating
their changes. Run `just pre-pr-checks` before submitting a PR (Postgres tests may be skipped when
no custom queries were modified).

## Repository layout

- `src/` — Rust workspace (all backend crates)
- `frontend/` — SvelteKit UI; the login page is `frontend/src/routes/oidc/authorize/+page.svelte`
  The whole frontend is compiled into static HTML for any production build.
- `book/` — mdBook source for user-facing docs (`docs/` = built site). Not contributor
  documentation. Building the book currently requires `mdbook-0.4`
- `rauthy-client/` — Rust client library + examples
- `vendor/` — Compatibility-preserving security patches; provenance in `vendor/README.md`
- `assets/build_tools/` — Checksum-pinned tool bootstrap and reviewed dependency locks
- `CONTRIBUTING.md` provides important information for getting started

## Commands and crates

Use `just -l` and [justfile](./justfile) for recipes. Run `just pre-pr-checks` before pushing.
Integration tests in `src/bin/tests/` need seeded bootstrap data on :8081. Recipes set
`PUB_URL=localhost:8081 RP_ORIGIN=http://localhost:8081`; use `just test-backend`,
`just test-hiqlite`, or `just test-postgres`. Unit tests need no running backend.

Crates under `src/`:

- `bin`: CLI, bootstrap, TLS, middleware (`main.rs`, `server.rs`)
- `api`: actix handlers; `service`: business logic and OIDC flow
- `data`: entities, DB methods, migrations, config, email
- `api_types`: shared request/response types; `error`: `ErrorResponse`
- `jwt`: JWT/JWK; `middlewares`: blacklist, CSRF, principal, logging
- `common`: utilities; `macros`: proc macros; `notify`: Slack/Matrix
- `schedulers`: background jobs; `wasm-modules`: frontend WASM

## Area mapping: api → service → data

Handlers live in `src/api/src/<area>.rs`, business logic in the matching module under
`src/service/src/` (simple requests go straight to `src/data/src/`), and DB-touching entity methods
in `src/data/src/entity/<entity>.rs`. Areas include: `oidc`, `pam`, `users`, `clients`, `groups`,
`roles`, `scopes`, `sessions`, `api_keys`, `auth_providers`, `backup`, `blacklist`, `email`,
`events`, `fed_cm`, `kv`, `tos`, `themes`, `atproto`, `shared_devices` (PIN login on shared PCs), `practice_roles` (optional shared roles and locks).

Entity files contain the struct and DB/cache methods
(`find_*`, `create`, `update`, `save`, `delete`).

### Notable deviations from the pattern

- OIDC request-param validation lives in **`service/src/oidc/validation.rs`**
  (`validate_auth_code_req_params`) — not under `api/`.
- Grant-type logic for `/oidc/token` lives in `service/src/oidc/grant_types/<grant>.rs`, dispatched
  by `get_token_set` (`service/src/oidc/mod.rs`).
- Client-level checks (enabled, force_mfa, redirect_uri, PKCE) are entity methods on
  `data/src/entity/clients.rs`, called from the service layer.

## Cross-cutting concerns

- Login defense: handler PoW (`pow.difficulty`), `service/src/login_delay.rs`,
  `data/src/entity/cred_stuff_detect.rs`, `middlewares/src/ip_blacklist.rs`.
- Error normalization: `api/src/oidc.rs::post_authorize_handle`.
- Sessions: `data/src/entity/sessions.rs::{is_valid,set_authenticated}`.
- MFA cookie: `data/src/entity/mfa_cookie.rs`, checked by
  `service/src/oidc/authorize.rs::post_authorize`.
- Password checks: `data/src/entity/users.rs::validate_password`.
- Auth codes: `service/src/oidc/authorize.rs::finish_authorize`.
- Config/defaults: `data/src/rauthy_config.rs` (`Vars*` structs).

## Documentation conventions

- Point at **functions**, not line numbers — line numbers rot, function names are stable.
- Document *where* things are and what invariants must hold; don't re-explain code step by step.
- Keep this file an index (hard 80 lines, as all markdown files)
- Module-level `//!` docs are the authoritative local reference where present.
