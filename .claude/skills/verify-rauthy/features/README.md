# Rauthy verification map

Maintained source for verifying Rauthy's user-facing behavior. Read this index, then use the
matching feature file as the recipe. `rv` = `.claude/skills/verify-rauthy/scripts/rv`.

## Baseline preconditions

- Fresh run: `RV_RUN=<id> rv cleanup; RV_RUN=<id> rv launch` → `READY at http://localhost:8091`.
- `RV_RUN=<id> rv doctor` prints `DOCTOR: healthy` (issuer `http://localhost:8091/auth/v1/`).
- Seed data from `config-test.toml --test` (dev mode) + `bootstrap/*.json`: admin
  `init_admin@localhost` / `123SuperSafe` (role `rauthy_admin`), users `alfred@batcave`
  (`123SuperSafe`), `batman@batcave`, client `init_client` (secret in SKILL.md), UI client `rauthy`.
- Never drive an instance this run did not start. Use your own `RV_RUN` and, in parallel, a
  distinct `RV_PORT`.

## Driving conventions

- Below, `$API` = `http://localhost:$RV_PORT/auth/v1` and `$CS` = init_client secret.
- Browser: `rv browser <script.mjs>`; locate by role/label (`textbox "E-Mail"`,
  `getByLabel('Password', {exact:true})`, `form` → `button "Login"`). Locale pinned to `en-US`.
- Admin API: `rv login` once, then `rv api METHOD /path [json]` (status on stderr, body on stdout).
- Restore seed state after a mutation (delete what you created) or use a fresh `RV_RUN`.

## Proof and skip reporting

- Save everything under `$RV_ROOT/$RV_RUN/evidence/<feature-id>/` (`rv env` prints it).
- UI proof: before + after screenshot and ARIA snapshot, plus `browser.log` HTTP statuses.
- API proof: command, `HTTP <code>` line and body (`2>&1 | tee …/<step>.txt`).
- Mutation proof: a second, read-only view of the stored value (GET after POST, 404 after DELETE).
- Report an unreachable path with the attempted command and the unmet precondition. Do not
  report a skipped entry point as verified through a different one.

## Feature entry contract

Each file: H1 + one paragraph, then exactly `Sub-features`, `How to get to it (user POV)`,
`Driving it with rv`, `Gotchas`. User paths, stable handles, required state, commands and
observable proof only — no implementation walkthroughs.

## Features

- [Login](./login.md) — browser login page (success, wrong password) and API login session.
- [Token endpoint](./tokens.md) — password, client_credentials, refresh grants; userinfo;
  introspection.
- [Discovery & JWKS](./discovery.md) — `.well-known/openid-configuration` and `/oidc/certs`.
- [Admin: users](./admin-users.md) — Admin UI user list and user create/read/delete via admin API.

Not mapped yet (add when touched): password reset / registration (need Mailcrab on :1025/:1080,
`just mailcrab-start`), passkeys/MFA (WebAuthn virtual authenticator), device flow, upstream auth
providers, PAM, SCIM, forward-auth (`just nginx-start`).
