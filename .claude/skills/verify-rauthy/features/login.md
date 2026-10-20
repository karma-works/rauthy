# Login

A user signs in with email + password on Rauthy's login page (`/auth/v1/oidc/authorize`), solving
a proof-of-work in the browser, and lands back on the page that sent them (account or admin UI).
Wrong credentials keep them on the login page with an error.

## Sub-features

- `login-browser-ok` — valid credentials from `/auth/v1/account` end on the account page.
- `login-browser-denied` — wrong password shows `Invalid credentials`, stays on authorize page.
- `login-api` — the same session/PoW/authorize/token sequence the page uses, scripted.

## How to get to it (user POV)

- Open `/auth/v1/account` (or `/auth/v1/admin`) while logged out → redirected to the login page.
- Type the email, choose `Login`, the `Password` field appears, type it, choose `Login` again.
- Programmatic clients do `POST /oidc/session` → `POST /pow` → `POST /oidc/authorize` → token.

## Driving it with rv

Preconditions:

- `rv doctor` healthy; seeded `init_admin@localhost` / `123SuperSafe` unchanged.

- **Browser success.** Run `rv browser pw-login.mjs login /auth/v1/account`. Prints
  `OK logged in as init_admin@localhost; now at …/auth/v1/account`. `02-after.aria.txt` contains
  `E-Mail init_admin@localhost` and `link "Admin UI"`; `browser.log` shows
  `[http 202] POST …/oidc/authorize`.
- **Browser denied.** Run
  `rv browser pw-login.mjs login-badpw /auth/v1/account init_admin@localhost wrongpass denied`.
  Prints `OK login … denied as expected`; `02-after.aria.txt` contains `Invalid credentials`;
  `browser.log` shows `[http 401] POST …/oidc/authorize`.
- **API login.** Run `rv login`. stderr shows `HTTP 201 POST /auth/v1/oidc/session`,
  `HTTP 200 POST /auth/v1/pow`, `HTTP 202 POST /auth/v1/oidc/authorize?…`,
  `HTTP 200 POST /auth/v1/oidc/token`.
- **Proof of session.** Run `rv api GET /oidc/sessioninfo`. `HTTP 200`, body has
  `"state":"Auth"` and `"roles":"rauthy_admin"`.

## Gotchas

- The login page has two buttons named `Login` (form submit and Passkey); scope to `form`.
- The first `Login` click only submits the email (a `POST /oidc/authorize` returning 401 is
  expected there); the password field appears afterwards.
- Do not wait for `networkidle` — the admin UI polls. Wait for the URL change and `main`.
- Repeated failures trigger login delay / IP blacklisting (`login_delay.rs`, `ip_blacklist.rs`);
  if logins suddenly hang or 429, start a fresh `RV_RUN`.
- Clients with `force_mfa` (e.g. `bootstrap_client_1`) reject password-only logins by design.
