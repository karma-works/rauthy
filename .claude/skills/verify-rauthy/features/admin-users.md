# Admin: users

A `rauthy_admin` sees all users in the Admin UI and creates, reads and deletes users through the
admin API the UI calls.

## Sub-features

- `admin-ui-users` — Admin UI user list shows the seeded users.
- `admin-user-create` — `POST /users` creates a user.
- `admin-user-read` — `GET /users/{id}` returns the stored user.
- `admin-user-delete` — `DELETE /users/{id}` removes it; a later `GET` is 404.

## How to get to it (user POV)

- Log in, choose `link "Admin UI"` on the account page, or open `/auth/v1/admin/users`.
- In the list: `searchbox "Search"`, `button "Add New"`, one button per user
  (`button "AB alfred@batcave Alfred Batman"`).
- The UI uses `$API/users…` with the session cookie + `x-csrf-token`.

## Driving it with rv

Preconditions:

- `rv doctor` healthy; `rv login` done (`rv api GET /oidc/sessioninfo` → `"state":"Auth"`).
- No user `verify-user@batcave.io` exists.
- `E=$(rv env | sed -n 's/^EVIDENCE=//p')/admin-users; mkdir -p $E`.

- **UI list.** `rv browser pw-login.mjs admin-ui /auth/v1/admin/users`. `02-after.aria.txt` has
  `link "Users"`, `button "Add New"`, `searchbox "Search"` and buttons for `alfred@batcave`,
  `batman@batcave`, `init_admin@localhost`.
- **Create.** Run:

  ```bash
  rv api POST /users '{"email":"verify-user@batcave.io","given_name":"Verify",
    "family_name":"User","language":"en","roles":["user"]}' 2>&1 | tee $E/01-create.txt
  ```

  `HTTP 200 POST /users`, body has a new `id`, `"roles":["user"]`, `"email_verified":false`.
- **Read back.** `ID=$(sed -n 2p $E/01-create.txt | jq -r .id)`, then
  `rv api GET /users/$ID 2>&1 | tee $E/02-readback.txt` → `HTTP 200`, same email and roles.
- **Delete.** `rv api DELETE /users/$ID 2>&1 | tee $E/03-delete.txt` → `HTTP 204`.
- **Proof gone.** `rv api GET /users/$ID 2>&1 | tee $E/04-gone.txt` → `HTTP 404`,
  `"error":"NotFound"`.

## Gotchas

- Unknown roles in `roles` are silently dropped; assert the returned `roles`, not the request.
- New users have no password; logging in as them needs the password-reset email (Mailcrab).
- The admin API rejects bearer tokens; only session cookie + CSRF (or an API key) work.
- The bootstrap API key in `bootstrap/api_keys.json` is expired (`exp` 2024) — don't use it.
- Seeded admins (`admin@localhost`, `init_admin@localhost`) are protected by anti-lockout
  checks; don't delete them in a journey.
