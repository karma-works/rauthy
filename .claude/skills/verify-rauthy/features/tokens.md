# Token endpoint

Relying parties obtain tokens from `/oidc/token` with the grants a client allows, then use them
at `/oidc/userinfo` and validate them at `/oidc/introspect`.

## Sub-features

- `token-password` — password grant returns access, id and refresh token.
- `token-cc` — client_credentials grants with form credentials and Basic-only authentication
  return access tokens; missing, empty, short and incorrect secrets remain denied.
- `token-refresh` — refresh_token grant returns a new access token.
- `token-denied` — wrong password returns 401 `Invalid user credentials`.
- `userinfo` — bearer access token returns the user's claims.
- `introspect` — client-authenticated introspection reports `active: true`.

## How to get to it (user POV)

- An OIDC client POSTs form-encoded requests to `$API/oidc/token`.
- It calls `$API/oidc/userinfo` with `Authorization: Bearer <access_token>`.
- It calls `$API/oidc/introspect` with HTTP Basic `client_id:secret` and `token=<access_token>`.

## Driving it with rv

Preconditions:

- `rv doctor` healthy. `API=http://localhost:8091/auth/v1`,
  `CS=LjERi0WSEz1E9OY9KFJaMjlwV1Uf3nuIuOUnJnoJQNm2i7YMjTDMy4PbAKnYRgFy`.

```bash
TOK="$API/oidc/token"; C=(-d client_id=init_client -d client_secret=$CS)
TS=$(curl -s $TOK -d grant_type=password "${C[@]}" \
  -d username=init_admin@localhost -d password=123SuperSafe)
AT=$(jq -r .access_token <<<"$TS"); RT=$(jq -r .refresh_token <<<"$TS")
curl -s $API/oidc/userinfo -H "Authorization: Bearer $AT"
curl -s $API/oidc/introspect -u init_client:$CS -d token=$AT
curl -s -w ' %{http_code}\n' $TOK -d grant_type=refresh_token "${C[@]}" -d refresh_token=$RT
curl -s -w ' %{http_code}\n' $TOK -d grant_type=client_credentials "${C[@]}"
curl -s -w ' %{http_code}\n' $TOK -u init_client:$CS -d grant_type=client_credentials
curl -s -w ' %{http_code}\n' $TOK -d grant_type=password "${C[@]}" \
  -d username=init_admin@localhost -d password=wrong
```

- **Password grant.** `jq -c keys <<<"$TS"` →
  `["access_token","expires_in","id_token","refresh_token","scope","token_type"]`.
- **Userinfo.** `200`, body has `"email":"init_admin@localhost"`, `"roles":["rauthy_admin"]`.
- **Introspect.** `200`, `"active":true`, `"client_id":"init_client"`.
- **Refresh / client credentials.** Each ends in ` 200` with a new `access_token`. Basic-only
  authentication sends neither `client_id` nor `client_secret` in the form. Missing secrets remain
  `400`; incorrect Basic secrets remain `401`. The HTTP owner is `test_client_credentials_flow`.
- **Denied.** `401`, `{"error":"Unauthorized","message":"Invalid user credentials"}`.
- **Proof.** Save each response with `| tee <evidence>/tokens/<step>.json`; decode claims with
  `cut -d. -f2 <<<"$AT" | tr '_-' '/+' | base64 -d 2>/dev/null` → `iss` is
  `http://localhost:8091/auth/v1/`.

## Gotchas

- `init_client` access tokens live 60 s in the test config; introspect/userinfo right away.
- The admin API does not accept bearer tokens (`GET /users` with Bearer → 401); use `rv login`.
- `config-test.toml` sets `disable_refresh_token_nbf = true`; on other configs an immediate
  refresh can be rejected as "not yet valid".
- `dpop_http = true` in dev mode — DPoP proofs over plain HTTP are accepted only here.
- Public clients and confidential clients without the `client_credentials` flow remain denied;
  the HTTP owner creates and deletes only its own dedicated flow-guard client.
