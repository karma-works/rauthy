# Discovery & JWKS

Relying parties configure themselves from the OIDC discovery document and verify token signatures
with the published JWKS.

## Sub-features

- `discovery` — `/.well-known/openid-configuration` lists issuer, endpoints and grants.
- `jwks` — `/oidc/certs` publishes the signing keys referenced by token `kid`s.

## How to get to it (user POV)

- `GET $API/.well-known/openid-configuration` (also `/.well-known/oauth-authorization-server`).
- `GET` the `jwks_uri` from the discovery document.

## Driving it with rv

Preconditions:

- `rv doctor` healthy. `API=http://localhost:8091/auth/v1`.

```bash
curl -s $API/.well-known/openid-configuration \
  | jq -c '{issuer,token_endpoint,jwks_uri,grant_types_supported}'
```

- **Discovery.** `issuer` is `http://localhost:8091/auth/v1/`, `jwks_uri` is
  `…/auth/v1/oidc/certs`, grants include `authorization_code`, `client_credentials`, `password`,
  `refresh_token`, device code and token exchange.
- **JWKS.** `curl -s $API/oidc/certs | jq -c '[.keys[]|{kid,alg}]'`. Four keys: `RS256`, `RS384`,
  `RS512`, `EdDSA`.
- **Cross-check.** Get a token (see [tokens](./tokens.md)); its header `kid`
  (`cut -d. -f1 <<<"$AT" | base64 -d`) is one of the JWKS `kid`s.

## Gotchas

- The issuer has a trailing `/`; compare exactly.
- The issuer follows `PUB_URL`. A wrong issuer means you hit another instance or `.env`
  overrides `PUB_URL` — run `rv doctor`.
- Dev seed JWKs are fixed (`db_migrate_dev.rs`), so `kid`s are stable across fresh runs.
