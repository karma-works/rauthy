# Selbstbedienung über die Rauthy-API (A2.1)

Geprüft am Code auf Branch `a2-self-service`. Pfade relativ zu `/auth/v1`.

## 1. Kurz

Die App läuft auf derselben Origin wie Rauthy. Ihr Browser-JS ruft die Rauthy-API direkt mit
`fetch` auf. Der Browser schickt das Sitzungs-Cookie von selbst mit (HttpOnly, JS liest es nie).
Für jede Anfrage außer GET braucht die App den CSRF-Token im Header `x-csrf-token`. Den Token
holt sie mit `GET /oidc/sessioninfo/xsrf`. Andere Subdomains reichen nicht: die Middleware
`CsrfProtectionMiddleware` lässt Nicht-GET nur bei `sec-fetch-site: same-origin` durch, sonst
400 „cross-origin request forbidden for this resource“ (`access.sec_header_block`, Default an).

## 2. Sitzung, Cookie, CSRF

| Punkt | Wert (Default) | Wo im Code / Config |
|---|---|---|
| Cookie-Name | `__Host-RauthySession` | `COOKIE_SESSION`, `access.cookie_mode` |
| Cookie-Pfad | `/` (bei `host` fest) | `ApiCookie::build_with_same_site` |
| Attribute | HttpOnly, SameSite=Lax, Secure | `ApiCookie::build_with_same_site` |
| Max. Lebensdauer | 10 h, nicht verlängerbar | `lifetimes.session_lifetime` |
| Leerlauf-Timeout | 90 min seit `last_seen` | `lifetimes.session_timeout` |
| IP-Bindung | an | `access.session_validate_ip` |
| CSRF-Header | `x-csrf-token` | `CSRF_HEADER` |
| CSRF-Quelle | `csrf_token` aus xsrf-Antwort | `get_session_xsrf` |
| CSRF-Ablauf | keiner, keine Rotation | `Session::new`, `validate_csrf` |

- `cookie_mode = secure`: `__Secure-RauthySession`, Pfad `/auth` (`access.cookie_set_path`).
  `danger-insecure`: ohne Präfix und Secure, nur lokal. Der Cookie-Wert ist verschlüsselt.
- Leerlauf: jede Anfrage mit gültiger Sitzung setzt `last_seen` neu, höchstens alle 10 s
  (`get_session_from_cookie`). Auch GET-Abfragen halten die Sitzung also wach.
- IP-Bindung: die Sitzung gilt nur von der IP, mit der sie angelegt wurde (`Session::is_valid`).
- CSRF: 32 Zeichen, einmal pro Sitzung erzeugt, gilt bis Sitzungsende. GET wird nicht geprüft.
  Sonst prüft `get_session_from_cookie`; Ausnahme sind `…/webauthn/register/start` und
  `…/register/finish`, die prüfen im Handler (`validate_session_csrf_exception`).
- Die xsrf-Antwort enthält `exp` (absolutes Ende) und `timeout` (Leerlauf-Ende) zum Warnen.

## 3. Abläufe

Alle Aufrufe mit `credentials: 'same-origin'` (Default), JSON-Body, Header `x-csrf-token`
bei POST/DELETE. `{id}` ist die `user_id` aus der xsrf-Antwort.

### Passkeys anzeigen

1. `GET /oidc/sessioninfo/xsrf` → `csrf_token`, `user_id`, `exp`, `timeout` (nur im Speicher).
2. `GET /users/{id}/webauthn` → 200, Liste `PasskeyResponse`: `name`, `registered`, `last_used`,
   `user_verified?`, `resident_key?`, `aaguid?`, `description`, neu `kind?`
   (`internal|hybrid|security_key`) und `shared_device?` (`yes|no|unknown`). `kind` stammt aus
   Browser-Angaben (`passkey_kind`), ist nicht geprüft und nur zur Anzeige.

### mfa_mod_token holen (vor Hinzufügen und Entfernen)

Token: 32 Zeichen, gilt 120 s (fest, `MfaModToken::new`), gebunden an User und IP
(`MfaModToken::validate`). Wird beim Benutzen **nicht** gelöscht: 120 s lang mehrfach nutzbar.

- Konto mit Passkey (Passkey-only): Weg über WebAuthn.
  1. `POST /users/webauthn_start` mit `{"purpose":"MfaModToken"}` → 200 `{code, rcr, exp}`.
  2. `navigator.credentials.get(rcr)` (Base64url → ArrayBuffer wie in `authentication.ts`).
     Browser-Timeout: `webauthn.req_exp` (60 s).
  3. `POST /users/webauthn_finish` mit `{code, data}` → **202** `{code, user_id}`; `code` hat 48
     Zeichen, einmal nutzbar, lebt `webauthn.data_exp` (90 s).
  4. `POST /users/{id}/mfa_token` mit `{"mfa_code": code}` → 200 `{id, user_id, exp, ip}`.
- Konto nur mit Passwort: `POST /users/{id}/mfa_token` mit `{"password": …}`. Hat das Konto
  Passkeys (oder aktives OTP), lehnt Rauthy das Passwort mit 400 ab.

### Passkey hinzufügen

1. mfa_mod_token holen (siehe oben).
2. `POST /users/{id}/webauthn/register/start` mit `passkey_name` (1–32 Zeichen, `RE_USER_NAME`),
   `mfa_mod_token_id`, optional `allow_rk`, neu optional `hints` (max. 3, aus
   `client-device|hybrid|security-key`) → 200 Creation-Options (`publicKey`, inkl. `hints`).
3. `navigator.credentials.create(options)`.
4. `POST /users/{id}/webauthn/register/finish` mit `passkey_name` (gleich wie in Schritt 2),
   `data` (inkl. `data.response.transports` aus `getTransports()`), neu optional
   `authenticator_attachment` (`platform|cross-platform`) und `shared_device`
   (`yes|no|unknown`) → **201** ohne Body. Die Sitzung wird dabei auf `is_mfa = true` gesetzt.
   Finish braucht keinen mfa_mod_token; die Start-Daten leben `webauthn.req_exp` (60 s).

### Passkey entfernen

1. mfa_mod_token holen.
2. `DELETE /users/{id}/webauthn/delete/{name}` mit Body `{"mfa_mod_token_id": …}` → 200.
   Ohne Token: 400 „missing `mfa_mod_token_id`“. Den letzten Passkey eines Passkey-only-Kontos
   lehnt Rauthy mit 400 ab (`AccountType::may_remove_own_passkey`); Admins dürfen ihn löschen.

## 4. Fehlercodes

Fehler-Body ist JSON `{timestamp, error, message}` (`ErrorResponse`). Bei 401 kommt zusätzlich
`WWW-Authenticate: OAuth`.

| Fall | Antwort | App soll |
|---|---|---|
| Sitzung fehlt, abgelaufen, Leerlauf, andere IP | 401 „No valid session“ | neu anmelden |
| CSRF falsch/fehlt (außer register) | 401 „No valid session“ | siehe Hinweis |
| CSRF falsch bei register start/finish | 401 `CSRFTokenError` | Token neu holen |
| mfa_mod_token unbekannt/abgelaufen | 401 „Invalid MfaModToken id“ | Token neu holen |
| mfa_mod_token andere IP/User | 403 `Forbidden` | Token neu, Proxy prüfen |
| fremde `{id}` | 403 `Forbidden` | Fehler zeigen |
| Passwort falsch bei `mfa_token` | 400 „Invalid password“ | erneut fragen |
| Validierung (Name, Längen) | 400 „Payload validation error…“ | Eingabe prüfen |
| Attestation fehlt (falls erzwungen) | 406 `NotAccepted` | anderes Gerät |
| Zeremonie fehlgeschlagen | 401 (`webauthn_finish`), 400 (`register/finish`) | wiederholen |
| nicht same-origin | 400 „cross-origin request forbidden…“ | Deployment prüfen |

„Neu anmelden“ = normaler OIDC-Start der App über `/auth/v1/oidc/authorize`. Bei falschem
CSRF verwirft `get_session_from_cookie` die Sitzung still, daher dieselbe Meldung wie bei
abgelaufener Sitzung. Abgelaufener mfa_mod_token: „MfaModToken has expired“.

Hinweis: 401 ist mehrdeutig. Bei 401 einmal `GET /oidc/sessioninfo/xsrf` aufrufen. Bei 200 lebt
die Sitzung: neuen `csrf_token` bzw. mfa_mod_token holen und einmal wiederholen. Bei 401 neu
anmelden lassen.

## 5. Offene Punkte und Fallstricke

- IP-Bindung: Sitzung (`session_validate_ip`) und mfa_mod_token hängen an der Client-IP aus
  `real_ip_from_req`. Hinter Proxies müssen `server.proxy_mode`, `server.trusted_proxies` bzw.
  `access.peer_ip_header_name` stimmen, sonst zählt die Proxy-IP oder es kommt 401/403.
  Wechselnde IPs (Mobilfunk, IPv6-Privacy) beenden die Sitzung.
- Die xsrf-Antwort enthält die Sitzungs-`id`. Die App darf sie nie loggen, speichern oder
  weitergeben; auch `csrf_token` nur im Speicher halten (Rauthy selbst nutzt localStorage,
  `saveCsrfToken`; für die App nicht nötig).
- Eine falsche CSRF-Anfrage aktualisiert trotzdem `last_seen` (Touch vor CSRF-Prüfung).
- Die 120 s des mfa_mod_token sind nicht konfigurierbar (`TODO make configurable`).
- Gleichzeitige Registrierungen mit gleichem `passkey_name` teilen sich einen Cache-Eintrag
  (`reg_{name}_{user}`); die App sollte Doppelklicks sperren.
- Nicht geprüft: Verhalten mit `session_renew_mfa = true`, Rate-Limits/Blacklist auf diesen
  Pfaden, und ob der OIDC-Login der App immer dieselbe Rauthy-Sitzung wiederverwendet.

## Eigene Sitzungen (A2.4, folgt)

Die Endpunkte zum Anzeigen und Beenden eigener Sitzungen folgen in einem späteren PR.
