# Praxis-PCs mit PIN: API für ArztAgent

Umsetzung der [Spezifikation](SPEC-PHASE2-PIN-AM-PRAXIS-PC.md). Code:
`rauthy_data::entity::shared_devices`, Handler in `src/api/src/shared_devices.rs`. Alles
antwortet `404`, solange `shared_devices.enable` aus ist.

## Einschalten (Compose, nur Umgebungsvariablen)

```env
SHARED_DEVICES_ENABLE=true
SHARED_DEVICES_CLIENT_IDS=aa-practice-web
```

`SHARED_DEVICES_CLIENT_IDS` ist eine Liste, ein Client je Zeile. Nur diese Clients nehmen einen PIN
an, und nur bei ihnen genügt ein PIN `force_mfa`. Der API-Key braucht die Gruppe `SharedDevices`
(Read, Create, Update, Delete). Rauthy liest `BOOTSTRAP_API_KEY` sonst nur beim ersten Start mit
leerer Datenbank; mit `BOOTSTRAP_API_KEY_SYNC=true` übernimmt eine laufende Instanz neue Rechte des
Keys bei jedem Start (Secret nur, wenn `BOOTSTRAP_API_KEY_SECRET` gesetzt ist). Empfehlung:
Access-Token von `aa-practice-web` höchstens 300 s, damit die Leerlaufgrenze von Rauthy greift
(siehe unten).

## Admin-API (Backend → Rauthy)

Praxis-IDs: 1–64 Zeichen `[A-Za-z0-9_-]`, z. B. die Organisations-UUID.

- `PUT /shared_devices/practices/{id}`: anlegen oder ändern, `{"name", "idle_timeout"?,
  "notify_user_ids"}`. `idle_timeout` 120–900 s, Standard 300. `notify_user_ids`: Rauthy-Benutzer,
  die Mails zu Sperre und IP-Wechsel bekommen (höchstens 50). Antwort wie GET.
- `GET /shared_devices/practices/{id}`: Praxis mit `devices` und `members` (`user_id`, `has_pin`,
  `pin_created`). Wer den Restrisiko-Hinweis bestätigt hat: `risk_ack_by`, `risk_ack_at`.
- `DELETE /shared_devices/practices/{id}`: löscht alles der Praxis und beendet die Sitzungen an
  ihren PCs.
- `PUT /shared_devices/practices/{id}/members/{user_id}`: Person darf einen PIN haben. `204`, auch
  wenn sie schon Mitglied ist.
- `DELETE /shared_devices/practices/{id}/members/{user_id}`: entfernt PIN und Mitgliedschaft,
  beendet ihre Sitzungen an den PCs der Praxis.
- `POST /shared_devices/practices/{id}/registrations`: `{"user_id", "label", "return_uri"?}` →
  `{"id", "url", "exp"}`. Gilt 10 Minuten, einmal. `user_id` braucht einen Passkey. `return_uri`
  muss den Origin einer Redirect-URI eines PIN-Clients haben.
- `PUT /shared_devices/devices/{id}`: `{"label", "ip_lock"}`. `ip_lock: true` lehnt Anmeldungen
  aus einem anderen Netz ab (IPv6 je /64).
- `DELETE /shared_devices/devices/{id}`: Widerruf; beendet alle Sitzungen am PC.
- `GET /shared_devices/practices/{id}/events?limit=100`: Ereignisse, neueste zuerst, 90 Tage.

Ereignisarten: `registered`, `revoked`, `pin_login`, `passkey_login`, `other_login`,
`pin_failed`, `locked`, `unlocked`, `ip_changed`, `ip_blocked`, `pin_changed`. Felder:
`device_id?`, `user_id?`, `ip?`, `created`. Kein User-Agent, kein Ort.

Abgleich durch das Backend: Praxis bei Anlage und Änderung der Organisation, Empfänger = alle
mit `team.manage`, Mitglieder = aktive Mitgliedschaften. Deaktivieren einer Mitgliedschaft →
Mitglied entfernen.

## Registrierung eines PCs

1. Praxis-App, angemeldet mit frischem Passkey: Backend prüft `team.manage` und ruft
   `POST …/registrations` mit der eigenen Rauthy-ID der Person.
2. Die App öffnet `url` (`/auth/v1/shared_devices/register?id=…`) im selben Browser,
   Top-Level-Navigation. Die Seite verlangt die Rauthy-Sitzung genau dieser Person und einen
   Passkey; beim ersten PC der Praxis den Restrisiko-Hinweis.
3. Danach Link „Zurück zur Anwendung“ auf `return_uri`. Ab jetzt zeigt die Anmeldeseite in
   diesem Browser das PIN-Feld.

Ein PC, der in diesem Browser schon registriert war, wird dabei widerrufen.

## PIN der Person

Im Rauthy-Konto (`/auth/v1/account`, Bereich MFA): „PIN erzeugen“ bzw. „Neuer PIN“, mit
Passkey. API dazu:

- `GET /users/{id}/shared_device_pins` → `[{practice_id, practice_name, pin_created?}]`
- `POST /users/{id}/shared_device_pins/{practice_id}` mit `{"mfa_mod_token_id"}` →
  `{"pin"}`, einmalig. Höchstens 10 je Tag und Praxis. Beendet die PIN-Sitzungen der Person.

## Anmeldung und Tokens

- Die App startet `/oidc/authorize` wie bisher. Am registrierten PC zeigt Rauthy das PIN-Feld,
  außer die Anfrage hat `max_age` (Nachweis für kritische Aktionen): dann nur Passkey.
- Sperrbildschirm der App: `/oidc/authorize?prompt=login`. Am PC meldet Rauthy nie still an;
  `prompt=none` ergibt `login_required`.
- Token nach PIN: `amr: ["pin", "swk"]`, `auth_time` = Zeitpunkt der PIN-Eingabe. Nach Passkey
  am PC: `amr: ["mfa"]`. Beide tragen `aa_shared_device` (ID des PCs) im Access- und ID-Token.
- `aa_shared_device` ist die UUID des PCs (zufällig, ohne Namen oder Ort).
- Wird der letzte Passkey eines Kontos gelöscht (z. B. „Anmeldung zurücksetzen“), löscht Rauthy
  auch dessen PINs und beendet seine PIN-Sitzungen.
- Backend-Regel: `pin` und `swk` nur zusammen mit `aa_shared_device` für die Tagesarbeit;
  kritische Aktionen weiter nur mit `mfa` und `auth_time` höchstens 15 Minuten alt.
- Sitzung am PC höchstens 10 h. Jede Anmeldung am PC beendet die anderen Sitzungen dort samt
  Refresh-Tokens.
- Refresh-Token einer Sitzung am PC gilt nur bis Leerlaufzeit nach seinem frühesten
  Nutzungszeitpunkt (Ablauf des Access-Tokens minus 60 s). Die App erneuert Tokens nur bei
  Aktivität; nach Leerlauf braucht sie den PIN.
- 5 falsche PINs an einem PC innerhalb von 24 Stunden sperren ihn. Ein richtiger PIN setzt den
  Zähler nicht zurück, sonst könnte ein Mitglied zwischen eigenen Anmeldungen die PINs der
  Kollegen raten. Der PIN eines deaktivierten Kontos zählt als falsch. Eine Passkey-Anmeldung
  eines Mitglieds am PC entsperrt ihn und setzt den Zähler zurück. Antworten von
  `POST /oidc/authorize/pin`: `401 {"error":"wrong_pin", "remaining":n}`,
  `423 {"error":"locked"}`, `401 {"error":"invalid_device"}`, `403` bei IP-Sperre.
- Auf einem registrierten PC lehnt Rauthy das Anlegen von Passkeys ab (`403`).
- Eine Sitzung aus einer PIN-Anmeldung dient nur der Anmeldung selbst (Authorize, Callback,
  Logout). Konto, Admin-Oberfläche und Device-Code-Freigabe sehen sie nicht; dafür braucht es
  den Passkey.
- Nach der Registrierung ist die Person, die registriert hat, in diesem Browser abgemeldet.
- `max_age` erzwingt den Passkey nur auf der Anmeldeseite. Das Backend muss deshalb `amr` prüfen
  (siehe oben), nicht `max_age`.

## Gespeicherte Daten (Datenschutz)

Praxis (Name, Leerlaufzeit, Empfänger, Bestätigung des Hinweises), Mitglieder mit
`HMAC-SHA256` des PINs, PCs (Name, Hash des Geräte-Tokens, öffentlicher Schlüssel, IP bei
Registrierung und zuletzt, Fehlversuche, Sperre), Ereignisse 90 Tage. Sitzungen tragen die ID des
PCs. Eine Datenbank-Migration zwischen Postgres und Hiqlite übernimmt diese Tabellen nicht.
