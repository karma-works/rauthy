# Plan: ArztAgent-Anmeldung und Selbstbedienung im Fork

Stand 20.10.2026, Basis `main` = `5e7078b` (F1 und F2 erledigt). Gegenstück im Produkt-Repo:
`karma-works/arzt-agent`, Datei `PLAN-PRAXIS-UI-ANMELDUNG.md` (Phasen, App-Seite, Raster) und
`PLAN-RAUTHY-KONTO-PASSKEYS.md` (F3–F6). Dieser Plan beschreibt nur die Arbeit in diesem Fork, so
dass ein Agent sie ohne das Gespräch umsetzen kann.

Mocks (synthetische Daten) liegen unter [`mocks/`](mocks/); Maße und Farben stammen aus
`design/tokens.json` in arzt-agent (Teal `#315F59`, Fläche `#F7F6F2`, Tinte `#2F3433`,
Nebentext `#606966`, Rahmen `#DDDAD2`/`#7A817D`, Radius 6/8/12, Schrift Geist).

## Rahmen

- **Reihenfolge:** Phase 1 (A1–A4) vor Phase 2 (B1–B2).
- **Upstream-fähig bleiben:** jedes Paket als eigener, kleiner Commit bzw. PR. ArztAgent-spezifisches
  Verhalten hinter Schaltern, die **nur als Umgebungsvariable** gesetzt werden (das Upstream-Image
  bricht bei unbekannten Schlüsseln in `config.toml` ab), wie bei F1/F2.
- **Migrationen:** Postgres und Hiqlite immer paarweise; nächste Nummern `V35`/`40`. Am Ende den
  ausgelieferten Migrationssatz am gewählten Commit prüfen.
- **Prüfen:** `just pre-pr-checks`; Integrationstests mit Hiqlite und Postgres, wenn Abfragen sich
  ändern; Playwright mit virtuellem Authenticator (`WebAuthn.addVirtualAuthenticator`) für jeden
  neuen Ablauf.
- **Image:** nach dem Merge nativ amd64 mit `fido-mds-prep` bauen, Digest an arzt-agent
  (`ops/rauthy/IMAGE`) melden.
- **Texte:** Deutsch über `frontend/src/i18n/common/de.ts` (und `en.ts` als Fallback), keine fest
  eingebauten Texte.

## Phase 1

### A1 – Anmeldeseite im ArztAgent-Layout
Mocks: [`mocks/01-anmeldung-desktop.png`](mocks/01-anmeldung-desktop.png),
[`mocks/02-anmeldung-smartphone.png`](mocks/02-anmeldung-smartphone.png).

**Ziel:** Ein einziger Anmeldebildschirm. Die Praxis-App leitet ohne eigene Zwischenseite
direkt auf `/auth/v1/oidc/authorize` weiter (Arbeit in arzt-agent).

**Umsetzung** in `frontend/src/routes/oidc/authorize/+page.svelte` (heute 952 Zeilen; die neue
Darstellung als eigene Komponente, z. B. `frontend/src/lib/authorize/SplitLogin.svelte`):
- Schalter `LOGIN_LAYOUT=split` (Umgebungsvariable; Vorgabe `default` = heutiges Layout). Greift
  nur für Clients mit `force_mfa`, wenn für Personal nur Passkeys erlaubt sind.
- Kopf: Client-Logo (vorhandene Logo-API), Titel „Anmelden bei ArztAgent“, eine Zeile Erklärung.
- **Karte links „Login an bestehendem Gerät“** (Kennzeichnung oben, Überschrift „Ich habe mich
  hier schon angemeldet“, kurzer Text): nur der Knopf „Mit Passkey anmelden“. Startet die
  vorhandene Anmeldung mit auffindbarem Passkey (`authenticate_rk`, heute Knopf „Passkey“), ohne
  E-Mail.
- **Karte rechts „Neulogin“** (Überschrift „Erstes Mal hier oder anderes Gerät“): Feld
  „E-Mail-Adresse“ und Knopf „Weiter“. Danach die vorhandene Passkey-Abfrage für diese Person
  (Browser bietet Handy per QR und Sicherheitsschlüssel an). Antwort und Wartezeit dürfen nicht
  verraten, ob das Konto existiert.
- Desktop: zwei gleich breite Karten nebeneinander (je ca. 440 px, 32 px Abstand). Unter 720 px
  untereinander mit Trenner „oder“.
- Darunter: „Passkey verloren? Mit Wiederherstellungscode fortfahren“ (Link auf A3, bis dahin
  ausgeblendet) „oder an die Praxis-Administration wenden“.
- Fußzeile: Impressum, Datenschutz, Hilfe (F2, `LEGAL_*`).
- Maße: Knöpfe und Felder 48 px hoch, Radius 8, Karten Radius 12 mit 32 px Innenabstand, Text
  16 px, Kennzeichnung 13 px Großbuchstaben. Farben über das Theme des Clients (Theme-API), nicht
  fest im Code; arzt-agent setzt sie per `PUT /theme/{client_id}`.
- Fehlermeldungen (Passkey nicht gefunden, abgebrochen, Zeitüberschreitung) erscheinen in der
  jeweiligen Karte, nicht seitenweit.
- Barrierefreiheit: Karten als `<section>` mit Überschrift, Fokusreihenfolge links → rechts,
  Kontrast ≥ 4,5:1, Tastatur vollständig.

**Tests:** Svelte-Check; Playwright: beide Wege mit virtuellem Authenticator, Layout-Schalter aus →
altes Layout unverändert; Smartphone-Breite.

### A2 – Selbstbedienung aus der Praxis-App (gleiche Adresse)
Mocks: [`mocks/03-mein-konto.png`](mocks/03-mein-konto.png),
[`mocks/04-geraet-hinzufuegen.png`](mocks/04-geraet-hinzufuegen.png).

Die Praxis-App baut „Mein Konto“ selbst und ruft Rauthy im Browser unter derselben Adresse auf
(`/auth/v1`), mit Rauthys Sitzungs-Cookie und dem CSRF-Token aus
`GET /auth/v1/oidc/sessioninfo/xsrf`. Vorhanden sind bereits `GET /users/{id}/webauthn`,
`POST /users/{id}/mfa_token`, `POST /users/{id}/webauthn/register/start|finish` und
`DELETE /users/{id}/webauthn/delete/{name}` (alle mit Sitzung und CSRF).

Aufgaben:
1. **Prüfen und dokumentieren** (`arztagent/SELBSTBEDIENUNG-API.md`): Cookie-Name und -Pfad,
   Lebensdauer der Sitzung, CSRF-Ablauf, Fehlercodes bei abgelaufener Sitzung, Ablauf des
   `mfa_mod_token`. Ergebnis: ein Ablauf, den die App ohne Rauthy-Seite gehen kann.
2. **Art des Geräts speichern:** bei `register/finish` die Transports bzw. die Authenticator-
   Anbindung des Passkeys auswerten und als `kind` speichern (`internal` → „Dieser Computer“,
   `hybrid` → „Smartphone“, `usb`/`nfc` → „Sicherheitsschlüssel“). Zusammen mit F3 in einer
   Migration (`passkeys.kind`, `passkeys.shared_device_choice`), in `PasskeyResponse` ausgeben.
3. **Hinweis an den Browser:** `register/start` nimmt optional `hints` an
   (`hybrid`, `security-key`, `client-device`) und reicht sie in die Optionen weiter; die App
   setzt sie nach der Auswahl in Mock 4. Browser ohne Unterstützung ignorieren sie.
4. **Eigene Sitzungen:** Endpunkte für die eigene Person, mit Sitzung, CSRF und frischem
   `mfa_mod_token`: `GET /users/{id}/sessions` (Gerät/Browser grob, letzte Aktivität, keine
   IP-Adresse) und `DELETE /users/{id}/sessions` („Überall abmelden“, außer der aktuellen
   Sitzung). Heute können das nur Admins (`delete_sessions_for_user`).
5. **F3 (Frage nach gemeinsam genutzten PCs)** wie in arzt-agent `PLAN-RAUTHY-KONTO-PASSKEYS.md`
   beschrieben; die Antwort kommt bei der App aus Mock 4 („Dieser Computer“ mit Warnung).

**Tests:** Integrationstests je Endpunkt (fremde Person → 403, ohne CSRF → 403, ohne frischen
Token → 403); Playwright-Ablauf „Gerät hinzufügen und entfernen“ über die API.

### A3 – Wiederherstellungscodes (= F4)
Mock: [`mocks/05-wiederherstellungscodes.png`](mocks/05-wiederherstellungscodes.png).

Entschieden (20.10.2026):
- **Zehn Einmalcodes**, Format `ABCD-EFGH-JKLM` (Base32 ohne verwechselbare Zeichen). Die
  ersten vier Zeichen sind ein Suchschlüssel, der Rest wird mit Argon2id gehasht.
- **Anzeigen nur direkt nach dem Erzeugen.** Kein späteres Wiederanzeigen; „Neue Codes erzeugen“
  macht alle alten ungültig und verlangt einen frischen `mfa_mod_token`.
- Erzeugen bei der ersten Passkey-Einrichtung angeboten (Einrichtungsseite) und jederzeit aus
  der App.
- **Einlösen:** öffentliche Seite „Passkey verloren?“: E-Mail + Code + Proof of Work, Antwort
  immer gleich. Gültiger Code wird verbraucht, Mail mit Link an die verifizierte Adresse
  (`MagicLinkUsage::PasskeyRecovery`, 15 Minuten). Der Link öffnet nur „Neuen Passkey
  registrieren“: keine Sitzung, kein Token, kein `mfa_method`.
- Vorhandene Passkeys bleiben; die Person entfernt den verlorenen danach selbst.
- **Bremse:** vorhandene IP-Sperre plus höchstens 5 Fehlversuche je Konto in 24 h, danach
  Einlösen gesperrt bis zum Zurücksetzen durch die Praxis-Administration.
- Ereignisse `RecoveryCodeUsed`, `RecoveryCodeFailed`, `RecoveryCodesRegenerated`; Mail an die
  Person bei Einlösen und Neuerzeugung.

Endpunkte:
- `POST /users/{id}/recovery_codes` (Sitzung, CSRF, frischer `mfa_mod_token`) → die zehn Codes,
  einmalig im Klartext.
- `GET /users/{id}/recovery_codes` → `{remaining, created}`; dasselbe für den Admin-API-Key
  (arzt-agent zeigt „Codes vorhanden ja/nein“ auf der Team-Seite).
- `DELETE /users/{id}/recovery_codes` nur Admin-API-Key (Zurücksetzen durch die Praxis).
- `POST /users/recover` (öffentlich) und die Einlöse-Seite im Layout von A1.
- Tabelle `recovery_codes (user_id, lookup, hash, created, used)`, Löschen kaskadiert.

Die Darstellung der Codes (Kopieren, Textdatei, Drucken) baut die Praxis-App; Rauthy liefert nur
die Codes. Auf der Einrichtungsseite (`frontend/src/routes/users/{id}/reset/reset/+page.svelte`)
dieselben drei Aktionen im Layout von Mock 5.

**Vor dem Bau:** Spezifikation kurz von einem Security-Review prüfen lassen (wie am 12.10.).

### A4 – Theme und Logo per API für beide Seiten
- Prüfen, dass Theme und Logo eines Clients auch auf Kontoseite, Einrichtungsseite,
  Einlöse-Seite und `/device` greifen, nicht nur auf der Anmeldung; sonst ergänzen.
- Die Schrift „Geist“ als Teil des Themes zulassen (heute nicht vorgesehen): Feld `font_family`
  im Theme oder Schalter `THEME_FONT_URL`/`THEME_FONT_FAMILY` (nur Umgebungsvariable). Schrift
  selbst hosten, keine externe Font-Quelle zur Laufzeit (Datenschutz).
- Den API-Key-Rechtegruppen-Bedarf für `PUT /theme/{id}` und `PUT /clients/{id}/logo`
  dokumentieren (arzt-agent setzt sie in `prepare_rauthy.py`).

## Phase 2 – Anmeldung am gemeinsamen Praxis-PC per Handy

Mocks: [`mocks/07-qr-anmeldung-pc.png`](mocks/07-qr-anmeldung-pc.png),
[`mocks/08-qr-freigabe-handy.png`](mocks/08-qr-freigabe-handy.png).

Grundlage ist die vorhandene Geräteanmeldung (`POST /oidc/device`, `POST /oidc/device/verify`,
Seite `frontend/src/routes/device/+page.svelte`, `force_mfa` im Device-Flow aus dem Fork).

### B1 – Device-Code mit Zahlenabgleich
- Der Praxis-Client (`aa-practice-web`, öffentlich) darf den Device-Code-Flow nutzen.
- Zu jedem Device-Code eine zweistellige **Abgleichszahl**; die Antwort von `POST /oidc/device`
  enthält sie zusätzlich (`aa_match`), `verification_uri_complete` enthält den Benutzercode für
  den QR-Code.
- **Freigabeseite** (`/device`) im Layout von Mock 8, nach Anmeldung mit Passkey auf dem Handy:
  Angaben zum anfragenden Gerät (Bezeichnung, Browser und Betriebssystem aus dem User-Agent,
  Zeit; Ort nur nach Freigabe durch den Datenschutz), drei Zahlenknöpfe (eine richtig, zwei
  zufällig), „Das war ich nicht – ablehnen“.
- Falsche Zahl → Code sofort ungültig, Sicherheitsereignis, Hinweis an die Person.
- Gültigkeit höchstens 120 s (`DEVICE_GRANT_CODE_LIFETIME`), Code nur einmal verwendbar,
  vorhandenes Rate Limit (`DEVICE_GRANT_RATE_LIMIT`) prüfen.
- Die Sitzung am PC ist kurz: Refresh-Token mit kurzer Lebensdauer für so erzeugte Anmeldungen
  (Wert mit arzt-agent abstimmen, Vorschlag 15 Minuten ohne Aktivität).

### B2 – Gerät als „gemeinsamer Praxis-PC“ kennzeichnen
Die Praxis-App darf keine Cookies oder `localStorage` setzen (Speicher-Regel in arzt-agent).
Vorschlag: Rauthy setzt nach Bestätigung durch eine Praxis-Administration ein signiertes,
langlebiges Cookie `aa_shared_device` unter `/auth` mit Gerätebezeichnung (z. B. „Empfang 1“) und
Praxis. Ist es gesetzt, zeigt die Anmeldeseite (A1) direkt den QR-Weg (Mock 7) und legt auf
diesem Gerät keine Passkeys an. Alternative bewerten und mit arzt-agent entscheiden, bevor gebaut
wird.

**Vor dem Bau:** Security-Review des Ablaufs (eigener QR-Code ohne Bluetooth-Nähe-Prüfung;
Gegenmittel Zahlenabgleich, kurze Gültigkeit, Gerätekennzeichnung).

## Abnahme (DEV, `https://dev.arztagent.app`)
1. Anmeldung: beide Karten funktionieren in Chrome und Safari, Mac und Windows, iPhone und
   Android; das alte Layout ist mit `LOGIN_LAYOUT=default` unverändert.
2. App „Mein Konto“: Gerät hinzufügen (Smartphone per QR, Sicherheitsschlüssel), Art wird richtig
   angezeigt, entfernen, „Überall abmelden“.
3. Codes: erzeugen, einlösen → nur Passkey-Einrichtung; 6. Fehlversuch gesperrt.
4. Phase 2: QR am gekennzeichneten PC, Zahlenabgleich, falsche Zahl sperrt, Ablehnen meldet.
