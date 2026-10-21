# Phase 2: Anmeldung per PIN am gemeinsamen Praxis-PC

Entschieden am 21.10.2026 mit dem Product Owner (ersetzt „PC per Handy“). Am registrierten
Praxis-PC meldet sich eine Person mit einem vierstelligen PIN an, wie im bisherigen PVS. Der PIN
gilt nur zusammen mit dem Geräte-Token und dem Browser-Schlüssel dieses PCs. Ein persönlicher
Passkey bleibt nötig für die Einrichtung, zum Entsperren eines gesperrten PCs und für kritische
Aktionen. Die Freigabe per Handy (früher C2) und der Device-Code-Flow entfallen.

## Rollen und Daten in Rauthy

Rauthy kennt keine Praxisrollen. Das ArztAgent-Backend pflegt per Admin-API (Rechtegruppe
`SharedDevices`):

- **Praxis** (`practice_id` = Organisations-ID): Name, Leerlaufzeit (120–900 s, Standard 300),
  Empfänger für Warnungen (Rauthy-Benutzer-IDs der Praxis-Administration).
- **Mitglieder**: Wer an den PCs der Praxis einen PIN haben darf. Entfernen löscht den PIN und
  beendet die PIN-Sitzungen der Person an diesen PCs.
- **PCs**: Name, IP bei der Registrierung, Schalter „harte IP-Sperre“, Sperrzustand, Zähler der
  Fehlversuche, zuletzt gesehen. Widerruf löscht den PC und beendet seine Sitzungen.
- **Ereignisse je PC** (Tabelle `shared_device_events`, 90 Tage, nur Sicherheitszweck): Person,
  Art, IP. Kein User-Agent, kein Ort.

## Registrierung (C1)

1. Die Praxis-Administration meldet sich am PC in der Praxis-App mit Passkey an und wählt „Diesen
   PC als Praxis-PC registrieren“.
2. Das Backend prüft `team.manage` und legt per Admin-API eine Registrierung an
   (`POST /shared_devices/practices/{id}/registrations`, Benutzer, Name, Rücksprung-URL). Sie gilt
   10 Minuten, einmal, nur für diesen Benutzer.
3. Die App öffnet `/auth/v1/shared_devices/register?id=…` im selben Browser. Rauthy verlangt die
   eigene Sitzung dieses Benutzers und einen frischen Passkey (`MfaModToken`). Ein weitergeleiteter
   Link nützt niemandem: Im fremden Browser fehlt die Sitzung, und der Passkey ist an die Adresse
   gebunden (per Handy zusätzlich an die Bluetooth-Nähe).
4. Beim ersten PC der Praxis bestätigt die Administration den Hinweis zum Restrisiko (PC nur in
   Praxisräumen, PIN geheim halten). Rauthy speichert, wer wann bestätigt hat.
5. Der Browser erzeugt einen nicht exportierbaren ECDSA-P-256-Schlüssel (WebCrypto, IndexedDB).
   Rauthy speichert den öffentlichen Schlüssel und setzt das Cookie `rauthy_shared_device` (Präfix
   nach `cookie_mode`, in PROD `__Host-`; 256 Bit zufällig, nur als Hash gespeichert, HttpOnly,
   SameSite=Lax, 400 Tage, bei jeder Anmeldung erneuert). Danach ist die registrierende Person in
   diesem Browser abgemeldet.

Auf einem registrierten PC lehnt Rauthy das Anlegen von Passkeys ab.

## PIN (C4)

- Je Person und Praxis ein PIN. Rauthy würfelt ihn (4 Ziffern, keine Folgen wie 1234 oder 0000,
  frei in der Praxis) und zeigt ihn einmal im Konto an. „Neuer PIN“ würfelt neu und beendet die
  PIN-Sitzungen der Person. Keine Selbstwahl, damit eine Kollision keinen fremden PIN verrät.
  Erzeugen verlangt einen frischen Passkey.
- Gespeichert wird `HMAC-SHA256(abgeleiteter Schlüssel, practice_id ‖ PIN)` mit Schlüssel-ID.
  Weil der PIN allein die Person bestimmt, muss Rauthy über alle Personen der Praxis suchen;
  Argon2 je Person ginge nicht. Bei 10.000 möglichen PINs schützt ein langsamer Hash ohnehin nicht,
  der Schutz kommt vom Server-Schlüssel, vom Gerät und von der Sperre.

## Anmeldung am PC (C4)

1. Die App startet wie immer `/oidc/authorize` (Code + PKCE). Erkennt die Anmeldeseite einen
   registrierten PC und ist der Client freigegeben (`shared_devices.client_ids`), zeigt sie das
   PIN-Feld. Mit `max_age` in der Anfrage (Nachweis für kritische Aktionen) zeigt sie nur den
   Passkey.
2. Der PC holt eine Challenge (60 s, einmal) und signiert sie mit seinem Schlüssel.
3. `POST /auth/v1/oidc/authorize/pin` mit PIN, Signatur und den Parametern der Anfrage. Rauthy
   prüft Cookie, Signatur, IP-Regel, Sperre und PIN und stellt den Code aus.
4. Nach 5 falschen PINs innerhalb von 24 Stunden ist der PC gesperrt, die Empfänger bekommen eine
   Mail. Ein richtiger PIN setzt den Zähler nicht zurück (Ergebnis des Security-Reviews: sonst
   könnte ein Mitglied zwischen eigenen Anmeldungen unbemerkt die PINs der Kollegen raten). Eine
   Person der Praxis entsperrt ihn, indem sie sich am PC mit ihrem Passkey anmeldet. Keine
   Entsperrung nach Zeitablauf.
5. IP: Weicht sie von der Registrierung ab, warnt Rauthy die Empfänger (höchstens einmal am Tag je
   PC). Mit harter IP-Sperre lehnt Rauthy die Anmeldung ab, ohne den PIN zu prüfen.

## Sitzung am PC (C3)

- Jede Sitzung aus dem Browser eines registrierten PCs trägt dessen ID, auch nach Passkey.
- Höchstens 10 h. Eine neue Anmeldung am PC beendet alle anderen Sitzungen dort samt
  Refresh-Tokens.
- Leerlauf: Die App sperrt den Bildschirm nach der Leerlaufzeit und erneuert dann keine Tokens.
  Rauthy begrenzt jedes Refresh-Token auf die Leerlaufzeit nach seiner frühesten Nutzung
  (gleitend, höchstens bis zum Sitzungsende). Eine Sitzung am PC meldet `/oidc/authorize` nie
  stillschweigend wieder an; `prompt=none` ergibt `login_required`.
- Tokens: `amr = ["pin", "swk"]` nach PIN, `["mfa"]` nach Passkey; `auth_time` ist die
  Anmeldung. Claim `aa_shared_device` (UUID des PCs) im Access- und ID-Token. Ein PIN genügt
  `force_mfa` nur bei den freigegebenen Clients.
- Kein MFA-Merk-Cookie am PC.
- Eine PIN-Sitzung dient nur der Anmeldung. Konto, Admin-Oberfläche und Device-Code-Freigabe sehen
  sie nicht; dafür braucht es den Passkey.

## Aufgaben in ArztAgent

- Backend: `amr` `pin` mit `aa_shared_device` für die Tagesarbeit annehmen; kritische Aktionen
  (Export, Einstellungen, Benutzerverwaltung, Anmeldung zurücksetzen) verlangen weiter `mfa` mit
  `auth_time` höchstens 15 Minuten alt.
- Praxis, Mitglieder, Empfänger und Leerlaufzeit per Admin-API abgleichen; PC-Verwaltung in der
  Praxis-App (Liste, Umbenennen, IP-Sperre, Widerrufen, Ereignisse).
- Sperrbildschirm nach der Leerlaufzeit: `/oidc/authorize` mit `prompt=login`.
- TOM-Text und Bestätigungshinweis; Datenschutzprüfung vor dem Go-live.

## Restrisiko

- Den PIN abzuphishen nützt allein nichts. Die Registrierung ist die eigentliche Hürde.
- Raten: bei 15 Personen etwa 0,75 % Treffer je Sperre; nur ein Passkey hebt die Sperre auf.
- Schadsoftware auf dem PC kann Token und Schlüssel dort benutzen, aber nicht mitnehmen. Dagegen
  helfen IP-Warnung oder IP-Sperre, Ereignisse und Widerruf.
- Kollegen können einen PIN beim Eintippen sehen. Dagegen hilft „Neuer PIN“.

API im Detail: [PRAXIS-PC-API.md](PRAXIS-PC-API.md) (mit dem Code).
