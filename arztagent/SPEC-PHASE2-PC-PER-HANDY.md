# Spezifikation Phase 2: Anmeldung am gemeinsamen Praxis-PC per Handy

Stand 20.10.2026. Ersetzt B1 und B2 aus `PLAN-ANMELDUNG-UND-KONTO.md` (PR #13). Grundlage:
Security-Review vom 20.10.2026 und Entscheidungen des Product Owners. **Vor dem Bau mit arzt-agent
abstimmen** (offene Fragen unten).

## Warum nicht Device-Code (RFC 8628)

Der Device-Code-Flow gibt Tokens an den aus, der den Code abfragt, egal wo er sitzt. Ein Angreifer
startet die Anmeldung auf seinem Rechner und schickt der Mitarbeiterin QR-Code und Abgleichszahl
(„Bitte neue Praxissoftware bestätigen“). Bestätigt sie per Passkey, hat er Zugriff auf
Patientendaten. Die Zahl hilft nicht, weil der Angreifer den Bildschirm mit der Zahl selbst
kontrolliert. Passkeys per QR (hybrid) schützen sich über Bluetooth-Nähe; eine Webseite kann das
nicht. **Entschieden:** Device-Code bleibt für `aa-practice-web` aus.

## Entschiedenes Design

**1. Registrierte gemeinsame PCs (Voraussetzung).** Nur PCs, die eine Praxis-Administration
registriert hat, bieten die Anmeldung per Handy an.
- Tabelle `shared_devices (id, practice, label, token_hash, key_public, created_by, created,
  last_seen, last_seen_ip, revoked)`. `practice` = Gruppe in Rauthy (wie `aa_membership_id`).
- Registrierung: Am PC „Als gemeinsamen Praxis-PC einrichten“ → QR. Eine Praxis-Administration
  scannt, meldet sich mit Passkey an, vergibt den Namen („Empfang 1“). Rauthy setzt dem PC ein
  zufälliges Geräte-Token (256 Bit, nur gehasht gespeichert) als Cookie `__Host-aa_shared_device`
  (Secure, HttpOnly, SameSite=Strict, Path=/, ca. 400 Tage, beim Benutzen erneuert) und legt einen
  nicht exportierbaren Browser-Schlüssel (WebCrypto, IndexedDB unter der Rauthy-Adresse) an; bei
  jeder Anmeldung signiert der PC eine Challenge. Ein kopiertes Cookie allein reicht nicht.
- Widerruf und Liste für die Administration (`last_seen`); Cookies gelöscht → PC fällt auf die
  normale Anmeldung zurück, bis er neu registriert wird.
- Auf einem registrierten PC lehnt Rauthy das Anlegen von Passkeys serverseitig ab.

**2. Anmeldung, an die Sitzung des PCs gebunden.**
1. Der PC startet wie immer `/oidc/authorize` (Code + PKCE). Die Anmeldeseite (A1) erkennt den
   registrierten PC und zeigt direkt den QR-Weg.
2. `POST /auth/v1/xdevice/start` (gleiche Adresse, Sitzungs-Cookie, Geräte-Token + Signatur) →
   zufällige Anfrage-ID, QR mit Freigabe-Link. Gültig 90 s, einmal verwendbar.
3. Der PC fragt mit **seiner** Sitzung den Status ab; die Anfrage ist an `session.id` gebunden.
4. Das Handy öffnet den Link, die Person meldet sich mit Passkey an und sieht den Namen aus dem
   Register („Empfang 1 · Praxis … · 09:41“), nie Angaben aus der Anfrage. Knöpfe „Anmelden“
   und „Das war ich nicht“. Keine Abgleichszahl mit drei Knöpfen.
5. Freigeben darf nur, wer zur Praxis des PCs gehört.
6. Rauthy setzt die **Sitzung des PCs** auf angemeldet (`mfa_method` vom Handy, also Passkey) und
   gibt den Code an die `redirect_uri` aus. Ein weitergeleiteter QR-Code meldet so nur den Browser
   an, der ihn erzeugt hat – beim Angreifer ist das kein registrierter PC.

**3. Sitzung am gemeinsamen PC.** Kennzeichen an der Sitzung (`shared_device_id`):
- Leerlauf-Ende 15 min, Höchstdauer eine Schicht (10 h), kein MFA-Merk-Cookie.
- Keine Selbstbedienung von dort (keine Passkeys, kein Konto, keine Admin-UI).
- Neue Anmeldung am PC beendet die vorherige Sitzung dort; „Abmelden“ beendet die Rauthy-Sitzung
  und widerruft ihre Tokens. Refresh-Tokens höchstens bis zum Sitzungsende.
- Claim für die App (z. B. `aa_shared_device`), damit sie gemeinsames Gerät erkennt (Sperre,
  kein „Angemeldet bleiben“). `amr` = Passkey vom Handy.

**4. Ereignisse.** Start (Gerät), Freigabe (Person, Gerät), Ablehnung, Ablauf. „Das war ich
nicht“ meldet an Person und Praxis-Administration. Gespeichert wird die Geräte-ID, kein
User-Agent, kein Ort.

## Offene Fragen an arzt-agent (Empfehlung in Klammern)

1. Welche Rolle darf PCs registrieren und widerrufen? (Praxis-Administration, frischer Passkey)
2. Wo verwaltet die Praxis ihre PCs – Praxis-App über Admin-API oder Rauthy-Seite? (Praxis-App,
   Rauthy liefert API: Liste, Umbenennen, Widerrufen)
3. Sitzungsdauer am gemeinsamen PC? (15 min Leerlauf, 10 h Höchstdauer)
4. Praxis-IP als zusätzliches Signal? (nur Warnung bei Abweichung, keine harte Sperre)
5. Aufbewahrung der Anmelde-Ereignisse je PC? (90 Tage, nur Sicherheitszweck; Datenschutz und ggf.
   Betriebsrat einbinden, da Beschäftigtendaten)
6. Standort auf der Freigabeseite? (nein)
7. Wie reagiert die App auf den Claim `aa_shared_device` (Bildschirmsperre, Abmelden)?

## Arbeitspakete im Fork (nach Abstimmung)

- **C1** Register gemeinsamer PCs: Migration, Admin-API, Registrierung per QR, Cookie + Schlüssel,
  Sperre für Passkey-Anlage. Integrationstests, Playwright.
- **C2** Anmeldung per Handy: Start/Status/Freigabe, Bindung an `session.id`, Praxis-Prüfung,
  Freigabeseite, QR-Weg auf der Anmeldeseite (A1).
- **C3** Sitzungsregeln für gemeinsame PCs, Claim, Ereignisse, Benachrichtigung.
- Je Paket Security-Review des Codes; E2E-Test mit zwei Browsern (PC, Handy) gegen ein echtes
  Backend wie bei A3.
