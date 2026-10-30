# Optionales Praxiskonto mit Rollen-PINs

Stand: 29.10.2026. Neuer Modus ist je Praxis ausdrücklich einzuschalten.
Persönliche PINs und bestehende Wiederherstellung bleiben erhalten.

## Konfiguration

`SHARED_DEVICES_ENABLE=true`, `SHARED_DEVICES_CLIENT_IDS=aa-practice-web` und
`SHARED_DEVICES_PASSWORD_LOGIN=true` erlauben die zusätzliche Passwortanmeldung nur für
konfigurierte Praxisclients. Das Passwort ist kein MFA-Nachweis. Die Methode `password`
bezeichnet eine geprüfte Passwortanmeldung; `none` wird dadurch nicht freigegeben.
Die Konto-Einstellung verlangt weiterhin den vorhandenen Passkey. Beide bisherigen
Passkey-Anmeldewege bleiben erhalten. Passwort-Wiederherstellung wird nicht geändert.

## Rollen-API für das Anwendungsbackend

Alle folgenden Pfade brauchen den API-Key mit `SharedDevices` Read beziehungsweise Update.
Das Anwendungsbackend muss Praxiszugehörigkeit und Rechte selbst prüfen.

- `PUT /shared_devices/practices/{id}/roles` mit `{user_id}`: Rollenmodus bewusst
  einschalten; aktives Mitglied mit Passkey erforderlich. Vorhandene PINs nicht überschreiben.
- `GET .../roles`: drei Rollen mit `enabled` und `has_pin`.
- `PUT .../roles/{role}/pin` mit `{user_id, pin, session_id? , password?}`:
  Aktive Rollensitzung darf ausschließlich ihre eigene PIN ändern. Ohne Rollensitzung
  bestätigt das Praxiskonto sein Passwort zum Setzen oder Zurücksetzen einer Rollen-PIN.
- `DELETE .../roles`: ausschalten, Gerätesitzungen beenden, Rollen-PINs erhalten.
- `GET /shared_devices/sessions/{id}`: aktueller Geräte-/Praxis-/Konto-/Rollenbezug;
  muss an der API bei jeder geschützten Anfrage geprüft werden, nicht gecacht.

Rollen: `administration`, `management`, `staff`. Sie sind Obergrenzen bestehender
Kontorechte, keine Personen und keine zusätzlichen Rauthy-Administratoren.

## Ablauf und Schutz

Die Praxis-App erstellt nach Kontoanmeldung eine Geräteregistrierung. Der bestehende
Registrierungsdialog bestätigt mit Passkey oder ausdrücklich mit Kontopasswort.
Das Gerät behält den nicht exportierbaren P-256-Schlüssel in IndexedDB und das geschützte
Geräte-Cookie; kein Kontopasswort wird gespeichert. Vor dem Koppeln alle Rollen-PINs setzen.

`POST /oidc/authorize/pin` nimmt zusätzlich `role` an. Schlüsselbesitz und Rolle/PIN werden
geprüft. Im Rollenmodus dürfen persönliche PINs die Rollenauswahl nicht umgehen.
Eine PIN gilt praxisweit, ist frei wählbar und vierstellig. Speicherung: HMAC mit Kontext
für Praxis und Rolle; kein Klartext. Änderung beendet die bisherigen Sitzungen dieser Rolle.

Tokens freigegebener Praxisclients tragen `aa_shared_session`, `aa_practice_id` und bei Rollen
zusätzlich `aa_practice_role`. Andere Clients erhalten keine Praxisbindung. Das Anwendungsbackend
prüft Signatur, Praxis, Kontorechte, Rollenobergrenze
und lebende Gerätesitzung. Rollenwechsel beendet alte Sitzungen und Refresh-Tokens.
Passkeys oder Kennwörter allein werden nicht als Rollen-PIN-Nachweis ausgegeben.

Rollen-PIN: fünf Versuche, fünf Minuten Sperre je Rolle/Gerät. Passwort: fünf Versuche,
15 Minuten je Konto. Reservierung atomar vor dem Vergleich; weitere Versuche verlängern
nicht. Passkey-Anmeldungen lesen diese Passwortsperre nicht.

Keine Leerlaufsperre für Rollensitzungen; die bisherige absolute Sitzungsgrenze bleibt.
Geräteereignisse einschließlich Rolle bleiben im vorhandenen 90-Tage-Protokoll.
Abgelaufene Sperren werden beim nächsten Versuch und im vorhandenen Bereinigungslauf
entfernt. Sonstige Zähler hängen an Konto/Gerät, Rollensitzungen an der IdP-Sitzung.

## Migration und Rückweg

Postgres V41 beziehungsweise Hiqlite 46 sind additiv. Rollen-PINs werden nie aus persönlichen
PINs übernommen. Für den Rückweg zuerst den Rollenmodus über die API ausschalten.
SQLite-Bestandstabellen sind STRICT: neue Spalten als INTEGER/TEXT anlegen. Zeitparameter
in Rechenausdrücken ausdrücklich als BIGINT casten; beide Datenbankpfade testen.
Ein Downgrade benötigt keine Löschung der neuen Tabellen; keine Sitzungen aus dem neuen
Modus auf einem alten Backend weiterverwenden. Datenbankwechsel bleiben wie bisher getrennt.

Gemeinsame PINs identifizieren keine Person. Die Risikoentscheidung der Praxis vor echten
Daten bleibt offen (ArztAgent DS-011). Diese Datei ist keine rechtliche Freigabe.
