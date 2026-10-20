# Theme, Logo und Schrift (A4)

Geprüft am Code (Branch `a4-theme-font`). Pfade relativ zu `/auth/v1`.

## Welche Seite nutzt was

| Seite | Theme von | Logo von |
|---|---|---|
| Anmeldung `/oidc/authorize` | anfragender Client | anfragender Client |
| Kontoseite `/account` | `rauthy` | `rauthy`, nur wenn eigenes Logo hochgeladen |
| Einrichtung (Link aus der Mail) | `rauthy` | `rauthy`, nur wenn eigenes Logo hochgeladen |
| Passwort-Reset-Anfrage | `rauthy` | `rauthy` (wie bisher) |
| Geräteanmeldung `/device` | `rauthy` | `rauthy`, nur wenn eigenes Logo hochgeladen |
| Admin-UI | `rauthy` | – |

Für ArztAgent heißt das: Theme und Logo für `aa-practice-web` **und** für `rauthy` setzen. Die
Admin-UI bekommt dann dasselbe Theme; sie ist im Gateway ohnehin gesperrt.

## Setzen per API-Key

Beide Aufrufe brauchen die Rechtegruppe `Clients` mit `Update` (`put_theme`, `put_client_logo`).

- Theme: `PUT /theme/{client_id}` mit `ThemeRequestResponse` (`client_id`, `light`, `dark`, `border_radius`).
  Farben als HSL ohne `hsl()`, z. B. Teal `#315F59` → `[172, 32, 28]`. Variablen: `text`,
  `text_high`, `bg`, `bg_high`, `action` (Knöpfe), `accent` (Hervorhebung, „Neulogin“), `error`,
  `btn_text`, `theme_sun`, `theme_moon`.
- Logo: `PUT /clients/{client_id}/logo` als `multipart/form-data` (Feld beliebig, SVG/PNG/JPG).
  Löschen: `DELETE /clients/{client_id}/logo`.

## Schrift

`THEME_FONT_FAMILY=Geist` und `THEME_FONT_FILE=/app/fonts/<datei>.woff2` (Umgebungsvariablen in der
Compose-Datei, Datei per Volume einbinden, höchstens 2 MiB, WOFF2). Rauthy liest die Datei beim
Start und liefert sie unter `/theme_font` aus; keine externe Font-Quelle (Datenschutz). Eine
variable Datei deckt alle Stärken ab, z. B. `geist-latin-wght-normal-*.woff2` aus dem Praxis-
Frontend (`@fontsource-variable/geist`).

## Fallstricke

- Das Theme-CSS hat eine URL mit Zeitstempel des Themes und wird ein Jahr gecacht. Nach einer
  Änderung von Schrift oder Farben das Theme einmal neu speichern (`PUT /theme/...`), sonst sehen
  Browser mit Cache den alten Stand.
- Eine falsche `THEME_FONT_FILE` (fehlt, kein WOFF2, zu groß) bricht den Start ab.
- Das Logo erscheint auf Konto-, Einrichtungs- und Geräteseite erst, wenn für `rauthy` ein eigenes
  Logo hochgeladen ist.
