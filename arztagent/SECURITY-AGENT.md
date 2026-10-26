# Security-Automatik im Fork

Rauthy ist ArztAgents Identitätsanbieter. Dieser Fork muss Upstream-Sicherheitskorrekturen
schnell übernehmen und bekannte Lücken früh sehen. Einrichtung (Rechte, Rulesets, Secrets):
`scripts/security-setup.sh` und `PLAN-SECURITY-AGENT.md` im ArztAgent-Repo.

## Abläufe

| Workflow | Wann | Was |
|---|---|---|
| `upstream_sync.yaml` | täglich 05:17 UTC, manuell | neue Commits von `sebadob/rauthy` mergen, PR öffnen |
| `security_scan.yaml` | PR, `main`, montags | osv-scanner, gitleaks, zizmor, trivy → Code Scanning |
| CodeQL (Default Setup) | PR, `main`, wöchentlich | Rust, JS/TS, Actions → Code Scanning |
| Dependabot | täglich | Sicherheitsupdates Cargo/npm als ein PR, Label `security` |
| `tests.yaml` | PR, vom Sync angestoßen | Unit- und Integrationstests gegen Hiqlite |
| `arztagent_image.yaml` | Merge mit Label `upstream-sync`/`security` | Image `<version>-aa<n>` |

Danach öffnet ArztAgent (`rauthy-image-bump.yml`) selbst den PR für `ops/rauthy/IMAGE`.

## Upstream-Sync (`arztagent/upstream_sync.py`)

1. **Plan:** Commits in `upstream/main`, die `main` fehlen. Sicherheitsrelevant ist ein Commit
   mit Sicherheitswort (CVE, GHSA, XSS, bypass, race, revoke …) oder ein Fix, der Anmeldung,
   Token oder Auth-Code betrifft. Upstream-Advisories der letzten 180 Tage kommen in den PR.
2. **Merge** in `upstream-sync/<sha>`. Konfliktfrei: direkt zum PR.
3. **Konflikte:** Claude Code löst sie im Builder-Container nach
   `arztagent/upstream_sync_prompt.md` (beide Seiten erhalten, fmt/clippy/Unit-Tests), schreibt
   Notizen in die PR-Beschreibung. Ohne Schlüssel oder bei Fehlschlag: Issue mit Label
   `upstream-sync-conflict` und einer fertigen Anweisung für eine Claude-Code-Sitzung.
4. **Publish:** Ein eigener Job ohne Upstream-Code prüft, dass das Bundle genau ein Merge aus
   Fork- und Upstream-Stand ist und nichts unter `.github/` ändert, pusht, öffnet den PR und stößt
   `Code Style`, `Tests` und `Security scan` an (PRs mit dem Workflow-Token starten sonst nichts).
5. Ein neuerer Upstream-Stand ersetzt den offenen Sync-PR (alter PR wird geschlossen).

**Review:** Ein Mensch mergt. Bei KI-gelösten Konflikten jede genannte Datei im Diff lesen;
Fork-Härtungen (force_mfa, Passkeys, Wiederherstellungscodes) müssen erhalten sein.

## Secrets und Variablen

- `ANTHROPIC_API_KEY` (eigener Schlüssel mit Ausgabenlimit) oder `CLAUDE_CODE_OAUTH_TOKEN`:
  nur für die Konfliktlösung. Der Job baut Upstream-Code; der Schlüssel ist dort lesbar.
  Deshalb ein eigener, begrenzter Schlüssel, nie ein geteilter.
- `vars.UPSTREAM_SYNC_MODEL`: Modell-Alias für Claude Code (Standard `opus`).
- Sonst nur das Workflow-Token; kein Bot-Token mit Zugriff auf andere Repos liegt hier.

## Befunde und Fristen

- Triage-Liste: Security → Code scanning und Dependabot alerts dieses Repos.
- Fristen ab Fund: critical 24 h, high 7 Tage, medium 30 Tage, low beim nächsten Sync.
- Nicht zutreffende Befunde: in GitHub mit Begründung schließen, bei osv-scanner in
  `osv-scanner.toml` mit `reason` und `ignoreUntil`. Keine Ausnahme ohne Ablaufdatum.
- `.gitleaks.toml` erlaubt nur Upstream-Beispielschlüssel; ein echtes Secret wird rotiert.

## Eigene Funde: vertraulich

Dieses Repo ist öffentlich. Eine selbst gefundene, noch offene Lücke nie als Issue, PR oder
Commit-Text beschreiben:

1. Security → Advisories → *New draft security advisory* (privat).
2. Fix im temporären privaten Fork des Advisories, dort reviewen.
3. Image bauen, ArztAgent ausrollen, erst danach Advisory veröffentlichen und mergen.
4. Betrifft es Upstream: Ein Mensch meldet es über das Private Vulnerability Reporting von
   `sebadob/rauthy`, nie ein Bot.
