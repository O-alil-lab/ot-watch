# Security Policy — OT Watch

## Signalement de vulnérabilités
Merci de signaler toute vulnérabilité de manière responsable :
e-mail **security@otwatch.example** (ou issue privée GitHub).
Accusé de réception sous 72 h, correctif visé sous 30 jours selon la criticité.
Ne publiez pas de PoC exploitable publiquement avant le correctif.

## Périmètre
- `server.py` (dashboard live, endpoints `/api/*`, `/issue`, `/metrics`)
- `src/collect.py`, `src/render.py`, `src/validate.py`, `src/store.py`
- le pipeline de collecte (sources publiques CISA / NVD / KEV / FIRST EPSS — aucune donnée privée)

## Mesures en place
- **Anti-XSS** : échappement HTML systématique (`html.escape(quote=True)` côté serveur,
  `esc()` + `safeHref()` http/https-only côté client) — testé (payloads `<script>`,
  `javascript:`, `onerror=`).
- **En-têtes de sécurité** : CSP, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer` sur toutes les réponses.
- **Auth admin** : `POST /api/refresh` exige `Authorization: Bearer $OTWATCH_ADMIN_TOKEN`
  quand la variable d'env est définie + **rate-limit** 1/60 s.
- **Secrets** : jamais en dur — uniquement via variables d'environnement
  (`NVD_API_KEY`, `OTWATCH_ADMIN_TOKEN`) ; `.gitignore` couvre `.env`, `*.key`, `data/` ;
  pre-commit gitleaks (`scripts/pre-commit`) + grep de secrets en CI.
- **Robustesse réseau** : timeouts, cap de taille, écritures atomiques (`tmp` + `os.replace`),
  retries avec backoff sur la NVD, circuit implicite (dernières bonnes données servies).
- **Qualité** : 45 tests (unitaires + intégration + sécurité serveur), couverture ≥ 80 % (gate CI),
  ruff, AgentShield (0 finding bloquant) sur le harnais.

## Hors périmètre
Les données publiées (CVE, avis CISA) proviennent de sources publiques ; leur exactitude
doit être vérifiée auprès des éditeurs avant toute action en production OT.
