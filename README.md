# 🛡️ OT Watch — newsletter automatisée PLC / cybersécurité OT / CVE

Newsletter professionnelle qui **collecte automatiquement** les données depuis les sources
officielles (CISA, NVD, KEV) sur l'**automatisme (PLC)**, la **cybersécurité OT** (CVE,
avis éditeurs, menaces actives) et les **technologies** (OPC UA, Modbus, S7comm, IEC 62443,
NIS2…), puis **réécrit les articles** au niveau éditorial (dossier `editorial/`).

Conçu selon le workflow **ECC research-first** : `research/findings/` (notes sourcées) →
`research/plans/` (plan) → build (`src/`) → verify (exécution + rendu).

## Structure
```
newsletter-ot/
├── config.json          # sources, mots-clés NVD, regex éditeurs OT, fenêtre (jours), limites
├── run_all.sh           # pipeline complet (cron-ready)
├── src/
│   ├── collect.py       # CISA RSS + NVD API 2.0 + CISA KEV  ->  data/*.json
│   └── render.py        # data + editorial  ->  out/issue-<date>.html / .md
├── editorial/           # articles rédigés (markdown + en-tête clé: valeur)
├── research/
│   ├── findings/        # notes de recherche avec citations
│   └── plans/           # plan de build
├── data/                # snapshots JSON de la dernière collecte
└── out/                 # éditions générées (HTML + MD)
```

## Utilisation
```bash
cd /home/user/newsletter-ot
./run_all.sh                      # collecte + rendu de l'édition du jour
# ou séparément :
python3 src/collect.py            # seulement la collecte
python3 src/render.py             # seulement le rendu
```

## Automatisation (cron)
```bash
# Tous les lundis à 07:00 (heure du serveur)
0 7 * * 1  cd /home/user/newsletter-ot && ./run_all.sh >> out/cron.log 2>&1
```
Clé API NVD optionnelle (lève le rate limit) :
```bash
export NVD_API_KEY="..."   # ou dans le crontab
```

## Personnalisation
- **Sujets / éditeurs** : `nvd_keywords`, `vendor_regex`, `ot_kev_regex` dans `config.json`.
- **Fréquence de collecte** : `window_days` (défaut 14 jours glissants).
- **Contenu éditorial** : ajouter un fichier `editorial/NN-titre.md` avec en-tête
  `title:` / `kicker:` / `section:` / `lead: true|false`, séparé du corps par `---`.
- **Sortie** : `out/issue-AAAA-MM-JJ.html` (CSS inline, autonome, prêt à envoyer /
  à héberger) et `.md` (plateformes e-mail type Markdown).

## 🌐 Site temps réel (live, pas de démo)
```bash
cd /home/user/newsletter-ot
AUTO_REFRESH_SECONDS=1800 python3 server.py --host 0.0.0.0 --port 8000
# → http://localhost:8000          tableau de bord live (polling 15 s)
# → http://localhost:8000/issue    dernière newsletter HTML générée
# API : GET /api/data · GET /api/meta · POST /api/refresh (re-collecte CISA/NVD/KEV en fond)
```
Le tableau de bord affiche les **vraies données** collectées (CVE NVD avec badges CVSS,
avis CISA ICS, KEV OT, articles), se rafraîchit toutes les 15 s, re-collecte toutes les
`AUTO_REFRESH_SECONDS` (30 min par défaut) et via le bouton « 🔄 Re-collecter maintenant ».
Filtres : recherche texte, sévérité, ★KEV. Anti-XSS côté client (`esc()` + `safeHref()`).

## 🆕 v1.1 — quick wins P0 (31/10/2026)
- NVD par **CPE éditeurs** (`virtualMatchString`) + EPSS (FIRST) + **score de risque** CVSS/KEV/EPSS → tri par risque
- **Validation qualité** à chaque collecte (`src/validate.py`) + alerte si chute de volume
- **SQLite** (`data/otwatch.db`) + diff « nouvelles CVE/avis/KEV depuis la dernière collecte » (`meta.diff`)
- Serveur : en-têtes sécurité (CSP/nosniff/DENY), **token admin** `OTWATCH_ADMIN_TOKEN` sur `POST /api/refresh`, **rate-limit 1/60 s**, endpoint **`/metrics` (Prometheus)**, badge **STALE** si fraîcheur > 2× intervalle
- **CI GitHub Actions** (`.github/workflows/ci.yml`) + **gitleaks pre-commit** (`scripts/pre-commit`) + `SECURITY.md`
- 45 tests OK, couverture 87 % — voir `research/VERIFICATION-2026-10-31.md` (addendum v1.1)

## 🔔 v1.2 — push temps réel (SSE) + alerting
- **SSE** : `GET /api/stream` (Server-Sent Events) — le dashboard reçoit un push **instantané**
  à chaque fin de collecte (`{"type":"collected", diff, counts}`), avec keepalive `: ping` / 25 s
  et fallback polling 15 s. Testé en live et en test unitaire (socket réel + broadcast).
- **Alerting** (`src/alerts.py`, appelé à chaque collecte, cron OU bouton) : alerte si
  **nouvelle CVE CRITICAL / ★KEV / risque ≥ 7** ou nouvelle entrée KEV.
  Destinations via env (jamais en dur) : `OTWATCH_WEBHOOK_URL` (POST JSON),
  `OTWATCH_SLACK_WEBHOOK` (format Slack), SMTP (`OTWATCH_SMTP_HOST/PORT/USER/PASS/FROM/TO`, `OTWATCH_SMTP_SSL=1`).
  Sans destination configurée → **dry-run** : log JSONL dans `logs/alerts.jsonl`.
- 52 tests OK, couverture 83 %.

## ⭐ v1.3 — profil d'exposition « Mes actifs OT » + historique visuel (01/11/2026)
- **Profil d'exposition** (`config.json` → `exposure.keywords`, ~40 mots-clés OT : Siemens/S7/SIMATIC,
  Schneider/Modicon, Rockwell/ControlLogix, Modbus, OPC UA, SCADA, PLC…) : chaque CVE dont la
  description correspond est marquée `relevant: true` (⭐), **triée en premier** (puis par risque)
  dans la newsletter, le dashboard et `/api/data`.
- **Filtre dashboard** « ⭐ Mes actifs OT » (`#bRel`) + badges ⭐ dans les lignes ; tri client
  (relevant, puis risque).
- **Historique 30 j** : `src/store.py` → `history_daily(days=30)` (SQLite, jours vides = 0) exposé via
  `GET /api/history` → graphique **SVG inline** « 📈 Tendances » dans le dashboard (3 séries :
  total CVE publiées, CRITICAL, nouvelles entrées KEV en pointillés) — aucune librairie externe.
- Colonne `cves.relevant` migrée automatiquement (`ALTER TABLE` au démarrage si besoin).
- Collecte réelle v3 : **4/22 CVE** correspondent au profil « Mes actifs OT » (run #9, 227 s).
- 59 tests OK (`test_exposure.py`, `test_history.py`, +2 tests serveur), couverture 84 % (store 100 %).

## 📄 v1.4 — export PDF de l'édition (01/11/2026)
- **`src/render_pdf.py`** (fpdf2, A4, police DejaVu embarquée) produit **`out/issue-<date>.pdf`**
  à chaque `run_all.sh` (même date d'édition que le HTML/MD, dérivée de `meta.generated_at`) :
  bandeau titre, « En bref » (CVE/CRITICAL/★KEV/◆actifs OT/avis/KEV), **sparkline 30 j** (historique
  SQLite), articles éditoriaux, **tableau CVE trié par risque** (sévérité colorée, ★ KEV, ◆ ⭐ actifs OT,
  description), avis CISA ICS, entrées KEV OT (☠ ransomware), pied de page paginé + sources.
- Glyphes 100 % sûrs (testés via cmap DejaVu : ★ ☠ ⚠ ✓ ◆ ● →) — aucun emoji manquant.
- **Live** : `GET /issue.pdf` → `application/pdf` + `Content-Disposition: inline` + en-têtes sécurité ;
  bouton « 📄 Télécharger le PDF » dans le dashboard. `requirements.txt` + install idempotent dans
  `run_all.sh` + étape CI.
- Édition 2026-10-31 : **6 pages, 68 Ko** — vérifié (pypdf : CVE-2026-110936, « Tendances 30 jours », etc.).
- 63 tests OK (`test_pdf.py`), couverture 82 % (render_pdf 78 %).

## 🎯 Vision « plateforme de référence OT » + agents IA éditoriaux (01/11/2026)
Rapport ECC + deep-research 2026 : `research/REFERENCE-OT-WATCH-2026-11-01.md` — benchmark vs Claroty/Dragos/Nozomi/Tenable (collecte passive DPI, ATT&CK for ICS v20, SSVC), standards STIX 2.1/TAXII 2.1/MISP/OpenCTI, et architecture multi-agents (analyste RAG → rédacteur → fact-checker → illustrateur C2PA → éditeur humain) conforme AI Act Art. 50. `AGENTS.md` à la racine pour tous les agents IA travaillant sur le dépôt.

## 🧬 v1.5 — standards 2026 : export STIX 2.1 + ATT&CK for ICS + SSVC (01/11/2026)
- **`src/stix.py`** : bundle **STIX 2.1** (`out/issue-<date>.stix.json`, servi sur **`GET /stix`**,
  `application/stix+json`) — `vulnerability` par CVE (refs NVD + CISA KEV + **MITRE ATT&CK for ICS**
  + `x_otwatch_*` : cvss/epss/kev/risk/relevant/ssvc), `course-of-action` par avis CISA,
  `report` de l'édition, marking **TLP:WHITE** ; IDs **uuid5 déterministes** → dédup idempotente
  (compatible TAXII 2.1 / MISP / OpenCTI / CISA AIS). Bouton « 🧬 Export STIX 2.1 » dans le dashboard.
- **`src/enrich_ot.py`** : mapping **ATT&CK for ICS** (config `attack_ics`, 10 techniques T0xxx) +
  décision **SSVC** simplifiée CISA (exploitation KEV/EPSS/Poc, automatable, impact, mission via le
  profil d'exposition → **Track / Track* / Attend / Act**) ; stocké en SQLite (`attack_ics`, `ssvc`)
  et affiché dans newsletter (badge SSVC + liens techniques), PDF, dashboard.
- Collecte v5 : techniques mappées + SSVC `act` comptés dans les logs ; 78 tests OK
  (`test_enrich_ot.py`, `test_stix.py`), couverture 81 %.

## Quality gates (boucle de vérification ECC)
```bash
cd /home/user/newsletter-ot
python3 -m py_compile src/*.py tests/*.py      # phase 1 : build
python3 -m ruff check src tests --config ruff.toml   # phase 3 : lint
python3 -m coverage run -m unittest discover -s tests # phase 4 : tests
python3 -m coverage report --include="*/src/*"        # couverture (objectif ECC >= 80 %)
# phase 5 : security grep (secrets / eval / shell=True)
grep -rniE "(api[_-]?key|secret|token|password)\s*[:=]\s*[\"'][A-Za-z0-9+/=_.-]{8,}" src tests config.json
# phase 6 : AgentShield (ECC) sur la config agent + doctor
npx --yes ecc-agentshield scan --path /home/user/.claude
node /home/user/ecc/scripts/doctor.js
```
Dernier rapport : `research/VERIFICATION-2026-10-31.md` → **PASS** (23 tests OK, couverture 91 %, 0 secret, 0 finding bloquant AgentShield).

## Sources
- CISA — avis ICS : https://www.cisa.gov/news-events/ics-advisories (+ RSS https://www.cisa.gov/rss.xml)
- NVD API 2.0 : https://services.nvd.nist.gov/rest/json/cves/2.0
- CISA KEV : https://www.cisa.gov/known-exploited-vulnerabilities-catalog

*La newsletter est une veille informative : vérifiez toujours les correctifs auprès des éditeurs avant tout déploiement en production OT.*
