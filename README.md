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

## 🌐 v1.6 — collecte élargie « référence » : CISA ICS Advisories + GitHub GHSA + OTX (01/11/2026)
- **Nouvelles sources** (config `sources`) : flux dédié **CISA ICS Advisories** (`ics-advisories.xml`, dédupliqué
  avec le RSS global), **API GitHub GHSA** (10 requêtes OT : SCADA/Modbus/SIMATIC/Modicon/OPC UA…, sans clé,
  rate-limit respecté), **OTX AlienVault** si `OTWATCH_OTX_API_KEY` (env) fournie — les CVE trouvées sont
  réinjectées dans la collecte NVD par `cveId`. Résultat collecte v6 : **37 CVE** (+15 GHSA), **27 avis ICS** (+21).
- Les avis/CVE alimentent automatiquement le diff SQLite, les alertes, le dashboard, le PDF et le STIX.

## 🤖 v1.7 — pipeline d'agents IA éditoriaux (HITL + AI Act art. 50) (01/11/2026)
Package `agents/` (`python3 -m agents.pipeline draft|status|publish`) :
- **Analyste RAG** (`rag.py`) : brief structuré depuis `data/*.json` + SQLite (top CVE, KEV nouveaux,
  tendances 30 j) — chaque fait avec sa **citation primaire** (NVD/KEV/FIRST/ATT&CK).
- **Rédacteur** (`writer.py`) : article FR, chaque fait cité `[n]` ; moteur déterministe à partir de données
  vérifiées (quasi zéro hallucination) + LLM optionnel via `OTWATCH_LLM_CMD` (sa sortie est re-vérifiée).
- **Fact-checker 3 niveaux** (`factcheck.py`) : auto (CVE/KEV/URLs vs données + hôtes autorisés),
  web-vérification à faire, **revue humaine obligatoire** ; bloque la publication si échec.
- **Illustrateur** (`images.py`) : SVG 100 % data-driven (`out/drafts/<draft>/img/`) = visuels factuels
  reproductibles ; images IA possibles mais **C2PA + légende « générée par IA » obligatoires**, jamais de
  deepfake ni de « fausse photo ».
- **Gate HITL** (`pipeline.py`) : `publish` exige fact-check OK **et** fichier `<draft>.approved` (relecteur) ;
  publie dans `editorial/auto-<date>.md` (pris par render.py) + audit `logs/agents.jsonl`.
- Divulgation **AI Act art. 50** (en vigueur depuis 02/08/2026) intégrée au brouillon : « assisté par IA,
  revu par un humain » (exemption art. 50(4) grâce à la revue éditoriale humaine).
- Statut exposé dans `/api/data` (`agents`). 94 tests OK (`test_agents.py`, `test_sources_v2.py`).

## 🛰 v1.8 — serveur TAXII 2.1 read-only (P2 « plateforme de référence ») (01/11/2026)
- **`src/taxii.py`** + routes `/taxii2/*` dans `server.py` : discovery (`/taxii2/` → `application/taxii+json`),
  `/taxii2/collections`, collection **`otwatch-ot-cves`** (can_read, **can_write=false**), `/objects`
  (enveloppe STIX `application/stix+json`, filtre `?added_after=ISO8601` style client Sentinel/Splunk/OpenCTI/MISP),
  `/manifest`, `/versions`. Sert le dernier bundle STIX 2.1 (TLP:WHITE).
- **Read-only** : POST/PUT/DELETE → 405. **Auth optionnelle** : si `OTWATCH_TAXII_TOKEN` est défini,
  `Authorization: Bearer` exigé (401 sinon). En-têtes sécurité sur toutes les réponses.
- Live : 66 objets servis (37 vulnerabilities, 27 course-of-action, report, marking TLP:WHITE), manifest 66 entrées — vérifié en curl. Bouton « 🛰 TAXII 2.1 » dans le dashboard.
- 102 tests OK (`test_taxii.py` : discovery, read-only, added_after, manifest, 405, auth Bearer), couverture 82 % (taxii 81 %).

## 🕸 v1.9 — export MISP + inventaire d'actifs OT & SBOM CycloneDX (P2 OT-ISAC) (01/11/2026)
- **`src/misp_export.py`** : événement MISP 2.1 JSON par édition — attributs `cve` avec commentaire CVSS/EPSS/KEV/SSVC/ATT&CK for ICS, `link` vers les avis CISA, tags `TLP:WHITE`/`ot`/`ics`/`ics-ot`. **Push réel** `POST /events/add` si `OTWATCH_MISP_URL` + `OTWATCH_MISP_AUTHKEY` (+ `OTWATCH_MISP_VERIFY_SSL`) définis, sinon **dry-run** `out/issue-<date>.misp.json`. Édition 2026-11-01 : 49 attributs.
- **`src/assets.py`** : inventaire depuis `config.json["assets"]` (5 actifs d'exemple : S7-1500, Modicon M340, WinCC, PanelView, passerelle eWON — avec `purdue_level` + `criticality`) + composants du **SBOM CycloneDX** `data/sbom.cdx.json` ; `match_assets()` → `asset_impact` par CVE (CVE-2026-110936 touche `plc-s7-1500` + `scada-wincc`).
- `collect.py` : matching actifs à la collecte + persistance `data/assets.json` ; `store.py` : table `assets`, colonne `cves.assets`, `store_assets()`.
- `server.py` : routes **`/misp`** (dernier événement, `Content-Disposition` inline) et **`/api/assets`** (actifs + carte `impacted` CVE→actifs + niveaux Purdue), payload `/api/data` enrichi (`assets`, `quality`), boutons « 🕸 Export MISP » et « 🌍 العربية ».

## 🔁 v1.10 — lignage, replay hors-ligne, métriques qualité + backups/DR (01/11/2026)
- **Capture raw** : chaque source live est sauvegardée dans `data/raw/<run>/` (fichier sluggué + `manifest.json` : url, fetched_at, bytes — 43 fichiers pour le run 20261101T000347Z).
- **Lignage** : chaque CVE porte `found_by` (`keyword:…` / `cpe:…` / `watchlist …` / `ghsa/otx …`) ; `meta.quality` = {sources, nvd_records, cves_uniques, dup_rate, raw_dir}.
- **`src/replay.py`** : rejoue un run **hors-ligne** depuis `data/raw/<run>/manifest.json` → `data/replay/<run>.json`, **0 appel réseau** (reproductibilité/audit).
- **Backups/DR** : `scripts/backup.sh` → `backups/otwatch-data-<ts>.tar.gz` + symlink `latest.tar.gz` (rétention 30 j backups + raw) ; `scripts/restore.sh <tar> <dest>`.
- `server.py` `/metrics` : 4 nouvelles gauges Prometheus — `otwatch_assets_total`, `otwatch_quality_dup_rate`, `otwatch_quality_sources_total`, `otwatch_raw_files_total`.

## 🏆 v1.14 — plateforme « marché » : ECC 39/39, OpenAPI 3.1, Docker, gouvernance (01/11/2026)
- **harness-audit ECC repo scope 39/39** (rapports : `research/ecc-audit-2026-11-01/`) : plugin ECC installé (`~/.claude/plugins/ecc`), câblage projet `.claude/` — `settings.json` avec **guardrail PreToolUse** (`scripts/claude-hooks/guardrail.sh` bloque `rm -rf /`, `curl|sh`, lecture de credentials…), commandes `/verify` `/collecte` `/audit-ecc`, skill `ot-watch-ops`, `memory.md` — plus `.mcp.json` explicite.
- **Gouvernance GitHub** : PR template, issue templates (bug/feature), `CODEOWNERS` (chemins sécurité → @security), `dependabot.yml` (pip + github-actions hebdo), CI existante (ruff + py_compile + tests + gate couverture ≥ 80 % + grep secrets/dangerous primitives).
- **OpenAPI 3.1** : `docs/openapi.json` (toutes les routes, TAXII, sécurité Bearer) servi par **`/openapi.json`** + bouton « 📖 OpenAPI ».
- **Packaging** : `Dockerfile` (python:3.13-slim, user non-root, HEALTHCHECK), `docker-compose.yml` (volumes data/out/logs, secrets via `.env` gitignoré), `.dockerignore`, `LICENSE` MIT, `CHANGELOG.md`, `CONTRIBUTING.md`.
- tests `test_platform.py` : spec OpenAPI couvre les routes serveur, fichiers plateforme présents, guardrail bloque les commandes dangereuses.

## 📡 v1.13 — collecte réseau PASSIVE OT (Zeek/Suricata+ICSNPP/Malcolm sur SPAN/TAP) (01/11/2026)
- **Runbook** : `research/RUNBOOK-COLLECTE-PASSIVE-OT-2026-11-01.md` — règles d'or (jamais inline, jamais de scan actif), Zeek standalone, Suricata + ET ICSNPP, Malcolm (Docker), ports OT surveillés (502/20000/102/44818/4840/2404/47808), check-list hebdo, procédure incident.
- **`src/netwatch.py`** : parse les `conn.log` Zeek (lecture seule) → `data/netwatch.json` : **actifs OT découverts** (IP responder + services ICS + clients), **anomalies** (nouvel hôte OT, nouveau flux OT vs baseline), stats. Ports surchargeables via `config.json["netwatch"]["ot_ports"]`.
- **`scripts/zeek_to_assets.py`** : convertit les découvertes en propositions d'actifs pour `config.json["assets"]` (qui alimentent ensuite le score OT v1.12).
- Live : route **`/api/netwatch`** (404 tant qu'aucun rapport), `netwatch` dans `/api/data`, gauges `otwatch_netwatch_hosts_ot` / `otwatch_netwatch_anomalies_total`. Étape gardée dans `run_all.sh` (ne s'exécute que si `logs/zeek/conn.log*` existe).

## 🌍 v1.11 — édition arabe RTL (i18n AR) (01/11/2026)
- **`src/render_ar.py`** : édition arabe complète `out/issue-<date>.ar.html` + `.ar.md` — `<html lang="ar" dir="rtl">`, libellés arabe, CSS inline (aucune lib externe), même données que l'édition FR. Route **`/issue.ar`**, bouton « 🌍 العربية ».

## 🌐 En ligne sur GitHub Pages (gratuit)
**https://o-alil-lab.github.io/ot-watch/** — version statique du dashboard, régénérée toutes les 6 h par
`.github/workflows/pages.yml` (collecte → rendu → `scripts/build_static.py` → déploiement Pages).
Newsletter, PDF, STIX, MISP et OpenAPI sont publiés à côté. Les fonctions qui exigent un serveur
(SSE temps réel, re-collecte à la demande, TAXII) restent dans `server.py` / l'image Docker.
Clé NVD optionnelle : secret de dépôt `NVD_API_KEY`.
Déclenchement fiable toutes les 6 h par un Cron Trigger Cloudflare gratuit : `cloudflare/cron-trigger/`.

## 🚀 v1.15 — GitHub + GHCR + Linear, 100 % gratuit (01/11/2026)
Décision et sources : `docs/adr/ADR-2026-11-01-remote-github-linear-ghcr.md`.
```bash
# 1. créer un dépôt PUBLIC vide sur github.com, puis
GITHUB_REPO=<owner>/<repo> ./scripts/github-setup.sh      # DRY_RUN=1 pour simuler
# 2. roadmap -> Linear (dry-run d'abord)
python3 scripts/linear_import.py
LINEAR_API_KEY=... LINEAR_TEAM_ID=... python3 scripts/linear_import.py --apply --only P1
# 3. publier une image (scan Trivy puis push GHCR)
git tag v1.15.0 && git push origin v1.15.0
docker pull ghcr.io/<owner>/<repo>:latest
```
Après le premier push, passez le paquet GHCR en **public** (Package settings) pour un pull sans login.

## Quality gates (boucle de vérification ECC)
```bash
cd /home/user/newsletter-ot
python3 -m py_compile server.py src/*.py agents/*.py tests/*.py      # phase 1 : build
python3 -m ruff check server.py src agents tests --config ruff.toml   # phase 3 : lint
python3 -m coverage run -m unittest discover -s tests # phase 4 : tests
python3 -m coverage report --include="*/src/*,*/server.py,*/agents/*"        # couverture (objectif ECC >= 80 %)
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
