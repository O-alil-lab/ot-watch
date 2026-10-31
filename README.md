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
