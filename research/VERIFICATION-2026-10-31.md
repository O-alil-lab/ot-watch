# Rapport de vérification ECC — OT Watch (verification-loop, 31/10/2026)

Date : 2026-10-31 · Périmètre : `/home/user/newsletter-ot` (src, tests, config, editorial) + harnais ECC installé (`/home/user/.claude`, `.codex`, `.config/opencode`, `.cursor`)

## Phase 1 — Build ✅ PASS
`python3 -m py_compile src/collect.py src/render.py tests/*.py` → OK (Python 3.13)

## Phase 2 — Type check ✅ PASS (équivalent)
Pas de typage statique externe ; le build + la suite de tests typées (fixtures NVD/CVE) couvrent les contrats. (pyright non installé dans le sandbox ; py_compile + tests OK.)

## Phase 3 — Lint ✅ PASS
`ruff check src tests --config ruff.toml` → **All checks passed** (E,F,W,I,UP,SIM,BLE,RUF ; E501/EXE001/BLE001 ignorés avec justification documentée dans `ruff.toml`)

## Phase 4 — Tests + couverture ✅ PASS (objectif ECC ≥ 80 %)
`coverage run -m unittest discover -s tests` → **23 tests, 0 échec**
- `src/collect.py` : **86 %**
- `src/render.py` : **97 %**
- **TOTAL : 91 %**
Couverture sécurité : XSS (script/img-onerror/javascript: neutralisés), filtre faux positifs NVD (« Datalex PLC » rejeté), parsing RSS CISA, filtre KEV (« Graphics » ne matche pas `\bics\b`), pipeline collect→render mocké de bout en bout.

## Phase 5 — Security grep ✅ PASS
- Aucun secret hardcodé (`api_key|secret|token|password = "..."` → 0 hit ; seul hit = docstring `__pycache__`)
- Aucune primitive dangereuse (`eval(`, `exec(`, `shell=True`, `os.system`, `pickle`, `subprocess` → 0 hit)
- `NVD_API_KEY` lu **uniquement** via `os.environ.get` (jamais en dur) ; `.gitignore` couvre `.env`, `*.key`, `data/`, `__pycache__`
- Durcissement XSS du rendu : `html.escape(quote=True)` + `safe_url()` (schemes autorisés : http/https/mailto uniquement) sur toutes les données externes (NVD/CISA/KEV) et les liens éditoriaux — prouvé par tests.

## Phase 6 — AgentShield (ECC security-scan) + doctor ✅ PASS avec 1 faux positif revu
- `npx ecc-agentshield scan --path /home/user/newsletter-ot` → 0 finding (plateforme Python autonome, pas de config agent)
- `npx ecc-agentshield scan --path /home/user/.claude` → 200 fichiers scannés : **0 critical, 1 high, 104 medium, 48 low, 7 info**
  - Le **1 high** est un **faux positif revu** : `agents/ruby-reviewer.md:55` contient « skip validations » dans une checklist Ruby on Rails (vocabulaire ActiveRecord : `update_all` « skip validations and callbacks »), pas une instruction de contourner la vérification de skills.
  - Les medium/low sont des notes de design ECC (hooks lisant le transcript — comportement normal des hooks Stop/SessionEnd ; absence de bloc `permissions` dans settings.json, etc.). Aucune action bloquante.
- `node ecc/scripts/doctor.js` → **checked=5, ok=5, warnings=0, errors=0**

## Hardening appliqué pendant la revue
1. `render.py` : `safe_url()` anti-`javascript:`/`data:` + échappement `quote=True` + `with open(...)` partout.
2. `collect.py` : filtre anti-faux-positifs OT (`_is_ot`) + gestion rate-limit NVD (403/429 → pause 30 s, 5 tentatives) + watchlist CVE par `cveId` + context managers.
3. `tests/` : 23 tests unitaires + intégration (réseau mocké) ; `ruff.toml` ; `.gitignore`.

## Résultat global : ✅ PASS — la plateforme est créée, testée (91 % de couverture) et sécurisée.

---

# Addendum v1.1 — quick wins P0 implémentés (31/10/2026, ~23:00 UTC)

| # | Quick win | Statut | Preuve |
|---|---|---|---|
| 1 | Filtre NVD par CPE éditeurs (`virtualMatchString=cpe:2.3:*:<vendor>:*`) | ✅ | collecte v2 : 22 CVE (vs 19), CPE `siemens`, `schneider-electric`, `rockwell_automation`, `abb`… |
| 2 | Validation qualité (schéma CVE/CVSS/liens + alerte chute de volume >30 %) | ✅ | `src/validate.py`, 92 % couvert, `meta.validation.ok=true` sur la collecte v2 |
| 3 | SQLite + détection nouveautés (`data/otwatch.db`, diff par run) | ✅ | `src/store.py` 100 % couvert, run #4 : 22 nouvelles CVE détectées |
| 4 | Score de risque composite CVSS+KEV+**EPSS (FIRST)** | ✅ | EPSS enrichi 22/22 ; tri par risque ; CVE-2026-110936 ★KEV classée #1 |
| 5 | Token admin (`OTWATCH_ADMIN_TOKEN`) sur `POST /api/refresh` + en-têtes sécurité (CSP, nosniff, DENY, no-referrer) + rate-limit 1/60 s | ✅ | tests 401/429 OK ; headers vérifiés en live (curl) |
| 6 | `/metrics` Prometheus + indicateur STALE (SLO fraîcheur = 2×intervalle) | ✅ | `curl /metrics` → `otwatch_up 1`, `otwatch_stale 0`, `otwatch_data_freshness_seconds 256`… |
| 7 | CI GitHub Actions (ruff + py_compile + 45 tests + gate couverture ≥80 % + grep secrets) | ✅ | `.github/workflows/ci.yml` |
| 8 | gitleaks pre-commit + `SECURITY.md` | ✅ | `.gitleaks.toml`, `scripts/pre-commit` installé dans `.git/hooks`, `SECURITY.md` |

**Résultat boucle ECC après v1.1** : ruff 0 erreur · **45/45 tests OK** · couverture **87 %** (store 100 %, validate 92 %, render 96 %, collect 89 %, server 68 %) · collecte réelle v2 terminée en 222 s · serveur live redémarré (port 8000) avec toutes les nouvelles routes vérifiées en curl.

---

# Addendum v1.2 — SSE push + alerting (31/10/2026, ~23:10 UTC)

| Amélioration P1 | Statut | Preuve |
|---|---|---|
| SSE `/api/stream` (push instantané, keepalive 25 s, fallback polling) | ✅ | test socket réel (test_sse.py) + `curl -N /api/stream` → `data: {"type":"connected"}` en live |
| Broadcast après chaque collecte (`run_collect` → `broadcast`) | ✅ | événement `collected` avec diff/counts reçu par les clients connectés |
| Alerting nouvelles CVE CRITICAL/KEV/risque≥7 + nouveau KEV | ✅ | `src/alerts.py` : webhook JSON / Slack / SMTP (env uniquement), dry-run JSONL par défaut ; tests mockés (webhook appelé, payload OK) |
| Dashboard : EventSource + toast « 🆕 +N CVE » | ✅ | `EventSource('/api/stream')` présent dans la page servie |

**Boucle ECC v1.2** : ruff 0 erreur · **52/52 tests OK** · couverture **83 %** · serveur live v3 redémarré (port 8000), SSE vérifié en curl.

---

# Addendum v1.3 — profil d'exposition « Mes actifs OT » + historique visuel (01/11/2026, ~00:15 UTC)

| Amélioration P1 | Statut | Preuve |
|---|---|---|
| Profil d'exposition `config.exposure.keywords` (~40 mots-clés OT) → `c.relevant`, tri relevant-first (newsletter + dashboard + API) | ✅ | collecte v3 réelle : « exposition: 4/22 CVE » ; `/api/data` live : 4 `relevant:true`, top = CVE-2026-110936 (risque 6.23) en #1 |
| Filtre dashboard « ⭐ Mes actifs OT » + badges ⭐ + tri client (relevant, risque) | ✅ | `drawChart`, `#bRel`, ⭐ présents dans la page servie (curl) ; 4 ⭐ dans `out/issue-2026-10-31.html` |
| Historique SQLite 30 j `store.history_daily()` + `GET /api/history` + graphique SVG inline (3 séries) | ✅ | `/api/history` live → 30 points (9 non nuls) ; section « 📈 Tendances » servie ; migration `relevant` testée |
| Correction métriques `/metrics` (`kev_ot`/`advisories` vs clés `counts`) | ✅ | `curl /metrics` → `otwatch_kev_ot_total 13`, `otwatch_advisories_total 5` |

**Boucle ECC v1.3** : ruff 0 erreur · **59/59 tests OK** · couverture **84 %** (store 100 %, render 97 %, collect 90 %, validate 92 %, server 70 %, alerts 62 %) · collecte réelle v3 terminée en 227,6 s (run #9, 22 CVE, EPSS 22/22) · serveur live v4 redémarré sur 0.0.0.0:8000 — `/api/history`, `/api/data` (relevant), `/api/stream` (SSE `connected`), en-têtes sécurité et `/metrics` vérifiés en curl.

---

# Addendum v1.4 — export PDF de l'édition (01/11/2026, ~23:20 UTC)

| Amélioration | Statut | Preuve |
|---|---|---|
| `src/render_pdf.py` (fpdf2 + DejaVu TTF) → `out/issue-<date>.pdf` A4, 6 pages, 68 Ko | ✅ | `python3 src/render_pdf.py` OK ; pypdf : 6 pages, « OT Watch », CVE-2026-110936, « Tendances 30 jours », ◆ 4 actifs OT présents |
| Sparkline 30 j dans le PDF (store.history_daily) + résumé « En bref » + tableau CVE (sévérité colorée, ★KEV, ◆OT) | ✅ | texte extrait vérifié ; glyphes testés via cmap (★ ☠ ⚠ ✓ ◆ ● →) |
| Route live `GET /issue.pdf` (`application/pdf`, Content-Disposition inline, en-têtes sécurité) + bouton dashboard | ✅ | curl -D- → 200, 68282 o, `filename="issue-2026-10-31.pdf"`, nosniff/DENY ; `issue.pdf` présent dans `/` |
| Pipeline : `requirements.txt` (fpdf2>=2.8), install idempotent dans `run_all.sh`, étape CI `pip install -r requirements.txt` | ✅ | run_all.sh + ci.yml modifiés ; test_pdf.py |

**Boucle ECC v1.4** : ruff 0 erreur · **63/63 tests OK** · couverture **82 %** (store 100 %, render 97 %, collect 90 %, validate 92 %, render_pdf 78 %, server 68 %, alerts 62 %) · serveur live v5 redémarré (0.0.0.0:8000) — `/issue.pdf`, `/api/history`, `/api/stream` vérifiés en curl.
