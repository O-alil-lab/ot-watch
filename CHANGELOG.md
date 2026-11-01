# CHANGELOG — OT Watch

Format : Keep a Changelog. Versions sémantiques (vMAJEUR.MINEUR).

## v1.19 — 2026-11-01 — fusion des deux branches v1.15+
- Réunit l'archive v1.18 (i18n EN/AR, agents data-grounded, growth/SEO, worker Cloudflare, monétisation éthique) et la branche publiée sur GitHub (GitHub Pages, cron Cloudflare, correctifs TAXII/port/Docker, jeu de données de test figé).
- Site statique GitHub Pages : ajoute l'édition anglaise (`issue.en.html`) et le flux RSS (`feed.xml`) ; les routes qui exigent un serveur (abonnement, stats, intégration) restent sur `server.py` / Docker / worker Cloudflare.

## v1.18 — 2026-11-01 — acquisition (trafic) & monétisation éthique
- **Growth** (`src/growth.py` + routes) : `/feed.xml` (RSS 2.0), `/sitemap.xml`, `/robots.txt`, `/integrate` (snippets TAXII/STIX/MISP/webhook + communautés OT), `/stats` (chiffres publics sans tracking), `/subscribe` + `/unsubscribe` (e-mail/webhook, stockage local, dédup, aucun cookie), `/api/subscribers`, formulaire 🔔 sur le dashboard.
- **SEO** : hreflang FR/AR/EN + canonical + Open Graph + JSON-LD injectés dans `/issue`, `/issue.ar`, `/issue.en` (base = OTWATCH_BASE_URL ou Host) ; 8 nouvelles routes documentées dans `docs/openapi.json`.
- **Monétisation éthique** : `FUNDING.yml`, `docs/MONETIZATION.md` (dons Sponsors/Open Collective/Ko-fi ; grants NLnet/NGI ≤50 k€, OpenSSF Alpha-Omega, EU CEF ; services payants autour du gratuit : hébergement managé, SLA, rapports NIS2/CRA, formations ; **jamais** de pub/tracking/vente de données) et `docs/COMMUNITY.md` (ISAGCA, ICS Village, OT-ISAC, FIRST, MISP, S4x/ISA ; checklist awesome-lists ; modèle de talk).
- ECC consulté le 01/11/2026 ~21:56 (trafic + monétisation).
- Tests : +12 -> **156/156 OK** · ruff clean · couverture 80 % · harness-audit 0 failing.

## v1.17 — 2026-11-01 — i18n AR corrigé (bidi/RTL) + édition EN + rédaction agents data-grounded
- `src/render_ar.py` : isolation bidi (`<bdi>` + `dir="ltr"`) des IDs CVE, CVSS, risque, dates ; descriptions en `dir="auto"` ; pile de polices arabe système (`Noto Naskh Arabic`, Tahoma…) sans ressource externe ; line-height 1.6.
- **Édition EN** : `src/render_en.py` (out/issue-<date>.en.html/.md, `lang="en" dir="ltr"`), route `/issue.en` (server.py + worker Cloudflare `_render_min_en` + R2), bouton 🇬🇧 sur le dashboard, étape `run_all.sh`, entrée OpenAPI.
- Worker : coquille « ال edition » corrigée en « إصدار », cellules CVE/CVSS en `dir="ltr"` isolé.
- `agents/rag.py` : brief enrichi (ot_score, ot_score_detail, asset_impact, ssvc_detail, vector, cwes, new_kev_facts), sources dédupliquées NVD/KEV/FIRST/ATT&CK.
- `agents/writer.py` : guide éditorial fixe, section « impact OT » 100 % calculée depuis les données (KEV/SSVC/actifs/Purdue/ATT&CK/score OT), dédup descriptions, `lang=fr|en`, divulgation AI Act art. 50 bilingue, LLM optionnel toujours re-vérifié (anti-hallucination + HITL).
- `agents/pipeline.py` : brouillon produit article.md + article.en.md avec fact-check des deux.
- Tests : 144/144 OK (AR bidi, EN, worker, writer EN, brief OT) · ruff clean · couverture 80 % · harness-audit 0 failing.

## v1.16 — 2026-11-01 — déploiement LIVE Cloudflare free tier
- `workers/` (wrangler.toml + otwatch_worker.py + migrations + deploy.sh), `docs/deploy/CLOUDFLARE-FREE-TIER-2026-11-01.md`, workflow `deploy-cloudflare.yml`, tests `test_cloudflare_deploy.py`.

## v1.16b — 2026-11-01 — OT Watch en ligne sur GitHub Pages (branche parallèle)
- `scripts/build_static.py` : dashboard statique (chemins relatifs, snapshots `api/data.json` / `api/history.json`), newsletter HTML/PDF/AR, STIX, MISP, OpenAPI.
- `.github/workflows/pages.yml` : collecte toutes les 6 h, données conservées via le cache Actions (historique 30 j), garde-fou anti-collecte vide, déploiement GitHub Pages.
- Tests `test_static_site.py`.

## v1.15 — 2026-11-01 — stack DevOps gratuite (GitHub + GHCR + Linear)
- ADR `docs/adr/ADR-2026-11-01-remote-github-linear-ghcr.md` (offres gratuites vérifiées sur sources primaires).
- `.github/workflows/docker.yml` : job `scan` lecture seule (Trivy v0.35.0, CRITICAL/HIGH bloquant ; versions ≤ v0.34.2 compromises, CVE-2026-33634) puis job `push` GHCR via `GITHUB_TOKEN`.
- `scripts/github-setup.sh` (remote + push, garde-fous, `DRY_RUN=1`) ; `scripts/linear_import.py` (roadmap → Linear, dry-run par défaut, idempotent, plafond Free).
- Restauration `.claude/` (settings + guardrail, commandes /verify /collecte /audit-ecc /devops, skill ot-watch-ops) et `.github/` (PR/issue templates, CODEOWNERS, dependabot pip/actions/docker).
- Correctif TAXII : discovery et collections répondent sans bundle généré ; `out/` absent ne lève plus d'exception.
- CI : lint étendu à `scripts/`, `pyyaml` pour les tests de workflow. Tests `test_devops_wiring.py`.

## v1.14 — 2026-11-01 — plateforme « marché » (ECC 39/39, packaging, OpenAPI)
- harness-audit ECC repo scope **39/39** : plugin ECC installé (~/.claude/plugins/ecc), `.claude/` projet (settings.json + guardrail PreToolUse, commands /verify /collecte /audit-ecc, skill ot-watch-ops, memory.md), `.mcp.json`, `.github/` (PR template, issue templates, CODEOWNERS, dependabot pip+actions).
- `docs/openapi.json` + route **`/openapi.json`** + bouton dashboard.
- `Dockerfile` + `docker-compose.yml` + `.dockerignore` ; `LICENSE` MIT, `CONTRIBUTING.md`.
- tests `test_platform.py` (spec OpenAPI vs routes serveur, fichiers plateforme présents).

## v1.13 — 2026-11-01 — collecte passive OT
- Runbook `research/RUNBOOK-COLLECTE-PASSIVE-OT-2026-11-01.md` (SPAN/TAP, Zeek, Suricata+ICSNPP, Malcolm ; jamais inline, jamais de scan actif).
- `src/netwatch.py` (conn.log Zeek → actifs découverts + anomalies → data/netwatch.json), `scripts/zeek_to_assets.py`, `/api/netwatch`, gauges netwatch, étape gardée run_all.sh.

## v1.9–v1.12 — 2026-11-01 — P2 « tout » + score OT
- v1.9 export MISP (`/misp`, dry-run ou push OTWATCH_MISP_URL/AUTHKEY) + inventaire actifs/SBOM CycloneDX (`/api/assets`).
- v1.10 capture raw + manifest, lignage found_by, meta.quality, replay hors-ligne (`src/replay.py`), backups/DR 30 j, gauges qualité/raw.
- v1.11 édition arabe RTL (`/issue.ar`).
- v1.12 score OT exposition × Purdue × criticité (+safety/+KEV/+SSVC), colonne cves.ot_score, badge OT FR/AR + dashboard, gauges impacted/max.

## v1.8 — 2026-11-01 — serveur TAXII 2.1 read-only (`/taxii2/*`, collection `otwatch-ot-cves`, added_after, 405 POST, Bearer optionnel)
## v1.7 — 2026-10-31 — pipeline agents IA éditoriaux (HITL, AI Act art. 50)
## v1.6 — 2026-10-31 — collecte élargie (CISA ICS advisories, GHSA, OTX optionnel)
## v1.5 — 2026-10-31 — STIX 2.1 + ATT&CK for ICS + SSVC
## v1.4 — 2026-10-31 — export PDF
## v1.3 — 2026-10-31 — profil d'exposition + historique 30 j
## v1.2 — 2026-10-31 — SSE + alerting webhook/Slack/SMTP
## v1.1 — 2026-10-31 — quick wins P0 ECC (CPE NVD, EPSS, validation, SQLite, sécurité serveur, /metrics, CI)
