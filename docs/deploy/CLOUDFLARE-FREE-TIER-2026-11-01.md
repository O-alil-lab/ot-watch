# ☁️ Déployer OT Watch LIVE sur Cloudflare — 100 % free tier (2026-11-01)

**Réponse : OUI**, avec une architecture adaptée. Python Workers est **GA depuis le 21/09/2026** (Pyodide), donc le code Python d'OT Watch tourne nativement sur Workers, avec bindings D1/R2/KV natifs.

## Limites free tier 2026 (vérifiées 01/11/2026, sources developers.cloudflare.com + freetier.co)

| Ressource | Free tier | Conséquence pour OT Watch |
|---|---|---|
| Workers requests | **100 000/jour** (compte entier, reset 00:00 UTC, sinon erreur 1027) | OK pour un dashboard de veille perso/équipe |
| CPU par requête HTTP | **10 ms** (le temps d'attente réseau/fetch ne compte PAS) | handlers en lecture D1/KV/R2 restent < 10 ms ; ne JAMAIS parser de gros XML dans une requête HTTP |
| Wall time requête HTTP | **illimité** tant que le client reste connecté ; `waitUntil` 30 s | SSE `/api/stream` OK (streaming natif, pas de limite de durée) |
| Subrequests | **50/requête**, 6 connexions sortantes simultanées | collecte cron limitée à ~40 fetch (RSS + KEV + NVD par CVE watchlist) |
| Cron triggers | **5/compte**, wall time **15 min** par invocation | 1 cron toutes les 6 h suffit (notre run fait ~8 min en local) |
| Mémoire / taille worker | 128 MB / 64 MiB | OK |
| **D1** (SQLite edge) | 5 Go total (500 Mo/DB, 10 DB), **5M lectures/j**, 100k écritures/j | remplace `data/otwatch.db` — mêmes schémas (`workers/migration/0001_init.sql`) |
| **KV** | 100k lectures/j, **1 000 écritures/j**, 1 Go | payload `/api/data`, `meta.json`, `assets.json` (lecture-heavy = parfait) |
| **R2** | **10 Go**, 1M écritures/mo, 10M lectures/mo, **egress 0 $** | artefacts `out/` (HTML/AR/PDF/STIX/MISP) servis depuis R2 |
| Pages (statique) | sites illimités, bande passante illimitée, 500 builds/mo | alternative : publier `out/` en statique sur Pages |
| Secrets/env | 64 vars × 5 Ko par worker | `wrangler secret put` pour OTWATCH_* |

## Architecture déployée (voir `workers/`)

```
navigateur ──► Worker Python (workers/otwatch_worker.py)  ── lecture ──► D1 (cves/runs) + KV (payload) + R2 (éditions)
                   │  /  /api/*  /issue*  /stix  /misp  /taxii2/*  /metrics  /openapi.json  /api/stream (SSE)
                   ▲
cron Cloudflare ───┘  scheduled() toutes les 6 h : RSS CISA + KEV + NVD(par CVE watchlist)
                        → écrit D1 (upsert cves/runs) + KV (meta/payload) + R2 (issue-latest.html/.ar.html)
```

- **Ce qui marche tel quel en free** : dashboard live, toutes les API en lecture, SSE, TAXII/STIX/MISP/AR/OpenAPI, métriques Prometheus, score OT (lu depuis D1), cron de collecte légère, secrets, domaine `*.workers.dev` ou perso.
- **Ce qu'il faut adapter (déjà fait dans `workers/`)** :
  - SQLite local → **D1** (mêmes tables) ; JSON `data/*.json` → **KV** ; `out/` → **R2**.
  - La collecte HTTP synchrone (8 min, gros `ics-advisories.xml` de 6 Mo) ne tient PAS dans 10 ms CPU → le cron fait une collecte **légère** (RSS ~500 Ko + NVD par CVE + KEV + EPSS, < 50 subrequests) ; le parsing lourd reste côté `run_all.sh` (local/CI/GitHub Actions) qui pousse ensuite les artefacts complets vers R2/D1 via l'API Cloudflare.
  - L'auto-refresh serveur toutes les 30 min → remplacé par le **cron Cloudflare** (4 runs/jour, dans les 5 gratuits).
  - PDF : fpdf2 est pure-Python (compatible Pyodide) mais les fontes DejaVu doivent être embarquées ; en attendant, le PDF complet est servi depuis R2 (poussé par la CI), le worker sert HTML/AR/STIX/MISP nativement.

## Déploiement (5 min, 0 $)

```bash
cd workers/
export CLOUDFLARE_API_TOKEN=... CLOUDFLARE_ACCOUNT_ID=...
npx wrangler d1 create otwatch                 # copier database_id -> wrangler.toml
npx wrangler kv namespace create OTWATCH        # copier id -> wrangler.toml
npx wrangler r2 bucket create otwatch-out
npx wrangler d1 execute otwatch --file=migrations/0001_init.sql --remote
npx wrangler secret put OTWATCH_ADMIN_TOKEN     # optionnel (refresh manuel)
./deploy.sh                                     # = npx wrangler deploy
# → https://otwatch-live.<sous-domaine>.workers.dev
```

CI auto : `.github/workflows/deploy-cloudflare.yml` déploie sur chaque tag `v*.*.*` (secrets GitHub `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`).

## Quand le free tier ne suffit plus
- > 100k req/jour (Error 1027) ou handlers > 10 ms CPU → Workers Paid **5 $/mois** (10M req/mo, 30 s CPU).
- Écritures KV > 1 000/j ou D1 > 100k writes/j → réduire la fréquence du cron.
- Besoin de parser le gros XML CISA en cron → Workers Paid, ou garder la grosse collecte en GitHub Actions (gratuit, repo public) qui pousse vers R2/D1 via API.

## Sources (veille 2026-11-01)
- developers.cloudflare.com/workers/platform/limits — 100k/j, 10 ms CPU, 50 subrequests, 5 crons, wall time illimité en HTTP, cron 15 min, KV/D1/R2 bindings.
- blog.cloudflare.com + creuto.com/exlever — **Python Workers GA 21/09/2026**, Pyodide, FastAPI/Django natifs, PEP 783 PyEmscripten, bindings natifs D1/R2/KV/Queues, free tier 100k req/jour compatible Python.
- freetier.co / aidevhub.net — D1 free 5 Go/5M reads/j/100k writes/j ; KV 100k reads/j, 1k writes/j, 1 Go ; R2 10 Go, egress 0 $ ; Pages illimité en statique.
- developers.cloudflare.com/agents — SSE natif, pas de limite de durée, streaming non caché.
