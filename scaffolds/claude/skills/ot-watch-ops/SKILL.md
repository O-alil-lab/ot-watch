---
name: ot-watch-ops
description: Opérations OT Watch — collecte, serveur live, exports standards, DevOps gratuit (GitHub/Linear/GHCR/Cloudflare), conformité.
---
- Pipeline : `./run_all.sh` ; serveur local `python3 server.py` (0.0.0.0:8000) ; Cloudflare free : `workers/` (wrangler.toml + otwatch_worker.py, cron 6 h, D1/KV/R2).
- Routes : /, /api/data, /api/history, /api/meta, /api/stream (SSE), /api/refresh (Bearer), /metrics, /issue(.pdf/.ar), /stix, /misp, /api/assets, /api/netwatch, /taxii2/*, /openapi.json.
- DevOps : scripts/github-setup.sh, scripts/linear_import.py, .github/workflows/docker.yml (GHCR), .github/workflows/deploy-cloudflare.yml.
- Sécurité : secrets env uniquement, guardrail .claude/settings.json, en-têtes sécurité serveur, bind 0.0.0.0, URLs relatives navigateur.
- Conformité : revue humaine + divulgation IA (AI Act Art. 50), images SVG data-driven.
- Gates : /verify (ruff + tests + couv >= 80 % + secrets + harness-audit 39/39).
