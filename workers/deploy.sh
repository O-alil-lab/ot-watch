#!/usr/bin/env bash
# Déploie OT Watch LIVE sur Cloudflare (free tier). Requis en env :
#   CLOUDFLARE_API_TOKEN  (API token avec Workers:Edit — Settings > API Tokens)
#   CLOUDFLARE_ACCOUNT_ID
# Puis : npx wrangler deploy  (depuis workers/)
set -euo pipefail
cd "$(dirname "$0")"
: "${CLOUDFLARE_API_TOKEN:?définir CLOUDFLARE_API_TOKEN}"
: "${CLOUDFLARE_ACCOUNT_ID:?définir CLOUDFLARE_ACCOUNT_ID}"
# 1) ressources si pas encore créées (idempotent) :
#    npx wrangler d1 create otwatch            -> copier database_id dans wrangler.toml
#    npx wrangler kv namespace create OTWATCH   -> copier id dans wrangler.toml
#    npx wrangler r2 bucket create otwatch-out
#    npx wrangler d1 migrations apply otwatch --local=false  (ou wrangler d1 execute ... --file=migrations/0001_init.sql)
# 2) secrets runtime (une seule fois) :
#    npx wrangler secret put OTWATCH_ADMIN_TOKEN
#    npx wrangler secret put OTWATCH_TAXII_TOKEN   # optionnel
#    npx wrangler secret put OTWATCH_MISP_URL / OTWATCH_MISP_AUTHKEY / NVD_API_KEY  # optionnel
# 3) deploy :
npx --yes wrangler deploy
echo "✅ LIVE sur https://otwatch-live.<votre-sous-domaine>.workers.dev  (ou domaine perso via dashboard)"
