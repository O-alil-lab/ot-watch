#!/usr/bin/env bash
# OT Watch — pipeline complet : collecte automatique puis rendu de la newsletter.
# Prêt pour cron, ex. hebdomadaire le lundi à 07:00 :
#   0 7 * * 1  cd /home/user/newsletter-ot && ./run_all.sh >> out/cron.log 2>&1
set -euo pipefail
cd "$(dirname "$0")"

# NVD_API_KEY (optionnel) : lève le rate limit de l'API NVD (5 req/30s -> 50 req/30s)
# export NVD_API_KEY="votre-cle-nvd"

python3 src/collect.py
python3 src/render.py

echo "[run_all] dernière édition :"
ls -t out/issue-*.html | head -1
