#!/usr/bin/env bash
# OT Watch — pipeline complet : collecte automatique puis rendu de la newsletter.
# Prêt pour cron, ex. hebdomadaire le lundi à 07:00 :
#   0 7 * * 1  cd /home/user/newsletter-ot && ./run_all.sh >> out/cron.log 2>&1
set -euo pipefail
cd "$(dirname "$0")"

# NVD_API_KEY (optionnel) : lève le rate limit de l'API NVD (5 req/30s -> 50 req/30s)
# export NVD_API_KEY="..."  # clé NVD optionnelle (placeholder)

python3 src/collect.py
python3 src/render.py

# deps runtime (fpdf2 pour le PDF) — install idempotent si absent
python3 -c "import fpdf" 2>/dev/null || pip install --quiet -r requirements.txt
python3 src/render_pdf.py

echo "[run_all] dernière édition :"
ls -t out/issue-*.html | head -1
ls -t out/issue-*.pdf | head -1
