#!/usr/bin/env bash
# OT Watch — backup data/ (P2 DR) : snapshot tar.gz horodaté + rétention 30 jours.
# Usage : scripts/backup.sh [SRC_DATA_DIR] [BACKUP_DIR]
#   SRC_DATA_DIR par défaut : <repo>/data   BACKUP_DIR : <repo>/backups
# cron ex. : 15 3 * * *  cd /home/user/newsletter-ot && scripts/backup.sh >> out/cron.log 2>&1
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${1:-$ROOT/data}"
DST="${2:-$ROOT/backups}"
mkdir -p "$DST"
TS="$(date -u +%Y%m%dT%H%M%SZ)"

# rétention : supprime les backups > 30 jours
find "$DST" -name 'otwatch-data-*.tar.gz' -mtime +30 -delete 2>/dev/null || true
# rétention raw : supprime les runs raw > 30 jours
find "$SRC/raw" -maxdepth 1 -type d -mtime +30 -exec rm -rf {} + 2>/dev/null || true

tar -czf "$DST/otwatch-data-$TS.tar.gz" -C "$SRC" .
# garde aussi une copie « latest » pratique pour le restore
ln -sf "otwatch-data-$TS.tar.gz" "$DST/latest.tar.gz"
echo "[backup] $DST/otwatch-data-$TS.tar.gz ($(du -h "$DST/otwatch-data-$TS.tar.gz" | cut -f1)) — rétention 30 j"
