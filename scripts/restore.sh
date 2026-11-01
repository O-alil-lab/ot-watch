#!/usr/bin/env bash
# OT Watch — restore depuis un backup (P2 DR).
# Usage : scripts/restore.sh [BACKUP_TARBALL] [DEST_DATA_DIR]
#   défaut : backups/latest.tar.gz -> <repo>/data   (écrase data/ : arrêt recommandé)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARBALL="${1:-$ROOT/backups/latest.tar.gz}"
DEST="${2:-$ROOT/data}"
[ -f "$TARBALL" ] || { echo "[restore] archive introuvable: $TARBALL"; exit 1; }
mkdir -p "$DEST"
tar -xzf "$TARBALL" -C "$DEST"
echo "[restore] $TARBALL -> $DEST ($(ls "$DEST" | tr '\n' ' '))"
