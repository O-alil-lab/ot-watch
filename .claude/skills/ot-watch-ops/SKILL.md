---
name: ot-watch-ops
description: Opérer OT Watch — collecte, rendu, serveur, gates qualité, publication GHCR. Utiliser pour toute tâche d'exploitation de ce dépôt.
---
# OT Watch — exploitation

- Collecte + rendu : `./run_all.sh` (réseau requis ; sources dégradées signalées dans `data/meta.json`).
- Rejeu hors-ligne : `python3 src/replay.py` depuis `data/raw/`.
- Serveur : `OTWATCH_HOST=0.0.0.0 python3 server.py` ; santé `GET /api/meta`, métriques `GET /metrics`.
- Gates : commande `/verify`.
- Publication image : tag `vX.Y.Z` → workflow `docker.yml` (Trivy CRITICAL/HIGH bloquant) → GHCR.
- Sauvegarde / restauration : `scripts/backup.sh`, `scripts/restore.sh`.
- Règles : secrets en env uniquement ; collecte OT passive uniquement ; édition IA soumise à relecture humaine (AI Act art. 50).
