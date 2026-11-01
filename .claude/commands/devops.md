---
description: Brancher le dépôt sur la stack gratuite GitHub + Linear + GHCR
---
Suis `docs/adr/ADR-2026-11-01-remote-github-linear-ghcr.md` :
1. Vérifie que `GITHUB_REPO` (owner/repo) est fourni ; sinon demande-le. Puis `./scripts/github-setup.sh`.
2. Linear : `python3 scripts/linear_import.py` (dry-run) ; n'utilise `--apply` qu'avec l'accord explicite de l'utilisateur et `LINEAR_API_KEY`/`LINEAR_TEAM_ID` en env.
3. Image : un tag `vX.Y.Z` poussé déclenche `.github/workflows/docker.yml` → `ghcr.io/<owner>/ot-watch`.
Ne pousse jamais en `--force` et ne lis jamais `.env`.
