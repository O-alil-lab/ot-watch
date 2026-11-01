#!/usr/bin/env bash
# Configure le remote GitHub « origin » et pousse la branche principale.
# AUCUN secret requis ici : le push utilise vos credentials git existants
# (credential helper, SSH, ou gh auth login).
#
# Usage :
#   GITHUB_REPO=<owner>/<repo> ./scripts/github-setup.sh           # ex. GITHUB_REPO=acme/ot-watch
#   GITHUB_REPO=acme/ot-watch BRANCH=main ./scripts/github-setup.sh
#
# Pré-requis : le dépôt existe déjà sur github.com (créé à la main ou via API),
#   public recommandé (Actions illimité, CODEOWNERS actif, image GHCR publique).
set -euo pipefail
cd "$(dirname "$0")/.."

REPO="${GITHUB_REPO:-}"
BRANCH="${BRANCH:-main}"
[ -n "$REPO" ] || { echo "ERREUR: définir GITHUB_REPO=<owner>/<repo> (ex. GITHUB_REPO=acme/ot-watch)" >&2; exit 2; }
case "$REPO" in */*) ;; *) echo "ERREUR: GITHUB_REPO doit être <owner>/<repo>" >&2; exit 2;; esac

echo "[github-setup] remote origin -> https://github.com/${REPO}.git"
git remote remove origin 2>/dev/null || true
git remote add origin "https://github.com/${REPO}.git"

echo "[github-setup] branche principale -> ${BRANCH}"
git branch -M "$BRANCH"

echo "[github-setup] push -u origin ${BRANCH} (utilisez vos credentials GitHub si demandés)"
git push -u origin "$BRANCH"

echo "[github-setup] push des tags"
git push origin --tags || true

cat <<EOF

✅ Remote branché. Prochaines étapes (voir docs/adr/ADR-2026-11-01-remote-github-linear-ghcr.md) :
1. Sur github.com/${REPO} : Settings → Actions → "Allow all actions" ; branche ${BRANCH} protégée (require PR + CI green).
2. Secrets optionnels (Settings → Secrets → Actions) : OTWATCH_ADMIN_TOKEN, OTWATCH_MISP_URL/AUTHKEY,
   OTWATCH_TAXII_TOKEN, NVD_API_KEY — JAMAIS dans le dépôt.
3. Linear : Settings → Integrations → GitHub → connecter ; puis
   LINEAR_API_KEY=... LINEAR_TEAM_ID=... python3 scripts/linear_import.py   (dry-run par défaut)
4. Taggez une release : git tag v1.15.0 && git push origin v1.15.0
   → .github/workflows/docker.yml publie ghcr.io/${REPO%%/*}/ot-watch:v1.15.0 (GITHUB_TOKEN, aucun PAT)
5. Pull public : docker pull ghcr.io/${REPO%%/*}/ot-watch:latest
EOF
