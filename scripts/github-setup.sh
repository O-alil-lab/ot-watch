#!/usr/bin/env bash
# Branche le dépôt local sur GitHub : remote origin, branche main, push initial.
# Usage : GITHUB_REPO=<owner>/<repo> ./scripts/github-setup.sh
# Prérequis : dépôt vide créé sur github.com (public recommandé : Actions + GHCR gratuits),
#             authentification git HTTPS ou SSH déjà configurée. Aucun secret lu ici.
set -euo pipefail

if [[ -z "${GITHUB_REPO:-}" ]]; then
  echo "erreur : définissez GITHUB_REPO=<owner>/<repo> (ex. GITHUB_REPO=O-alil-lab/ot-watch)" >&2
  exit 1
fi
if [[ ! "$GITHUB_REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "erreur : GITHUB_REPO invalide : '$GITHUB_REPO' (attendu owner/repo)" >&2
  exit 1
fi

proto="${GITHUB_PROTO:-https}"
if [[ "$proto" == "ssh" ]]; then
  url="git@github.com:${GITHUB_REPO}.git"
else
  url="https://github.com/${GITHUB_REPO}.git"
fi

cd "$(dirname "$0")/.."
git rev-parse --git-dir >/dev/null

if [[ -n "$(git status --porcelain)" ]]; then
  echo "erreur : arbre de travail non propre — committez d'abord (git status)." >&2
  exit 1
fi

if git remote get-url origin >/dev/null 2>&1; then
  current="$(git remote get-url origin)"
  if [[ "$current" != "$url" ]]; then
    echo "erreur : origin pointe déjà vers $current (attendu $url). Corrigez-le à la main." >&2
    exit 1
  fi
else
  git remote add origin "$url"
fi

git branch -M main
if [[ "${DRY_RUN:-0}" == "1" ]]; then
  echo "[dry-run] git push -u origin main  -> $url"
  exit 0
fi
git push -u origin main
git push origin --tags
echo "OK : $url — ouvrez https://github.com/${GITHUB_REPO}/actions pour suivre CI et Docker."
