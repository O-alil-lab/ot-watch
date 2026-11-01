# ADR-2026-11-01 — Remote Git, PR/Linear et registre d'images : la meilleure stack 100 % gratuite (2026)

**Statut** : accepté · **Date** : 2026-11-01 · **Décideurs** : OT Watch
**Contexte** : brancher un vrai remote GitHub (PR + CI), suivi Linear, et pousser l'image Docker sur un registre gratuit. Recherche menée avec ECC (`ecc consult`) + veille web 2026 (sources en bas).

## Décision

| Besoin | Choix retenu | Pourquoi (gratuit, 2026) |
|---|---|---|
| Remote Git + PR | **GitHub.com** (`owner/ot-watch`, repo public ou privé — les deux gratuits) | Free = dépôts publics **et** privés illimités, collaborateurs illimités ; PR gratuites ; CODEOWNERS appliqué gratuitement sur dépôt **public** ; Actions **illimité** sur dépôt public (2 000 min/mo sur privé + 500 Mo) [1][2][3] |
| CI | **GitHub Actions** (déjà en place : `.github/workflows/ci.yml`) + nouveau `docker.yml` | runners Linux gratuits et sans plafond sur repo public ; `GITHUB_TOKEN` automatique (1 000 req API/h) [1][3] |
| Suivi projet / issues | **Linear Free** | 0 $ : membres illimités, 250 issues actives, 2 équipes, **intégration GitHub incluse dès le gratuit** (branche `OTW-123-…`, PR liée auto, statut déplacé à l'open/merge de la PR), API GraphQL complète [4][5][6] |
| Registre Docker | **GHCR** (`ghcr.io/<owner>/otwatch`) en primaire | images **publiques illimitées** (stockage + bande pass illimités) ; push depuis Actions **sans aucun secret** via `secrets.GITHUB_TOKEN` + `permissions: packages: write` [7][8][9] |
| Miroir optionnel | Docker Hub (public) | découvrabilité maximale ; *rate limits* 100 pulls/6 h anonyme / 200 authentifié → on ne s'y appuie pas pour la prod ; programme OSS Sponsored supprime les limites [10][11] |

**Rejetés** : GitLab.com Free (registre généreux mais 400 min CI/mo, 5 users max, projet séparé) [2][11] · Quay.io (scan Clair gratuit mais **0 repo privé** en gratuit) [10][11] · Oracle OCI Always-Free (20 Go mais signup lourd) [11] · Scaleway CR 75 Go (bon plan B européen) [12] · Harbor self-hosted (gratuit mais infra à gérer).

## Conséquences

- Le build/push Docker se fait **uniquement sur les runners Actions** (pas de docker local requis) : `.github/workflows/docker.yml`.
- Aucun PAT requis : `GITHUB_TOKEN` suffit pour GHCR. Un PAT fine-grained (`packages:write`) n'est utile que pour un push manuel hors Actions [7][8].
- Secrets à créer côté GitHub (Settings → Secrets) : uniquement les optionnels d'OT Watch (`OTWATCH_ADMIN_TOKEN`, `OTWATCH_MISP_URL/AUTHKEY`, `OTWATCH_TAXII_TOKEN`, `NVD_API_KEY`) — jamais commités.
- Linear : clé API perso (`LINEAR_API_KEY`, header `Authorization: <clé>` sans préfixe Bearer) + `LINEAR_TEAM_ID`, uniquement côté `scripts/linear_import.py` (env, jamais en dur) [13][14].

## Mise en œuvre (check-list)

1. Créer le dépôt sur github.com (`New repository` → `ot-watch`, public recommandé pour Actions illimité + CODEOWNERS).
2. `GITHUB_REPO=<owner>/ot-watch ./scripts/github-setup.sh` → remote `origin`, branche `main`, push `-u`.
3. Activer dans le dépôt : Actions (Settings → Actions → allow), Packages/GHCR (lié au dépôt), branch protection `main` (require PR + CI green — gratuit sur public).
4. Linear : Settings → Integrations → GitHub → connecter l'org ; créer l'équipe (ex. `OTW`) ; `LINEAR_TEAM_ID=... LINEAR_API_KEY=... python3 scripts/linear_import.py` importe la roadmap (dry-run par défaut).
5. Push d'un tag `v1.15.0` → `docker.yml` build + push `ghcr.io/<owner>/otwatch:v1.15.0` + `latest`, scan Trivy en amont.
6. `docker pull ghcr.io/<owner>/otwatch:latest` — public, aucun login.

## Sources (veille 2026-11-01)

[1] cicdcalculator.com — GitHub Actions free tier 2026 (public illimité ; privé 2 000 min + 500 Mo ; $0.006/min au-delà) · [2] eathealthy365.com — GitHub Free 2026 (dépôts privés illimités, CODEOWNERS public only, comparaison GitLab 400 min / Bitbucket 50 min) · [3] cicdcalculator.com/github-actions — GITHUB_TOKEN 1 000 req/h, 10 Go cache · [4][5][6] revues Linear 2026 — Free : 250 issues, 2 teams, intégration GitHub incluse, auto-link PR↔issue · [7][8][9] guides GHCR 2026 — `permissions: packages: write` + `secrets.GITHUB_TOKEN`, `docker/login-action` ghcr.io, images publiques illimitées · [10][11] comparatifs registries 2026 — Docker Hub 1 privé + rate limits, Quay 0 privé gratuit, GitLab CR généreux, OCI Always Free 20 Go · [12] deckrun.com — Scaleway CR 75 Go gratuits · [13][14] linear.rest / skills.rest — API GraphQL `api.linear.app/graphql`, `issueCreate`, clé perso en header sans « Bearer ».
