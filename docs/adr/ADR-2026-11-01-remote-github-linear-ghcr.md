# ADR 2026-11-01 — Remote Git, suivi projet et registre Docker 100 % gratuits

- Statut : accepté
- Contexte : OT Watch n'a pas de remote ; l'historique local a été perdu à plusieurs reprises dans le bac à sable de développement. Il faut un remote, de la CI, un suivi des tâches et un registre d'images, sans coût.

## Décision

| Besoin | Choix | Justification (vérifiée le 2026-11-01) |
|---|---|---|
| Remote + PR + CI | **GitHub.com, dépôt public** | Actions gratuit pour les runners standards sur dépôt public (docs GitHub). Sur dépôt privé, le quota gratuit s'applique ; les baisses de prix 2026 ne changent pas les quotas gratuits. |
| Registre d'images | **GHCR** `ghcr.io/<owner>/<repo>` | Paquets publics gratuits ; stockage et bande passante du Container registry actuellement gratuits (préavis d'un mois avant changement) ; transferts depuis Actions via `GITHUB_TOKEN` non décomptés. Push sans PAT. |
| Suivi projet | **Linear Free** | Membres illimités, 2 équipes, 250 issues max. La roadmap actuelle compte ~43 items : marge suffisante. Intégration GitHub (liaison branche/PR) à confirmer sur la page tarifs Linear au moment de l'activation. |

## Conséquences

- `scripts/github-setup.sh` : remote `origin`, branche `main`, push. Refuse sans `GITHUB_REPO`, avec un arbre sale ou un `origin` divergent ; `DRY_RUN=1` disponible.
- `.github/workflows/docker.yml` : job `scan` (lecture seule, Trivy CRITICAL/HIGH bloquant) puis job `push` (GHCR, `packages: write`). Les deux sont séparés pour qu'un outil tiers de scan ne voie jamais un jeton d'écriture.
- `scripts/linear_import.py` : dry-run par défaut ; `--apply` avec `LINEAR_API_KEY`/`LINEAR_TEAM_ID` en env ; idempotent par titre ; plafond `--max` (200) sous la limite Free.
- Dependabot couvre pip, github-actions et docker.

## Risque chaîne d'approvisionnement

`aquasecurity/trivy-action` jusqu'à v0.34.2 a été compromis le 2026-03-19 (CVE-2026-33634, au KEV CISA) ; v0.35.0 est la version saine. Le workflow l'utilise et devrait idéalement l'épingler par SHA de commit complet. Si un ancien tag a tourné dans un pipeline du propriétaire, faire tourner les secrets concernés.

## Options écartées

- GitLab.com Free : quota CI plus faible sur le niveau gratuit.
- Docker Hub en registre principal : limites de pull anonymes ; possible en miroir.
- Quay.io, registres cloud « always free », Harbor auto-hébergé : soit pas de dépôt privé gratuit, soit inscription lourde, soit infrastructure à maintenir.

## Sources

- GitHub Docs — Actions billing and usage : https://docs.github.com/en/enterprise-cloud@latest/actions/concepts/billing-and-usage
- GitHub Docs — GitHub Packages billing : https://github.com/github/docs/blob/main/content/billing/concepts/product-billing/github-packages.md
- GitHub Changelog — Actions pricing update (2025-12-16) : https://github.blog/changelog/2025-12-16-coming-soon-simpler-pricing-and-a-better-experience-for-github-actions/
- Linear Free plan (synthèse tierce) : https://omidsaffari.com/blog/linear-pricing
- CVE-2026-33634 (Trivy / trivy-action) : https://stack.watch/vuln/CVE-2026-33634/
