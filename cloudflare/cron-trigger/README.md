# Cron Cloudflare → publication GitHub Pages

Le Worker sert aussi le bouton « 🔄 Mettre à jour maintenant » du site : `POST /refresh`
(origine `https://o-alil-lab.github.io` uniquement ; refusé si une collecte tourne ou date de moins de 15 min).

Un Cron Trigger Cloudflare (offre gratuite) relance `.github/workflows/pages.yml` toutes les 6 h
via l'API GitHub. Plus fiable que le seul `schedule` GitHub (retards possibles, désactivé après
60 jours sans activité sur le dépôt). Le `schedule` GitHub reste actif en secours, et le job `keepalive`
de `pages.yml` le ré-active à chaque passage : ce Worker est donc optionnel.

## Déploiement
1. Token GitHub *fine-grained* : dépôt `O-alil-lab/ot-watch` uniquement, permission **Actions : Read and write**.
2. `cd cloudflare/cron-trigger && npx wrangler deploy`
3. `npx wrangler secret put GITHUB_TOKEN` (coller le token).

Vérification : onglet *Logs* du Worker, ou https://github.com/O-alil-lab/ot-watch/actions (événement `workflow_dispatch`).
