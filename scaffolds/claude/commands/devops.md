# /devops — remote GitHub + Linear + GHCR (100 % gratuit) + Cloudflare free tier
1. `GITHUB_REPO=<owner>/ot-watch ./scripts/github-setup.sh`
2. Linear : `LINEAR_API_KEY=... LINEAR_TEAM_ID=... python3 scripts/linear_import.py --apply`
3. Image : `git tag vX.Y.Z && git push origin vX.Y.Z` → ghcr.io/<owner>/ot-watch:vX.Y.Z
4. Cloudflare free : `cd workers && CLOUDFLARE_API_TOKEN=... CLOUDFLARE_ACCOUNT_ID=... ./deploy.sh`
ADR : docs/adr/ADR-2026-11-01-remote-github-linear-ghcr.md · plan CF : docs/deploy/CLOUDFLARE-FREE-TIER-2026-11-01.md
