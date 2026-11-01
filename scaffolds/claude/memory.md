# Mémoire projet — OT Watch
- Architecture : src/collect.py → data/ + SQLite + raw/ ; src/render*.py → out/ ; server.py (0.0.0.0:8000) ; src/assets.py (score OT) ; src/netwatch.py (Zeek passif) ; workers/ (Cloudflare free).
- Versions v1.1 → v1.16 (CHANGELOG.md).
- Décisions : TAXII read-only, MISP optionnel env, backups 30 j, replay hors-ligne, score OT = exposition×Purdue×criticité+safety+KEV/SSVC (cap 10), DevOps gratuit GitHub+Linear+GHCR (ADR docs/adr/), Cloudflare free (docs/deploy/).
- Le bac à sable efface parfois .claude/, .github/, out/ et reset .git → `bash scripts/restore-sandbox.sh` puis re-commit ; preuves : research/VERIFICATION-2026-10-31.md.
