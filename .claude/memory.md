# Mémoire projet — OT Watch (newsletter-ot)

- Pipeline : `./run_all.sh` → collecte (CISA ICS, NVD CPE, KEV, EPSS, GHSA, OTX opt.) → SQLite `data/` → rendu `out/` (HTML/MD/PDF/STIX/AR).
- Serveur : `python3 server.py` (stdlib), dashboard + `/api/*`, `/taxii2/*`, `/openapi.json`, `/metrics`.
- Gates avant commit : `ruff check . --config ruff.toml`, `python3 -m unittest discover -s tests`, couverture ≥ 80 % sur `src/` + `server.py`.
- Secrets uniquement via env (`NVD_API_KEY`, `OTWATCH_ADMIN_TOKEN`, `OTWATCH_TAXII_TOKEN`, `OTWATCH_OTX_API_KEY`, `LINEAR_API_KEY`). Jamais dans le dépôt.
- Collecte réseau OT : passive uniquement (SPAN/TAP, Zeek). Jamais de scan actif.
- Stack DevOps gratuite : GitHub (public) + Actions, GHCR, Linear Free — voir `docs/adr/ADR-2026-11-01-remote-github-linear-ghcr.md`.
