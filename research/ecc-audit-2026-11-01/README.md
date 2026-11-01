# Rapports d'audit ECC — 2026-11-01 (lancés sur /home/user/newsletter-ot)

- `harness-audit-final.txt` / `.json` : **39/39** (16 checks, 0 failing) après câblage v1.14. Avant : 19/39 (`harness-audit.txt`).
- `platform-audit.txt` : checks internes ECC (package.json d'ECC lui-même, miroirs Linear…) — non applicables à OT Watch ; seul point pertinent : working tree propre ✅.
- `observability.txt` : 0/21 car la cible est ECC (ecc2/, scripts/) et non ce dépôt — non applicable ; l'observabilité d'OT Watch est couverte par `/metrics` (18+ gauges Prometheus), SSE `/api/stream`, `logs/runs.jsonl`, `data/meta.json` (quality/validation).
- `doctor-final.txt` : 2/3 OK ; l'erreur restante = artefacts compilés OpenCode d'ECC (`npm run build:opencode` fait, install interactif non scriptable en sandbox) — sans impact sur OT Watch.
- `doctor.txt` : état initial.
