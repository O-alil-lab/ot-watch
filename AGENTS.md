# AGENTS.md — OT Watch (veille OT/ICS)

Instructions projet pour tout agent IA (Claude Code, Codex, Opencode, Cursor) travaillant sur ce dépôt.

## Langue & ton
- **Français** pour toute réponse utilisateur et tout contenu éditorial de la newsletter.
- IDs techniques verbatim (CVE-2026-…, ICSA-26-…, T0843…). Pas d'emojis ambigus dans le code ; ✅/★/◆ autorisés dans les sorties utilisateur.

## Architecture (ne pas casser)
- `src/collect.py` → collecte auto (CISA RSS, NVD API 2.0, CISA KEV, FIRST EPSS) → `data/*.json` + SQLite `data/otwatch.db` (via `src/store.py`, diff par run, `history_daily`).
- `src/render.py` → `out/issue-<date>.html|.md` (CSS inline uniquement, aucune ressource externe, échappement HTML de tout contenu externe).
- `src/render_pdf.py` → `out/issue-<date>.pdf` (fpdf2 + DejaVu ; glyphes sûrs ★ ☠ ⚠ ✓ ◆ ● → uniquement).
- `server.py` → dashboard live `0.0.0.0:8000` : `/`, `/api/data`, `/api/history`, `/api/stream` (SSE), `/api/refresh` (Bearer `OTWATCH_ADMIN_TOKEN`), `/metrics`, `/issue`, `/issue.pdf`. Toujours bind `0.0.0.0`, en-têtes sécurité sur toutes les réponses, URLs relatives côté navigateur (jamais localhost côté client).
- `src/alerts.py` : alerting env-only (`OTWATCH_WEBHOOK_URL`, `OTWATCH_SLACK_WEBHOOK`, `OTWATCH_SMTP_*`), dry-run JSONL sinon.
- Pipeline complet : `./run_all.sh` (~4 min, réseau requis).

## Quality gates ECC (à chaque changement significatif)
```bash
cd /home/user/newsletter-ot
python3 -m py_compile server.py src/*.py tests/*.py
python3 -m ruff check server.py src tests --config ruff.toml
python3 -m coverage run -m unittest discover -s tests
python3 -m coverage report --include="*/src/*,*/server.py,*/agents/*"   # objectif >= 80 %
! grep -rniE "(api[_-]?key|secret|token|password)\s*[:=]\s*[\"'][A-Za-z0-9+/=_.-]{8,}" src tests config.json server.py
```
Commit : le hook pre-commit (ruff + grep secrets) tourne automatiquement. Docs de vérification : `research/VERIFICATION-2026-10-31.md`. Roadmaps : `research/plans/` + `research/REFERENCE-OT-WATCH-2026-11-01.md`.

## Règles de sécurité & conformité
- Jamais de secret en dur (env uniquement) ; gitleaks/pre-commit actif.
- Contenu généré par IA (futur pipeline éditorial) : revue éditoriale humaine obligatoire, divulgation « assisté par IA », images IA signées C2PA + légende visible (AI Act Art. 50, applicable depuis 02/08/2026).
- Ne jamais introduire de ressource externe dans le HTML servi (aperçu sandboxé sans réseau) ; graphiques = SVG inline.
