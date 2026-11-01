# /verify — quality gates ECC complets du dépôt OT Watch
1. `python3 -m py_compile server.py src/*.py agents/*.py tests/*.py workers/otwatch_worker.py`
2. `python3 -m ruff check server.py src agents tests --config ruff.toml`
3. `python3 -m coverage run -m unittest discover -s tests` puis `python3 -m coverage report --include="*/src/*,*/server.py,*/agents/*" --fail-under=80`
4. grep secrets (rien ne doit sortir) sur src tests config.json server.py
5. `node /home/user/ecc/scripts/harness-audit.js --root . --scope repo` (39/39)
Ne committe que si tout est vert. Voir AGENTS.md et research/VERIFICATION-2026-10-31.md.
