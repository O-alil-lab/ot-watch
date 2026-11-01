---
description: Lance les quality gates OT Watch (lint, tests, couverture, grep secrets)
---
Exécute dans l'ordre et arrête-toi au premier échec :
1. `ruff check . --config ruff.toml`
2. `python3 -m coverage run -m unittest discover -s tests && python3 -m coverage report --include="*/src/*,*/server.py" --fail-under=80`
3. Le grep secrets/primitives dangereuses de `.github/workflows/ci.yml`.
Rapporte le résultat de chaque gate en une ligne.
