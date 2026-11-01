## Résumé
<!-- Quoi et pourquoi. Lien Linear : OTW-123 -->

## Vérifications
- [ ] `ruff check . --config ruff.toml`
- [ ] `python3 -m unittest discover -s tests` vert, couverture ≥ 80 %
- [ ] Aucun secret ajouté (gitleaks / grep CI)
- [ ] CHANGELOG.md mis à jour si comportement visible
- [ ] `docs/openapi.json` à jour si une route change
