# Contribuer à OT Watch

Merci de votre intérêt ! La plateforme vise le niveau « plateforme de référence OT » (voir `research/REFERENCE-OT-WATCH-2026-11-01.md`).

## Pré-requis
- Python 3.13, `pip install -r requirements.txt` (+ `ruff`, `coverage` pour les gates).
- Sandbox Linux ; dépôt dans `/home/user/newsletter-ot`.

## Boucle de contribution
1. Branche depuis `master` ; PR avec `.github/PULL_REQUEST_TEMPLATE.md` rempli.
2. Quality gates **obligatoires** (commande `/verify` si vous utilisez un agent ECC) :
   - `python3 -m py_compile server.py src/*.py agents/*.py tests/*.py`
   - `python3 -m ruff check server.py src agents tests --config ruff.toml`
   - `python3 -m coverage run -m unittest discover -s tests` + `coverage report --include="*/src/*,*/server.py,*/agents/*" --fail-under=80`
   - grep secrets (pre-commit automatique)
   - `node /home/user/ecc/scripts/harness-audit.js --root . --scope repo` sans régression
3. Docs à jour : README.md + `research/VERIFICATION-2026-10-31.md` (addendum) + roadmap.
4. Revue : CODEOWNERS (chemins sécurité → @security).

## Règles non négociables
- Français pour réponses/docs ; IDs techniques verbatim.
- Aucun secret en dur (env uniquement). Jamais de ressource externe côté navigateur (iframe sandbox) : CSS/JS inline, SVG inline, URLs relatives.
- Serveur : bind `0.0.0.0`, en-têtes sécurité sur **toutes** les réponses.
- Contenu IA : revue humaine + divulgation (AI Act Art. 50) ; images data-driven avec provenance.
- Voir `SECURITY.md` pour déclarer une vulnérabilité.
