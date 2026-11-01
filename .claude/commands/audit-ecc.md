---
description: Audit harness ECC du dépôt
---
Depuis la racine du workspace : `node ecc/scripts/harness-audit.js --scope repo --root newsletter-ot` (si ECC est présent), sinon vérifie à la main les fichiers listés dans `tests/test_platform.py::TestGouvernanceEcc.FILES`. Rapporte le score et les écarts.
