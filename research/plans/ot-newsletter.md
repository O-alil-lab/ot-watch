# Plan — Newsletter OT/PLC cybersécurité (ECC research-first)

Objectif : produire une newsletter professionnelle automatisée couvrant l'automatisme (PLC),
la cybersécurité OT (CVE, avis CISA, KEV) et les technologies associées (OPC UA, Modbus,
IEC 62443, S7comm, EtherNet/IP…).

## 1. Recherche (fait — voir research/findings/)
- Sources primaires : CISA ICS advisories (RSS + page), NVD API 2.0, CISA KEV catalog.
- Sujets 2026 : avis Siemens du 22/10/2026 (ICSA-26-295-*), AA26-231A (IA vs S7),
  AA26-097A (acteurs iraniens, exfiltration fichiers projet PLC), CVE-2026-6284 (Horner),
  tendances IEC 62443 / NIS2 / OPC UA.

## 2. Build
- `src/collect.py` : collecte auto (CISA RSS, NVD fenêtre glissante, KEV) -> `data/*.json`
- `src/render.py` : rend `out/issue-<date>.html` + `.md` (données + éditorial)
- `editorial/*.md` : articles rédigés/réécrits (niveau éditorial humain+)
- `run_all.sh` : pipeline complet (cron-ready)

## 3. Verify
- Exécuter collect + render, vérifier que l'HTML s'affiche (CSS inline, pas de ressources externes),
  vérifier les compteurs (CVE, avis, KEV) et les liens.

## Risques / limites
- NVD sans clé API = rate limit (5 req/30 s) -> sleep 6.5 s entre requêtes, NVD_API_KEY optionnel.
- Faux positifs NVD (keywordSearch plein texte) -> filtre regex éditeurs OT sur la description.
- Contenu éditorial : toujours sourcé ; la newsletter avertit de vérifier auprès des éditeurs.
