# /collecte — pipeline complet OT Watch
`./run_all.sh` (collecte live CISA/NVD/KEV/EPSS + renders HTML/PDF/STIX/MISP/AR + netwatch si logs Zeek). ~8 min.
Vérif live : `curl -s http://127.0.0.1:8000/api/data | jq .meta` et `/metrics`.
