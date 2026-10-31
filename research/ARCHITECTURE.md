# Architecture d'OT Watch — trouver → transformer → afficher

```
┌────────────────────────── SOURCES PUBLIQUES (Internet) ──────────────────────────┐
│  CISA RSS (rss.xml)          NVD API 2.0                     CISA KEV (JSON)     │
│  avis ICS ICSA-/AA-          CVE fenêtre glissante           catalogue KEV        │
│  + page ics-advisories       + watchlist par cveId           (exploitation connue)│
└───────────────┬──────────────────────────┬──────────────────────────┬─────────────┘
                │  HTTP (urllib)           │  HTTP + rate-limit      │  HTTP
                ▼                          ▼                          ▼
┌──────────────────────── 1. COLLECTE : src/collect.py ─────────────────────────────┐
│  • lit config.json (URLs, mots-clés NVD, regex éditeurs OT, fenêtre en jours)      │
│  • CISA : parse le RSS, ne garde que les avis ICS/alertes dans la fenêtre          │
│  • NVD : keywordSearch + pubStartDate/pubEndDate, puis watchlist ?cveId=...        │
│  • filtre anti-faux-positifs _is_ot() (ex. « Datalex PLC » rejeté)                 │
│  • extrait CVSS/CWE/refs, dédoublonne, marque ★KEV si la CVE est au catalogue KEV   │
│  • gère le rate-limit NVD (403/429 → pause 30 s, 5 tentatives)                    │
│  • écrit des snapshots JSON : data/cves.json, cisa_advisories.json, kev.json       │
└───────────────┬───────────────────────────────────────────────────────────────────┘
                │  JSON normalisés + triés (CVSS décroissant)
                ▼
┌──────────────────── 2. TRANSFORMATION (2 couches) ────────────────────────────────┐
│  a) Déterministe (code, testé) :                                                    │
│     collect.py normalise → render.py prépare les blocs (badges CVSS colorés,       │
│     troncatures, drapeau ★KEV, compteurs)                                           │
│  b) Éditoriale (agent) :                                                            │
│     editorial/*.md = articles écrits par l'agent à partir de research/findings     │
│     (méthode ECC deep-research) : en-tête clé:valeur + markdown                     │
│     → parse_editorial() + md_to_html() convertit en HTML                            │
│  NB : le pipeline runtime est 100 % déterministe (pas d'appel LLM à l'exécution) : │
│  reproductible, testable (23 tests), auditable. Les 71 agents ECC installés dans   │
│  ~/.claude/agents servent à produire l'analyse éditoriale, pas à exécuter le cron.  │
└───────────────┬───────────────────────────────────────────────────────────────────┘
                │  données + articles prêts
                ▼
┌──────────────────── 3. AFFICHAGE : src/render.py ─────────────────────────────────┐
│  • lit data/*.json + editorial/*.md                                                  │
│  • génère out/issue-<date>.html : CSS 100 % inline, aucune ressource externe        │
│    (s'affiche tel quel dans le viewer sandbox, les clients mail, un navigateur)     │
│  • génère aussi out/issue-<date>.md (version texte / plateformes e-mail)            │
│  • mise en page : en-tête, barre de métadonnées, « À la une », tableau CVE avec     │
│    badges CVSS colorés, avis CISA, KEV, articles de fond, pied de page avec sources │
│  • sécurité à l'affichage : html.escape(quote=True) + safe_url() (http/https/mailto │
│    uniquement) → anti-XSS, prouvé par tests/test_render.py                          │
└───────────────┬───────────────────────────────────────────────────────────────────┘
                ▼
        out/issue-YYYY-MM-DD.html / .md   →   envoyée / hébergée / ouverte dans le viewer
```

## Commandes
```bash
./run_all.sh                 # 1+2+3 enchaînés (cron-ready)
python3 src/collect.py       # collecte seule
python3 src/render.py        # affichage seul
python3 -m unittest discover -s tests   # vérifie que la transformation est correcte
```
