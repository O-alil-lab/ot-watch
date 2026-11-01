# 🌐 Communauté & acquisition — OT Watch (v1.18, 01/11/2026)

Consultations ECC du 01/11/2026 (~21:56) : capabilities recommandées `security`, `content`, `operators`, `research`.
Veille web 2026 jointe. Principe : **zéro friction + sortie actionnable + écosystème threat intel** — pas d'ads, pas de growth hacking.

## 1. Canaux d'acquisition qui fonctionnent en 2026 (niche OT/ICS)

| Canal | Action concrète | Statut |
|---|---|---|
| Écosystème threat intel | TAXII 2.1 + STIX 2.1 + export MISP exposés (`/taxii2/*`, `/stix`, `/misp`) ; rejoindre les communautés MISP, ISAC sectoriels (OT-ISAC), FIRST/TF-CSIRT | ✅ API en place — rejoindre les communautés |
| CI/CD zero-config | GitHub Actions (`.github/workflows/ci.yml`) + image GHCR publique | ✅ en place |
| Éditions multilingues + RSS + SEO | `/issue` FR, `/issue.ar` AR (RTL corrigé), `/issue.en` EN, `/feed.xml`, `sitemap.xml`, hreflang FR/AR/EN, Open Graph | ✅ v1.18 |
| Contenu régulier sourcé | éditions data-driven (CVE/KEV/EPSS/SSVC/ATT&CK), cross-post dev.to / LinkedIn / Mastodon infosec.exchange | 🔲 à faire (voir §3) |
| awesome-lists GitHub | soumettre à awesome-ics-security / awesome-threat-intel / awesome-ics (voir §4) | 🔲 à faire |
| Conférences OT | proposer un talk/atelier : S4x27 (sold out 1 100 billets), ISA OT Cybersecurity Summit 2027 (Athènes), ICS Village | 🔲 modèle ci-dessous |

## 2. Communautés à rejoindre (liens vérifiés 01/11/2026)

- **ISAGCA** — ISA Global Cybersecurity Alliance (IEC 62443) : https://isagca.org
- **ICS Village** — ateliers/CTF avec vrai matériel industriel : https://icsvillage.com
- **OT Cybersecurity Coalition (OTCC)** : https://otcybercoalition.org
- **CISA — OT-ISAC & avis ICS** : https://www.cisa.gov/topics/industrial-control-systems
- **FIRST / TF-CSIRT** : https://www.first.org · https://tf-csirt.org
- **MISP Project** (fédération de communautés de partage) : https://www.misp-project.org
- **ICS Security Switzerland** (association, meetups Lucerne/Zurich) : https://www.icssec.ch
- **S4x27** : https://s4xevents.com — **ISA OT Cybersecurity Summit 2027 (Athènes)** : https://www.isa.org

## 3. Modèle de cross-post (édition → réseaux)

1. `python3 run_all.sh` génère `out/issue-<date>.{html,md}` + `.ar.*` + `.en.*` + RSS.
2. Le `.md` FR sert de base au post LinkedIn/dev.to (300-500 mots + top 3 CVE + lien `/issue`).
3. Post Mastodon sur infosec.exchange avec hashtags #OTsecurity #ICS #threatintel + lien `/issue.en`.
4. Soumettre le flux RSS à des agrégateurs (ex. RSS-Bot, Slack `/feed add <url>/feed.xml` dans les communautés).

## 4. Checklist soumission awesome-lists

- [ ] awesome-ics-security (github.com/.../awesome-ics-security) — catégorie « threat intelligence / monitoring »
- [ ] awesome-threat-intel — catégorie « TAXII/STIX servers auto-hébergés gratuits »
- [ ] awesome-selfhosted — catégorie « monitoring/alerting »
- [ ] awesome-cisa-kev — catégorie « outils de priorisation KEV/EPSS »
- PR : description 1 ligne + capture dashboard + mention « 100 % gratuit, self-host, Cloudflare free tier possible ».

## 5. Modèle de proposition de talk (S4x / ISA Summit)

**Titre** : « OT Watch : une veille CVE OT/ICS 100 % gratuite, auto-hébergée et auditable (TAXII/STIX/MISP) »
**Résumé (150 mots)** : pipeline de collecte live (CISA/NVD/KEV/FIRST EPSS), scoring OT par profil d'actifs (Purdue), éditions FR/AR/EN, conformité AI Act art. 50 avec revue humaine obligatoire, déploiement Cloudflare free tier. Démo live : `/api/data` → `/taxii2/*`.
**Pourquoi l'audience OT en a besoin** : NVD seul est insuffisant en 2026 (backlog), le multi-source + EPSS + KEV est devenu la norme ; un flux TAXII auto-hébergé se branche directement dans les SIEM/SOAR existants.
**Bio** : mainteneur du projet, focus opérations OT (Purdue L0-L3).
