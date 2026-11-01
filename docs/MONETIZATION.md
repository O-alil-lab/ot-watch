# 💰 Monétisation éthique — OT Watch (v1.18, 01/11/2026)

**Engagement fondamental** : OT Watch reste **100 % gratuit et open source**, auto-hébergeable
gratuitement (Cloudflare free tier, GHCR, GitHub Actions sur dépôt public). On ne monétise **jamais**
le cœur : pas de version « pro » du code, pas de paywall sur les données, **pas de publicité, pas de
tracking, pas de vente de données, pas de dark patterns** (faux compteurs d'urgence, dark UI de
désabonnement, etc.).

Consultations ECC 01/11/2026 + veille 2026 (sources en bas).

## 1. Canaux de financement, du plus accessible au plus structuré

### 1.1 Dons individuels — à activer dès le dépôt public
- `FUNDING.yml` (racine) : GitHub Sponsors, Open Collective, Ko-fi.
- Page « Soutenir » dans le README pointant ici.
- Transparence : dons utilisés pour le temps de maintenance, pas de promesse de fonctionnalité.

### 1.2 Grants (subventions) — le levier réaliste pour un outil de sécu open source en 2026
| Programme | Montant indicatif 2026 | Commentaire |
|---|---|---|
| **NLnet / NGI** (NLnet Foundation) | ~5 k€ à 50 k€ (typique 5-30 k€) | Formulaire ~6 questions, cycle de décision ~2 mois, taux ~15-25 %, éligible monde entier, focus open internet/sécurité/standards ouverts — **le plus « builder-friendly » d'Europe** |
| **OpenSSF Alpha-Omega** | grants + audits de sécurité offerts (70+ grants, >20 M$ distribués ; +12,5 M$ annoncés mars 2026 par Anthropic/AWS/GitHub/Google/Microsoft/OpenAI) | Candidature projet ou demande d'audit de sécurité (très pertinent pour un outil de veille CVE) |
| **EU CEF / NGI / Digital Europe** | appels à projets pluriannuels | Pour volets « résilience cyber des infrastructures critiques » (OT) |
| **GitHub Secure Open Source / fonds écosystème** | ponctuel | Surveille les appels 2026 |

**Candidature NLnet — modèle de réponses (à adapter)** :
1. *Quoi ?* — plateforme de veille CVE OT/ICS auto-hébergeable, 100 % gratuite, avec flux TAXII/STIX/MISP.
2. *Pour qui ?* — SOC/asset owners OT (PME industrielles, collectivités) sans budget outil cyber.
3. *Pourquoi c'est d'intérêt général ?* — connaissance ouverte des vulnérabilités des systèmes industriels = bien public de sécurité.
4. *Pourquoi maintenant ?* — NIS2/CRA entrent en application ; la menace OT explose (KEV OT en hausse).
5. *Plan de travail* — itérations de 3-6 mois (ex. : connecteur asset management, éditions automatisées, i18n).
6. *Budget* — paliers 5-10-25-50 k€ justifiés en jours-personnes + infra gratuite.

### 1.3 Revenus de services **autour** du gratuit (le code reste libre)
- **Hébergement managé payant** : déploiement + supervision sur l'infra du client ou Cloudflare paid (5 $/mois) — service, pas licence.
- **Support & SLA** : contrat de support (réponse < 24 h, runbooks,Astrea) pour équipes OT.
- **Rapports de conformité personnalisés** : export PDF/CSV ciblé NIS2 / CRA / IEC 62443 (très demandé depuis le sommet ISA Prague 2026).
- **Formations** : IEC 62443, lecture du score OT, intégration TAXII dans un SOC (payant, le contenu de base reste gratuit).
- **Flux threat intel premium** : enrichissements propriétaires (ex. corrélation SBOM interne) en complément du flux gratuit — jamais en remplacement.

## 2. Contraintes légales & éthiques (déjà en place ou à documenter)

- **AI Act art. 50** : divulgation « assisté par IA + revue humaine obligatoire » dans chaque édition et brouillon ✅ (agents/writer.py).
- **RGPD** : aucun cookie, aucun tracking, abonnement local sans profilage, droit à l'oubli via `POST /unsubscribe` ✅ (v1.18) ; ne jamais vendre les e-mails d'abonnés.
- **C2PA / transparence** : métadonnées de génération conservées (out/meta.json).
- **À ne jamais faire** : dark patterns, vente de données, fausse urgence, verrouillage propriétaire du cœur.

## 3. Sources (veille 01/11/2026)

- NLnet grants 2026 (montants, cycle 2 mois, 6 questions, 15-25 %) — guide grantchain.eu
- OpenSSF / Linux Foundation / Alpha-Omega : 12,5 M$ (mars 2026), 70+ grants >20 M$, audits offerts — openssf.org, hpcwire.com
- Sommet ISA OT Cybersecurity Prague 2026 : NIS2/CRA en application, rapports de conformité demandés — industrialethernet.net, automation.com
- État de l'open source sécurité 2026 : multi-source vuln intel + EPSS + SBOM = attentes du marché — vulert.com
- Communautés OT 2026 : ICS Village, ISAGCA, ICS Security Switzerland, S4x27 — protectitallpod.com, icssec.ch
