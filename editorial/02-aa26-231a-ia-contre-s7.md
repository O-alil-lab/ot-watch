title: Menace active confirmée : des scripts générés par IA ciblent les PLC Siemens S7 (AA26-231A)
kicker: Menace active
section: Threat intelligence
lead: false
---
Le 19 août 2026, la NSA, la CISA, le FBI, le DOE et l'EPA ont publié l'alerte conjointe **AA26-231A** : des acteurs malveillants utilisent des **scripts Python générés par IA**, appuyés sur la bibliothèque open source **python-snap7**, pour attaquer des PLC Siemens S7 exposés sur Internet via le protocole **S7comm (TCP/102)**.

## Pourquoi c'est un tournant
Jusqu'ici, écrire un exploit ICS demandait une expertise rare. L'IA abaisse radicalement cette barrière : n'importe quel acteur peut générer un script fonctionnel déguisé en outil de supervision, avec **lecture/écriture de la mémoire du PLC, des données de configuration et de la logique ladder**.

Aucun CVE n'est associé à cette campagne — **la vulnérabilité, c'est l'exposition elle-même** : PLC accessibles depuis Internet, authentification faible, firmware obsolète. Les familles visées couvrent toute la gamme S7 : S7-200, S7-300, S7-400, S7-1200 et S7-1500, y compris les contrôleurs de sécurité F-series.

## Un impact réel, pas théorique
Fin juillet 2026, une station de traitement d'eau du **Minnesota** a été perturbée ; environ **30 systèmes d'eau ont été affectés dans au moins sept États**. Les agences qualifient la menace d'« active » : ce ne sont plus de la reconnaissance théorique mais du pré-positionnement opérationnel.

## Checklist pour les exploitants
- **Retirer les PLC S7 de toute exposition Internet directe** — bloquer le TCP/102 au périmètre.
- Activer les **niveaux de protection** Siemens et des **mots de passe forts** sur chaque CPU.
- Restreindre l'accès aux seuls postes d'ingénierie autorisés (listes blanches réseau).
- **Surveiller le trafic S7comm** (détection d'IDS dédiée, baselining des requêtes read/write).
- Vérifier l'intégrité des projets TIA Portal contre des sauvegardes hors ligne connues bonnes.

*Sources : [AA26-231A via ThreatAft](https://threataft.com/articles/siemens-s7-plcs-ai-generated-exploits-cisa-aa26-231a), [checklist Safeguard](https://safeguard.sh/resources/blog/siemens-s7-plc-alert-aa26-231a-checklist), [CISA KEV / avis](https://www.cisa.gov/). Note connexe : la librairie snap7 elle-même a une CVE-2026-111280 (écriture hors limites dans `opReadArea()`) — mettez à jour vos outils qui l'embarquent.*
