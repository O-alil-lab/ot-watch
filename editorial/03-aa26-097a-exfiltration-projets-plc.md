title: AA26-097A — acteurs iraniens : l'exfiltration de fichiers projet PLC devient le nouveau butin
kicker: Menace active
section: Threat intelligence
lead: false
---
L'alerte **AA26-097A** de la CISA (mise à jour juillet–août 2026) documente une escalade attributed à des acteurs affiliés à l'Iran contre des PLC exposés aux États-Unis : initialement **Rockwell Automation MicroLogix 1100/1400**, le ciblage s'est élargi aux **Schneider Electric BMX P34 / Modicon M340** et aux **Siemens S7-1200**, dans les secteurs eau, énergie et collectivités.

## La nouveauté inquiétante
Les attaquants ne se contentent plus de perturber : ils **exfiltrent les fichiers projet des PLC** (logique ladder, configurations) en utilisant les logiciels d'ingénierie des éditeurs — **Studio 5000 Logix Designer, EcoStruxure Control Expert, TIA Portal** — exécutés sur des infrastructures louées tierces. Disposer du code de l'automate, c'est disposer de la carte exacte du process : cela prépare une manipulation de précision (modifier la logique, désactiver des alarmes) bien plus dangereuse qu'un arrêt brutal. De nouveaux IOC (IP) couvrent la période septembre 2025 – juillet 2026.

## Le détail qui fait froid dans le dos
L'avis reste associé à la **CVE-2021-22681**, une faille d'authentification sur des PLC exposés, **sans correctif possible** (« unpatchable »). Autrement dit : pour cette classe de risque, le seul remède est architectural.

## Ce que cela change pour la défense OT
- **L'intégrité du code automate devient un enjeu de sécurité à part entière** : hash des projets, sauvegardes hors ligne immuables, comparaison régulière, détection des modifications dans les blocs de code réutilisables (AOI).
- **Segmentez et filtrez les protocoles industriels** : un PLC n'a jamais besoin d'être joignable depuis Internet ni depuis le réseau bureautique.
- **Verrouillez les postes d'ingénierie** (les « crown jewels » de l'OT) : MFA, droits minimaux, journalisation des téléchargements de projet vers les CPU.

*Sources : [Tenable — coordinated cyberattack on Minnesota water utilities](https://www.tenable.com/blog/coordinated-cyberattack-on-minnesota-water-utilities-what-you-need-to-know), [Breached.company — CISA AA26-097A](https://breached.company/cisa-national-water-sector-warning-plc-exposure-2026/), [OT Security Wire — secteur énergie](https://otsecuritywire.com/sectors/energy/).*
