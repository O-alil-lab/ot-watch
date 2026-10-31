title: 22 octobre 2026 — CISA republication de 17 avis Siemens : vos S7-1500 en première ligne
kicker: À la une
section: Avis éditeurs
lead: true
---
Le 22 octobre, la CISA a republication **17 avis de sécurité Siemens** (ICSA-26-295-01 à -18), dans un lot de 19 avis ICS. Derrière la masse, trois dossiers doivent retenir l'attention immédiate des exploitants de sites industriels.

## Ce qui brûle maintenant
**1. Le serveur web des S7-1500, noté 9.6 — sans correctif disponible.** L'avis ICSA-26-295-14 regroupe les CVE-2026-63350 à CVE-2026-63357 : les fichiers trace importés (traces, CSV de signaux calculés) ne sont pas correctement nettoyés avant d'être rendus dans l'interface web. Résultat : un attaquant peut, par ingénierie sociale, faire importer un fichier piégé à un utilisateur autorisé disposant du droit « Read diagnostics » — et exécuter du JavaScript dans sa session, puis **piloter le PLC dans la limite des droits de cet utilisateur**. Aucune version corrigée n'est disponible à ce stade.

> **Action immédiate** : désactiver le serveur web des S7-1500 lorsqu'il n'est pas indispensable, et restreindre les ports 80/443 aux seuls postes d'ingénierie. C'est la parade la plus efficace tant qu'aucun patch n'existe.

**2. Les S7-1500 « MFP », notées 10.0.** Les CPU 1518(F)-4 PN/DP MFP et les modules TM MFP embarquent un sous-système GNU/Linux additionnel touché par des centaines de CVE de composants tiers. Siemens prépare des correctifs et publie des mesures d'atténuation : appliquez-les dès leur disponibilité et isolez ces équipements.

**3. Siemens Software Center déjà exploité (KEV).** La CVE-2026-110936 (CWE-427, élément de chemin de recherche incontrôlé) affecte les versions < 4.0.9.8 et figure **au catalogue KEV** : une exploitation active est documentée. Corrigez en priorité.

## Le reste du lot
Le lot couvre aussi un contournement de Secure Boot des SIMATIC IPC via une clé de test (CVE-2026-72895), RUGGEDCOM CROSSBOW, WinCC, Industrial Edge, PSS SINCAL, SENTRON 3NA COM et la bibliothèque cliente .NET de l'API S7 Webserver. La méthode reste la même : **inventaire des actifs → confrontation aux 17 avis → correctifs planifiés**, la plupart des sites Siemens hébergeant au moins un nœud S7-1500 ou WinCC concerné.

*Sources : [CISA ICSA-26-295-14](https://www.cisa.gov/news-events/ics-advisories/icsa-26-295-14), [ICSA-26-295-03](https://www.cisa.gov/news-events/ics-advisories/icsa-26-295-03), [analyse Red Tiger Security](https://www.redtigersecurity.com/advisory/siemens-cisa-ics-advisories-oct-2026), [NVD](https://nvd.nist.gov/).*
