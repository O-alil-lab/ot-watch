title: Veille technologies OT 2026 — IEC 62443, NIS2, OPC UA, Modbus : durcir sans casser la production
kicker: Technologies & standards
section: Veille techno
lead: false
---
## Standards : la conformité devient le socle
- **IEC 62443** s'élargit en 2026 : la partie **-1-6** couvre enfin la sécurité des **dispositifs IIoT** (capteurs, actionneurs connectés au cloud/edge), la **-6-2** définit l'évaluation de conformité des fournisseurs, la **-1-5** des profils de sécurité par application. Le référentiel passe de 4 à 6 catégories.
- **NIS2 (UE)** : notification d'alerte précoce sous **24 h**, notification d'incident sous **72 h**, rapport final sous un mois — et responsabilité personnelle des dirigeants (art. 20). Pour les entités « importantes », les sanctions atteignent 7 M€ ou 1,4 % du chiffre d'affaires mondial.
- Le modèle **Purdue** (zones et conduits) reste la colonne vertébrale : séparer IT, DMZ industrielle (IDMZ) et OT, avec des conduits contrôlés entre les couches.

## Protocoles : le talon d'Achille historique
**Modbus, DNP3, BACnet, S7comm et OPC Classic n'ont ni authentification ni chiffrement natifs** : s'ils sont atteignables, des commandes d'écriture passent. Le durcissement passe par la segmentation, des IDS spécialisés ICS, des listes blanches de fonctions Modbus, et le remplacement progressif par des versions sécurisées (OPC UA avec mTLS, MQTT sur TLS).

## OPC UA : puissant mais exigeant
Les failles récentes d'**Eclipse Milo** (bypass d'autorisation, fuite de diagnostics, oracle de padding Basic128Rsa15, DoS par quotas d'éléments surveillés) rappellent la règle : imposer **mTLS, autorisation, quotas et restrictions SSRF** sur chaque serveur OPC UA, notamment les passerelles IIoT (Eclipse Arrowhead/Ditto également visées).

## Tendances de fond (rapports 2026)
- Le rapport **Waterfall / ICS STRIVE 2026** note une baisse de 25 % des incidents à impact physique en 2025 (57 contre 76), attribuée au plateau du ransomware — mais anticipe une **reprise en 2026-2027**, notamment avec l arrival d'attaques « auto-entraînées » par IA côté offensif.
- Côté manufacturing, le ransomware a progressé de **56 % en 2025** (1 466 incidents documentés), avec **25 % provoquant l'arrêt complet du site**.

> **Priorités 2026 pour une usine** : (1) inventaire complet des actifs OT, (2) segmentation zones/conduits, (3) IAM strict + MFA sur les accès distants, (4) supervision passive (les vieux systèmes ne supportent pas d'agents), (5) playbooks de réponse à incident spécifiques OT, (6) sauvegardes hors ligne et testées des logiques PLC.

*Sources : [IIoT World — tendances ICS/OT 2026](https://www.iiot-world.com/ics-security/ics-ot-cybersecurity-trends-2026/), [IIoT World — guide manufacturing 2026](https://www.iiot-world.com/ics-security/ot-cybersecurity-manufacturing-2026/), [Deltaroot — IEC 62443 en 2026](https://deltaroot.net/blog/iec62443-2026-ot-security-trends), [Waterfall 2026 OT Cyber Threat Report](https://go.waterfall-security.com/hubfs/Gated%20content/2026%20OT%20Cyber%20Threat%20Report%20-%20Waterfall%20Security%20Solutions-1.pdf), [OT Security Wire — Modbus](https://otsecuritywire.com/articles/), [Agentic AI — brief OT/ICS](https://agentic-ai-daily-reports.netlify.app/cyber).*
