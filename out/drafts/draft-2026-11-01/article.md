title: Veille OT/ICS  -  5 CVE prioritaires cette fenêtre
kicker: Brouillon agent IA  -  REVUE HUMAINE REQUISE avant publication
lead: true
section: Analyse automatique
---

# Veille OT/ICS  -  fenêtre de 14 jours

**22 CVE OT** surveillées, **13 entrées KEV OT**, **5 avis CISA ICS** dans la fenêtre. Tendance publications CVE : -100 % vs la semaine précédente. À la une : **CVE-2026-110936** (CVSS 8.4 · risque 6.23/10 · EPSS 0.010 · ★ KEV (exploitation confirmée) · SSVC ACT · ◆ correspond à votre profil « Mes actifs OT »). [1]

## À retenir en 30 secondes
- **CVE-2026-110936**  -  CVSS 8.4 · risque 6.23/10 · EPSS 0.010 · ★ KEV (exploitation confirmée) · SSVC ACT · ◆ correspond à votre profil « Mes actifs OT ». [24] A vulnerability has been identified in Siemens Software Center (All versions < V4.0.9.8). The affected application loads dynamic-link librar
- **CVE-2026-116014**  -  CVSS 9.2 · risque 4.61/10 · EPSS 0.004 · SSVC ACT · ATT&CK for ICS T0885 · ◆ correspond à votre profil « Mes actifs OT ». [25] open62541 1.5.0 before 1.5.7 contains an integer overflow in UA_DataType_fromStructureDescription() that wraps the 16-bit memSize field for 
- **CVE-2026-92817**  -  CVSS 8.7 · risque 4.36/10 · EPSS 0.005 · SSVC TRACK* · ◆ correspond à votre profil « Mes actifs OT ». [26] The Ignition Perspective module does not properly validate session privileges when determining Designer-level access. An authenticated user 

## CVE prioritaires (tri : profil actifs OT, puis risque)
### CVE-2026-110936  -  CVSS 8.4 · risque 6.23/10 · EPSS 0.010 · ★ KEV (exploitation confirmée) · SSVC ACT · ◆ correspond à votre profil « Mes actifs OT »
A vulnerability has been identified in Siemens Software Center (All versions < V4.0.9.8). The affected application loads dynamic-link libraries (DLLs) from an uncontrolled search path. This could allow an authenticated local attacker to place a specially crafted DLL in a directory that the applicati

### CVE-2026-116014  -  CVSS 9.2 · risque 4.61/10 · EPSS 0.004 · SSVC ACT · ATT&CK for ICS T0885 · ◆ correspond à votre profil « Mes actifs OT »
open62541 1.5.0 before 1.5.7 contains an integer overflow in UA_DataType_fromStructureDescription() that wraps the 16-bit memSize field for large custom structure definitions. A malicious OPC UA server can supply DataType definitions via UA_Client_getRemoteDataTypes(), causing decodeBinaryStructure(

### CVE-2026-92817  -  CVSS 8.7 · risque 4.36/10 · EPSS 0.005 · SSVC TRACK* · ◆ correspond à votre profil « Mes actifs OT »
The Ignition Perspective module does not properly validate session privileges when determining Designer-level access. An authenticated user with access to a Vision project could provide their valid Vision session identifier and gain Designer-level privileges. An attacker could exploit these elevated

### CVE-2026-72895  -  CVSS 8.4 · risque 4.20/10 · EPSS 0.001 · SSVC TRACK* · ◆ correspond à votre profil « Mes actifs OT »
A vulnerability has been identified in SIMATIC IPC BX-21A (All versions < V31.01.13), SIMATIC IPC RW-543A (All versions < V1.1.4), SIMATIC IPC227G / IPC277G / IPC277G PRO / IPC327G / IPC377G (All versions < V28.01.15). A BIOS vendor test key is present in the UEFI Secure Boot key database. This coul

### CVE-2026-111280  -  CVSS 8.3 · risque 4.17/10 · EPSS 0.005 · SSVC TRACK
snap7 through 1.4.3 contains an out-of-bounds write vulnerability in TSnap7MicroClient::opReadArea() that allows malicious S7 peers to overflow client buffers via an unchecked DataLength field. Rogue or impersonated PLCs can return crafted ReadVar responses causing memcpy of up to 65535 bytes into c

## ⭐ Vos actifs OT concernés
- CVE-2026-110936  -  CVSS 8.4 · risque 6.23/10 · EPSS 0.010 · ★ KEV (exploitation confirmée) · SSVC ACT · ◆ correspond à votre profil « Mes actifs OT »
- CVE-2026-116014  -  CVSS 9.2 · risque 4.61/10 · EPSS 0.004 · SSVC ACT · ATT&CK for ICS T0885 · ◆ correspond à votre profil « Mes actifs OT »
- CVE-2026-92817  -  CVSS 8.7 · risque 4.36/10 · EPSS 0.005 · SSVC TRACK* · ◆ correspond à votre profil « Mes actifs OT »
- CVE-2026-72895  -  CVSS 8.4 · risque 4.20/10 · EPSS 0.001 · SSVC TRACK* · ◆ correspond à votre profil « Mes actifs OT »

## Avis CISA ICS de la fenêtre
- [ICSA-26-302-03  -  Hitachi Energy CoreTec Product](https://www.cisa.gov/news-events/ics-advisories/icsa-26-302-03) (Wed, 28 Oc)
- [ICSA-26-302-02  -  Hitachi Energy TRO600 series products](https://www.cisa.gov/news-events/ics-advisories/icsa-26-302-02) (Wed, 28 Oc)
- [ICSA-26-302-01  -  Siemens Mendix SAML Module](https://www.cisa.gov/news-events/ics-advisories/icsa-26-302-01) (Wed, 28 Oc)
- [ICSA-26-300-02  -  Mitsubishi Electric and Mitsubishi Electric Iconics Digital Solutions GENESIS, GENESIS64, ICONICS Suite, Hyper Historian, AnalytiX, MobileHMI, IoTWorX, MC Works64, GENESIS32 and BizViz](https://www.cisa.gov/news-events/ics-advisories/icsa-26-300-02) (Mon, 26 Oc)
- [ICSA-26-300-01  -  EPICS Base](https://www.cisa.gov/news-events/ics-advisories/icsa-26-300-01) (Mon, 26 Oc)

## Actions recommandées lundi 07:00
- Patcher d'abord les CVE ★KEV et SSVC `act` sur les actifs exposés (SLA 24-72 h).
- Vérifier l'exposition réseau (niveau Purdue) des actifs du profil « Mes actifs OT ».
- Revue des logs des capteurs passifs (alertes ATT&CK for ICS mappées).

## Méthodologie, sources & transparence
Rédaction assistée par IA à partir de données structurées vérifiées (CISA/NVD/KEV/FIRST EPSS), fact-checking automatisé en 3 niveaux, puis **revue éditoriale humaine obligatoire avant publication** (AI Act, art. 50  -  exemption de labelling public-interest car revue humaine avec responsabilité éditoriale).
Sources primaires : https://nvd.nist.gov/vuln/detail/CVE-2026-109618 ; https://nvd.nist.gov/vuln/detail/CVE-2026-109619 ; https://nvd.nist.gov/vuln/detail/CVE-2026-110936 ; https://nvd.nist.gov/vuln/detail/CVE-2026-111280 ; https://nvd.nist.gov/vuln/detail/CVE-2026-111497 ; https://nvd.nist.gov/vuln/detail/CVE-2026-115723 ; https://nvd.nist.gov/vuln/detail/CVE-2026-115803 ; https://nvd.nist.gov/vuln/detail/CVE-2026-116014
Illustrations : visuels générés depuis les données collectées (reproductibles, voir out/img/).
