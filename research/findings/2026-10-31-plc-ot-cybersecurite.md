# Findings — Veille PLC/OT cybersécurité (31 oct. 2026)

## Avis CISA ICS récents (22 oct. 2026 : 19-20 avis)
- CISA a publié le 22/10/2026 **19-20 avis ICS** dont **17 Siemens** (ICSA-26-295-01 à -18).
  - **ICSA-26-295-14 — Siemens SIMATIC S7 PLCs Web Server, CVSS 9.6** : CVE-2026-63350 à -63357.
    Fichiers trace importés (trace/CSV) mal nettoyés -> XSS dans la session d'un utilisateur autorisé
    -> exécution de JS et **opérations PLC dans les droits de l'utilisateur**. **Aucun correctif dispo.**
    [CISA ICSA-26-295-14](https://www.cisa.gov/news-events/ics-advisories/icsa-26-295-14)
  - **ICSA-26-295-11 / -16 — S7-1500 CPU 1518(F)-4 PN/DP MFP et TM MFP, CVSS 10** : centaines de CVE
    du sous-système GNU/Linux additionnel. [redtigersecurity](https://www.redtigersecurity.com/advisory/siemens-cisa-ics-advisories-oct-2026)
  - **ICSA-26-295-03 — Siemens Software Center < 4.0.9.8, CVE-2026-110936 (CWE-427)** : **déjà au catalogue KEV** (exploitation active).
  - Autres : SIMATIC IPC Secure Boot bypass via clé de test (CVE-2026-72895), RUGGEDCOM CROSSBOW,
    WinCC, Industrial Edge, PSS SINCAL, SENTRON 3NA COM, S7 Webserver API .NET.
  - [noticenearby](https://noticenearby.com/papers/cisa-ics-advisories-siemens-kiloview-intersystems-iris-oct-22-2026) | [opentext](https://community.opentextcybersecurity.com/vulnerability-vault-228/cisa-releases-20-industrial-control-systems-advisories-october-22-2026-365986)
- Flux RSS CISA courant : derniers avis **ICSA-26-302-01/02/03** et **ICSA-26-300-01/02** (26 oct. 2026),
  dont Mitsubishi Electric GENESIS/ICONICS/MC Works64 (ICSA-26-300-02) et EPICS Base (ICSA-26-300-01).
  [CISA RSS](https://www.cisa.gov/rss.xml)

## Menaces actives
- **AA26-231A (19 août 2026, NSA/CISA/FBI/DOE/EPA)** : scripts Python **générés par IA** (python-snap7)
  contre PLC Siemens S7 **exposés sur Internet** (TCP/102, S7comm) : S7-200/300/400/1200/1500 (dont F).
  **Aucun CVE** — la faille = exposition + mots de passe faibles. Incident confirmé : station d'eau du Minnesota
  fin juillet 2026, ~30 systèmes d'eau dans ≥7 États. [threataft](https://threataft.com/articles/siemens-s7-plcs-ai-generated-exploits-cisa-aa26-231a) | [safeguard.sh](https://safeguard.sh/resources/blog/siemens-s7-plc-alert-aa26-231a-checklist)
- **AA26-097A (juillet-août 2026, acteurs iraniens)** : ciblage Rockwell MicroLogix 1100/1400, élargi à
  **Schneider BMX P34 / Modicon M340** et **Siemens S7-1200**. Nouvelle tactique : exfiltration des **fichiers projet PLC**
  via Studio 5000 / EcoStruxure Control Expert / TIA Portal sur infrastructure louée. IOC sept. 2025–juil. 2026.
  CVE-2021-22681 **non corrigeable**. [tenable](https://www.tenable.com/blog/coordinated-cyberattack-on-minnesota-water-utilities-what-you-need-to-know) | [breached.company](https://breached.company/cisa-national-water-sector-warning-plc-exposure-2026/)

## CVE marquantes du trimestre (NVD, fenêtre oct. 2026)
- **CVE-2026-63350..63357** (S7-1500 web server, ci-dessus, NVD) — [NVD](https://services.nvd.nist.gov/rest/json/cves/2.0)
- **CVE-2026-6284 — Horner Automation (Cscape), CVSS 9.3, CWE-521** : pas de complexité de mot de passe ni de
  verrouillage -> brute force réseau. Publiée 17/04/2026. [sentinelone](https://www.sentinelone.com/vulnerability-database/cve-2026-6284/)
- **CVE-2026-5817 — ABB AC500 : RCE via serveur Modbus TCP, sans authentification.**
- **CVE-2026-27565 / 27546 / 27557 — Pepperl+Fuchs, CVSS 9.8** : upload fichier IODD -> RCE root persistant après reboot ; auth bypass `_account_`. Corrigé en 1.7.4. [securityonline](https://securityonline.info/industrial-firmware-vulnerabilities/)
- **CVE-2026-18963 — Siemens Industrial Edge Management, CVSS 9.1** : bypass du flux reset Keycloak (pas de vérification e-mail) -> prise de compte. [viakoo](https://www.viakoo.com/blog/daily-ot-security-news-september-23-2026/) | [aviatrix](https://aviatrix.ai/threat-research-center/siemens-industrial-edge-management-cve-2026-18963-authentication-bypass-2026/)
- **CVE-2026-12663 — Rockwell ControlFLASH ≤ V15.07, CVSS 7.3** : droits "Everyone" en écriture sur le dossier d'installation -> exécution de code. [CISA ICSA-26-246-03](https://www.cisa.gov/news-events/ics-advisories/icsa-26-246-03)
- **CVE-2026-111280 — snap7 ≤ 1.4.3** : OOB write dans `TSnap7MicroClient::opReadArea()` — la librairie utilisée dans les attaques AA26-231A.
- **CVE-2026-6891 — bundle WAGO PFC / AVEVA Plant SCADA / Beckhoff TwinCAT** (21/05/2026).
- **CVE-2026-59310 — VMware vCenter, CVSS 9.8, exploitation active** : risque aigu quand vCenter héberge historian/HMI/SCADA virtualisés. [otsecuritywire](https://otsecuritywire.com/sectors/energy/)
- **CVE-2026-43499 — GhostLock (kernel Linux)** : privesc root ~5 s, 97 % fiabilité — historiens/SCADA Linux. [otsecuritywire](https://otsecuritywire.com/sectors/energy/)
- **CVE-2026-20182 — Siemens RUGGEDCOM ROS < 5.9.1, exploitation active** (KEV). [otsecuritywire](https://otsecuritywire.com/)
- **CVE-2026-88020 — OpenPLC Runtime v3, XSS CVSS 6.1** (EOL). [viakoo](https://www.viakoo.com/blog/daily-ot-security-news-september-23-2026/)
- **CVE-2026-92817 — Ignition Perspective module** ; **CVE-2025-7639 — AVEVA Enterprise SCADA (désérialisation)**. [otsecuritywire](https://otsecuritywire.com/)

## Tendances & technologies OT 2026
- Cadres : **IEC 62443** (nouveautés 2026 : -1-6 sécurité IIoT, -6-2 évaluation fournisseurs, -1-5 profils),
  **NIST SP 800-82**, **NIS2** (notification 24 h/72 h, responsabilité des dirigeants), modèle **Purdue** (zones/conduits), zero trust OT (PKI par actif).
  [iiot-world](https://www.iiot-world.com/ics-security/ics-ot-cybersecurity-trends-2026/) | [iiot-world manufacturing](https://www.iiot-world.com/ics-security/ot-cybersecurity-manufacturing-2026/) | [deltaroot](https://deltaroot.net/blog/iec62443-2026-ot-security-trends)
- Protocoles « legacy » sans auth/chiffrement : **Modbus, DNP3, BACnet, S7comm, OPC classic** — si atteignables, des commandes d'écriture passent. Durcissement : segmentation, IDS ICS, listes blanches. [macksofytrainings](https://www.macksofytrainings.com/ot-security-needs-in-2026-detailed-guide-to-protect-ics-scada/) | [otsecuritywire Modbus](https://otsecuritywire.com/articles/)
- **OPC UA (Eclipse Milo)** : bypass d'autorisation, fuite de diagnostics, oracle de padding Basic128Rsa15, DoS quotas — imposer mTLS, authZ, quotas. [agentic-ai-daily-reports](https://agentic-ai-daily-reports.netlify.app/cyber)
- Rapports : Waterfall/ICS STRIVE **2026 OT Cyber Threat Report** (incidents à impact physique -25 % en 2025 : 57 vs 76, ransomware en plateau) ; ransomware manufacturing +56 % en 2025 (1 466 incidents, 25 % d'arrêts de site). [waterfall](https://go.waterfall-security.com/hubfs/Gated%20content/2026%20OT%20Cyber%20Threat%20Report%20-%20Waterfall%20Security%20Solutions-1.pdf) | [iiot-world](https://www.iiot-world.com/ics-security/ot-cybersecurity-manufacturing-2026/)
- Exposé : 91 000 serveurs RDP et 29 000 VNC exposés (Forescout, avril 2026), dont 670 VNC sans auth vers des panneaux ICS/OT. [substack itsecalikhan](https://itsecalikhan.substack.com/p/april-2026-otics-cybersecurity-the)

## Sources machine (collecte auto)
- CISA RSS global : https://www.cisa.gov/rss.xml (contient les avis ICSA/ICSAA récents)
- Page avis ICS : https://www.cisa.gov/news-events/ics-advisories
- NVD API 2.0 : https://services.nvd.nist.gov/rest/json/cves/2.0 (rate limit 5 req/30 s sans clé)
- CISA KEV : https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
