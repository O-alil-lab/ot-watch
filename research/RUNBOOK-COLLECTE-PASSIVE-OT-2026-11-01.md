# 📡 Runbook — collecte réseau PASSIVE OT/ICS (Zeek / Suricata+ICSNPP / Malcolm)

**Date** : 2026-11-01 · **Périmètre** : réseau industriel (Purdue L0–L3.5) · **Règle d'or** : **jamais inline, jamais de scan actif**. On observe uniquement, sur copie de trafic (SPAN/TAP) ou sur des logs existants.

---

## 0. Principes de sécurité opérationnelle (OT)

1. **Passif uniquement** : miroir de port (SPAN) ou TAP optique vers le capteur. Aucun équipement OT ne voit le capteur ; le capteur n'émet **aucun** paquet sur le réseau OT (interface en `PROMISC` RX-only, pas de gateway par défaut sur OT).
2. **Pas de scan actif** (pas de ping sweep, pas de scan de ports, pas de requêtes S7/Modbus « discovery »). La découverte d'actifs se fait **uniquement** à partir du trafic observé (`conn.log` Zeek → `src/netwatch.py`).
3. **Segmentation** : le capteur vit en L3.5/DMZ industrielle, management via un lien séparé (out-of-band). Accès restreint (bastion + MFA), logs du capteur chiffrés au repos, rétention 30–90 j.
4. **Disponibilité** : un capteur qui tombe ne doit jamais bloquer la production → SPAN/TAP uniquement, jamais inline (un TAP fail-open est acceptable, un équipement inline non).
5. Conformité interne : déclarez la collecte passive à l'OT security owner ; conservez la preuve de configuration (ce runbook + `data/netwatch.json` horodaté).

## 1. Architecture cible

```
 [switch OT L1/L2] --SPAN/TAP--> [capteur passif]
                                    ├─ Zeek        (conn.log, dns.log, modbus.log, s7comm.log, enip.log, opcua.log, iec60870.log…)
                                    ├─ Suricata + ruleset ET ICSNPP (alerts JSON : eve.json)
                                    └─ (option Malcolm = Arkime + Zeek + Suricata + NetFlow, tout en Docker)
                                          │
                                          ▼  transfert régulier (rsync/scp) vers OT Watch
                                   OT Watch : src/netwatch.py -> data/netwatch.json -> /api/netwatch
```

## 2. Option A — Zeek autonome (léger, recommandé pour démarrer)

```bash
# Debian/Ubuntu
sudo apt-get install -y zeek          # ou build depuis source (zeek.org) pour la dernière version
# Démarrage en standalone sur l'interface miroir (ex. ens19, RX-only)
sudo zeek -i ens19 local   # ou: zeekctl deploy avec un node standalone
```

`local.zeek` minimal (protocoles ICS activés par défaut dans Zeek) :

```zeek
@load packages          # zeek packages si installés (zeek/spicy-… optionnel)
redef ignore_checksums = T;   # souvent nécessaire sur SPAN (checksums invalides)
# Les analyseurs ICS sont built-in : modbus, dnp3, enip, s7comm, opcua, iec60870, bacnet…
# Politique de rétention des logs :
redef LogAscii::use_json = T;
```

Vérification : `ls /usr/local/zeek/logs/current/ | grep -E 'conn|modbus|s7comm|enip|opcua'`.

**Transfert vers OT Watch** (cron, ex. toutes les heures) :

```bash
rsync -az /usr/local/zeek/logs/current/conn.log otwatch-host:/home/user/newsletter-ot/logs/zeek/
# puis côté OT Watch :
cd /home/user/newsletter-ot && python3 src/netwatch.py
curl -s http://127.0.0.1:8000/api/netwatch | jq '.stats'
```

## 3. Option B — Suricata + jeu de règles ICSNPP (détection d'attaques)

```bash
sudo apt-get install -y suricata
# Règles Emerging Threats ICSNPP (gratuites) :
sudo suricata-update enable et/open   # puis sélection du source emerging-icsnpp (ou oinkmaster)
sudo suricata-update
```

`suricata.yaml` : interface miroir en AF_PACKET, `HOME_NET: "[10.10.0.0/16, 192.168.1.0/24]"` (vos plages OT), sorties `eve-log` JSON activées, `stats` activé. Démarrage : `sudo suricata -i ens19 -c /etc/suricata/suricata.yaml`.

Règles utiles (ET ICSNPP) : `alert tcp any any -> $HOME_NET 502` (Modbus non whitelisté), signatures S7comm write, EtherNet/IP CIP, DNP3, OPC UA non autorisé, scans horizontaux, beaconing vers l'extérieur (L4/L5).

Alerte → OT Watch : copier `eve.json` vers `logs/suricata/` et ajouter plus tard un connecteur (hors scope de ce runbook ; les alertes Suricata restent dans eve.json et peuvent être corrélées manuellement avec `data/netwatch.json`).

## 4. Option C — Malcolm (tout-en-un, Docker)

```bash
git clone --depth 1 https://github.com/idaholab/Malcolm.git && cd Malcolm
./scripts/install.py            # configure docker + sysctl (vm.max_map_count…)
./scripts/start                # Arkime (PCAP) + Zeek + Suricata + NetFlow + dashboards (https://localhost:443)
```
Exportez périodiquement `conn.log` de Zeek (Malcolm) vers OT Watch (`logs/zeek/`) → même pipeline `netwatch.py`.

## 5. Ports OT/ICS surveillés par défaut (config.json["netwatch"]["ot_ports"])

| Port | Protocole | Éditeur typique |
|---|---|---|
| 502/TCP | Modbus/TCP | Schneider, Siemens, Wago… |
| 20000/TCP/UDP | DNP3 | GE, SEL, Schneider… (secteur énergie) |
| 102/TCP | S7comm (ISO-on-TCP) | Siemens S7 |
| 44818/TCP UDP | EtherNet/IP (CIP) | Rockwell/Allen-Bradley |
| 4840/TCP | OPC UA | multi-éditeurs (open62541, KEPServer…) |
| 2404/TCP | IEC 60870-5-104 | multi-éditeurs (énergie) |
| 47808/UDP | BACnet/IP | BMS/bâtiment |
| 34980 | propriétaire (ex. Wago) | Wago |

## 6. Intégration OT Watch — découverte d'actifs & anomalies

```bash
cd /home/user/newsletter-ot
python3 src/netwatch.py                 # lit config.json["netwatch"]["conn_logs"] -> data/netwatch.json
python3 scripts/zeek_to_assets.py --assets   # bloc JSON à copier dans config.json["assets"]
```

- `data/netwatch.json` : `assets_discovered` (IP responder + services OT + clients), `anomalies` (**nouvel hôte OT**, **nouveau flux OT** vs baseline précédente), `flows`, `stats`.
- API live : `GET /api/netwatch` (404 tant qu'aucun rapport n'existe), métriques `/metrics` : `otwatch_netwatch_hosts_ot`, `otwatch_netwatch_anomalies_total`.
- Les actifs découverts alimentent ensuite le **score OT** (v1.12) : copiez les propositions dans `config.json["assets"]` (avec `purdue_level`/`criticality` revus par l'OT owner), la prochaine collecte matchera les CVE dessus (`asset_impact` → `ot_score`).

## 7. Procédure hebdomadaire (check-list)

1. Vérifier que le SPAN/TAP alimente bien le capteur (`tcpdump -i ens19 -c 10` côté capteur, RX-only).
2. `python3 src/netwatch.py` ; lire `anomalies` : tout **nouvel hôte OT** doit être identifié (CMDB) ou investigué ; tout **nouveau flux OT** (ex. 502 depuis une IP inconnue) → alerte OT security owner.
3. Corréler `eve.json` (Suricata) : alertes ICSNPP de la semaine → tickets.
4. Revoir `config.json["assets"]` : IPs découvertes → `asset_id` stables, niveaux Purdue à jour.
5. Nettoyage : purger les logs Zeek > 30 j côté capteur ; `backups/` OT Watch conservés 30 j (`scripts/backup.sh`).
6. Mettre à jour ce runbook si topologie change (nouveau VLAN OT, nouveau protocole).

## 8. En cas d'incident (alerte ICSNPP / anomalie grave)

1. **Ne pas toucher au réseau OT** : aucune action inline depuis le capteur.
2. Isoler le segment concerné via les équipements réseau prévus à cet effet (procédures OT existantes), pas via le capteur.
3. Capturer un PCAP de référence (Arkime/Malcolm ou `tcpdump -w`) **avant** toute remédiation, horodaté, signé (sha256) — preuve forensic.
4. Notifier : OT security owner, RSSI, et si exigence réglementaire (NIS2 / secteurs régulés) l'autorité compétente dans les délais.
5. Post-incident : alimenter `config.json["assets"]`/watchlist CVE, rejouer la collecte (`src/replay.py` depuis `data/raw/`) pour vérifier la couverture.

## 9. Limites connues

- Le trafic chiffré (OPC UA over TLS, HTTPS L4) n'est pas déchiffré côté capteur (volontaire) : s'appuie sur les métadonnées + certificats.
- Zeek sur SPAN peut manquer des paquets si le lien miroir est saturé → surveiller `missed_bytes` dans conn.log ; préférer un TAP dédié sur les liens critiques.
- `netwatch.py` déduit les actifs des **réponses** (id.resp_h) : un équipement silencieux (capteur L0 qui n'initie rien) n'apparaît que s'il répond — compléter manuellement dans `config.json`.
