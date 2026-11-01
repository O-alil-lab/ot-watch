#!/usr/bin/env python3
"""
OT Watch — collecte réseau PASSIVE (P1 runbook) : analyse des logs Zeek (conn.log)
pour découvrir les actifs OT réellement présents sur le réseau (jamais de scan actif,
jamais inline — lecture seule de logs produits sur port SPAN/TAP).

  - parse_conn_log() : lit un conn.log Zeek (TSV, ligne d'en-tête #fields).
  - summarize()      : regroupe par (responder IP, port) les flux sur des ports OT/ICS,
                       devine le protocole/éditeur, détecte les nouveautés vs baseline.
  - run()            : produit data/netwatch.json (actifs découverts + anomalies),
                       consommé par /api/netwatch et le dashboard.

Ports OT/ICS surveillés (config.json["netwatch"]["ot_ports"] surchargeable) :
  502 Modbus/TCP · 20000 DNP3 · 102 S7comm · 44818 EtherNet/IP (CIP)
  4840 OPC UA · 2404 IEC 60870-5-104 · 47808 BACnet/IP · 34964/34980 Wago/…
Voir research/RUNBOOK-COLLECTE-PASSIVE-OT-2026-11-01.md et tests/test_netwatch.py.
"""
import glob
import json
import os
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")

DEFAULT_OT_PORTS = {
    "502": {"proto": "Modbus/TCP", "vendor_hint": "multi-éditeurs (Schneider/Siemens/…)"},
    "20000": {"proto": "DNP3", "vendor_hint": "multi-éditeurs (GE/SEL/…)"},
    "102": {"proto": "S7comm (ISO-on-TCP)", "vendor_hint": "Siemens"},
    "44818": {"proto": "EtherNet/IP (CIP)", "vendor_hint": "Rockwell/Allen-Bradley"},
    "4840": {"proto": "OPC UA", "vendor_hint": "multi-éditeurs (open62541/KEPServer/…)"},
    "2404": {"proto": "IEC 60870-5-104", "vendor_hint": "multi-éditeurs (secteur énergie)"},
    "47808": {"proto": "BACnet/IP", "vendor_hint": "BMS/bâtiment"},
    "34980": {"proto": "Wago/… propriétaire", "vendor_hint": "Wago"},
}


def parse_conn_log(path):
    """Parse un conn.log Zeek -> liste de dicts (champs standards Zeek)."""
    rows = []
    fields = None
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("#fields"):
                fields = line[len("#fields"):].strip().split("\t")
                continue
            if line.startswith("#"):
                continue
            if not fields:
                continue
            vals = line.split("\t")
            rows.append(dict(zip(fields, vals)))
    return rows


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def summarize(rows, cfg=None, baseline=None):
    """Agrège les flux conn.log -> {assets_discovered, anomalies, stats}.

    Un « actif découvert » = IP responder (id.resp_h) sur au moins un port OT/ICS.
    Une « anomalie » = nouveau couple (resp_h, resp_p) non présent dans la baseline,
    ou flux sur un port OT depuis une IP jamais vue.
    """
    cfg = cfg or {}
    ot_ports = {str(k): v for k, v in {**DEFAULT_OT_PORTS, **(cfg.get("ot_ports") or {})}.items()}
    base_flows = set()
    base_hosts = set()
    if baseline:
        base_flows = {(f.get("resp_h"), str(f.get("resp_p"))) for f in baseline.get("flows", [])}
        base_hosts = {a.get("ip") for a in baseline.get("assets_discovered", [])}

    per_host = {}   # resp_h -> {ports: {port: {conns, orig_bytes, resp_bytes, service}}, services}
    for r in rows:
        resp_h = r.get("id.resp_h") or ""
        resp_p = str(r.get("id.resp_p") or "")
        if not resp_h or resp_p not in ot_ports:
            continue
        h = per_host.setdefault(resp_h, {"ports": {}, "orig_h": set()})
        p = h["ports"].setdefault(resp_p, {"conns": 0, "orig_bytes": 0, "resp_bytes": 0})
        p["conns"] += 1
        p["orig_bytes"] += _int(r.get("orig_bytes"))
        p["resp_bytes"] += _int(r.get("resp_bytes"))
        if r.get("id.orig_h"):
            h["orig_h"].add(r["id.orig_h"])

    assets_discovered = []
    anomalies = []
    flows = []
    for ip, h in sorted(per_host.items()):
        services = []
        for port, p in sorted(h["ports"].items(), key=lambda kv: -kv[1]["conns"]):
            spec = ot_ports[port]
            services.append({"port": int(port), "proto": spec["proto"], "vendor_hint": spec["vendor_hint"],
                             "conns": p["conns"], "orig_bytes": p["orig_bytes"], "resp_bytes": p["resp_bytes"]})
            flows.append({"resp_h": ip, "resp_p": int(port), "conns": p["conns"]})
            if (ip, port) not in base_flows:
                anomalies.append({"type": "nouveau_flux_OT", "resp_h": ip, "resp_p": int(port),
                                  "proto": spec["proto"], "conns": p["conns"]})
        if ip not in base_hosts:
            anomalies.append({"type": "nouvel_hote_OT", "resp_h": ip,
                              "services": [s["proto"] for s in services]})
        assets_discovered.append({
            "ip": ip,
            "asset_id": "net-" + ip.replace(".", "-"),
            "name": f"Équipement OT découvert {ip}",
            "vendor": services[0]["vendor_hint"] if services else "",
            "product": " / ".join(sorted({s["proto"] for s in services})),
            "purdue_level": "L1", "criticality": "medium", "source": "netwatch",
            "clients": sorted(h["orig_h"]),
            "services": services,
        })

    stats = {
        "flows_OT": sum(f["conns"] for f in flows),
        "hosts_OT": len(assets_discovered),
        "ports_OT": sorted({f["resp_p"] for f in flows}),
        "total_rows": len(rows),
    }
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "assets_discovered": assets_discovered,
        "anomalies": anomalies,
        "flows": flows,
        "stats": stats,
    }


def run(conn_glob=None, out_path=None, cfg=None, baseline_path=None):
    """Lit les conn.log (glob), produit le rapport netwatch JSON. Retourne le rapport."""
    cfg = cfg or {}
    if conn_glob is None:
        conn_glob = cfg.get("conn_logs", "logs/zeek/conn.log*")
    if out_path is None:
        out_path = os.path.join(DATA, "netwatch.json")
    if baseline_path is None:
        baseline_path = out_path if os.path.exists(out_path) else None
    baseline = None
    if baseline_path and os.path.exists(baseline_path):
        with open(baseline_path, encoding="utf-8") as fh:
            baseline = json.load(fh)

    rows = []
    files = sorted(glob.glob(conn_glob))
    for f in files:
        rows.extend(parse_conn_log(f))
    report = summarize(rows, cfg, baseline)
    report["sources"] = files
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    return report


def main():
    cfg_path = os.path.join(ROOT, "config.json")
    cfg = {}
    if os.path.exists(cfg_path):
        with open(cfg_path, encoding="utf-8") as fh:
            cfg = json.load(fh)
    nw = cfg.get("netwatch", {})
    rep = run(nw.get("conn_logs"), cfg=nw)
    s = rep["stats"]
    print(f"[netwatch] {s['flows_OT']} flux OT sur {len(s['ports_OT'])} ports · "
          f"{s['hosts_OT']} hôtes OT découverts · {len(rep['anomalies'])} anomalies "
          f"-> data/netwatch.json")
    for a in rep["assets_discovered"][:10]:
        print(f"  - {a['ip']} ({a['product']}) clients={len(a['clients'])}")
    for an in rep["anomalies"][:10]:
        print(f"  ! {an['type']}: {an.get('resp_h')}:{an.get('resp_p', '')} {an.get('proto', '')}")


if __name__ == "__main__":
    main()
