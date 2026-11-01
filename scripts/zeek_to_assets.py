#!/usr/bin/env python3
"""Convertit les logs Zeek conn.log (collecte passive SPAN/TAP) en propositions
d'actifs OT pour config.json["assets"] — sans jamais toucher au réseau (lecture seule).

Usage :
  python3 scripts/zeek_to_assets.py [logs/zeek/conn.log ...] [--out data/netwatch.json] [--assets]
    --assets : imprime aussi le bloc JSON "assets" à copier dans config.json.
Voir research/RUNBOOK-COLLECTE-PASSIVE-OT-2026-11-01.md.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
import netwatch


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logs", nargs="*", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--assets", action="store_true", help="imprime le bloc assets pour config.json")
    args = ap.parse_args()

    cfg = {}
    cfg_path = os.path.join(netwatch.ROOT, "config.json")
    if os.path.exists(cfg_path):
        with open(cfg_path, encoding="utf-8") as fh:
            cfg = json.load(fh).get("netwatch", {})

    if args.logs:
        rows = []
        for f in args.logs:
            rows.extend(netwatch.parse_conn_log(f))
        rep = netwatch.summarize(rows, cfg)
        rep["sources"] = args.logs
    else:
        rep = netwatch.run(cfg.get("conn_logs"), out_path=args.out, cfg=cfg)

    print(json.dumps(rep, ensure_ascii=False, indent=2))
    if args.assets:
        proposals = [{k: a[k] for k in ("asset_id", "name", "vendor", "product", "purdue_level", "criticality")
                      if k in a} | {"ip": a["ip"]} for a in rep["assets_discovered"]]
        print("\n--- bloc à ajouter dans config.json -> \"assets\" ---")
        print(json.dumps(proposals, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
