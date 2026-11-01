#!/usr/bin/env python3
"""
OT Watch — replay depuis la couche raw (P2 « DR / rejouabilité »).
Rejoue data/raw/<run>/ SANS réseau : relit le manifest + les réponses brutes et recalcule
les artefacts (CVE NVD, avis RSS, KEV, GHSA) -> data/replay/<run>.json.
Usage : python3 src/replay.py [--raw data/raw/<run>]   (dernier run par défaut)
Permet de reproduire une édition hors-ligne (incident source, test de non-régression, audit).
Voir tests/test_replay.py.
"""
import argparse
import json
import os
import re
import sys
from datetime import UTC, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
DATA = os.path.join(ROOT, "data")

import collect  # noqa: E402  (parseurs purs : parse_rss_items, _cve_record...)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def latest_raw_dir(data_dir=DATA):
    raw = os.path.join(data_dir, "raw")
    if not os.path.isdir(raw):
        return None
    runs = sorted(d for d in os.listdir(raw) if os.path.isdir(os.path.join(raw, d)))
    return os.path.join(raw, runs[-1]) if runs else None


def replay(raw_dir, window_days=14):
    """Rejoue un run raw -> dict {cve_ids, advisories, kev_count, ghsa_ids, sources}."""
    with open(os.path.join(raw_dir, "manifest.json"), encoding="utf-8") as fh:
        entries = json.load(fh)
    out = {"raw_dir": raw_dir, "replayed_at": datetime.now(UTC).isoformat(), "sources": [],
           "cve_ids": set(), "advisories": [], "kev_count": 0, "ghsa_ids": set()}
    vendor_re = re.compile(collect.CFG["vendor_regex"], re.IGNORECASE)
    for e in entries:
        url, fn = e["url"], e["file"]
        path = os.path.join(raw_dir, fn)
        if not os.path.exists(path):
            continue
        out["sources"].append(url)
        with open(path, "rb") as fh:
            body = fh.read()
        if "known_exploited" in url:
            d = json.loads(body)
            ot_re = re.compile(collect.CFG["ot_kev_regex"], re.IGNORECASE)
            out["kev_count"] = sum(1 for v in d.get("vulnerabilities", []) if ot_re.search(
                " ".join(str(v.get(k, "")) for k in ("vendorProject", "product", "vulnerabilityName", "shortDescription"))))
        elif "rss.xml" in url or "ics-advisories.xml" in url:
            out["advisories"] += collect.parse_rss_items(body, window_days)
        elif "api.github.com/advisories" in url:
            data = json.loads(body)
            if isinstance(data, list):
                out["ghsa_ids"].update(a.get("cve_id") for a in data if a.get("cve_id"))
        elif "services.nvd.nist.gov" in url:
            d = json.loads(body)
            for v in d.get("vulnerabilities", []):
                rec = collect._cve_record(v["cve"], vendor_re)
                if rec:
                    out["cve_ids"].add(rec["id"])
                elif "cveId=" in url:
                    out["cve_ids"].add(v["cve"]["id"])
    out["cve_ids"] = sorted(out["cve_ids"])
    out["ghsa_ids"] = sorted(out["ghsa_ids"])
    out["advisories"] = len(out["advisories"])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", default=None, help="dossier data/raw/<run> (défaut: dernier)")
    args = ap.parse_args()
    raw_dir = args.raw or latest_raw_dir()
    if not raw_dir or not os.path.exists(os.path.join(raw_dir, "manifest.json")):
        print("[replay] aucun run raw trouvé (lancez ./run_all.sh)")
        return
    res = replay(raw_dir)
    os.makedirs(os.path.join(DATA, "replay"), exist_ok=True)
    dst = os.path.join(DATA, "replay", os.path.basename(raw_dir.rstrip("/")) + ".json")
    with open(dst, "w", encoding="utf-8") as fh:
        json.dump(res, fh, ensure_ascii=False, indent=2)
    print(f"[replay] {raw_dir} -> {dst} : {len(res['cve_ids'])} CVE, {res['advisories']} avis, "
          f"KEV {res['kev_count']}, {len(res['ghsa_ids'])} GHSA, {len(res['sources'])} sources rejouées (0 appel réseau)")


if __name__ == "__main__":
    main()
