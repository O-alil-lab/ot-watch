#!/usr/bin/env python3
"""Agent Analyste (RAG hybride) : construit un brief structuré et sourcé depuis les données
collectées (data/*.json = graphe de faits vérifiés, SQLite = historique) — chaque fait du brief
porte sa citation primaire (URL NVD/CISA/KEV/FIRST/ATT&CK)."""
import json
import os
import re
import sys
from datetime import UTC, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

NVD_URL = "https://nvd.nist.gov/vuln/detail/{cve}"
KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve={cve}"
FIRST_URL = "https://api.first.org/data/v1/epss?cve={cve}"
ATTCK_URL = "https://attack.mitre.org/techniques/{t}/"


def load_json(data_dir, name, default):
    p = os.path.join(data_dir, name)
    if not os.path.exists(p):
        return default
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def build_brief(data_dir, db_path=None, max_top=5):
    """Brief structuré : top CVE (déjà triées), avis, KEV nouveaux, tendances 30 j, citations."""
    cves = load_json(data_dir, "cves.json", [])
    advisories = load_json(data_dir, "cisa_advisories.json", [])
    kev = load_json(data_dir, "kev.json", [])
    meta = load_json(data_dir, "meta.json", {})

    def cve_facts(c):
        cites = [NVD_URL.format(cve=c["id"])]
        if c.get("kev"):
            cites.append(KEV_URL.format(cve=c["id"]))
        if c.get("epss") is not None:
            cites.append(FIRST_URL.format(cve=c["id"]))
        cites += [ATTCK_URL.format(t=t) for t in (c.get("attack_ics") or [])]
        cites += [r for r in (c.get("refs") or []) if isinstance(r, str) and r.startswith("http")]
        return {
            "id": c.get("id"), "cvss": c.get("cvss"), "severity": c.get("severity"),
            "epss": c.get("epss"), "risk": c.get("risk"), "kev": bool(c.get("kev")),
            "ssvc": c.get("ssvc"), "attack_ics": c.get("attack_ics") or [],
            "relevant": bool(c.get("relevant")), "published": (c.get("published") or "")[:10],
            "description": re.sub(r"\s+", " ", (c.get("description") or ""))[:300],
            "citations": cites,
        }

    history = []
    if db_path and os.path.exists(db_path):
        try:
            import store
            history = store.history_daily(db_path, days=30)
        except Exception:  # historique indisponible -> brief sans tendances
            history = []
    last7 = sum(s["total"] for s in history[-7:])
    prev7 = sum(s["total"] for s in history[-14:-7])

    diff = meta.get("diff", {})
    brief = {
        "generated_at": datetime.now(UTC).isoformat(),
        "window_days": meta.get("window_days", 14),
        "counts": meta.get("counts", {"cves": len(cves), "advisories": len(advisories), "kev": len(kev)}),
        "new_cves": diff.get("new_cves", []),
        "new_kev": diff.get("new_kev", []),
        "top_cves": [cve_facts(c) for c in cves[:max_top]],
        "relevant_cves": [cve_facts(c) for c in cves if c.get("relevant")][:max_top],
        "advisories": [{"code": a.get("code"), "title": a.get("title"), "link": a.get("link"),
                        "published": (a.get("published") or "")[:10],
                        "summary": re.sub(r"\s+", " ", a.get("summary") or "")[:240],
                        "citations": [a.get("link")] if a.get("link") else []} for a in advisories[:10]],
        "kev_total": len(kev),
        "trends": {"history": history, "last7_total": last7, "prev7_total": prev7,
                   "delta_pct": round(100 * (last7 - prev7) / prev7, 1) if prev7 else None},
        "exposure_label": "Mes actifs OT",
        "sources": sorted({u for c in cves for u in
                           [NVD_URL.format(cve=c["id"])] + ([KEV_URL.format(cve=c["id"])] if c.get("kev") else [])}),
    }
    return brief
