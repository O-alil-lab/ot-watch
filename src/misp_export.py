#!/usr/bin/env python3
"""
OT Watch — connecteur MISP (P2 « partage communautaire » / OT-ISAC).
Produit un événement MISP (JSON) depuis les données collectées :
  out/issue-<date>.misp.json  — attributs type "cve" (avec CVSS/EPSS/KEV/SSVC/ATT&CK en commentaire),
  "link" pour les avis CISA, tags TLP:WHITE/ot/ics.
Si OTWATCH_MISP_URL + OTWATCH_MISP_AUTHKEY sont définis -> POST /events/add (push réel vers l'instance
MISP / communauté OT-ISAC) ; sinon dry-run (fichier + log). OTWATCH_MISP_VERIFY_SSL=0 pour désactiver
la vérification TLS (labo uniquement). Servi aussi sur GET /misp.
Voir tests/test_misp.py.
"""
import json
import os
import urllib.request
from datetime import UTC, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
OUT = os.path.join(ROOT, "out")
os.makedirs(OUT, exist_ok=True)


def load_json(name, default):
    p = os.path.join(DATA, name)
    if not os.path.exists(p):
        return default
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def build_misp_event(cves, advisories, meta, issue_date):
    attrs = []
    for c in cves:
        comment = (f"CVSS {c.get('cvss')} | EPSS {c.get('epss')} | risque {c.get('risk')} | "
                   f"KEV={bool(c.get('kev'))} | SSVC={c.get('ssvc')} | ATT&CK ICS {','.join(c.get('attack_ics') or [])} | "
                   f"profil actifs OT={bool(c.get('relevant'))}")
        attrs.append({"type": "cve", "value": c.get("id"), "comment": comment, "to_ids": bool(c.get("kev")),
                      "category": "Payload delivery" if c.get("kev") else "Network", "distribution": "5"})
    for a in advisories:
        attrs.append({"type": "link", "value": a.get("link") or a.get("code"), "comment": f"{a.get('code')} — {a.get('title')}",
                      "category": "External analysis", "distribution": "5"})
    return {"Event": {
        "info": f"OT Watch — veille OT/ICS — édition {issue_date} ({len(cves)} CVE OT, {len(advisories)} avis CISA ICS)",
        "threat_level_id": "2", "analysis": "2", "distribution": "0", "published": False,
        "Tag": [{"name": "TLP:WHITE"}, {"name": "ot"}, {"name": "ics"}, {"name": "ics-ot"}],
        "Attribute": attrs,
        "date": issue_date,
    }}


def push_to_misp(event, base_url, authkey, verify_ssl=True, timeout=30):
    """POST /events/add — renvoie l'id MISP de l'événement créé."""
    url = base_url.rstrip("/") + "/events/add"
    req = urllib.request.Request(url, data=json.dumps(event).encode("utf-8"), method="POST",
                                 headers={"Authorization": authkey, "Accept": "application/json",
                                          "Content-Type": "application/json"})
    ctx = None
    if not verify_ssl:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return (data.get("Event") or {}).get("id")


def main():
    meta = load_json("meta.json", {})
    cves = load_json("cves.json", [])
    advisories = load_json("cisa_advisories.json", [])
    fname = (meta.get("generated_at") or datetime.now(UTC).isoformat())[:10]
    event = build_misp_event(cves, advisories, meta, fname)
    out_path = os.path.join(OUT, f"issue-{fname}.misp.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(event, fh, ensure_ascii=False, indent=2)
    n = len(event["Event"]["Attribute"])
    base = os.environ.get("OTWATCH_MISP_URL", "")
    key = os.environ.get("OTWATCH_MISP_AUTHKEY", "")
    if base and key:
        verify = os.environ.get("OTWATCH_MISP_VERIFY_SSL", "1") != "0"
        try:
            eid = push_to_misp(event, base, key, verify_ssl=verify)
            print(f"[misp] {out_path} ({n} attributs) + PUSH MISP event id={eid} ({base})")
            return
        except Exception as exc:  # le fichier local reste la source de vérité
            print(f"[misp] push échoué ({exc}) -> dry-run local : {out_path} ({n} attributs)")
            return
    print(f"[misp] dry-run (OTWATCH_MISP_URL/AUTHKEY non définis) -> {out_path} ({n} attributs)")


if __name__ == "__main__":
    main()
