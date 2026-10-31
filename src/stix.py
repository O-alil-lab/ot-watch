#!/usr/bin/env python3
"""
OT Watch — export STIX 2.1 (OASIS) de l'édition (roadmap « plateforme de référence ») :
  out/issue-<AAAA-MM-JJ>.stix.json  → bundle STIX 2.1 (vulnerability, course-of-action,
  report, marking-definition TLP:WHITE), servi aussi par le serveur live sur GET /stix
  (Content-Type: application/stix+json) — compatible TAXII 2.1 / MISP / OpenCTI / CISA AIS.

Conventions :
  - IDs déterministes (uuid5) → dédup idempotente côté consommateur.
  - Chaque vulnérabilité référence NVD + KEV (si applicable) + MITRE ATT&CK for ICS
    (external_references source_name="mitre-attack") + nos champs OT en x_otwatch_*.
  - TLP:WHITE (données publiques CISA/NVD/FIRST) via marking-definition + object_marking_refs.
Voir tests/test_stix.py.
"""
import json
import os
import uuid
from datetime import UTC, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
OUT = os.path.join(ROOT, "out")
os.makedirs(OUT, exist_ok=True)

STIX_NS = "https://otwatch.local/stix/"
MEDIA_TYPE = "application/stix+json"


def _sid(kind, key):
    return f"{kind}--{uuid.uuid5(uuid.NAMESPACE_URL, STIX_NS + kind + '/' + key)}"


def load_json(name, default):
    p = os.path.join(DATA, name)
    if not os.path.exists(p):
        return default
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def _ts(value, default=None):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except (ValueError, TypeError):
        return default or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def tlp_white_marking():
    return {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": _sid("marking-definition", "tlp-white"),
        "created": "2026-01-01T00:00:00.000Z",
        "definition_type": "tlp",
        "name": "TLP:WHITE",
        "definition": {"tlp": "white"},
    }


def cve_to_vulnerability(c, marking_id):
    """STIX 2.1 vulnerability SDO pour une CVE, avec refs NVD/KEV/ATT&CK-ICS et props OT."""
    cve_id = c.get("id", "UNKNOWN")
    ext = [{"source_name": "NVD", "external_id": cve_id, "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"}]
    if c.get("kev"):
        ext.append({"source_name": "CISA KEV", "external_id": cve_id,
                    "url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve={cve_id}"})
    for tech in c.get("attack_ics") or []:
        ext.append({"source_name": "mitre-attack", "external_id": tech,
                    "url": f"https://attack.mitre.org/techniques/{tech}/",
                    "description": "MITRE ATT&CK for ICS"})
    for ref in c.get("refs") or []:
        if isinstance(ref, str) and ref.startswith("http"):
            ext.append({"source_name": "reference", "url": ref})
    created = _ts(c.get("published"))
    obj = {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": _sid("vulnerability", cve_id),
        "created": created,
        "modified": _ts(c.get("lastModified"), created),
        "name": cve_id,
        "description": (c.get("description") or "")[:4000],
        "object_marking_refs": [marking_id],
        "external_references": ext,
        "x_otwatch_cvss": c.get("cvss"),
        "x_otwatch_severity": c.get("severity"),
        "x_otwatch_epss": c.get("epss"),
        "x_otwatch_kev": bool(c.get("kev")),
        "x_otwatch_risk": c.get("risk"),
        "x_otwatch_relevant": bool(c.get("relevant")),
        "x_otwatch_ssvc": c.get("ssvc"),
        "x_otwatch_attack_ics": c.get("attack_ics") or [],
    }
    return {k: v for k, v in obj.items() if v is not None}


def advisory_to_course_of_action(a, marking_id):
    code = a.get("code") or "ICSA"
    ext = []
    if a.get("link"):
        ext.append({"source_name": "CISA", "url": a["link"]})
    return {
        "type": "course-of-action",
        "spec_version": "2.1",
        "id": _sid("course-of-action", code),
        "created": _ts(a.get("published")),
        "modified": _ts(a.get("published")),
        "name": f"{code} — {a.get('title', '')}"[:256],
        "description": (a.get("summary") or "")[:2000],
        "object_marking_refs": [marking_id],
        "external_references": ext,
    }


def build_bundle(cves, advisories, meta, issue_date):
    """Bundle STIX 2.1 complet : marking TLP:WHITE + vulnerabilities + COA + report."""
    marking = tlp_white_marking()
    marking_id = marking["id"]
    objects = [marking]
    vuln_ids = []
    for c in cves:
        v = cve_to_vulnerability(c, marking_id)
        objects.append(v)
        vuln_ids.append(v["id"])
    coa_ids = []
    for a in advisories:
        coa = advisory_to_course_of_action(a, marking_id)
        objects.append(coa)
        coa_ids.append(coa["id"])
    report = {
        "type": "report",
        "spec_version": "2.1",
        "id": _sid("report", f"otwatch-{issue_date}"),
        "created": _ts(meta.get("generated_at")),
        "modified": _ts(meta.get("generated_at")),
        "name": f"OT Watch — veille OT/ICS — édition du {issue_date}",
        "description": (f"{len(cves)} CVE OT, {len(advisories)} avis CISA ICS, fenêtre "
                        f"{meta.get('window_days', 14)} j. Généré automatiquement depuis CISA/NVD/KEV/FIRST EPSS."),
        "report_types": ["threat-report"],
        "labels": ["ot", "ics", "ransomware-KEV" if any(c.get("kev") for c in cves) else "ot"],
        "published": _ts(meta.get("generated_at")),
        "object_refs": vuln_ids + coa_ids,
        "object_marking_refs": [marking_id],
    }
    objects.append(report)
    return {
        "type": "bundle",
        "id": _sid("bundle", f"otwatch-{issue_date}"),
        "objects": objects,
    }


def main():
    meta = load_json("meta.json", {})
    cves = load_json("cves.json", [])
    advisories = load_json("cisa_advisories.json", [])
    fname = (meta.get("generated_at") or datetime.now(UTC).isoformat())[:10]
    issue_date = fname
    bundle = build_bundle(cves, advisories, meta, issue_date)
    out_path = os.path.join(OUT, f"issue-{fname}.stix.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, ensure_ascii=False, indent=2)
    n_vuln = sum(1 for o in bundle["objects"] if o["type"] == "vulnerability")
    n_coa = sum(1 for o in bundle["objects"] if o["type"] == "course-of-action")
    print(f"[stix] {out_path} ({os.path.getsize(out_path)} o, {n_vuln} vulnerabilities, {n_coa} course-of-action, TLP:WHITE)")


if __name__ == "__main__":
    main()
