#!/usr/bin/env python3
"""
OT Watch — validation qualité des données collectées (ECC data-quality gates).
Bloque/publie avec avertissement si le schéma est violé ou si le volume chute brutalement
(signe d'une source cassée). Appelé à chaque collecte, avant écriture finale.
"""
import re
from datetime import datetime

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")


def _check_cve(c, issues):
    cid = c.get("id", "")
    if not CVE_RE.match(cid):
        issues.append(f"id CVE invalide: {cid!r}")
    cvss = c.get("cvss")
    if cvss is not None and not (isinstance(cvss, (int, float)) and 0.0 <= cvss <= 10.0):
        issues.append(f"{cid}: CVSS hors [0,10]: {cvss!r}")
    if not (c.get("description") or "").strip():
        issues.append(f"{cid}: description vide")
    pub = c.get("published") or ""
    if pub and not DATE_RE.match(pub):
        issues.append(f"{cid}: published invalide: {pub!r}")


def validate_all(payload):
    """payload = {cves, advisories, kev}. Retourne {ok, issues, counts}."""
    issues = []
    cves = payload.get("cves", [])
    for c in cves:
        _check_cve(c, issues)
    for a in payload.get("advisories", []):
        link = a.get("link", "")
        if not link.lower().startswith(("http://", "https://")):
            issues.append(f"avis {a.get('code') or a.get('title')!r}: lien non http(s): {link!r}")
        if not (a.get("title") or "").strip():
            issues.append("avis sans titre")
    for k in payload.get("kev", []):
        if not CVE_RE.match(k.get("cveID", "")):
            issues.append(f"KEV id invalide: {k.get('cveID')!r}")
    counts = {
        "cves": len(cves),
        "advisories": len(payload.get("advisories", [])),
        "kev": len(payload.get("kev", [])),
    }
    return {"ok": not issues, "issues": issues[:50], "counts": counts, "checked_at": datetime.utcnow().isoformat() + "Z"}


def volume_check(prev_counts, new_counts, threshold=0.3):
    """Alerte si le nombre de CVE chute de plus de `threshold` (ex. source NVD cassée)."""
    issues = []
    prev = (prev_counts or {}).get("cves", 0)
    new = (new_counts or {}).get("cves", 0)
    if prev > 0 and new < prev * (1 - threshold):
        issues.append(f"volume CVE en chute: {prev} -> {new} (-{int(100 * (1 - new / prev))}%) : vérifier la source NVD")
    return issues
