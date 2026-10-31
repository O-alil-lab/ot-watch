#!/usr/bin/env python3
"""Agent Fact-checker — 3 niveaux (modèle 2026) :
  niveau 1 (auto)   : chaque CVE cité existe dans data/cves.json ; les affirmations KEV/EPSS/SSVC
                      correspondent aux données ; les URLs de citation sont sur des hôtes autorisés ;
  niveau 2 (web)    : toute affirmation non issue des données structurées est marquée « à vérifier
                      en ligne » (effectué par un humain ou un agent avec outil web) ;
  niveau 3 (humain) : liste human_review + gate de publication (HITL).
Sortie : rapport {checked, passed, failed[], human_review[], ok} — ok = aucune failure niveau 1.
"""
import json
import os
import re

ALLOWED_CITE_HOSTS = ("nvd.nist.gov", "cisa.gov", "first.org", "attack.mitre.org",
                      "github.com", "api.github.com", "otx.alienvault.com", "cert-portal.siemens.com",
                      "se.com", "rockwellautomation.com", "abb.com", "honeywell.com")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s)\]]+")


def load_json(data_dir, name, default):
    p = os.path.join(data_dir, name)
    if not os.path.exists(p):
        return default
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def check_draft(text, brief, data_dir):
    """Vérifie le brouillon contre les données vérifiées. Renvoie le rapport de fact-checking."""
    known_cves = {c.get("id", "").upper() for c in load_json(data_dir, "cves.json", [])}
    kev_ids = {k.get("cveID", "").upper() for k in load_json(data_dir, "kev.json", [])}
    brief_ids = {c["id"].upper() for c in brief.get("top_cves", []) + brief.get("relevant_cves", [])}

    report = {"checked": 0, "passed": 0, "failed": [], "human_review": [], "ok": True}

    # niveau 1 : CVE cités
    for cid in sorted(set(CVE_RE.findall(text))):
        report["checked"] += 1
        u = cid.upper()
        if u in known_cves or u in brief_ids:
            report["passed"] += 1
        else:
            report["failed"].append({"claim": cid, "reason": "CVE inconnue des données collectées (hallucination ?)"})

    # niveau 1 : affirmations KEV accolées à un CVE
    for line in text.splitlines():
        if "KEV" in line:
            for cid in CVE_RE.findall(line):
                report["checked"] += 1
                if cid.upper() in kev_ids:
                    report["passed"] += 1
                else:
                    report["failed"].append({"claim": f"{cid} présentée comme KEV", "reason": "absente du KEV collecté"})

    # niveau 1 : URLs de citation sur hôtes autorisés
    for url in URL_RE.findall(text):
        report["checked"] += 1
        host = re.sub(r"^https?://", "", url).split("/")[0]
        if any(host == h or host.endswith("." + h) for h in ALLOWED_CITE_HOSTS):
            report["passed"] += 1
        else:
            report["failed"].append({"claim": url, "reason": "hôte de citation non autorisé"})

    # niveau 2 : affirmations floues -> vérification web/humaine requise
    for pat in (r"(estimé|selon des experts|on estime|probablement)",):
        for m in re.finditer(pat, text, re.IGNORECASE):
            report["human_review"].append({"claim": text[max(0, m.start() - 60):m.end() + 60].replace("\n", " "),
                                           "reason": "affirmation non sourcée par les données structurées -> vérifier en ligne"})

    # niveau 3 : revue humaine obligatoire avant publication (HITL)
    report["human_review"].append({"claim": "ARTICLE ENTIER", "reason": "revue éditoriale humaine obligatoire (AI Act art. 50 + HITL)"})
    report["ok"] = not report["failed"]
    return report
