#!/usr/bin/env python3
"""
OT Watch — enrichissement OT 2026 (roadmap « plateforme de référence ») :
  - map_attack_ics() : rattache chaque CVE/avis aux techniques MITRE ATT&CK for ICS
    (v20, oct. 2026) via les mots-clés de config.attack_ics.
  - ssvc_decision()  : arbre de décision SSVC (CISA/CERT-CC, perspective « patch applier »)
    simplifié : exploitation (KEV=active, EPSS/Poc=poc), automatable (CVSS + vecteur réseau),
    impact technique (CVSS), mission (profil d'exposition = actif OT surveillé)
    → Track / Track* / Attend / Act.
Les deux champs sont stockés (c['attack_ics'], c['ssvc']) et exportés en STIX 2.1.
Voir tests/test_enrich_ot.py.
"""
def map_attack_ics(text, attack_cfg):
    """Renvoie la liste triée des techniques ATT&CK for ICS dont un mot-clé matche le texte."""
    text = (text or "").lower()
    hits = []
    for tech, spec in (attack_cfg or {}).items():
        for kw in spec.get("keywords", []):
            if kw.lower() in text:
                hits.append(tech)
                break
    return sorted(set(hits))


def ssvc_decision(c, ssvc_cfg):
    """Arbre SSVC simplifié → dict {decision, exploitation, automatable, technical_impact, mission}."""
    cfg = ssvc_cfg or {}
    epss_poc = cfg.get("epss_poc", 0.1)
    auto_cvss = cfg.get("automatable_cvss", 9.0)
    total_cvss = cfg.get("total_impact_cvss", 9.0)
    poc_kws = cfg.get("poc_keywords", ["proof of concept", "public exploit", "poc"])
    desc = (c.get("description") or "").lower()
    cvss = c.get("cvss") or 0
    vector = (c.get("vector") or "").upper()

    if c.get("kev"):
        exploitation = "active"
    elif (c.get("epss") or 0) >= epss_poc or any(k in desc for k in poc_kws):
        exploitation = "poc"
    else:
        exploitation = "none"

    automatable = "yes" if cvss >= auto_cvss and ("NETWORK" in vector or cvss >= auto_cvss) else "no"
    impact = "total" if cvss >= total_cvss else "partial"
    mission = "high" if c.get("relevant") else "low"

    if exploitation == "active" or (automatable == "yes" and impact == "total"):
        decision = "act"
    elif exploitation == "poc" or impact == "total" or automatable == "yes":
        decision = "attend"
    elif mission == "high":
        decision = "track*"
    else:
        decision = "track"

    return {"decision": decision, "exploitation": exploitation, "automatable": automatable,
            "technical_impact": impact, "mission": mission}


def enrich(cves, cfg):
    """Ajoute c['attack_ics'] (liste T0xxx) et c['ssvc'] (décision SSVC) à chaque CVE."""
    attack_cfg = cfg.get("attack_ics", {})
    ssvc_cfg = cfg.get("ssvc", {})
    n_tech = 0
    n_act = 0
    for c in cves:
        c["attack_ics"] = map_attack_ics(f"{c.get('description') or ''} {c.get('id') or ''}", attack_cfg)
        s = ssvc_decision(c, ssvc_cfg)
        c["ssvc"] = s["decision"]
        c["ssvc_detail"] = s
        n_tech += len(c["attack_ics"])
        n_act += 1 if s["decision"] == "act" else 0
    return cves, n_tech, n_act
