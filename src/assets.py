#!/usr/bin/env python3
"""
OT Watch — inventaire d'actifs OT + matching CVE<->actifs + import SBOM CycloneDX (P2).

Sources d'actifs :
  - config.json -> "assets" : [{asset_id, name, vendor, product, firmware, purdue_level, criticality}]
  - data/sbom.cdx.json (optionnel) : SBOM CycloneDX 1.x -> composants (supplier/name/version) = actifs.
match_assets() : une CVE "impacte" un actif si un mot-clé vendor/produit de l'actif matche la
CVE (description/vendor) -> c['asset_impact'] = [asset_id...]. Le score de risque peut ainsi
prendre le niveau Purdue / la criticité en compte (exposé en API + dashboard).
Stockage SQLite : table assets + colonne cves.assets (JSON).
Voir tests/test_assets.py.
"""
import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")

PURDUE = {"L0": "processus (capteurs/actionneurs)", "L1": "contrôle (PLC/RTU)", "L2": "supervision (HMI/SCADA)",
          "L3": "site (MES/historian)", "L3.5": "DMZ industrielle", "L4": "entreprise IT"}


PRIVATE_ASSETS_FILE = os.environ.get("OTWATCH_ASSETS_FILE", os.path.join(ROOT, "config.assets.local.json"))


def config_assets(cfg, private_file=None):
    """Inventaire réel : fichier privé (ignoré par git) s'il existe, sinon les exemples de config.json."""
    path = private_file or PRIVATE_ASSETS_FILE
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data.get("assets", []) if isinstance(data, dict) else data
    return cfg.get("assets", [])


def load_assets(cfg, data_dir=DATA, private_file=None):
    """Actifs depuis l'inventaire (privé ou exemples) + SBOM CycloneDX éventuel. Normalisés et dédupliqués."""
    assets = []
    for a in config_assets(cfg, private_file):
        assets.append({
            "asset_id": a.get("asset_id") or re.sub(r"\W+", "-", (a.get("name") or "asset").lower()).strip("-"),
            "name": a.get("name", ""), "vendor": a.get("vendor", ""), "product": a.get("product", ""),
            "firmware": a.get("firmware", ""), "purdue_level": a.get("purdue_level", "L1"),
            "criticality": a.get("criticality", "medium"), "safety": bool(a.get("safety", False)), "source": "config",
        })
    sbom = os.path.join(data_dir, "sbom.cdx.json")
    if os.path.exists(sbom):
        with open(sbom, encoding="utf-8") as fh:
            bom = json.load(fh)
        if bom.get("bomFormat") == "CycloneDX":
            for comp in bom.get("components", []):
                name = comp.get("name", "")
                assets.append({
                    "asset_id": "sbom-" + re.sub(r"\W+", "-", name.lower()).strip("-")[:40],
                    "name": name, "vendor": (comp.get("supplier") or {}).get("name", "") if isinstance(comp.get("supplier"), dict) else str(comp.get("supplier") or ""),
                    "product": name, "firmware": comp.get("version", ""), "purdue_level": "L1",
                    "criticality": "medium", "source": "sbom",
                })
    seen = set()
    out = []
    for a in assets:
        if a["asset_id"] in seen:
            continue
        seen.add(a["asset_id"])
        out.append(a)
    return out


def _keywords(a):
    kws = [a.get("vendor", ""), a.get("product", ""), a.get("name", "")]
    return [re.escape(k.strip().lower()) for k in kws if k and k.strip() and len(k.strip()) >= 3]


def match_assets(cves, assets):
    """c['asset_impact'] = liste d'asset_id impactés (mot-clé vendor/produit dans la CVE)."""
    compiled = [(a, re.compile("|".join(_keywords(a)), re.IGNORECASE) if _keywords(a) else None) for a in assets]
    for c in cves:
        blob = f"{c.get('description') or ''} {c.get('id') or ''}"
        c["asset_impact"] = [a["asset_id"] for a, rx in compiled if rx and rx.search(blob)]
    return cves


def impacted_map(cves):
    m = {}
    for c in cves:
        for aid in c.get("asset_impact") or []:
            m.setdefault(aid, []).append(c.get("id"))
    return m


# ---------------------------------------------------------------- score OT
# Score OT = exposition x Purdue x criticité (+ safety) + bonus KEV/SSVC.
# Pondérations par défaut surchargeables via config.json["ot_scoring"].
DEFAULT_OT_SCORING = {
    "purdue_weights": {"L0": 1.0, "L1": 1.0, "L2": 0.9, "L3": 0.7, "L3.5": 0.5, "L4": 0.3},
    "criticality_weights": {"high": 1.2, "medium": 1.0, "low": 0.8},
    "safety_bonus": 0.3,      # +30 % si l'actif est un SIS (safety instrumented system)
    "kev_bonus": 1.0,         # +1.0 pt si CVE au catalogue KEV (exploitation connue)
    "ssvc_act_bonus": 1.0,    # +1.0 pt si décision SSVC = Act
    "cap": 10.0,
}


def _asset_factor(a, sc):
    """Facteur d'exposition d'un actif : poids Purdue x criticité (+ bonus safety)."""
    pw = sc.get("purdue_weights", {}).get(str(a.get("purdue_level", "L1")), 1.0)
    cw = sc.get("criticality_weights", {}).get(str(a.get("criticality", "medium")).lower(), 1.0)
    f = pw * cw
    if a.get("safety"):
        f += sc.get("safety_bonus", 0.3)
    return round(f, 3)


def score_ot(c, assets_by_id, cfg=None):
    """c['ot_score'] (0-10, None si aucun actif impacté) + c['ot_score_detail'].

    ot_score = min(cap, risk_base x max(facteur actifs impactés) + bonus KEV + bonus SSVC Act)
    """
    sc = dict(DEFAULT_OT_SCORING)
    sc.update((cfg or {}).get("ot_scoring", {}))
    impacted = [assets_by_id[a] for a in (c.get("asset_impact") or []) if a in assets_by_id]
    if not impacted:
        c["ot_score"] = None
        c["ot_score_detail"] = {"base": c.get("risk") if c.get("risk") is not None else (c.get("cvss") or 0),
                                "assets": [], "kev_bonus": 0.0, "ssvc_bonus": 0.0, "score": None}
        return c
    base = c.get("risk") if c.get("risk") is not None else (c.get("cvss") or 0)
    per_asset = [{"asset_id": a["asset_id"], "purdue_level": a.get("purdue_level"),
                  "criticality": a.get("criticality"), "safety": bool(a.get("safety")),
                  "factor": _asset_factor(a, sc)} for a in impacted]
    asset_factor = max(x["factor"] for x in per_asset)
    kev_bonus = sc.get("kev_bonus", 0) if c.get("kev") else 0.0
    ssvc_bonus = sc.get("ssvc_act_bonus", 0) if (c.get("ssvc") or "").lower() == "act" else 0.0
    score = min(sc.get("cap", 10.0), round(base * asset_factor + kev_bonus + ssvc_bonus, 2))
    c["ot_score"] = score
    c["ot_score_detail"] = {"base": base, "asset_factor": asset_factor, "assets": per_asset,
                            "kev_bonus": kev_bonus, "ssvc_bonus": ssvc_bonus, "score": score}
    return c


def score_ot_all(cves, assets, cfg=None):
    """Applique score_ot() à chaque CVE. Retourne (cves, n_impactées)."""
    by_id = {a["asset_id"]: a for a in assets}
    n = 0
    for c in cves:
        score_ot(c, by_id, cfg)
        n += 1 if c.get("ot_score") is not None else 0
    return cves, n


def save_assets_json(assets, data_dir=DATA):
    os.makedirs(data_dir, exist_ok=True)
    with open(os.path.join(data_dir, "assets.json"), "w", encoding="utf-8") as fh:
        json.dump(assets, fh, ensure_ascii=False, indent=2)


def load_assets_json(data_dir=DATA):
    p = os.path.join(data_dir, "assets.json")
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)
