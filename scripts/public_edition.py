#!/usr/bin/env python3
"""Édition publique d'OT Watch : données et éditions sans aucune information propre à l'organisation.

Le site public (GitHub Pages) ne doit jamais exposer :
- l'inventaire des actifs OT (noms, firmware, niveau Purdue, criticité, safety) ;
- le lien CVE -> actifs (asset_impact, score OT et son détail, marqueur « Mes actifs ») ;
- l'état interne du pipeline (erreurs, brouillons d'agents, validation, chemins de capture).

Ce module produit une copie nettoyée de data/ puis régénère toutes les éditions (FR, AR, EN, PDF,
STIX, MISP) à partir de cette copie, dans un dossier séparé. Les données complètes restent privées.
"""
import json
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

# champs CVE qui révèlent le profil d'exposition de l'organisation
PRIVATE_CVE_FIELDS = ("relevant", "asset_impact", "ot_score", "ot_score_detail")
# champs meta internes au pipeline
PRIVATE_META_FIELDS = ("validation", "quality")
PUBLIC_FILES = ("cves.json", "kev.json", "cisa_advisories.json", "meta.json")
RENDERERS = ("render", "render_ar", "render_en", "render_pdf", "stix", "misp_export")


def _load(path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def _dump(path, obj):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=1)


def public_cve(cve):
    return {k: v for k, v in cve.items() if k not in PRIVATE_CVE_FIELDS}


def public_meta(meta):
    return {k: v for k, v in meta.items() if k not in PRIVATE_META_FIELDS}


def make_public_data(src_dir, dst_dir):
    """Copie nettoyée de data/ : CVE sans lien aux actifs, aucun inventaire, meta sans état interne."""
    os.makedirs(dst_dir, exist_ok=True)
    for name in PUBLIC_FILES:
        obj = _load(os.path.join(src_dir, name), None)
        if obj is None:
            continue
        if name == "cves.json":
            obj = [public_cve(c) for c in obj]
        elif name == "meta.json":
            obj = public_meta(obj)
        _dump(os.path.join(dst_dir, name), obj)
    _dump(os.path.join(dst_dir, "assets.json"), [])
    db = os.path.join(src_dir, "otwatch.db")
    if os.path.exists(db):  # historique agrégé par jour (comptes CVE/KEV), sans actifs
        shutil.copy(db, os.path.join(dst_dir, "otwatch.db"))
    return dst_dir


def render_public_editions(data_dir, out_dir):
    """Exécute chaque générateur d'édition sur les données publiques, sortie dans out_dir."""
    os.makedirs(out_dir, exist_ok=True)
    done = []
    for name in RENDERERS:
        mod = __import__(name)
        saved = (mod.DATA, mod.OUT, getattr(mod, "PUBLIC", None))
        mod.DATA, mod.OUT = data_dir, out_dir
        if saved[2] is not None:
            mod.PUBLIC = True
        try:
            mod.main()
            done.append(name)
        finally:
            mod.DATA, mod.OUT = saved[0], saved[1]
            if saved[2] is not None:
                mod.PUBLIC = saved[2]
    return done


def assert_no_private_data(text, asset_ids):
    """Garde-fou : échoue si un identifiant d'actif ou un champ privé apparaît dans un fichier public."""
    needles = [*asset_ids, "asset_impact", "ot_score_detail", "x_otwatch_relevant\": true"]
    leaks = [n for n in needles if n and n in text]
    if leaks:
        raise ValueError(f"données privées dans le site public : {leaks[:5]}")


def private_asset_ids(src_dir):
    assets = _load(os.path.join(src_dir, "assets.json"), [])
    if isinstance(assets, dict):
        assets = assets.get("assets", [])
    return [a.get("asset_id") for a in assets if isinstance(a, dict) and a.get("asset_id")]
