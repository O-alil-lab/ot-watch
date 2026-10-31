#!/usr/bin/env python3
"""
OT Watch — collecteur automatique (v2).
Sources : CISA (RSS avis ICS), NVD API 2.0 (recherche mots-clés + CPE éditeurs + watchlist),
CISA KEV, FIRST EPSS (score d'exploitation).
Pipeline : collecte -> filtre OT -> enrichissement EPSS -> score de risque ->
validation qualité -> stockage SQLite (diff nouveautés) -> snapshots JSON atomiques.
Usage : python3 src/collect.py   (NVD_API_KEY env optionnel)
"""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(ROOT, "config.json"), encoding="utf-8") as _fh:
    CFG = json.load(_fh)
DATA = os.path.join(ROOT, "data")
os.makedirs(DATA, exist_ok=True)

import alerts
import enrich_ot
import store
import validate


def log(*args):
    print("[collect]", *args, flush=True)


def fetch(url, timeout=40, headers=None):
    req = urllib.request.Request(
        url, headers={"User-Agent": CFG.get("user_agent", "ot-watch/1.0"), **(headers or {})}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _dump_json(obj, name):
    """Écriture atomique : tmp + os.replace (le serveur web lit ces fichiers en parallèle)."""
    tmp = os.path.join(DATA, name + ".tmp")
    dst = os.path.join(DATA, name)
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, dst)


# ---------------------------------------------------------------- CISA RSS
def parse_rss_items(raw, window_days):
    """Parse un flux RSS/Atom CISA -> liste d'avis {code,title,link,published,summary} filtrés fenêtre."""
    root = ET.fromstring(raw)
    cutoff = datetime.now(UTC) - timedelta(days=window_days)
    items = []
    for it in root.iter("item"):
        title = (it.findtext("title") or "").strip()
        link = (it.findtext("link") or "").strip()
        pub = (it.findtext("pubDate") or "").strip()
        desc = re.sub(r"<[^>]+>", " ", it.findtext("description") or "")
        desc = re.sub(r"\s+", " ", desc).strip()
        is_ics = (
            "/ics-advisories/" in link
            or "/ics-alerts/" in link
            or re.search(r"\b(ICSA|ICSAA|AA)\d{2}-\d{3}", title)
        )
        if not is_ics:
            continue
        try:
            from email.utils import parsedate_to_datetime

            dt = parsedate_to_datetime(pub)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
        except Exception:
            dt = None
        if dt and dt < cutoff:
            continue
        code = ""
        m = re.search(r"(icsa-\d{2}-\d{3}-\d+|icsaa-\d{2}-\d{3}|aa\d{2}-\d{3}[a-z])", link.lower())
        if m:
            code = m.group(1).upper()
        items.append({"code": code, "title": title, "link": link, "published": pub, "summary": desc[:500]})
    items.sort(key=lambda x: x["published"], reverse=True)
    return items


def collect_cisa(window_days):
    """Avis ICS récents : flux global CISA + flux dédié ICS Advisories, dédupliqués par code/lien."""
    seen, out = set(), []
    for key in ("cisa_rss", "cisa_ics_rss"):
        url = CFG["sources"].get(key)
        if not url:
            continue
        try:
            items = parse_rss_items(fetch(url, timeout=60), window_days)
        except Exception as exc:
            log(f"CISA {key}: échec ({exc})")
            continue
        for it in items:
            k = (it.get("code") or it.get("link") or it.get("title")).lower()
            if k in seen:
                continue
            seen.add(k)
            out.append(it)
    out.sort(key=lambda x: x["published"], reverse=True)
    return out


# ------------------------------------------------------- sources additionnelles 2026
def collect_ghsa_cves():
    """CVE OT découvertes via l'API publique GitHub GHSA (sans clé, rate-limit 60/h)."""
    api = CFG["sources"].get("ghsa_api")
    queries = CFG["sources"].get("ghsa_queries", [])
    per_page = int(CFG["sources"].get("ghsa_per_page", 15))
    sleep_s = float(CFG["sources"].get("ghsa_sleep_seconds", 2))
    ids = set()
    for q in queries:
        url = f"{api}?type=reviewed&per_page={per_page}&query={urllib.parse.quote(q)}"
        try:
            data = json.loads(fetch(url, timeout=40, headers={"Accept": "application/vnd.github+json"}))
        except Exception as exc:
            log(f"GHSA '{q}': échec ({exc})")
            continue
        if not isinstance(data, list):
            continue
        for adv in data:
            cid = adv.get("cve_id")
            if cid:
                ids.add(cid)
        time.sleep(sleep_s)
    return sorted(ids)


def collect_otx_cves():
    """CVE OT via AlienVault OTX (clé API optionnelle via env OTWATCH_OTX_API_KEY ; sinon ignoré)."""
    key = os.environ.get(CFG["sources"].get("otx_env_key", "OTWATCH_OTX_API_KEY"), "")
    if not key:
        return []
    api = CFG["sources"].get("otx_api")
    ids = set()
    for q in CFG["sources"].get("otx_queries", []):
        url = f"{api}?q={urllib.parse.quote(q)}&limit=20"
        try:
            data = json.loads(fetch(url, timeout=40, headers={"X-OTX-API-KEY": key}))
        except Exception as exc:
            log(f"OTX '{q}': échec ({exc})")
            continue
        blob = json.dumps(data)
        ids.update(re.findall(r"CVE-\d{4}-\d{4,7}", blob, re.IGNORECASE))
        time.sleep(1)
    return sorted(ids)


# ---------------------------------------------------------------- NVD
OT_CONTEXT_RE = re.compile(
    r"(industrial|automation|automat|scada|\bics\b|\bot\b|control system|modbus|profinet|s7comm|"
    r"ethernet/ip|firmware|\bhmi\b|process control|plc project|ladder|opc[ -]?ua|sensor|actuator)",
    re.IGNORECASE,
)


def _is_ot(desc, cpe_blob, vendor_re):
    """Filtre anti-faux-positifs : 'PLC' seul ne suffit pas (ex. 'Datalex PLC' = logiciel voyage)."""
    if vendor_re.search(cpe_blob):
        return True
    strong = re.compile(
        r"\b(siemens|schneider|rockwell|allen[- ]?bradley|modicon|simatic|scada|\bhmi\b|opc[ -]?ua|"
        r"ethernet/ip|\benip\b|modbus|profinet|s7comm|codesys|beckhoff|twincat|wago|mitsubishi electric|"
        r"omron|\babb\b|honeywell|yokogawa|emerson|phoenix contact|pepperl|ruggedcom|snap7|ignition|"
        r"aveva|wonderware|unitronics|openplc|controllogix|compactlogix|micrologix|experion|iconics|genesis|epics)\b",
        re.IGNORECASE,
    )
    if strong.search(desc):
        return True
    return bool(re.search(r"\bplcs?\b", desc, re.IGNORECASE) and OT_CONTEXT_RE.search(desc))


def _cve_record(c, vendor_re):
    desc = next((x["value"] for x in c.get("descriptions", []) if x.get("lang") == "en"), "")
    cpes = []
    for conf in c.get("configurations", []):
        for node in conf.get("nodes", []):
            cpes.extend(m.get("cpeName", "") for m in node.get("cpeMatch", []))
    cpe_blob = " ".join(cpes)
    if not _is_ot(desc, cpe_blob, vendor_re):
        return None
    metrics = c.get("metrics", {})
    score = sev = vector = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        if key in metrics:
            m = metrics[key][0]["cvssData"]
            score, sev, vector = m.get("baseScore"), m.get("baseSeverity"), m.get("vectorString")
            break
    cwes = [
        w.get("description")
        for w in c.get("weaknesses", [])
        for w in w.get("description", [])
        if w.get("description")
    ]
    return {
        "id": c["id"],
        "published": c.get("published"),
        "lastModified": c.get("lastModified"),
        "description": desc[:700],
        "cvss": score,
        "severity": (sev or "").upper() or None,
        "vector": vector,
        "cwes": cwes[:3],
        "refs": [r["url"] for r in c.get("references", [])][:6],
    }


def _nvd_get(url, label, vendor_re, api_key, cves, allow_any=False):
    headers = {"apiKey": api_key} if api_key else None
    for attempt in range(5):
        try:
            d = json.loads(fetch(url, headers=headers))
            n = 0
            for v in d.get("vulnerabilities", []):
                rec = _cve_record(v["cve"], vendor_re)
                if rec is None and not allow_any:
                    continue
                if rec is None:
                    c = v["cve"]
                    rec = {
                        "id": c["id"], "published": c.get("published"), "lastModified": c.get("lastModified"),
                        "description": next((x["value"] for x in c.get("descriptions", []) if x.get("lang") == "en"), "")[:700],
                        "cvss": None, "severity": None, "vector": None, "cwes": [],
                        "refs": [r["url"] for r in c.get("references", [])][:6],
                    }
                cves[rec["id"]] = rec
                n += 1
            log(f"NVD '{label}': {n} CVE retenues (total {len(cves)})")
            return True
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                log(f"NVD '{label}' rate-limit (HTTP {e.code}), pause 30s (tentative {attempt + 1}/5)")
                time.sleep(30)
                continue
            log(f"NVD '{label}' erreur HTTP {e.code}")
            return False
        except Exception as e:
            log(f"NVD '{label}' tentative {attempt + 1} échouée: {e}")
            time.sleep(12 * (attempt + 1))
    log(f"NVD '{label}' abandonné après échecs")
    return False


def nvd_collect(window_days, extra_ids=None):
    """CVE via mots-clés + CPE éditeurs (précision) + watchlist par cveId (+ ids GHSA/OTX)."""
    end = datetime.now(UTC)
    start = end - timedelta(days=window_days)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    window_q = urllib.parse.urlencode(
        {"pubStartDate": start.strftime(fmt), "pubEndDate": end.strftime(fmt), "resultsPerPage": 100}
    )
    vendor_re = re.compile(CFG["vendor_regex"], re.IGNORECASE)
    api_key = os.environ.get("NVD_API_KEY")
    sleep_s = 1.2 if api_key else CFG.get("nvd_sleep_seconds", 7)
    cves = {}
    time.sleep(2)

    # 1) mots-clés (découverte large)
    for kw in CFG["nvd_keywords"]:
        url = f"{CFG['sources']['nvd_api']}?keywordSearch={urllib.parse.quote(kw)}&{window_q}"
        _nvd_get(url, kw, vendor_re, api_key, cves)
        time.sleep(sleep_s)

    # 2) CPE éditeurs OT (précision) — virtualMatchString cpe:2.3:*:<vendor>:*:*...
    for vendor in CFG.get("nvd_cpe_vendors", []):
        cpe = f"cpe:2.3:*:{vendor}:*:*:*:*:*:*:*:*"
        url = (
            f"{CFG['sources']['nvd_api']}?virtualMatchString={urllib.parse.quote(cpe, safe='')}&"
            f"pubStartDate={start.strftime(fmt)}&pubEndDate={end.strftime(fmt)}&resultsPerPage=200"
        )
        _nvd_get(url, f"cpe:{vendor}", vendor_re, api_key, cves, allow_any=True)
        time.sleep(sleep_s)

    # 3) watchlist par cveId (fiable même si rate-limité)
    for cid in list(CFG.get("cve_watchlist", [])) + list(extra_ids or []):
        if cid in cves:
            continue
        url = f"{CFG['sources']['nvd_api']}?cveId={cid}"
        _nvd_get(url, f"watchlist {cid}", vendor_re, api_key, cves, allow_any=True)
        time.sleep(sleep_s)
    return list(cves.values())


# ---------------------------------------------------------------- EPSS + risque
def enrich_epss(cves):
    """Ajoute epss/percentile (FIRST EPSS API) + score de risque composite."""
    if not CFG.get("use_epss", True) or not cves:
        return cves
    ids = [c["id"] for c in cves]
    epss_map = {}
    for i in range(0, len(ids), 50):  # l'API FIRST accepte des lots de CVE
        chunk = ",".join(ids[i : i + 50])
        url = f"{CFG['epss_api']}?cve={urllib.parse.quote(chunk, safe=',')}"
        try:
            d = json.loads(fetch(url, timeout=30))
            for row in d.get("data", []):
                epss_map[row["cve"]] = float(row.get("epss") or 0.0)
        except Exception as e:
            log(f"EPSS indisponible pour le lot {i}: {e}")
        time.sleep(1)
    w = CFG.get("risk_weights", {"cvss": 0.5, "epss": 0.3, "kev": 0.2})
    for c in cves:
        epss = epss_map.get(c["id"])
        c["epss"] = epss
        cvss_n = (c.get("cvss") or 0) / 10.0
        kev_n = 1.0 if c.get("kev") else 0.0
        c["risk"] = round(10 * (w["cvss"] * cvss_n + w["epss"] * (epss or 0.0) + w["kev"] * kev_n), 2)
    log(f"EPSS: enrichi {len(epss_map)}/{len(cves)} CVE")
    return cves


def sort_by_risk(cves):
    return sorted(cves, key=lambda c: (c.get("risk") if c.get("risk") is not None else (c.get("cvss") or 0)), reverse=True)


def apply_exposure(cves):
    """Marque c['relevant']=True si la CVE correspond au profil d'exposition (config.exposure.keywords)."""
    kws = CFG.get("exposure", {}).get("keywords", [])
    exp_re = re.compile("|".join(re.escape(k) for k in kws), re.IGNORECASE) if kws else None
    n = 0
    for c in cves:
        c["relevant"] = bool(exp_re and exp_re.search(c.get("description") or ""))
        n += 1 if c["relevant"] else 0
    log(f"exposition: {n}/{len(cves)} CVE correspondent au profil « {CFG.get('exposure', {}).get('label', 'mes actifs')} »")
    return cves


def sort_by_priority(cves):
    """Tri : CVE pertinentes pour mon profil d'abord, puis score de risque décroissant."""
    return sorted(cves, key=lambda c: (bool(c.get("relevant")),
                                        c.get("risk") if c.get("risk") is not None else (c.get("cvss") or 0)), reverse=True)


# ---------------------------------------------------------------- KEV
def collect_kev():
    """Entrées KEV liées à l'OT/ICS."""
    d = json.loads(fetch(CFG["sources"]["cisa_kev"], timeout=60))
    ot_re = re.compile(CFG["ot_kev_regex"], re.IGNORECASE)
    out = []
    for v in d.get("vulnerabilities", []):
        blob = " ".join(
            [v.get("vendorProject", ""), v.get("product", ""), v.get("vulnerabilityName", ""), v.get("shortDescription", "")]
        )
        if ot_re.search(blob):
            out.append({k: v.get(k) for k in (
                "cveID", "vendorProject", "product", "vulnerabilityName",
                "dateAdded", "dueDate", "knownRansomwareCampaignUse",
                "requiredAction", "shortDescription",
            )})
    out.sort(key=lambda x: x.get("dateAdded", ""), reverse=True)
    return out


# ---------------------------------------------------------------- main
def main():
    window_days = int(CFG.get("window_days", 14))
    t0 = datetime.now(UTC)
    log(f"démarrage — fenêtre {window_days} jours")

    cisa = collect_cisa(window_days)
    log(f"CISA: {len(cisa)} avis ICS dans la fenêtre")

    ghsa_ids = collect_ghsa_cves()
    log(f"GHSA: {len(ghsa_ids)} CVE OT détectées via GitHub advisories")
    otx_ids = collect_otx_cves()
    if otx_ids:
        log(f"OTX: {len(otx_ids)} CVE supplémentaires (clé API fournie)")
    else:
        log("OTX: ignoré (pas de clé OTWATCH_OTX_API_KEY)")

    cves = nvd_collect(window_days, extra_ids=sorted(set(ghsa_ids) | set(otx_ids)))
    log(f"NVD: {len(cves)} CVE OT au total")

    kev = collect_kev()
    log(f"KEV: {len(kev)} entrées OT/ICS")

    kev_ids = {k["cveID"] for k in kev}
    for c in cves:
        c["kev"] = c["id"] in kev_ids

    cves, n_tech, n_act = enrich_ot.enrich(apply_exposure(enrich_epss(cves)), CFG)
    cves = sort_by_priority(cves)
    log(f"ATT&CK for ICS: {n_tech} techniques mappées · SSVC act: {n_act}/{len(cves)}")

    # validation qualité (schéma + volume vs collecte précédente)
    prev_meta = {}
    try:
        with open(os.path.join(DATA, "meta.json"), encoding="utf-8") as fh:
            prev_meta = json.load(fh)
    except Exception:
        pass
    payload = {"cves": cves, "advisories": cisa, "kev": kev}
    validation = validate.validate_all(payload)
    validation["issues"] += validate.volume_check(prev_meta.get("counts"), validation["counts"])
    validation["ok"] = not validation["issues"]
    if not validation["ok"]:
        log(f"VALIDATION KO: {validation['issues'][:5]}")
    else:
        log("validation OK")

    # stockage SQLite + diff nouveautés
    diff = store.store_run(payload, validation=validation)
    log(f"store: run #{diff['run_id']} — nouvelles CVE: {len(diff['new_cves'])}, nouveaux avis: {len(diff['new_advisories'])}, nouveau KEV: {len(diff['new_kev'])}")

    meta = {
        "generated_at": t0.isoformat(),
        "window_days": window_days,
        "counts": validation["counts"],
        "validation": validation,
        "diff": {"new_cves": diff["new_cves"], "new_advisories": diff["new_advisories"], "new_kev": diff["new_kev"], "run_id": diff["run_id"]},
    }
    _dump_json(cisa, "cisa_advisories.json")
    _dump_json(cves, "cves.json")
    _dump_json(kev, "kev.json")
    _dump_json(meta, "meta.json")
    alerts.dispatch(meta, cves)  # webhook/Slack/e-mail si configuré, sinon log JSONL
    log(f"terminé en {(datetime.now(UTC) - t0).total_seconds():.1f}s -> {DATA}")


if __name__ == "__main__":
    sys.exit(main())
