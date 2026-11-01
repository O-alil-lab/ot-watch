#!/usr/bin/env python3
"""
OT Watch — store persistant SQLite (stdlib) : historique + détection des nouveautés + tendances.
Tables : runs, cves (avec colonne `relevant` = correspond au profil d'exposition), advisories, kev.
Upsert par clé métier -> idempotent, rejouable. Retourne le diff « nouveau depuis la dernière collecte ».
"""
import json
import os
import sqlite3
from datetime import UTC, datetime, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
DB_PATH = os.path.join(DATA, "otwatch.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  finished_at TEXT NOT NULL,
  n_cves INTEGER, n_advisories INTEGER, n_kev INTEGER,
  ok INTEGER, validation TEXT
);
CREATE TABLE IF NOT EXISTS cves (
  cve_id TEXT PRIMARY KEY,
  first_seen_run INTEGER, last_seen_run INTEGER,
  cvss REAL, severity TEXT, kev INTEGER, epss REAL, risk REAL, relevant INTEGER DEFAULT 0,
  attack_ics TEXT, ssvc TEXT, assets TEXT,
  published TEXT, description TEXT, refs TEXT
);
CREATE TABLE IF NOT EXISTS advisories (
  code TEXT PRIMARY KEY,
  first_seen_run INTEGER, last_seen_run INTEGER,
  title TEXT, link TEXT, published TEXT, summary TEXT
);
CREATE TABLE IF NOT EXISTS assets (
  asset_id TEXT PRIMARY KEY, name TEXT, vendor TEXT, product TEXT, firmware TEXT,
  purdue_level TEXT, criticality TEXT, source TEXT
);
CREATE TABLE IF NOT EXISTS kev (
  cve_id TEXT PRIMARY KEY,
  first_seen_run INTEGER, last_seen_run INTEGER,
  vendor TEXT, product TEXT, date_added TEXT, due_date TEXT, ransomware INTEGER
);
"""


def _migrate(conn):
    """Ajoute les colonnes apparues après la v1 (ex. cves.relevant)."""
    cols = [r[1] for r in conn.execute("PRAGMA table_info(cves)").fetchall()]
    if "relevant" not in cols:
        conn.execute("ALTER TABLE cves ADD COLUMN relevant INTEGER DEFAULT 0")
    if "attack_ics" not in cols:
        conn.execute("ALTER TABLE cves ADD COLUMN attack_ics TEXT")
    if "ssvc" not in cols:
        conn.execute("ALTER TABLE cves ADD COLUMN ssvc TEXT")
    if "assets" not in cols:
        conn.execute("ALTER TABLE cves ADD COLUMN assets TEXT")
    if "ot_score" not in cols:
        conn.execute("ALTER TABLE cves ADD COLUMN ot_score REAL")


def _connect(db_path=None):
    os.makedirs(DATA, exist_ok=True)
    conn = sqlite3.connect(db_path or DB_PATH)
    conn.executescript(SCHEMA)
    _migrate(conn)
    return conn


def store_run(payload, validation=None, db_path=None):
    """Enregistre une collecte. Retourne {new_cves, new_advisories, new_kev, run_id}."""
    conn = _connect(db_path)
    try:
        cur = conn.cursor()
        now = datetime.now(UTC).isoformat()
        counts = validation.get("counts", {}) if validation else {}
        cur.execute(
            "INSERT INTO runs (finished_at, n_cves, n_advisories, n_kev, ok, validation) VALUES (?,?,?,?,?,?)",
            (now, counts.get("cves", 0), counts.get("advisories", 0), counts.get("kev", 0),
             1 if (validation or {}).get("ok", True) else 0, json.dumps(validation or {})),
        )
        run_id = cur.lastrowid

        new_cves = []
        for c in payload.get("cves", []):
            exists = cur.execute("SELECT 1 FROM cves WHERE cve_id=?", (c["id"],)).fetchone()
            if not exists:
                new_cves.append(c["id"])
            cur.execute(
                """INSERT INTO cves (cve_id, first_seen_run, last_seen_run, cvss, severity, kev, epss, risk, relevant, attack_ics, ssvc, assets, ot_score, published, description, refs)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(cve_id) DO UPDATE SET last_seen_run=excluded.last_seen_run, cvss=excluded.cvss,
                     severity=excluded.severity, kev=excluded.kev, epss=excluded.epss, risk=excluded.risk,
                     relevant=excluded.relevant, attack_ics=excluded.attack_ics, ssvc=excluded.ssvc, assets=excluded.assets,
                     ot_score=excluded.ot_score, published=excluded.published, description=excluded.description, refs=excluded.refs""",
                (c["id"], run_id, run_id, c.get("cvss"), c.get("severity"), 1 if c.get("kev") else 0,
                 c.get("epss"), c.get("risk"), 1 if c.get("relevant") else 0, json.dumps(c.get("attack_ics") or []), c.get("ssvc"), json.dumps(c.get("asset_impact") or []), c.get("ot_score"), c.get("published"),
                 (c.get("description") or "")[:700], json.dumps(c.get("refs", []))),
            )

        new_adv = []
        for a in payload.get("advisories", []):
            code = a.get("code") or a.get("link") or a.get("title")
            exists = cur.execute("SELECT 1 FROM advisories WHERE code=?", (code,)).fetchone()
            if not exists:
                new_adv.append(code)
            cur.execute(
                """INSERT INTO advisories (code, first_seen_run, last_seen_run, title, link, published, summary)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(code) DO UPDATE SET last_seen_run=excluded.last_seen_run, title=excluded.title,
                     link=excluded.link, published=excluded.published, summary=excluded.summary""",
                (code, run_id, run_id, a.get("title", ""), a.get("link", ""), a.get("published", ""), (a.get("summary") or "")[:500]),
            )

        new_kev = []
        for k in payload.get("kev", []):
            exists = cur.execute("SELECT 1 FROM kev WHERE cve_id=?", (k["cveID"],)).fetchone()
            if not exists:
                new_kev.append(k["cveID"])
            cur.execute(
                """INSERT INTO kev (cve_id, first_seen_run, last_seen_run, vendor, product, date_added, due_date, ransomware)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(cve_id) DO UPDATE SET last_seen_run=excluded.last_seen_run""",
                (k["cveID"], run_id, run_id, k.get("vendorProject", ""), k.get("product", ""),
                 k.get("dateAdded", ""), k.get("dueDate", ""),
                 1 if (k.get("knownRansomwareCampaignUse") or "").lower() == "known" else 0),
            )

        conn.commit()
        return {"run_id": run_id, "new_cves": new_cves, "new_advisories": new_adv, "new_kev": new_kev}
    finally:
        conn.close()


def store_assets(assets, db_path=None):
    """Upsert idempotent de l'inventaire d'actifs OT."""
    conn = _connect(db_path)
    try:
        with conn:
            for a in assets or []:
                conn.execute(
                    """INSERT INTO assets (asset_id, name, vendor, product, firmware, purdue_level, criticality, source)
                       VALUES (?,?,?,?,?,?,?,?)
                       ON CONFLICT(asset_id) DO UPDATE SET name=excluded.name, vendor=excluded.vendor,
                         product=excluded.product, firmware=excluded.firmware, purdue_level=excluded.purdue_level,
                         criticality=excluded.criticality, source=excluded.source""",
                    (a.get("asset_id"), a.get("name"), a.get("vendor"), a.get("product"), a.get("firmware"),
                     a.get("purdue_level"), a.get("criticality"), a.get("source")),
                )
    finally:
        conn.close()


def history_daily(db_path=None, days=30):
    """Série quotidienne sur `days` jours : {date, total, critical, kev, kev_added} (jours vides = 0)."""
    conn = _connect(db_path)
    try:
        since = (datetime.now(UTC) - timedelta(days=days - 1)).strftime("%Y-%m-%d")
        cve_rows = conn.execute(
            """SELECT substr(published,1,10) d, COUNT(*), SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END), SUM(kev)
               FROM cves WHERE substr(published,1,10) >= ? GROUP BY d""",
            (since,),
        ).fetchall()
        kev_rows = conn.execute(
            "SELECT substr(date_added,1,10) d, COUNT(*) FROM kev WHERE substr(date_added,1,10) >= ? GROUP BY d",
            (since,),
        ).fetchall()
    finally:
        conn.close()
    cve_map = {d: {"total": t, "critical": c or 0, "kev": k or 0} for d, t, c, k in cve_rows}
    kev_map = {d: n for d, n in kev_rows}
    series = []
    for i in range(days):
        d = (datetime.now(UTC) - timedelta(days=days - 1 - i)).strftime("%Y-%m-%d")
        row = cve_map.get(d, {"total": 0, "critical": 0, "kev": 0})
        series.append({"date": d, "total": row["total"], "critical": row["critical"],
                       "kev": row["kev"], "kev_added": kev_map.get(d, 0)})
    return series


def history(db_path=None):
    """Compat : comptage de CVE par date de publication."""
    return [{"date": s["date"], "count": s["total"]} for s in history_daily(db_path)]
