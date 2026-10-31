#!/usr/bin/env python3
"""
OT Watch — store persistant SQLite (stdlib) : historique + détection des nouveautés.
Tables : runs, cves, advisories, kev. Upsert par clé métier -> idempotent, rejouable.
Retourne le diff « nouveau depuis la dernière collecte » (base des alertes).
"""
import json
import os
import sqlite3
from datetime import UTC, datetime

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
  cvss REAL, severity TEXT, kev INTEGER, epss REAL, risk REAL,
  published TEXT, description TEXT, refs TEXT
);
CREATE TABLE IF NOT EXISTS advisories (
  code TEXT PRIMARY KEY,
  first_seen_run INTEGER, last_seen_run INTEGER,
  title TEXT, link TEXT, published TEXT, summary TEXT
);
CREATE TABLE IF NOT EXISTS kev (
  cve_id TEXT PRIMARY KEY,
  first_seen_run INTEGER, last_seen_run INTEGER,
  vendor TEXT, product TEXT, date_added TEXT, due_date TEXT, ransomware INTEGER
);
"""


def _connect(db_path=None):
    os.makedirs(DATA, exist_ok=True)
    conn = sqlite3.connect(db_path or DB_PATH)
    conn.executescript(SCHEMA)
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
                """INSERT INTO cves (cve_id, first_seen_run, last_seen_run, cvss, severity, kev, epss, risk, published, description, refs)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(cve_id) DO UPDATE SET last_seen_run=excluded.last_seen_run, cvss=excluded.cvss,
                     severity=excluded.severity, kev=excluded.kev, epss=excluded.epss, risk=excluded.risk,
                     published=excluded.published, description=excluded.description, refs=excluded.refs""",
                (c["id"], run_id, run_id, c.get("cvss"), c.get("severity"), 1 if c.get("kev") else 0,
                 c.get("epss"), c.get("risk"), c.get("published"), (c.get("description") or "")[:700],
                 json.dumps(c.get("refs", []))),
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


def history(db_path=None, days=30):
    """Comptage de CVE par jour d'apparition (pour les futurs graphes)."""
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT substr(published,1,10) d, COUNT(*) n FROM cves WHERE published IS NOT NULL GROUP BY d ORDER BY d"
        ).fetchall()
        return [{"date": d, "count": n} for d, n in rows]
    finally:
        conn.close()
