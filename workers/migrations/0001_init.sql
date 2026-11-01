-- Schéma identique à src/store.py (D1 = SQLite edge)
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
  attack_ics TEXT, ssvc TEXT, assets TEXT, ot_score REAL,
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
