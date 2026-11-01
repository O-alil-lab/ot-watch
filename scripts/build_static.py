#!/usr/bin/env python3
"""Construit une version statique d'OT Watch pour GitHub Pages.

Le serveur Python (server.py) reste la version complète (SSE, re-collecte à la demande,
TAXII). GitHub Pages ne sert que des fichiers : on exporte donc le dashboard avec des
chemins relatifs et des instantanés JSON, régénérés par le workflow .github/workflows/pages.yml.

Usage : python3 scripts/build_static.py [--out site] [--data data] [--outdir out]
"""
import argparse
import json
import os
import re
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "src"))

import growth  # noqa: E402
import server  # noqa: E402
import store  # noqa: E402

PAGES_INTERVAL_S = 6 * 3600  # cadence du workflow pages.yml
PAGES_BASE = os.environ.get("OTWATCH_PAGES_BASE", "https://o-alil-lab.github.io/ot-watch")
SUBSCRIBE_BLOCK = re.compile(r'<div style="margin:0 0 14px;[^"]*">\s*<form id="subForm".*?</form>.*?</div>', re.S)
RSS_LINK = ('<div style="margin:0 0 14px"><a href="feed.xml" style="color:#f59e0b">📡 Suivre la veille via le flux RSS</a>'
            ' — abonnement e-mail/webhook disponible sur la version serveur.</div>')

# (motif dans DASHBOARD_HTML, remplacement statique)
REWRITES = [
    ("fetch('/api/data')", "fetch('api/data.json',{cache:'no-store'})"),
    ("fetch('/api/history')", "fetch('api/history.json',{cache:'no-store'})"),
    ('href="/issue.pdf"', 'href="issue.pdf"'),
    ('href="/issue.ar"', 'href="issue.ar.html"'),
    ('href="/issue.en"', 'href="issue.en.html"'),
    ('href="/issue"', 'href="issue.html"'),
    ('href="/feed.xml"', 'href="feed.xml"'),
    # pages qui exigent le serveur (abonnés, /metrics, TAXII) : retirées de la version statique
    ('    <a href="/integrate" target="_blank"><button class="ghost">🔌 Intégrer</button></a>\n', ""),
    ('    <a href="/stats" target="_blank"><button class="ghost">📊 Stats</button></a>\n', ""),
    ("document.getElementById('subForm').addEventListener", "document.getElementById('subForm')?.addEventListener"),
    ('href="/stix"', 'href="stix.json"'),
    ('href="/misp"', 'href="misp.json"'),
    ('href="/openapi.json"', 'href="openapi.json"'),
    # pas de serveur TAXII sur Pages : le bundle STIX reste disponible via stix.json
    ('    <a href="/taxii2/collections" target="_blank"><button class="ghost">🛰 TAXII 2.1</button></a>\n', ""),
    # pas de serveur : pas de SSE ni de re-collecte à la demande
    ('<button id="btnRefresh">🔄 Re-collecter maintenant</button>',
     '<button id="btnRefresh">🕒 Collecte auto toutes les 6 h</button>'),
    ("'⏳ Collecte en cours…':'🔄 Re-collecter maintenant'",
     "'⏳ Collecte en cours…':'🕒 Collecte auto toutes les 6 h'"),
    ("if (window.EventSource) {", "if (false) {"),
    ("await fetch('/api/refresh',{method:'POST'});toast('🔄 Collecte lancée (CISA/NVD/KEV)…');",
     "toast('Version GitHub Pages : collecte automatique toutes les 6 h');"),
    ("setInterval(loadData,15000);", "setInterval(loadData,300000);"),
]

BANNER = ('<div style="background:#1e293b;color:#cbd5e1;font:13px system-ui;padding:8px 16px;'
          'text-align:center">Version publique GitHub Pages · données mises à jour automatiquement '
          'toutes les 6 h · <a style="color:#f59e0b" '
          'href="https://github.com/O-alil-lab/ot-watch">code source</a></div>')

EXPORTS = [  # (fonction server.latest_issue_*, fichier de sortie)
    ("latest_issue_html", "issue.html"),
    ("latest_issue_pdf", "issue.pdf"),
    ("latest_issue_ar", "issue.ar.html"),
    ("latest_issue_en", "issue.en.html"),
    ("latest_issue_stix", "stix.json"),
    ("latest_issue_misp", "misp.json"),
]


def static_dashboard(html):
    """Réécrit le dashboard serveur en page statique ; échoue si un motif a disparu."""
    for old, new in REWRITES:
        if old not in html:
            raise ValueError(f"motif introuvable dans DASHBOARD_HTML : {old!r}")
        html = html.replace(old, new)
    html, n = SUBSCRIBE_BLOCK.subn(RSS_LINK, html, count=1)
    if n != 1:
        raise ValueError("formulaire d'abonnement introuvable dans DASHBOARD_HTML")
    return html.replace("<body>", "<body>\n" + BANNER, 1)


def build(out_dir, data_dir=None, issues_dir=None):
    data_dir = data_dir or server.DATA
    issues_dir = issues_dir or server.OUT
    server.DATA, server.OUT = data_dir, issues_dir
    growth.DATA, growth.OUT = data_dir, issues_dir
    os.makedirs(os.path.join(out_dir, "api"), exist_ok=True)

    with open(os.path.join(out_dir, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(static_dashboard(server.DASHBOARD_HTML))

    payload = server.api_payload()
    age = payload.get("freshness_seconds")
    payload.update({
        "collecting": False, "auto_interval_seconds": PAGES_INTERVAL_S, "static": True,
        # fraîcheur jugée sur la cadence du workflow Pages, pas sur celle du serveur
        "stale": bool(age is not None and age > PAGES_INTERVAL_S * server.CFG_STALE_N),
    })
    with open(os.path.join(out_dir, "api", "data.json"), "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False)

    db = os.path.join(data_dir, "otwatch.db")
    history = store.history_daily(db_path=db) if os.path.exists(db) else []
    with open(os.path.join(out_dir, "api", "history.json"), "w", encoding="utf-8") as fh:
        json.dump({"history": history}, fh, ensure_ascii=False)

    written = ["index.html", "api/data.json", "api/history.json"]
    for fn, name in EXPORTS:
        res = getattr(server, fn)()
        if not res:
            continue
        mode = "wb" if isinstance(res[0], bytes) else "w"
        with open(os.path.join(out_dir, name), mode, **({} if mode == "wb" else {"encoding": "utf-8"})) as fh:
            fh.write(res[0])
        written.append(name)

    with open(os.path.join(out_dir, "feed.xml"), "w", encoding="utf-8") as fh:
        fh.write(growth.rss_feed(PAGES_BASE))
    written.append("feed.xml")

    spec = os.path.join(ROOT, "docs", "openapi.json")
    if os.path.exists(spec):
        shutil.copy(spec, os.path.join(out_dir, "openapi.json"))
        written.append("openapi.json")
    open(os.path.join(out_dir, ".nojekyll"), "w").close()
    return written


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=os.path.join(ROOT, "site"))
    ap.add_argument("--data", default=None)
    ap.add_argument("--outdir", default=None, help="dossier des éditions générées (défaut out/)")
    args = ap.parse_args(argv)
    written = build(args.out, args.data, args.outdir)
    print(f"[build_static] {len(written)} fichiers -> {args.out} : {', '.join(written)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
