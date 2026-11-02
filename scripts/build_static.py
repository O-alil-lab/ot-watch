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
RSS_LINK = ('<div style="margin:0 0 14px"><a href="feed.xml" style="color:#f59e0b">📡 S\'abonner au flux RSS</a>'
            ' — gratuit, sans inscription : nouvelles CVE OT/ICS et avis CISA dans votre lecteur RSS'
            ' (Feedly, Inoreader, Outlook…).</div>')
FEED_XSL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "feed.xsl")

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
    # pas de serveur : SSE désactivé ; la re-collecte passe par le Worker Cloudflare (POST /refresh, limité)
    ('<button id="btnRefresh">🔄 Re-collecter maintenant</button>',
     '<button id="btnRefresh">🔄 Mettre à jour maintenant</button>'),
    ("'⏳ Collecte en cours…':'🔄 Re-collecter maintenant'",
     "'⏳ Collecte en cours…':'🔄 Mettre à jour maintenant'"),
    ("if (window.EventSource) {", "if (false) {"),
    ("await fetch('/api/refresh',{method:'POST'});toast('🔄 Collecte lancée (CISA/NVD/KEV)…');",
     "await refreshViaWorker();return;"),
    ("setInterval(loadData,15000);", "setInterval(loadData,300000);"),
]

WORKER_URL = os.environ.get("OTWATCH_WORKER_URL", "https://ot-watch-cron.alilououssama.workers.dev")

BANNER = ('<div style="background:#1e293b;color:#cbd5e1;font:13px system-ui;padding:8px 16px;'
          'text-align:center">Version publique GitHub Pages · mise à jour automatique toutes les 6 h '
          '(prochaine : <b id="nextRun">...</b>) · <a style="color:#f59e0b" '
          'href="https://github.com/O-alil-lab/ot-watch">code source</a></div>')

# Bouton « Mettre à jour maintenant » -> Worker Cloudflare (le jeton GitHub reste côté Worker).
# Créneaux auto : 00:17, 06:17, 12:17, 18:17 UTC (cron Cloudflare 17 */6 * * *), affichés en heure locale.
REFRESH_JS = """<script>
const OTW_WORKER = __WORKER__;
function otwNextRun(now) {
  const d = new Date(now); d.setUTCMinutes(17, 0, 0);
  d.setUTCHours(Math.floor(d.getUTCHours() / 6) * 6);
  while (d <= now) d.setUTCHours(d.getUTCHours() + 6);
  return d;
}
function otwShowNext() {
  const el = document.getElementById('nextRun');
  if (el) el.textContent = otwNextRun(new Date()).toLocaleTimeString('fr-FR', {hour: '2-digit', minute: '2-digit'});
}
async function refreshViaWorker() {
  const b = document.getElementById('btnRefresh');
  b.disabled = true;
  try {
    const r = await fetch(OTW_WORKER + '/refresh', {method: 'POST'});
    const j = await r.json();
    if (r.status === 202) {
      toast('🔄 Collecte lancée : le site se met à jour dans 5 à 8 min');
      b.textContent = '⏳ Collecte en cours…';
      setTimeout(() => location.reload(), 480000);
      return;
    }
    if (j.error === 'running') toast('⏳ Une collecte est déjà en cours, revenez dans quelques minutes');
    else if (j.error === 'too_soon') toast('✅ Données toutes fraîches — nouvelle collecte possible dans ' + Math.ceil(j.retry_after_s / 60) + ' min');
    else toast('Mise à jour indisponible pour le moment');
  } catch (e) {
    toast('Mise à jour indisponible pour le moment');
  }
  setTimeout(() => { b.disabled = false; }, 5000);
}
otwShowNext(); setInterval(otwShowNext, 60000);
</script>
""".replace("__WORKER__", json.dumps(WORKER_URL))

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
    html = html.replace("<body>", "<body>\n" + BANNER, 1)
    return html.replace("</body>", REFRESH_JS + "</body>", 1)


def build(out_dir, data_dir=None, issues_dir=None):
    data_dir = data_dir or server.DATA
    issues_dir = issues_dir or server.OUT
    saved = (server.DATA, server.OUT, growth.DATA, growth.OUT)
    server.DATA, server.OUT = data_dir, issues_dir
    growth.DATA, growth.OUT = data_dir, issues_dir
    try:
        return _write_site(out_dir, data_dir)
    finally:
        server.DATA, server.OUT, growth.DATA, growth.OUT = saved


def _write_site(out_dir, data_dir):
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

    # feuille XSL : le flux reste du RSS valide, mais s'affiche comme une page lisible dans un navigateur
    rss = growth.rss_feed(PAGES_BASE).replace(
        '<?xml version="1.0" encoding="UTF-8"?>\n',
        '<?xml version="1.0" encoding="UTF-8"?>\n<?xml-stylesheet type="text/xsl" href="feed.xsl"?>\n', 1)
    with open(os.path.join(out_dir, "feed.xml"), "w", encoding="utf-8") as fh:
        fh.write(rss)
    shutil.copy(FEED_XSL, os.path.join(out_dir, "feed.xsl"))
    written += ["feed.xml", "feed.xsl"]

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
