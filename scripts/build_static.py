#!/usr/bin/env python3
"""Construit la version publique d'OT Watch pour GitHub Pages.

Le serveur Python (server.py) reste la version complète et privée (profil d'actifs, SSE, TAXII,
abonnements). GitHub Pages ne sert que des fichiers : on publie un dashboard statique et des
éditions régénérées à partir d'une copie NETTOYÉE des données (voir scripts/public_edition.py),
sans inventaire d'actifs, sans lien CVE -> actifs et sans état interne du pipeline.

Usage : python3 scripts/build_static.py [--out site] [--data data]
"""
import argparse
import json
import os
import re
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, HERE)

import public_edition  # noqa: E402

import growth  # noqa: E402
import server  # noqa: E402
import store  # noqa: E402

PAGES_INTERVAL_S = 6 * 3600  # cadence du cron Cloudflare (17 */6 * * *)
PAGES_BASE = os.environ.get("OTWATCH_PAGES_BASE", "https://o-alil-lab.github.io/ot-watch")
WORKER_URL = os.environ.get("OTWATCH_WORKER_URL", "https://ot-watch-cron.alilououssama.workers.dev")
FEED_XSL = os.path.join(HERE, "feed.xsl")

# Champs de /api/data réservés à la version serveur (état interne, profil d'actifs)
PRIVATE_PAYLOAD_FIELDS = ("last_run", "last_error", "collect_runs", "agents", "assets", "netwatch",
                          "quality", "server_time", "freshness_seconds")

SUBSCRIBE_BLOCK = re.compile(r'<div style="margin:0 0 14px;[^"]*">\s*<form id="subForm".*?</form>.*?</div>', re.S)
RSS_LINK = ('<div class="rss"><a href="feed.xml">📡 S\'abonner au flux RSS</a>'
            ' — gratuit, sans inscription : nouvelles CVE OT/ICS et avis CISA dans votre lecteur RSS'
            ' (Feedly, Inoreader, Outlook…).</div>')
META_BLOCK = re.compile(r'<div class="meta">.*?</div>', re.S)
PUBLIC_META = (
    '<div class="meta">\n'
    '    <span>🕒 Dernière collecte : <b id="mGen">…</b> (<span id="mAgo">…</span>)</span>\n'
    '    <span>⏭️ Prochaine mise à jour : <b id="nextRun">…</b></span>\n'
    '    <span>🪟 Fenêtre : <b id="mWin">…</b> jours</span>\n'
    '    <span>🆕 Nouvelles CVE : <b id="mNew">…</b></span>\n'
    # éléments encore écrits par le script du dashboard, masqués sur la version publique
    '    <span hidden><span id="mSrv"></span><b id="mInt"></b><span id="mNext"></span>'
    '<b id="mRuns"></b><span id="mErr"></span></span>\n'
    '  </div>')

HEAD_EXTRA = (
    # pas d'en-têtes HTTP sur GitHub Pages : politique de sécurité déclarée dans la page
    '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'; '
    'script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:; '
    f'connect-src \'self\' {WORKER_URL}; base-uri \'none\'; form-action \'none\'; object-src \'none\'">\n'
    '<meta name="referrer" content="no-referrer">\n'
    '<meta name="description" content="Veille cybersécurité OT/ICS : CVE prioritaires des automates et systèmes '
    'industriels, avis CISA ICS et vulnérabilités exploitées (KEV), mise à jour toutes les 6 h.">\n'
    '<meta name="theme-color" content="#0b1220">\n')

# Styles publics, insérés APRÈS la feuille du dashboard pour qu'ils s'appliquent
PUBLIC_CSS = (
    '<style>\n'
    '#liveBadge{display:none!important}\n'
    '.rss{max-width:1180px;margin:16px auto 0;padding:0 20px;font-size:14px;color:var(--mut)}'
    '.rss a{color:var(--acc);font-weight:600}\n'
    '@media (max-width:640px){\n'
    ' header{padding:14px 16px}header>div:last-child{display:flex;flex-wrap:wrap;gap:6px}\n'
    ' header button{padding:7px 10px;font-size:13px}\n'
    ' .wrap{padding:14px 12px}.rss{padding:0 12px}\n'
    ' .cards{grid-template-columns:repeat(2,1fr)}.meta{flex-direction:column;gap:4px}\n'
    # tableaux -> cartes empilées (sinon la colonne « Détail » est écrasée à 2 caractères)
    ' table,tbody,tr,td{display:block;width:100%}thead{display:none}\n'
    ' tbody tr{border-bottom:1px solid var(--line);padding:10px 0}\n'
    ' tbody td{padding:3px 0!important;border:0!important;white-space:normal!important}\n'
    ' #tCve td:nth-child(2),#tCve td:nth-child(3){display:inline-block;width:auto;margin-right:10px}\n'
    ' #tCve td:nth-child(2)::before{content:"Risque ";color:var(--mut);font-size:11px}\n'
    ' #tCve td:nth-child(3)::before{content:"CVSS ";color:var(--mut);font-size:11px}\n'
    '}\n'
    '</style>\n')

# (motif dans DASHBOARD_HTML, remplacement public) — chaque motif DOIT exister (garde-fou de dérive)
REWRITES = [
    ("<title>OT Watch — Live</title>", "<title>OT Watch — veille cybersécurité OT/ICS</title>"),
    ("fetch('/api/data')", "fetch('api/data.json',{cache:'no-store'})"),
    ("fetch('/api/history')", "fetch('api/history.json',{cache:'no-store'})"),
    ('<div class="tag">Tableau de bord temps réel — PLC / CVE / avis CISA / KEV (sources live : CISA · NVD · KEV)</div>',
     '<div class="tag">Veille cybersécurité des automates et systèmes industriels — CVE, avis CISA ICS, '
     'vulnérabilités exploitées (KEV)</div>'),
    # badge « connecté » : propre au serveur temps réel
    ('<span id="liveBadge" class="live">', '<span id="liveBadge" class="live" hidden>'),
    ('⚠ DONNÉES STALES', '⚠ Données à rafraîchir'),
    ('href="/issue.pdf"', 'href="issue.pdf"'),
    ('href="/issue.ar"', 'href="issue.ar.html"'),
    ('href="/issue.en"', 'href="issue.en.html"'),
    ('href="/issue"', 'href="issue.html"'),
    ('href="/feed.xml"', 'href="feed.xml"'),
    ('href="/stix"', 'href="stix.json"'),
    ('href="/misp"', 'href="misp.json"'),
    # réservé au serveur : abonnés, statistiques internes, intégrations, TAXII, documentation d'API
    ('    <a href="/integrate" target="_blank"><button class="ghost">🔌 Intégrer</button></a>\n', ""),
    ('    <a href="/stats" target="_blank"><button class="ghost">📊 Stats</button></a>\n', ""),
    ('    <a href="/taxii2/collections" target="_blank"><button class="ghost">🛰 TAXII 2.1</button></a>\n', ""),
    ('    <a href="/openapi.json" target="_blank"><button class="ghost">📖 OpenAPI</button></a>\n', ""),
    ("document.getElementById('subForm').addEventListener", "document.getElementById('subForm')?.addEventListener"),
    # profil d'actifs (« Mes actifs OT », score OT) : privé, jamais publié
    ('<button id="bRel">⭐ Mes actifs OT</button>', '<button id="bRel" hidden>⭐</button>'),
    ('<th>OT</th>', ''),
    ('<td>${otBadge(c.ot_score)}</td>', ''),
    ("${c.relevant?' <span style=\"color:#f59e0b\" title=\"correspond à votre profil\">⭐</span>':''}", ''),
    ('<td colspan="6" style="color:#8ea0c2">Aucune CVE ne correspond au filtre.</td>',
     '<td colspan="5" style="color:#8ea0c2">Aucune CVE ne correspond au filtre.</td>'),
    ('Triées par CVSS.', 'Triées par niveau de risque.'),
    ('(30 derniers jours, historique SQLite)', '(30 derniers jours)'),
    ('<h2>🔴 CVE — PLC &amp; OT (live NVD)</h2>', '<h2>🔴 CVE — automates &amp; systèmes OT</h2>'),
    ('<h2>📋 Avis CISA ICS (live)</h2>', '<h2>📋 Avis CISA ICS</h2>'),
    ('écrits à partir des sources primaires (voir research/findings).', 'écrits à partir des sources primaires.'),
    ('<footer>OT Watch Live · données collectées en temps réel depuis CISA (RSS/ICS advisories), NVD API 2.0 et CISA KEV · affichage échappé/anti-XSS · <span id="clock"></span></footer>',
     '<footer>OT Watch · veille OT/ICS automatisée · sources : CISA, NVD, CISA KEV, FIRST EPSS · '
     'à vérifier auprès des sources primaires avant toute action · <span id="clock"></span></footer>'),
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

# Liens internes des éditions générées (pensées pour le serveur) -> fichiers du site
EDITION_LINKS = [('href="/issue.ar"', 'href="issue.ar.html"'), ('href="/issue.en"', 'href="issue.en.html"'),
                 ('href="/issue"', 'href="issue.html"')]

# Bouton « Mettre à jour maintenant » -> Worker Cloudflare (le jeton GitHub reste côté Worker).
# Créneaux auto : 00:17, 06:17, 12:17, 18:17 UTC, affichés en heure locale.
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
    """Réécrit le dashboard serveur en page publique ; échoue si un motif a disparu."""
    for old, new in REWRITES:
        if old not in html:
            raise ValueError(f"motif introuvable dans DASHBOARD_HTML : {old!r}")
        html = html.replace(old, new)
    for block, repl, what in ((SUBSCRIBE_BLOCK, RSS_LINK, "formulaire d'abonnement"),
                              (META_BLOCK, PUBLIC_META, "ligne d'état")):
        html, n = block.subn(lambda _m, r=repl: r, html, count=1)
        if n != 1:
            raise ValueError(f"{what} introuvable dans DASHBOARD_HTML")
    html = html.replace("</title>", "</title>\n" + HEAD_EXTRA, 1)
    html = html.replace("</head>", PUBLIC_CSS + "</head>", 1)
    return html.replace("</body>", REFRESH_JS + "</body>", 1)


def public_payload():
    payload = server.api_payload()
    age = payload.get("freshness_seconds")
    for k in PRIVATE_PAYLOAD_FIELDS:
        payload.pop(k, None)
    # le serveur recalcule « relevant » depuis les mots-clés du profil : on le retire à nouveau
    payload["cves"] = [public_edition.public_cve(c) for c in payload.get("cves", [])]
    payload.update({
        "collecting": False, "auto_interval_seconds": PAGES_INTERVAL_S, "static": True,
        # fraîcheur jugée sur la cadence du cron, pas sur celle du serveur
        "stale": bool(age is not None and age > PAGES_INTERVAL_S * server.CFG_STALE_N),
    })
    return payload


def build(out_dir, data_dir=None, issues_dir=None):
    """issues_dir est ignoré : les éditions publiques sont toujours régénérées depuis les données nettoyées."""
    del issues_dir
    src_data = data_dir or server.DATA
    asset_ids = public_edition.private_asset_ids(src_data)
    with tempfile.TemporaryDirectory(prefix="otwatch-public-") as tmp:
        pub_data = public_edition.make_public_data(src_data, os.path.join(tmp, "data"))
        pub_out = os.path.join(tmp, "out")
        public_edition.render_public_editions(pub_data, pub_out)
        saved = (server.DATA, server.OUT, growth.DATA, growth.OUT)
        server.DATA, server.OUT = pub_data, pub_out
        growth.DATA, growth.OUT = pub_data, pub_out
        try:
            written = _write_site(out_dir, pub_data)
        finally:
            server.DATA, server.OUT, growth.DATA, growth.OUT = saved
    _check_site(out_dir, written, asset_ids)
    return written


def _write_text(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _write_site(out_dir, data_dir):
    os.makedirs(os.path.join(out_dir, "api"), exist_ok=True)
    _write_text(os.path.join(out_dir, "index.html"), static_dashboard(server.DASHBOARD_HTML))
    _write_text(os.path.join(out_dir, "api", "data.json"), json.dumps(public_payload(), ensure_ascii=False))

    db = os.path.join(data_dir, "otwatch.db")
    history = store.history_daily(db_path=db) if os.path.exists(db) else []
    _write_text(os.path.join(out_dir, "api", "history.json"), json.dumps({"history": history}, ensure_ascii=False))

    written = ["index.html", "api/data.json", "api/history.json"]
    for fn, name in EXPORTS:
        res = getattr(server, fn)()
        if not res:
            continue
        content = res[0]
        if isinstance(content, bytes):
            with open(os.path.join(out_dir, name), "wb") as fh:
                fh.write(content)
        else:
            if name.endswith(".html"):
                for old, new in EDITION_LINKS:
                    content = content.replace(old, new)
            _write_text(os.path.join(out_dir, name), content)
        written.append(name)

    # feuille XSL : le flux reste du RSS valide, mais s'affiche comme une page lisible dans un navigateur
    rss = growth.rss_feed(PAGES_BASE).replace(
        '<?xml version="1.0" encoding="UTF-8"?>\n',
        '<?xml version="1.0" encoding="UTF-8"?>\n<?xml-stylesheet type="text/xsl" href="feed.xsl"?>\n', 1)
    _write_text(os.path.join(out_dir, "feed.xml"), rss)
    shutil.copy(FEED_XSL, os.path.join(out_dir, "feed.xsl"))
    _write_text(os.path.join(out_dir, "robots.txt"), f"User-agent: *\nAllow: /\nSitemap: {PAGES_BASE}/sitemap.xml\n")
    _write_text(os.path.join(out_dir, "sitemap.xml"), _sitemap(written))
    written += ["feed.xml", "feed.xsl", "robots.txt", "sitemap.xml"]
    open(os.path.join(out_dir, ".nojekyll"), "w").close()
    return written


def _sitemap(files):
    pages = [""] + [f for f in files if f.endswith((".html", ".pdf")) and f != "index.html"] + ["feed.xml"]
    urls = "".join(f"<url><loc>{PAGES_BASE}/{p}</loc></url>" for p in pages)
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{urls}</urlset>\n')


def _check_site(out_dir, written, asset_ids):
    """Dernier garde-fou : aucun identifiant d'actif ni champ privé dans les fichiers texte publiés."""
    for name in written:
        if name.endswith(".pdf"):
            continue
        with open(os.path.join(out_dir, name), encoding="utf-8") as fh:
            public_edition.assert_no_private_data(fh.read(), asset_ids)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=os.path.join(ROOT, "site"))
    ap.add_argument("--data", default=None)
    ap.add_argument("--outdir", default=None, help="(obsolète, ignoré)")
    args = ap.parse_args(argv)
    written = build(args.out, args.data, args.outdir)
    print(f"[build_static] {len(written)} fichiers -> {args.out} : {', '.join(written)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
