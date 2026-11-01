#!/usr/bin/env python3
"""Growth v1.18 : acquisition + rétention légères et éthiques.

- RSS 2.0 (/feed.xml) depuis data/ + dernière édition ;
- sitemap.xml + robots.txt (SEO) ;
- abonnement /subscribe (email ou webhook) : stockage local, dédup, AUCUN tracking
  (RGPD : pas de cookie, pas de fingerprint, droit à l'oubli via /unsubscribe) ;
- /stats : chiffres publics (preuve sociale) ;
- /integrate : page « copier-coller » TAXII / STIX / MISP / webhook / OpenAPI ;
- seo_head() : hreflang FR/AR/EN + Open Graph + JSON-LD injectés dans les éditions.
"""
import html
import json
import os
import re
import sys
from datetime import UTC, datetime
from xml.sax.saxutils import escape as xesc

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
OUT = os.path.join(ROOT, "out")
sys.path.insert(0, HERE)

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$")
WEBHOOK_RE = re.compile(r"^https://[^\s]{3,}$")

PAGE_CSS = ("body{font-family:'Segoe UI',system-ui,Tahoma,Arial,sans-serif;background:#f4f6fa;color:#1a2340;"
            "margin:0;padding:24px;line-height:1.6}.wrap{max-width:960px;margin:auto;background:#fff;"
            "border-radius:12px;padding:28px;box-shadow:0 2px 12px rgba(0,0,0,.08)}h1{font-size:22px;margin:0 0 4px}"
            "h2{font-size:17px;margin-top:24px}.meta{color:#64748b;font-size:13px;margin-bottom:18px}"
            "pre{background:#0f172a;color:#e2e8f0;padding:12px;border-radius:8px;overflow:auto;font-size:12px}"
            "code{background:#eef2f7;padding:1px 5px;border-radius:4px;font-size:12px}"
            ".cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:8px}.card{background:#1a2340;color:#fff;"
            "border-radius:10px;padding:12px 18px;min-width:120px}.card .n{font-size:24px;font-weight:700}"
            ".card .l{font-size:12px;opacity:.85}a{color:#2962ff}li{margin:4px 0}"
            "footer{margin-top:24px;color:#94a3b8;font-size:11px}")


def load_json(name, default):
    p = os.path.join(DATA, name)
    if not os.path.exists(p):
        return default
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------- abonnés
def _subs_file():
    return os.path.join(DATA, "subscribers.json")


def subscribe(email=None, webhook=None, subs_file=None):
    """Ajoute un abonné (email et/ou webhook). Retourne (ok, message). Pas de tracking."""
    subs_file = subs_file or _subs_file()
    email = (email or "").strip().lower()
    webhook = (webhook or "").strip()
    if email and not EMAIL_RE.match(email):
        return False, "email invalide"
    if webhook and not WEBHOOK_RE.match(webhook):
        return False, "webhook invalide (https:// requis)"
    if not email and not webhook:
        return False, "email ou webhook requis"
    subs = []
    if os.path.exists(subs_file):
        with open(subs_file, encoding="utf-8") as fh:
            subs = json.load(fh)
    entry = {"email": email or None, "webhook": webhook or None,
             "ts": datetime.now(UTC).isoformat(), "source": "web"}
    if any(s.get("email") == entry["email"] or (entry["webhook"] and s.get("webhook") == entry["webhook"]) for s in subs):
        return True, "déjà abonné"
    subs.append(entry)
    with open(subs_file, "w", encoding="utf-8") as fh:
        json.dump(subs, fh, ensure_ascii=False, indent=2)
    return True, "inscrit"


def unsubscribe(email, subs_file=None):
    subs_file = subs_file or _subs_file()
    if not os.path.exists(subs_file):
        return False
    with open(subs_file, encoding="utf-8") as fh:
        subs = json.load(fh)
    before = len(subs)
    subs = [s for s in subs if s.get("email") != (email or "").strip().lower()]
    if len(subs) == before:
        return False
    with open(subs_file, "w", encoding="utf-8") as fh:
        json.dump(subs, fh, ensure_ascii=False, indent=2)
    return True


def subscriber_count(subs_file=None):
    subs_file = subs_file or _subs_file()
    if not os.path.exists(subs_file):
        return 0
    with open(subs_file, encoding="utf-8") as fh:
        return len(json.load(fh))


# ---------------------------------------------------------------- SEO
def seo_head(base, lang, route, title, description, date_iso):
    """Bloc hreflang FR/AR/EN + canonical + Open Graph + JSON-LD à insérer dans <head>."""
    if not base:
        return ""
    routes = {"fr": "/issue", "ar": "/issue.ar", "en": "/issue.en"}
    alt = "".join(
        f'<link rel="alternate" hreflang="{lg}" href="{base}{rt}"' for lg, rt in routes.items()
    ) + f'<link rel="alternate" hreflang="x-default" href="{base}/issue">'
    og = (f'<meta property="og:type" content="article">'
          f'<meta property="og:title" content="{html.escape(title)}">'
          f'<meta property="og:description" content="{html.escape(description)}">'
          f'<meta property="og:url" content="{base}{route}">'
          f'<meta property="og:locale" content="{"ar_MA" if lang == "ar" else ("en_US" if lang == "en" else "fr_FR")}">'
          f'<meta name="twitter:card" content="summary">')
    ld_obj = {"@context": "https://schema.org", "@type": "NewsArticle", "headline": title,
              "datePublished": date_iso, "inLanguage": lang, "url": base + route}
    ld = '<script type="application/ld+json">' + json.dumps(ld_obj, ensure_ascii=False) + "</script>"
    return (f'<link rel="canonical" href="{base}{route}">{alt}{og}{ld}')


def sitemap(base):
    urls = ["/", "/issue", "/issue.ar", "/issue.en", "/issue.pdf", "/feed.xml",
            "/api/data", "/api/history", "/api/assets", "/openapi.json", "/stats",
            "/integrate", "/taxii2/collections"]
    lastmod = load_json("meta.json", {}).get("generated_at", "")[:10] or datetime.now(UTC).strftime("%Y-%m-%d")
    items = "".join(f"<url><loc>{xesc(base + u)}</loc><lastmod>{lastmod}</lastmod></url>" for u in urls)
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{items}</urlset>')


def robots(base):
    return f"User-agent: *\nAllow: /\nDisallow: /api/refresh\nSitemap: {base}/sitemap.xml\n"


# ---------------------------------------------------------------- RSS
def rss_feed(base):
    meta = load_json("meta.json", {})
    cves = load_json("cves.json", [])
    advisories = load_json("cisa_advisories.json", [])
    gen = meta.get("generated_at", datetime.now(UTC).isoformat())[:19].replace("T", " ") + " UTC"
    items = []
    for c in sorted(cves, key=lambda x: -(x.get("risk") or 0))[:10]:
        link = f"https://nvd.nist.gov/vuln/detail/{c['id']}"
        desc = (c.get("description") or "")[:280]
        badges = "★KEV " if c.get("kev") else ""
        items.append(f"<item><title>{xesc(badges + c['id'] + ' — CVSS ' + str(c.get('cvss')))}</title>"
                     f"<link>{xesc(link)}</link><guid>{xesc(link)}</guid>"
                     f"<description>{xesc(desc)}</description></item>")
    for a in advisories[:5]:
        link = a.get("link") or base
        items.append(f"<item><title>{xesc((a.get('code') or 'ICS') + ' — ' + (a.get('title') or ''))}</title>"
                     f"<link>{xesc(link)}</link><guid>{xesc(link)}</guid>"
                     f"<description>{xesc((a.get('summary') or '')[:280])}</description></item>")
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<rss version="2.0"><channel>'
            f"<title>OT Watch — veille OT/ICS</title><link>{xesc(base)}/</link>"
            "<description>Veille automatisée CVE OT/ICS (CISA/NVD/KEV/EPSS) — édition FR, AR et EN.</description>"
            f"<language>fr</language><lastBuildDate>{xesc(gen)}</lastBuildDate>"
            f"{''.join(items)}</channel></rss>")


# ---------------------------------------------------------------- stats
def stats_payload():
    meta = load_json("meta.json", {})
    cves = load_json("cves.json", [])
    kev = load_json("kev.json", [])
    advisories = load_json("cisa_advisories.json", [])
    assets = load_json("assets.json", [])
    if isinstance(assets, dict):
        assets = assets.get("assets", [])
    history = []
    try:
        import store
        history = store.history_daily(os.path.join(DATA, "otwatch.db"), days=30)
    except Exception:
        history = []
    return {
        "generated_at": meta.get("generated_at"),
        "window_days": meta.get("window_days", 14),
        "cves_now": len(cves), "kev_now": len(kev), "advisories_now": len(advisories),
        "assets": len(assets) if isinstance(assets, list) else 0,
        "cves_30d": sum(s.get("total", 0) for s in history),
        "runs_30d": len(history),
        "subscribers": subscriber_count(),
    }


def stats_html(base):
    s = stats_payload()
    cards = [
        (s["cves_30d"], "CVE publiées (30 j)"), (s["cves_now"], "CVE suivies (édition en cours)"),
        (s["kev_now"], "entrées KEV OT"), (s["advisories_now"], "avis CISA ICS"),
        (s["assets"], "actifs OT du profil"), (s["runs_30d"], "collectes (30 j)"),
        (s["subscribers"], "abonnés RSS/webhook"),
    ]
    cards_html = "".join(f'<div class="card"><div class="n">{n}</div><div class="l">{html.escape(lab)}</div></div>'
                         for n, lab in cards)
    return (f'<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>OT Watch — statistiques publiques</title><style>{PAGE_CSS}</style></head><body><div class="wrap">'
            f'<h1>📊 Statistiques publiques OT Watch</h1>'
            f'<div class="meta">Mise à jour à chaque collecte · générée le {html.escape((s["generated_at"] or "")[:19])} UTC · '
            f'<a href="{base}/feed.xml">RSS</a> · <a href="{base}/integrate">Intégrer</a></div>'
            f'<div class="cards">{cards_html}</div>'
            f'<h2>Transparence</h2><ul><li>Aucun cookie, aucun tracking : les chiffres ci-dessus viennent des données collectées, pas de vous.</li>'
            f'<li>Éditions : <a href="{base}/issue">FR</a> · <a href="{base}/issue.ar">العربية</a> · <a href="{base}/issue.en">EN</a>.</li>'
            f'<li>API ouverte : <a href="{base}/openapi.json">OpenAPI</a> · <a href="{base}/metrics">/metrics</a> (Prometheus) · '
            f'<a href="{base}/taxii2/collections">TAXII 2.1</a> · STIX 2.1 · MISP.</li></ul>'
            f'<footer>OT Watch — veille OT/ICS open source, 100 % gratuit. AI Act art. 50 : contenu assisté par IA, revu par un humain.</footer>'
            f'</div></body></html>')


# ---------------------------------------------------------------- page intégrations
def integrate_html(base):
    snippets = [
        ("Flux RSS (veille passive)", f"curl -s {base}/feed.xml"),
        ("API JSON des CVE OT (score OT, KEV, EPSS, SSVC, ATT&CK)", f"curl -s {base}/api/data | jq '.cves[:3]'"),
        ("Découverte TAXII 2.1", f"curl -s {base}/taxii2/collections"),
        ("Objets STIX 2.1 de la collection OT", f"curl -s {base}/taxii2/collections/otwatch-ot-cves/objects | jq '.objects[:2]'"),
        ("Export STIX / MISP prêts à l'emploi", f"curl -s {base}/stix -o stix.json ; curl -s {base}/misp -o event.json"),
        ("Alerting webhook à chaque collecte", 'POST /subscribe {"webhook": "https://votre-soc.example/hook"} — push SSE aussi sur /api/stream'),
        ("Abonnement e-mail (sans tracking)", 'POST /subscribe {"email": "vous@entreprise.tld"}'),
        ("Métriques Prometheus", f"curl -s {base}/metrics"),
        ("Spécification OpenAPI", f"curl -s {base}/openapi.json"),
    ]
    snip_html = "".join(f"<h2>{html.escape(t)}</h2><pre><code>{html.escape(c)}</code></pre>" for t, c in snippets)
    communities = [
        ("ISAGCA — ISA Global Cybersecurity Alliance (IEC 62443)", "https://isagca.org"),
        ("ICS Village (ateliers/CTF matériel OT)", "https://icsvillage.com"),
        ("OT Cybersecurity Coalition (OTCC)", "https://otcybercoalition.org"),
        ("CISA — OT-ISAC et avis ICS", "https://www.cisa.gov/topics/industrial-control-systems"),
        ("FIRST / TF-CSIRT (communautés CSIRT)", "https://www.first.org / https://tf-csirt.org"),
        ("MISP Project (communautés de partage de threat intel)", "https://www.misp-project.org"),
        ("ICS Security Switzerland (association, meetups)", "https://www.icssec.ch"),
        ("S4x27 — conférence ICS/OT (proposals de talks)", "https://s4xevents.com"),
        ("ISA OT Cybersecurity Summit 2027 (Athènes)", "https://www.isa.org"),
    ]
    comm_html = "".join(f'<li><a href="{u}">{html.escape(t)}</a></li>' for t, u in communities)
    return (f'<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>OT Watch — intégrer & partager</title><style>{PAGE_CSS}</style></head><body><div class="wrap">'
            f'<h1>🔌 Intégrer OT Watch dans votre SOC / votre veille</h1>'
            f'<div class="meta">Tout est gratuit, ouvert et documenté (<a href="{base}/openapi.json">OpenAPI</a>). '
            f'Retour à la <a href="{base}/">newsletter</a>.</div>'
            f'{snip_html}'
            f'<h2>🌐 Communautés OT/ICS à rejoindre (voir docs/COMMUNITY.md)</h2><ul>{comm_html}</ul>'
            f'<footer>OT Watch — 100 % gratuit et open source. Aucun tracking, aucun cookie. Voir docs/MONETIZATION.md pour soutenir le projet.</footer>'
            f'</div></body></html>')
