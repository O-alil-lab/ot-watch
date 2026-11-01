#!/usr/bin/env python3
"""
OT Watch — moteur de rendu.
Lit data/*.json (collecte auto) + editorial/*.md (articles rédigés) et produit :
  out/issue-<AAAA-MM-JJ>.html  (newsletter pro, CSS inline, aucune ressource externe)
  out/issue-<AAAA-MM-JJ>.md    (version markdown / plateforme e-mail)
Sécurité : tout contenu externe (NVD/CISA/KEV) est échappé HTML ; seules les URL
http/https/mailto sont autorisées (safe_url) -> anti-XSS. Voir tests/test_render.py.
"""
import html
import json
import os
import re
from datetime import UTC, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(ROOT, "config.json"), encoding="utf-8") as fh:
    CFG = json.load(fh)
DATA = os.path.join(ROOT, "data")
EDITO = os.path.join(ROOT, "editorial")
OUT = os.path.join(ROOT, "out")
os.makedirs(OUT, exist_ok=True)
NL = CFG["newsletter"]

ALLOWED_SCHEMES = ("http://", "https://", "mailto:")


def safe_url(u):
    """N'autorise que http/https/mailto — bloque javascript:, data:, etc. (anti-XSS)."""
    u = (u or "").strip()
    if u.lower().startswith(ALLOWED_SCHEMES):
        return u
    return "#"


def load_json(name, default):
    p = os.path.join(DATA, name)
    if not os.path.exists(p):
        return default
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def md_to_html(text):
    """Convertisseur markdown minimaliste (titres, gras, italique, liens, listes, code, citations)."""
    lines = text.split("\n")
    out, in_list = [], False

    def inline(s):
        s = html.escape(s, quote=True)
        s = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", s)
        s = re.sub(r"\*(.+?)\*", r"<em>\1</em>", s)
        s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
        s = re.sub(
            r"\[([^\]]+)\]\(([^)]+)\)",
            lambda m: f'<a href="{safe_url(m.group(2))}">{m.group(1)}</a>',
            s,
        )
        return s

    for ln in lines:
        if re.match(r"^\s*- ", ln):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{inline(ln.strip()[2:])}</li>")
            continue
        if in_list:
            out.append("</ul>")
            in_list = False
        s = ln.rstrip()
        if not s.strip():
            continue
        m = re.match(r"^(#{1,3})\s+(.*)", s)
        if m:
            level = len(m.group(1)) + 2
            out.append(f"<h{level}>{inline(m.group(2))}</h{level}>")
            continue
        if s.startswith("> "):
            out.append(f"<blockquote>{inline(s[2:])}</blockquote>")
            continue
        if s.strip() == "---":
            out.append("<hr>")
            continue
        out.append(f"<p>{inline(s)}</p>")
    if in_list:
        out.append("</ul>")
    return "\n".join(out)


def parse_editorial():
    """Chaque fichier editorial/*.md : en-tête 'clé: valeur' jusqu'à '---', puis markdown."""
    articles = []
    if not os.path.isdir(EDITO):
        return articles
    for fn in sorted(os.listdir(EDITO)):
        if not fn.endswith(".md"):
            continue
        with open(os.path.join(EDITO, fn), encoding="utf-8") as fh:
            raw = fh.read()
        head, _, body = raw.partition("\n---\n")
        meta = {}
        for line in head.split("\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                meta[k.strip()] = v.strip()
        articles.append(
            {
                "file": fn,
                "title": meta.get("title", fn),
                "kicker": meta.get("kicker", ""),
                "lead": meta.get("lead", "false").lower() == "true",
                "section": meta.get("section", "Analyse"),
                "body_html": md_to_html(body.strip()),
                "body_md": body.strip(),
            }
        )
    return articles


def sev_badge(score, severity):
    color = {"CRITICAL": "#b91c1c", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#65a30d"}.get(
        (severity or "").upper(), "#475569"
    )
    label = f"{score:.1f}" if isinstance(score, (int, float)) else (severity or "n/a")
    return (
        f'<span style="display:inline-block;background:{color};color:#fff;border-radius:4px;'
        f'padding:1px 7px;font-size:11px;font-weight:700;white-space:nowrap;">{label}</span>'
    )


def cve_block(c):
    kev = ' <span style="color:#b91c1c;font-weight:700;" title="Ajoutée au catalogue KEV (exploitation connue)">★KEV</span>' if c.get("kev") else ""
    rel = ' <span style="color:#f59e0b;font-weight:700;" title="Correspond à votre profil d\'exposition OT">⭐</span>' if c.get("relevant") else ""
    date = (c.get("published") or "")[:10]
    cwes = ", ".join(w for w in (c.get("cwes") or []) if w)[:80]
    ref = safe_url(c["refs"][0]) if c.get("refs") else f"https://nvd.nist.gov/vuln/detail/{c['id']}"
    desc = html.escape((c.get("description") or "").replace("\r", " ").replace("\n", " "))
    if len(desc) > 220:
        desc = desc[:217] + "…"
    extra = f" · risque {c['risk']}/10" if c.get("risk") is not None else ""
    if c.get("ot_score") is not None:
        det = c.get("ot_score_detail") or {}
        aids = ", ".join(a.get("asset_id", "") for a in det.get("assets", []))
        base, fac = det.get("base"), det.get("asset_factor")
        kb, sb, ots = det.get("kev_bonus"), det.get("ssvc_bonus"), c["ot_score"]
        title = f"Score OT exposition x Purdue x criticite : base {base} x facteur {fac} + KEV {kb} + SSVC {sb} — actifs : {aids}"
        extra += (f' · <span style="background:#0e7490;color:#fff;border-radius:4px;padding:0 5px;font-size:10px;font-weight:700;"'
                  f' title="{html.escape(title)}">OT {ots:.1f}/10</span>')
    if c.get("epss") is not None:
        extra += f" · EPSS {c['epss']:.3f}"
    ssvc = (c.get("ssvc") or "").upper()
    if ssvc:
        sc = {"ACT": "#b91c1c", "ATTEND": "#ea580c", "TRACK*": "#ca8a04", "TRACK": "#64748b"}.get(ssvc, "#64748b")
        extra += f' · <span style="background:{sc};color:#fff;border-radius:4px;padding:0 5px;font-size:10px;font-weight:700;" title="SSVC (CISA) : {ssvc}">SSVC {ssvc}</span>'
    techs = c.get("attack_ics") or []
    if techs:
        extra += " · ATT&CK ICS " + " ".join(
            f'<a href="https://attack.mitre.org/techniques/{t}/" style="color:#7c3aed;font-size:10px;font-weight:600;">{t}</a>' for t in techs)
    return f"""
    <tr>
      <td style="white-space:nowrap;"><a href="{ref}" style="color:#1d4ed8;font-weight:600;">{c['id']}</a>{kev}{rel}</td>
      <td style="text-align:center;">{sev_badge(c.get('cvss'), c.get('severity'))}</td>
      <td style="font-size:12.5px;color:#334155;">{desc}<br><span style="color:#94a3b8;font-size:11px;">{html.escape(cwes)} · publié le {date}{extra}</span></td>
    </tr>"""


def advisory_block(a):
    code = f'<span style="font-family:monospace;font-size:11px;background:#e2e8f0;border-radius:4px;padding:1px 6px;">{html.escape(a.get("code") or "ICS")}</span>'
    summ = html.escape(a.get("summary") or "")[:160]
    if len(a.get("summary") or "") > 160:
        summ += "…"
    return f"""
    <tr>
      <td style="white-space:nowrap;">{code}</td>
      <td><a href="{safe_url(a['link'])}" style="color:#1d4ed8;font-weight:600;">{html.escape(a['title'])}</a>
          <br><span style="font-size:12px;color:#64748b;">{summ}</span></td>
      <td style="white-space:nowrap;font-size:12px;color:#64748b;">{html.escape((a.get('published') or '')[:16])}</td>
    </tr>"""


def kev_block(k):
    ransom = " ⚠ ransomware" if (k.get("knownRansomwareCampaignUse") or "").lower() == "known" else ""
    action = html.escape((k.get("requiredAction") or "")[:120])
    return f"""
    <tr>
      <td style="white-space:nowrap;"><strong>{html.escape(k['cveID'])}</strong></td>
      <td style="font-size:12.5px;">{html.escape(k.get('vendorProject',''))} — {html.escape(k.get('product',''))}<br>
        <span style="color:#64748b;">{html.escape((k.get('vulnerabilityName') or '')[:110])}{ransom}</span></td>
      <td style="white-space:nowrap;font-size:12px;">{html.escape(k.get('dateAdded',''))} → échéance {html.escape(k.get('dueDate',''))}<br>
        <span style="color:#64748b;">{action}</span></td>
    </tr>"""


CSS = """
body{margin:0;background:#eef2f7;font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#0f172a;}
.wrap{max-width:680px;margin:0 auto;background:#ffffff;}
.header{background:#0b1f3a;color:#fff;padding:28px 32px;}
.header h1{margin:0;font-size:26px;letter-spacing:.5px;}
.header .tag{color:#fbbf24;font-size:13px;margin-top:6px;font-weight:600;letter-spacing:.4px;}
.meta{background:#132a4d;color:#cbd5e1;font-size:12px;padding:8px 32px;display:flex;justify-content:space-between;}
.section{padding:24px 32px;border-bottom:1px solid #e2e8f0;}
.section h2{font-size:18px;margin:0 0 4px;color:#0b1f3a;border-left:4px solid #f59e0b;padding-left:10px;}
.section .sub{font-size:12.5px;color:#64748b;margin:0 0 14px;}
.article{margin-bottom:22px;}
.article .kicker{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#b45309;}
.article h3{font-size:17px;margin:4px 0 8px;color:#0b1f3a;}
.article p{font-size:14px;line-height:1.65;color:#1e293b;margin:0 0 10px;}
.article ul{margin:0 0 10px 18px;padding:0;}
.article li{font-size:14px;line-height:1.6;color:#1e293b;margin-bottom:5px;}
.article a{color:#1d4ed8;}
.article code{background:#f1f5f9;padding:1px 5px;border-radius:4px;font-size:12.5px;}
.article blockquote{border-left:3px solid #f59e0b;margin:10px 0;padding:6px 12px;background:#fffbeb;color:#78350f;font-size:13.5px;}
.article h4{font-size:14.5px;margin:12px 0 6px;}
table{width:100%;border-collapse:collapse;font-size:13px;}
th{background:#f1f5f9;text-align:left;padding:7px 10px;font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:#475569;border-bottom:2px solid #e2e8f0;}
td{padding:9px 10px;border-bottom:1px solid #eef2f7;vertical-align:top;}
.callout{background:#fff7ed;border:1px solid #fed7aa;border-radius:8px;padding:14px 16px;font-size:13.5px;line-height:1.6;color:#7c2d12;margin-bottom:14px;}
.footer{background:#0b1f3a;color:#94a3b8;font-size:11.5px;padding:20px 32px;line-height:1.7;}
.footer a{color:#93c5fd;}
.footer strong{color:#e2e8f0;}
"""


def render_html(issue_date, cves, advisories, kev, meta, articles):
    lead = next((a for a in articles if a["lead"]), None)
    others = [a for a in articles if not a["lead"]]

    def article_html(a):
        kicker = f'<div class="kicker">{html.escape(a["kicker"])} · {html.escape(a["section"])}</div>' if a["kicker"] else ""
        return f'<div class="article">{kicker}<h3>{html.escape(a["title"])}</h3>{a["body_html"]}</div>'

    cves = sorted(cves, key=lambda c: (bool(c.get("relevant")), c.get("risk") if c.get("risk") is not None else (c.get("cvss") or 0)), reverse=True)
    cve_rows = "\n".join(cve_block(c) for c in cves[: CFG.get("max_cves", 14)])
    adv_rows = "\n".join(advisory_block(a) for a in advisories[: CFG.get("max_advisories", 12)])
    kev_rows = "\n".join(kev_block(k) for k in kev[: CFG.get("max_kev", 10)])
    lead_html = article_html(lead) if lead else '<div class="callout">Aucun article à la une cette édition.</div>'
    others_html = "\n".join(article_html(a) for a in others)

    gen = (meta.get("generated_at") or "")[:19].replace("T", " ") + " UTC"
    counts = meta.get("counts", {})

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{NL['name']} — {issue_date}</title>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <h1>🛡️ {html.escape(NL['name'])}</h1>
    <div class="tag">{html.escape(NL['tagline'])}</div>
  </div>
  <div class="meta">
    <span>{NL['issue_prefix']} du {issue_date} · fenêtre de {meta.get('window_days','14')} jours</span>
    <span>{counts.get('cves',0)} CVE · {counts.get('cisa_advisories',0)} avis CISA · {counts.get('kev_ot',0)} KEV OT</span>
  </div>

  <div class="section">
    <h2>À la une</h2>
    <p class="sub">L'analyse de la rédaction, réécrite à partir des sources primaires.</p>
    {lead_html}
  </div>

  <div class="section">
    <h2>🔴 CVE critiques de la période — PLC &amp; OT</h2>
    <p class="sub">Collectées automatiquement via l'API NVD (fenêtre de {meta.get('window_days','14')} jours), filtrées éditeurs industriels, triées par score CVSS. ★KEV = exploitation connue (CISA).</p>
    <table>
      <tr><th>CVE</th><th>CVSS</th><th>Détail</th></tr>
      {cve_rows}
    </table>
  </div>

  <div class="section">
    <h2>📋 Avis CISA ICS récents</h2>
    <p class="sub">Flux CISA (ics-advisories / alertes), fenêtre de {meta.get('window_days','14')} jours.</p>
    <table>
      <tr><th>Code</th><th>Avis</th><th>Publié</th></tr>
      {adv_rows}
    </table>
  </div>

  <div class="section">
    <h2>⚠️ Catalogue KEV — produits OT/ICS exploités</h2>
    <p class="sub">Known Exploited Vulnerabilities (CISA) : appliquer les correctifs avant la date d'échéance.</p>
    <table>
      <tr><th>CVE</th><th>Produit</th><th>Ajout / échéance</th></tr>
      {kev_rows}
    </table>
  </div>

  <div class="section">
    <h2>✍️ Analyses &amp; veille technologie</h2>
    <p class="sub">Articles de fond rédigés à partir des sources citées dans chaque article.</p>
    {others_html}
  </div>

  <div class="footer">
    <strong>Sources automatiques :</strong>
    <a href="{safe_url(CFG['sources']['cisa_rss'])}">CISA RSS</a> ·
    <a href="{safe_url(CFG['sources']['cisa_ics_page'])}">CISA ICS Advisories</a> ·
    <a href="https://nvd.nist.gov/">NVD API 2.0</a> ·
    <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA KEV</a><br>
    Généré automatiquement le {gen} · {html.escape(NL['editor'])}<br>
    {html.escape(CFG.get('disclaimer',''))}<br>
    Se désabonner : répondre à cet e-mail avec « STOP ».
  </div>
</div>
</body>
</html>"""


def counts_line(meta):
    c = meta.get("counts", {})
    return f"{c.get('cves',0)} CVE · {c.get('cisa_advisories',0)} avis CISA · {c.get('kev_ot',0)} entrées KEV OT — fenêtre {meta.get('window_days','14')} jours"


def render_md(issue_date, cves, advisories, kev, meta, articles):
    lines = [
        f"# 🛡️ {NL['name']} — {issue_date}",
        f"*{NL['tagline']}*",
        "",
        f"> {counts_line(meta)}",
        "",
        "## À la une",
    ]
    for a in articles:
        lines += ["", f"### {a['title']}", f"*({a['kicker']} — {a['section']})*", "", a["body_md"], ""]
    lines += ["", "## 🔴 CVE de la période (NVD, triées par CVSS)", ""]
    for c in cves[: CFG.get("max_cves", 14)]:
        kev = " **★KEV**" if c.get("kev") else ""
        lines.append(f"- **{c['id']}**{kev} — CVSS {c.get('cvss') or 'n/a'} ({c.get('severity') or '?'}) : {(c.get('description') or '')[:180]}")
    lines += ["", "## 📋 Avis CISA ICS récents", ""]
    for a in advisories[: CFG.get("max_advisories", 12)]:
        lines.append(f"- [{a.get('code') or 'ICS'} — {a['title']}]({a['link']})")
    lines += ["", "## ⚠️ KEV OT/ICS", ""]
    for k in kev[: CFG.get("max_kev", 10)]:
        lines.append(f"- **{k['cveID']}** — {k.get('vendorProject','')} {k.get('product','')} (ajout {k.get('dateAdded','')}, échéance {k.get('dueDate','')})")
    lines += [
        "",
        "---",
        f"*Généré automatiquement le {(meta.get('generated_at') or '')[:19]} UTC — sources : CISA, NVD, KEV.*",
        f"*{CFG.get('disclaimer','')}*",
        "",
    ]
    return "\n".join(lines)


def main():
    meta = load_json("meta.json", {"generated_at": datetime.now(UTC).isoformat(), "window_days": CFG.get("window_days", 14), "counts": {}})
    cves = load_json("cves.json", [])
    advisories = load_json("cisa_advisories.json", [])
    kev = load_json("kev.json", [])
    articles = parse_editorial()
    issue_date = datetime.now(UTC).strftime("%d %B %Y")
    mois = {"January": "janvier", "February": "février", "March": "mars", "April": "avril", "May": "mai", "June": "juin",
            "July": "juillet", "August": "août", "September": "septembre", "October": "octobre", "November": "novembre", "December": "décembre"}
    for en, fr in mois.items():
        issue_date = issue_date.replace(en, fr)
    fname = datetime.now(UTC).strftime("%Y-%m-%d")

    html_doc = render_html(issue_date, cves, advisories, kev, meta, articles)
    md_doc = render_md(issue_date, cves, advisories, kev, meta, articles)

    with open(os.path.join(OUT, f"issue-{fname}.html"), "w", encoding="utf-8") as fh:
        fh.write(html_doc)
    with open(os.path.join(OUT, f"issue-{fname}.md"), "w", encoding="utf-8") as fh:
        fh.write(md_doc)
    print(f"[render] {os.path.join(OUT, 'issue-' + fname + '.html')} ({len(html_doc)} o)")
    print(f"[render] {os.path.join(OUT, 'issue-' + fname + '.md')} ({len(md_doc)} o)")
    print(f"[render] articles: {len(articles)} | cves: {len(cves)} | avis: {len(advisories)} | kev: {len(kev)}")


if __name__ == "__main__":
    main()
