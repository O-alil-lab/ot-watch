#!/usr/bin/env python3
"""
OT Watch — édition arabe (i18n AR, P2) : out/issue-<date>.ar.html / .ar.md (dir="rtl" lang="ar").
Mêmes données vérifiées (data/*.json), libellés d'interface en arabe, IDs CVE en latin.
CSS inline, aucune ressource externe. Servi sur GET /issue.ar. Voir tests/test_i18n.py.
"""
import html
import json
import os
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
OUT = os.path.join(ROOT, "out")
os.makedirs(OUT, exist_ok=True)

AR = {
    "title": "نشرة OT Watch — أمن أنظمة التحكم الصناعية (OT/ICS)",
    "edition": "إصدار",
    "generated": "وُلدت آلياً في",
    "window": "نافذة",
    "days": "يوماً",
    "cves": "ثغرات CVE مراقبة",
    "critical": "حرجة",
    "kev": "★ KEV — استغلال مؤكد في البرية",
    "advisories": "تنبيهات CISA ICS",
    "risk": "درجة الخطورة",
    "ot": "درجة OT (العرض x بورده Purdue)",
    "cvss": "CVSS",
    "ssvc": "SSVC",
    "exposure": "◆ أصولي في ملف التعرض (Mes actifs OT)",
    "sources": "المصادر",
    "disclaimer": "نشرة آلية 100% من مصادر عامة (CISA / NVD / KEV / FIRST EPSS).",
    "top": "أهم الثغرات هذا الأسبوع",
    "published": "تاريخ النشر",
}


def load_json(name, default):
    p = os.path.join(DATA, name)
    if not os.path.exists(p):
        return default
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def sev_ar(sev):
    return {"CRITICAL": "حرجة", "HIGH": "عالية", "MEDIUM": "متوسطة", "LOW": "منخفضة"}.get((sev or "").upper(), sev or "-")


def ot_cell(c):
    ots = c.get("ot_score")
    return f"<b>{ots:.1f}</b>" if ots is not None else "-"


def render_ar_html(issue_date, cves, advisories, kev, meta):
    crit = sum(1 for c in cves if c.get("severity") == "CRITICAL")
    n_kev = sum(1 for c in cves if c.get("kev"))
    rel = sum(1 for c in cves if c.get("relevant"))
    rows = []
    for c in cves[:30]:
        kev_badge = '<span style="color:#b91c1c;font-weight:700;">★KEV</span>' if c.get("kev") else ""
        rel_badge = ' <span style="color:#f59e0b;font-weight:700;">◆</span>' if c.get("relevant") else ""
        ssvc = f' <span style="background:#7c3aed;color:#fff;border-radius:4px;padding:0 5px;font-size:10px;">{html.escape((c.get("ssvc") or "").upper())}</span>' if c.get("ssvc") else ""
        rows.append(
            f'<tr><td style="white-space:nowrap;" dir="ltr" align="right"><bdi><b>{html.escape(c["id"])}</b></bdi>{kev_badge}{rel_badge}{ssvc}</td>'
            f'<td style="text-align:center;" dir="ltr"><bdi>{html.escape(str(c.get("cvss")))}</bdi> — {html.escape(sev_ar(c.get("severity")))}</td>'
            f'<td style="text-align:center;" dir="ltr"><bdi>{c.get("risk") if c.get("risk") is not None else "-"}</bdi></td>'
            f'<td style="text-align:center;" dir="ltr">{ot_cell(c)}</td>'
            f'<td style="font-size:12px;color:#334155;"><span dir="auto">{html.escape((c.get("description") or "")[:160])}</span></td></tr>'
        )
    adv_rows = "".join(
        f'<li><bdi><b>{html.escape(a.get("code") or "ICS")}</b></bdi> — <a href="{html.escape(a.get("link") or "#")}" dir="auto">{html.escape(a.get("title") or "")}</a></li>'
        for a in advisories[:15]
    )
    return f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{AR["title"]}</title>
<style>
body{{font-family:'Noto Naskh Arabic','Segoe UI',Tahoma,Arial,sans-serif;background:#f4f6fa;color:#1a2340;margin:0;padding:24px;line-height:1.6;}}
.wrap{{max-width:960px;margin:auto;background:#fff;border-radius:12px;padding:28px;box-shadow:0 2px 12px rgba(0,0,0,.08);}}
h1{{font-size:22px;margin:0 0 4px;}} .meta{{color:#64748b;font-size:13px;margin-bottom:18px;}}
.cards{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px;}}
.card{{background:#1a2340;color:#fff;border-radius:10px;padding:12px 18px;min-width:130px;}}
.card .n{{font-size:24px;font-weight:700;}} .card .l{{font-size:12px;opacity:.85;}}
table{{width:100%;border-collapse:collapse;font-size:13px;}}
th{{background:#1a2340;color:#fff;padding:7px;text-align:right;}} td{{border-bottom:1px solid #e2e8f0;padding:6px;}}
footer{{margin-top:20px;color:#94a3b8;font-size:11px;}}
</style></head>
<body><div class="wrap">
<h1>🛡 {AR["title"]}</h1>
<div class="meta">{AR["edition"]} <span dir="ltr">{html.escape(issue_date)}</span> · {AR["generated"]} <span dir="ltr">{html.escape((meta.get("generated_at") or "")[:19].replace("T", " "))} UTC</span> · {AR["window"]} {meta.get("window_days", 14)} {AR["days"]}</div>
<div class="cards">
  <div class="card"><div class="n">{len(cves)}</div><div class="l">{AR["cves"]}</div></div>
  <div class="card" style="background:#b91c1c"><div class="n">{crit}</div><div class="l">{AR["critical"]}</div></div>
  <div class="card" style="background:#2962ff"><div class="n">{n_kev}</div><div class="l">{AR["kev"]}</div></div>
  <div class="card" style="background:#e8641b"><div class="n">{rel}</div><div class="l">{AR["exposure"]}</div></div>
  <div class="card" style="background:#0f766e"><div class="n">{len(advisories)}</div><div class="l">{AR["advisories"]}</div></div>
</div>
<h2>{AR["top"]}</h2>
<table><tr><th>CVE</th><th>{AR["cvss"]}</th><th>{AR["risk"]}</th><th>{AR["ot"]}</th><th>الوصف</th></tr>
{''.join(rows)}
</table>
<h2>{AR["advisories"]}</h2>
<ul>{adv_rows}</ul>
<footer>{AR["disclaimer"]} {AR["sources"]} : CISA, NVD, CISA KEV, FIRST EPSS.</footer>
</div></body></html>"""


def render_ar_md(issue_date, cves, advisories, kev, meta):
    lines = [f"# {AR['title']}", "",
             f"{AR['edition']} {issue_date} · {AR['window']} {meta.get('window_days', 14)} {AR['days']}", "",
             f"- {len(cves)} {AR['cves']} ({sum(1 for c in cves if c.get('severity') == 'CRITICAL')} {AR['critical']}, "
             f"{sum(1 for c in cves if c.get('kev'))} ★KEV, {sum(1 for c in cves if c.get('relevant'))} ◆ {AR['exposure']})",
             f"- {len(advisories)} {AR['advisories']}", ""]
    for c in cves[:30]:
        badges = ("★KEV " if c.get("kev") else "") + ("◆ " if c.get("relevant") else "") + (f"SSVC {c.get('ssvc','').upper()}" if c.get("ssvc") else "")
        lines.append(f"## {c['id']} — {badges} CVSS {c.get('cvss')} · {AR['risk']} {c.get('risk')}")
        lines.append((c.get("description") or "")[:200])
        lines.append("")
    lines.append(f"\n--\n{AR['disclaimer']}")
    return "\n".join(lines) + "\n"


def main():
    meta = load_json("meta.json", {})
    cves = load_json("cves.json", [])
    advisories = load_json("cisa_advisories.json", [])
    kev = load_json("kev.json", [])
    fname = (meta.get("generated_at") or datetime.now().isoformat())[:10]
    with open(os.path.join(OUT, f"issue-{fname}.ar.html"), "w", encoding="utf-8") as fh:
        fh.write(render_ar_html(fname, cves, advisories, kev, meta))
    with open(os.path.join(OUT, f"issue-{fname}.ar.md"), "w", encoding="utf-8") as fh:
        fh.write(render_ar_md(fname, cves, advisories, kev, meta))
    print(f"[render_ar] out/issue-{fname}.ar.html + .ar.md ({len(cves)} CVE, {len(advisories)} avis — édition arabe RTL)")


if __name__ == "__main__":
    main()
