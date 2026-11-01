#!/usr/bin/env python3
"""OT Watch — English edition (dir=ltr).

Companion to render.py (FR) and render_ar.py (AR). Writes
out/issue-<date>.en.html and out/issue-<date>.en.md.
All CSS inline, system fonts only (sandboxed iframe, no external resources).
"""
import html
import json
import os
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
OUT = os.path.join(ROOT, "out")

EN = {
    "title": "OT Watch — ICS/OT Cybersecurity Newsletter",
    "edition": "Edition",
    "generated": "Generated",
    "window": "Collection window:",
    "days": "days",
    "cves": "CVEs",
    "critical": "Critical",
    "kev": "in CISA KEV",
    "exposure": "OT-exposed",
    "advisories": "CISA ICS advisories",
    "top": "Top vulnerabilities (highest OT score)",
    "cvss": "CVSS",
    "risk": "Risk (EPSSxKEV)",
    "ot": "OT score",
    "disclaimer": "Automated watch product — AI Act Art. 50 transparency. Verify against primary sources before acting.",
    "sources": "Sources",
}


def load_json(name, default):
    p = os.path.join(DATA, name)
    if not os.path.exists(p):
        return default
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def sev_en(sev):
    return {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}.get((sev or "").upper(), sev or "-")


def ot_cell(c):
    ots = c.get("ot_score")
    return f"<b>{ots:.1f}</b>" if ots is not None else "-"


def render_en_html(issue_date, cves, advisories, kev, meta):
    crit = sum(1 for c in cves if c.get("severity") == "CRITICAL")
    n_kev = sum(1 for c in cves if c.get("kev"))
    rel = sum(1 for c in cves if c.get("relevant"))
    rows = []
    for c in sorted(cves, key=lambda x: -(x.get("ot_score") or 0))[:30]:
        kev_badge = '<span style="color:#b91c1c;font-weight:700;">★KEV</span>' if c.get("kev") else ""
        rel_badge = ' <span style="color:#f59e0b;font-weight:700;">◆</span>' if c.get("relevant") else ""
        ssvc = f' <span style="background:#7c3aed;color:#fff;border-radius:4px;padding:0 5px;font-size:10px;">{html.escape((c.get("ssvc") or "").upper())}</span>' if c.get("ssvc") else ""
        rows.append(
            f'<tr><td style="white-space:nowrap;"><b>{html.escape(c["id"])}</b>{kev_badge}{rel_badge}{ssvc}</td>'
            f'<td style="text-align:center;">{html.escape(str(c.get("cvss")))} — {html.escape(sev_en(c.get("severity")))}</td>'
            f'<td style="text-align:center;">{c.get("risk") if c.get("risk") is not None else "-"}</td>'
            f'<td style="text-align:center;">{ot_cell(c)}</td>'
            f'<td style="font-size:12px;color:#334155;">{html.escape((c.get("description") or "")[:160])}</td></tr>'
        )
    adv_rows = "".join(
        f'<li><b>{html.escape(a.get("code") or "ICS")}</b> — <a href="{html.escape(a.get("link") or "#")}">{html.escape(a.get("title") or "")}</a></li>'
        for a in advisories[:15]
    )
    return f"""<!DOCTYPE html>
<html lang="en" dir="ltr">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{EN["title"]}</title>
<style>
body{{font-family:'Segoe UI',system-ui,Tahoma,Arial,sans-serif;background:#f4f6fa;color:#1a2340;margin:0;padding:24px;line-height:1.6;}}
.wrap{{max-width:960px;margin:auto;background:#fff;border-radius:12px;padding:28px;box-shadow:0 2px 12px rgba(0,0,0,.08);}}
h1{{font-size:22px;margin:0 0 4px;}} .meta{{color:#64748b;font-size:13px;margin-bottom:18px;}}
.cards{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px;}}
.card{{background:#1a2340;color:#fff;border-radius:10px;padding:12px 18px;min-width:130px;}}
.card .n{{font-size:24px;font-weight:700;}} .card .l{{font-size:12px;opacity:.85;}}
table{{width:100%;border-collapse:collapse;font-size:13px;}}
th{{background:#1a2340;color:#fff;padding:7px;text-align:left;}} td{{border-bottom:1px solid #e2e8f0;padding:6px;}}
footer{{margin-top:20px;color:#94a3b8;font-size:11px;}}
</style></head>
<body><div class="wrap">
<h1>🛡 {EN["title"]}</h1>
<div class="meta">{EN["edition"]} {html.escape(issue_date)} · {EN["generated"]} {html.escape((meta.get("generated_at") or "")[:19].replace("T", " "))} UTC · {EN["window"]} {meta.get("window_days", 14)} {EN["days"]} · <a href="/issue">FR</a> · <a href="/issue.ar">العربية</a></div>
<div class="cards">
  <div class="card"><div class="n">{len(cves)}</div><div class="l">{EN["cves"]}</div></div>
  <div class="card" style="background:#b91c1c"><div class="n">{crit}</div><div class="l">{EN["critical"]}</div></div>
  <div class="card" style="background:#2962ff"><div class="n">{n_kev}</div><div class="l">{EN["kev"]}</div></div>
  <div class="card" style="background:#e8641b"><div class="n">{rel}</div><div class="l">{EN["exposure"]}</div></div>
  <div class="card" style="background:#0f766e"><div class="n">{len(advisories)}</div><div class="l">{EN["advisories"]}</div></div>
</div>
<h2>{EN["top"]}</h2>
<table><tr><th>CVE</th><th>{EN["cvss"]}</th><th>{EN["risk"]}</th><th>{EN["ot"]}</th><th>Description</th></tr>
{''.join(rows)}
</table>
<h2>{EN["advisories"]}</h2>
<ul>{adv_rows}</ul>
<footer>{EN["disclaimer"]} {EN["sources"]}: CISA, NVD, CISA KEV, FIRST EPSS.</footer>
</div></body></html>"""


def render_en_md(issue_date, cves, advisories, kev, meta):
    lines = [f"# {EN['title']}", "",
             f"{EN['edition']} {issue_date} · {EN['window']} {meta.get('window_days', 14)} {EN['days']}", "",
             f"- {len(cves)} {EN['cves']} ({sum(1 for c in cves if c.get('severity') == 'CRITICAL')} {EN['critical']}, "
             f"{sum(1 for c in cves if c.get('kev'))} ★KEV, {sum(1 for c in cves if c.get('relevant'))} ◆ {EN['exposure']})",
             f"- {len(advisories)} {EN['advisories']}", ""]
    for c in sorted(cves, key=lambda x: -(x.get("ot_score") or 0))[:30]:
        badges = ("★KEV " if c.get("kev") else "") + ("◆ " if c.get("relevant") else "") + (f"SSVC {c.get('ssvc','').upper()}" if c.get("ssvc") else "")
        lines.append(f"## {c['id']} — {badges} CVSS {c.get('cvss')} · {EN['risk']} {c.get('risk')}")
        lines.append((c.get("description") or "")[:200])
        lines.append("")
    lines.append(f"\n--\n{EN['disclaimer']}")
    return "\n".join(lines) + "\n"


def main():
    meta = load_json("meta.json", {})
    cves = load_json("cves.json", [])
    advisories = load_json("cisa_advisories.json", [])
    kev = load_json("kev.json", [])
    fname = (meta.get("generated_at") or datetime.now().isoformat())[:10]
    with open(os.path.join(OUT, f"issue-{fname}.en.html"), "w", encoding="utf-8") as fh:
        fh.write(render_en_html(fname, cves, advisories, kev, meta))
    with open(os.path.join(OUT, f"issue-{fname}.en.md"), "w", encoding="utf-8") as fh:
        fh.write(render_en_md(fname, cves, advisories, kev, meta))
    print(f"[render_en] out/issue-{fname}.en.html + .en.md ({len(cves)} CVE, {len(advisories)} advisories — English edition)")


if __name__ == "__main__":
    main()
