#!/usr/bin/env python3
"""
OT Watch — export PDF de l'édition (roadmap P2 « Export PDF »).
Lit data/*.json + editorial/*.md (mêmes entrées que render.py) et produit :
  out/issue-<AAAA-MM-JJ>.pdf   (édition imprimable A4, police DejaVu, aucune ressource externe)
Le nom de fichier est dérivé de meta.generated_at pour rester cohérent avec le HTML/MD.
Sécurité : tout texte externe (NVD/CISA/KEV) est passé tel quel à fpdf2 (échappement
unicode géré par la police TTF) ; aucune URL cliquable dangereuse n'est émise.
Voir tests/test_pdf.py.
"""
import json
import os
import re
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
OUT = os.path.join(ROOT, "out")
os.makedirs(OUT, exist_ok=True)

FONT_DIR = "/usr/share/fonts/truetype/dejavu"

try:
    from fpdf import FPDF
except ImportError:  # environnements sans fpdf2 : le pipeline HTML/MD continue
    FPDF = None

NAVY = (26, 35, 64)
ORANGE = (232, 100, 27)
RED = (192, 57, 43)
BLUE = (41, 98, 255)
GREEN = (39, 174, 96)
GRAY = (110, 110, 120)
LIGHT = (244, 246, 250)

SEV_COLORS = {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": (243, 156, 18), "LOW": GREEN, "NONE": GRAY}


def load_json(name, default):
    p = os.path.join(DATA, name)
    if not os.path.exists(p):
        return default
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def parse_editorial():
    """Réutilise la convention editorial/*.md (en-tête clé: valeur puis markdown)."""
    edito = os.path.join(ROOT, "editorial")
    articles = []
    if not os.path.isdir(edito):
        return articles
    for fn in sorted(os.listdir(edito)):
        if not fn.endswith(".md"):
            continue
        with open(os.path.join(edito, fn), encoding="utf-8") as fh:
            raw = fh.read()
        head, _, body = raw.partition("\n---\n")
        meta = {}
        for line in head.split("\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                meta[k.strip()] = v.strip()
        articles.append({"title": meta.get("title", fn), "kicker": meta.get("kicker", ""), "body": body.strip()})
    return articles


def strip_md(text):
    """Markdown -> texte brut pour le PDF (titres, gras, liens, listes, code)."""
    out = []
    for line in text.split("\n"):
        line = re.sub(r"^#{1,6}\s*", "", line)
        line = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", line)
        line = re.sub(r"[*_`>]+", "", line)
        out.append(line.rstrip())
    return "\n".join(out).strip()


class OTWatchPDF(FPDF):
    def footer(self):
        self.set_y(-14)
        self.set_font("DejaVu", "", 7)
        self.set_text_color(*GRAY)
        self.cell(0, 5, f"OT Watch — veille OT/ICS générée automatiquement — page {self.page_no()}/{{nb}}",
                  align="C", new_x="LMARGIN", new_y="NEXT")
        self.cell(0, 4, "Sources : CISA (RSS + KEV), NVD API 2.0, FIRST EPSS — voir README.md", align="C",
                  new_x="LMARGIN", new_y="NEXT")


def _header_band(pdf, issue_date, meta):
    pdf.set_fill_color(*NAVY)
    pdf.rect(0, 0, 210, 26, style="F")
    pdf.set_xy(15, 6)
    pdf.set_font("DejaVu", "B", 20)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 9, "OT Watch — veille OT/ICS", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(15)
    pdf.set_font("DejaVu", "", 10)
    pdf.cell(0, 6, f"Édition du {issue_date}  ·  fenêtre {meta.get('window_days', 14)} jours  ·  "
                   f"générée le {meta.get('generated_at', '')[:19].replace('T', ' ')} UTC",
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_y(32)


def _section(pdf, title, color=NAVY):
    if pdf.get_y() > 262:
        pdf.add_page()
    pdf.set_font("DejaVu", "B", 12.5)
    pdf.set_text_color(*color)
    pdf.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(*color)
    pdf.set_line_width(0.4)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(2)
    pdf.set_text_color(30, 30, 30)


def _resume(pdf, cves, advisories, kev, meta):
    crit = sum(1 for c in cves if c.get("severity") == "CRITICAL")
    n_kev = sum(1 for c in cves if c.get("kev"))
    rel = sum(1 for c in cves if c.get("relevant"))
    counts = meta.get("counts", {})
    pdf.set_fill_color(*LIGHT)
    pdf.set_font("DejaVu", "", 9.5)
    pdf.set_text_color(30, 30, 30)
    y0 = pdf.get_y()
    pdf.rect(15, y0, 180, 14, style="F")
    pdf.set_xy(18, y0 + 2.5)
    pdf.cell(0, 5, f"En bref : {len(cves)} CVE OT ({crit} CRITICAL, {n_kev} ★ KEV)  ·  ◆ {rel} de vos actifs OT  ·  "
                   f"{len(advisories)} avis CISA ICS ({counts.get('advisories', len(advisories))})  ·  {len(kev)} entrées KEV OT",
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_xy(18, y0 + 8)
    pdf.set_font("DejaVu", "I", 8)
    pdf.set_text_color(*GRAY)
    pdf.cell(0, 4, "Score de risque = 0,5 x CVSS + 0,3 x EPSS + 0,2 x KEV (config.json risk_weights) — tri décroissant.",
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_y(y0 + 17)


def _sparkline(pdf, series):
    """Mini histogramme 30 j (store.history_daily) : total CVE publiées + nouveaux KEV."""
    if not series:
        return
    _section(pdf, "Tendances 30 jours (historique SQLite)", BLUE)
    w, h, x0, y0 = 180.0, 22.0, 15.0, pdf.get_y() + 4
    mx = max([s["total"] for s in series] + [s["kev_added"] for s in series] + [1])
    bw = w / len(series)
    pdf.set_draw_color(200, 205, 215)
    pdf.line(x0, y0, x0 + w, y0)
    for i, s in enumerate(series):
        bh = (s["total"] / mx) * h
        pdf.set_fill_color(*ORANGE)
        pdf.rect(x0 + i * bw + 0.4, y0 - bh, bw - 0.8, bh, style="F")
        if s["kev_added"]:
            kh = (s["kev_added"] / mx) * h
            pdf.set_fill_color(*BLUE)
            pdf.rect(x0 + i * bw + 0.4, y0 - bh - kh, bw - 0.8, kh, style="F")
    pdf.set_xy(x0, y0 + 2)
    pdf.set_font("DejaVu", "", 7)
    pdf.set_text_color(*GRAY)
    pdf.cell(0, 4, f"{series[0]['date']} → {series[-1]['date']}   ■ total CVE publiées   ■ nouveaux KEV",
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_y(y0 + 8)


def _cve_table(pdf, cves):
    _section(pdf, f"Vulnérabilités CVE surveillées ({len(cves)}, triées par risque)", NAVY)
    cols = [("CVE", 36), ("CVSS", 13), ("Sévérité", 22), ("EPSS", 13), ("Risque", 15), ("KEV", 12), ("OT", 12)]

    def header_row():
        pdf.set_fill_color(*NAVY)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("DejaVu", "B", 8)
        x = 15
        for name, w in cols:
            pdf.set_xy(x, pdf.get_y())
            pdf.cell(w, 6, name, border=0, fill=True, align="C")
            x += w
        pdf.ln(6)
        pdf.set_text_color(30, 30, 30)

    header_row()
    pdf.set_font("DejaVu", "", 8)
    for c in cves:
        if pdf.get_y() > 252:
            pdf.add_page()
            header_row()
            pdf.set_font("DejaVu", "", 8)
        y = pdf.get_y()
        sev = (c.get("severity") or "NONE").upper()
        row = [c.get("id", "?"), f"{c.get('cvss') or 0:.1f}", sev,
               f"{100 * (c.get('epss') or 0):.1f}%", f"{c.get('risk') or 0:.2f}",
               "★" if c.get("kev") else "", "◆" if c.get("relevant") else ""]
        if c.get("relevant"):
            pdf.set_fill_color(255, 243, 214)
            pdf.rect(15, y, 123, 6, style="F")
        x = 15
        for i, (val, (name, w)) in enumerate(zip(row, cols)):
            pdf.set_xy(x, y)
            if name == "Sévérité":
                pdf.set_fill_color(*SEV_COLORS.get(sev, GRAY))
                pdf.set_text_color(255, 255, 255)
                pdf.cell(w, 6, val, border=0, fill=True, align="C")
                pdf.set_text_color(30, 30, 30)
            elif name == "KEV" and c.get("kev"):
                pdf.set_text_color(*RED)
                pdf.cell(w, 6, val, align="C")
                pdf.set_text_color(30, 30, 30)
            elif name == "OT" and c.get("relevant"):
                pdf.set_text_color(*ORANGE)
                pdf.cell(w, 6, val, align="C")
                pdf.set_text_color(30, 30, 30)
            else:
                pdf.cell(w, 6, val, align="C" if name != "CVE" else "L")
            x += w
        pdf.set_xy(15, y + 6)
        pdf.set_font("DejaVu", "", 7)
        pdf.set_text_color(*GRAY)
        desc = re.sub(r"\s+", " ", (c.get("description") or ""))[:170]
        pdf.multi_cell(0, 3.6, desc, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("DejaVu", "", 8)
        pdf.set_text_color(30, 30, 30)
        pdf.ln(1)


def _articles(pdf, articles):
    if not articles:
        return
    _section(pdf, f"Articles éditoriaux ({len(articles)})", NAVY)
    for a in articles:
        if pdf.get_y() > 240:
            pdf.add_page()
        pdf.set_font("DejaVu", "B", 10.5)
        pdf.set_text_color(*NAVY)
        pdf.multi_cell(0, 5.5, a["title"], new_x="LMARGIN", new_y="NEXT")
        if a.get("kicker"):
            pdf.set_font("DejaVu", "I", 8.5)
            pdf.set_text_color(*ORANGE)
            pdf.multi_cell(0, 4.5, a["kicker"], new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("DejaVu", "", 8.5)
        pdf.set_text_color(40, 40, 40)
        pdf.multi_cell(0, 4.4, strip_md(a.get("body", "")), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)


def _advisories(pdf, advisories):
    if not advisories:
        return
    _section(pdf, f"Avis CISA ICS ({len(advisories)})", ORANGE)
    pdf.set_font("DejaVu", "", 8.5)
    for a in advisories:
        if pdf.get_y() > 262:
            pdf.add_page()
        pdf.set_font("DejaVu", "B", 8.5)
        pdf.set_text_color(*NAVY)
        pub = (a.get("published") or "")[:10]
        pdf.multi_cell(0, 4.6, f"{a.get('code', '')} — {a.get('title', '')}  ({pub})", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("DejaVu", "", 7.5)
        pdf.set_text_color(*GRAY)
        pdf.multi_cell(0, 4, re.sub(r"\s+", " ", a.get("summary", ""))[:220], new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1.5)


def _kev_table(pdf, kev):
    if not kev:
        return
    _section(pdf, f"KEV — exploitées dans la nature, filtre OT ({len(kev)})", RED)
    pdf.set_font("DejaVu", "", 8)
    for k in kev:
        if pdf.get_y() > 262:
            pdf.add_page()
        ransom = " ☠" if str(k.get("knownRansomwareCampaignUse", "")).lower() == "known" else ""
        pdf.set_font("DejaVu", "B", 8)
        pdf.set_text_color(*RED)
        pdf.cell(34, 5, k.get("cveID", "?"), new_x="RIGHT", new_y="TOP")
        pdf.set_font("DejaVu", "", 8)
        pdf.set_text_color(30, 30, 30)
        pdf.multi_cell(0, 5, f"{k.get('vendorProject', '')} {k.get('product', '')} — ajouté le {k.get('dateAdded', '')}{ransom}",
                       new_x="LMARGIN", new_y="NEXT")


def render_pdf(issue_date, cves, advisories, kev, meta, articles, out_path, history=None):
    """Construit le PDF et renvoie le chemin. Lève ImportError si fpdf2 absent."""
    if FPDF is None:
        raise ImportError("fpdf2 requis : pip install -r requirements.txt")
    pdf = OTWatchPDF(orientation="P", unit="mm", format="A4")
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_font("DejaVu", "", os.path.join(FONT_DIR, "DejaVuSans.ttf"))
    pdf.add_font("DejaVu", "B", os.path.join(FONT_DIR, "DejaVuSans-Bold.ttf"))
    pdf.add_font("DejaVu", "I", os.path.join(FONT_DIR, "DejaVuSans.ttf"))  # pas d'Oblique Sans : fallback regular
    pdf.add_page()
    _header_band(pdf, issue_date, meta)
    _resume(pdf, cves, advisories, kev, meta)
    if history:
        _sparkline(pdf, history)
    _articles(pdf, articles)
    _cve_table(pdf, cves)
    _advisories(pdf, advisories)
    _kev_table(pdf, kev)
    pdf.output(out_path)
    return out_path


def main():
    if FPDF is None:
        print("[render_pdf] fpdf2 absent -> PDF ignoré (pip install -r requirements.txt pour l'activer)")
        return
    meta = load_json("meta.json", {})
    cves = load_json("cves.json", [])
    advisories = load_json("cisa_advisories.json", [])
    kev = load_json("kev.json", [])
    articles = parse_editorial()
    fname = (meta.get("generated_at") or datetime.now().isoformat())[:10]
    issue_date = fname
    try:
        d = datetime.fromisoformat(meta.get("generated_at", fname))
        mois = {"January": "janvier", "February": "février", "March": "mars", "April": "avril", "May": "mai",
                "June": "juin", "July": "juillet", "August": "août", "September": "septembre",
                "October": "octobre", "November": "novembre", "December": "décembre"}
        issue_date = d.strftime("%d %B %Y")
        for en, fr in mois.items():
            issue_date = issue_date.replace(en, fr)
    except ValueError:
        pass
    history = None
    try:
        import store  # historique SQLite (v1.3)
        history = store.history_daily(os.path.join(DATA, "otwatch.db"), days=30)
    except Exception:  # le PDF reste produit sans sparkline
        history = None
    out_path = os.path.join(OUT, f"issue-{fname}.pdf")
    render_pdf(issue_date, cves, advisories, kev, meta, articles, out_path, history=history)
    print(f"[render_pdf] {out_path} ({os.path.getsize(out_path)} o, {len(cves)} CVE)")


if __name__ == "__main__":
    main()
