#!/usr/bin/env python3
"""Agent Illustrateur : visuels 100 % data-driven (générés depuis data/*.json + SQLite) ->
out/img/*.svg. Ce sont les « photos factuelles » de l'article : reproductibles, versionnées,
vérifiables. Toute illustration générée par IA (hors pipeline) doit être signée C2PA, porter
l'IPTC trainedAlgorithmicMedia et une légende visible « générée par IA » (AI Act art. 50) —
jamais utilisée là où le lecteur attend une photo réelle."""
import html
import os
from datetime import UTC, datetime

PALETTE = {"total": "#e8641b", "critical": "#c0392b", "kev": "#2962ff", "bg": "#ffffff", "grid": "#e2e8f0", "txt": "#334155"}


def _svg_open(w, h, title):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
            f'role="img" aria-label="{html.escape(title)}">\n<title>{html.escape(title)}</title>\n'
            f'<!-- provenance: généré depuis data/*.json + data/otwatch.db le {datetime.now(UTC).isoformat()} — reproductible -->\n'
            f'<rect width="{w}" height="{h}" fill="{PALETTE["bg"]}"/>\n')


def sparkline_svg(history, w=720, h=180):
    """Courbe 30 j : total CVE publiées + nouveaux KEV."""
    if not history:
        return None
    pad = 40
    pad, n = 40, len(history)
    mx = max([s["total"] for s in history] + [s["kev_added"] for s in history] + [1])
    bw = (w - 2 * pad) / n
    pts = " ".join(f"{pad + i * bw:.1f},{h - pad - (s['total'] / mx) * (h - 2 * pad):.1f}" for i, s in enumerate(history))
    kev_pts = " ".join(f"{pad + i * bw:.1f},{h - pad - (s['kev_added'] / mx) * (h - 2 * pad):.1f}" for i, s in enumerate(history) if s["kev_added"])
    s = _svg_open(w, h, "Tendances 30 jours — publications CVE et nouveaux KEV (données OT Watch)")
    for gy in range(0, h - pad, 30):
        s += f'<line x1="{pad}" y1="{gy}" x2="{w - pad}" y2="{gy}" stroke="{PALETTE["grid"]}" stroke-width="1"/>\n'
    s += f'<polyline points="{pts}" fill="none" stroke="{PALETTE["total"]}" stroke-width="2.5"/>\n'
    if kev_pts:
        s += f'<polyline points="{kev_pts}" fill="none" stroke="{PALETTE["kev"]}" stroke-width="2" stroke-dasharray="5,3"/>\n'
    s += f'<text x="{pad}" y="{h - 12}" font-size="11" fill="{PALETTE["txt"]}" font-family="sans-serif">{history[0]["date"]} → {history[-1]["date"]}</text>\n'
    s += f'<text x="{w - 190}" y="20" font-size="11" fill="{PALETTE["total"]}" font-family="sans-serif">■ CVE publiées</text>\n'
    s += f'<text x="{w - 190}" y="36" font-size="11" fill="{PALETTE["kev"]}" font-family="sans-serif">■ nouveaux KEV</text>\n'
    return s + "</svg>\n"


def severity_donut_svg(cves, w=360, h=220):
    counts = {}
    for c in cves:
        counts[c.get("severity", "NONE")] = counts.get(c.get("severity", "NONE"), 0) + 1
    colors = {"CRITICAL": PALETTE["critical"], "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#65a30d", "NONE": "#64748b"}
    total = sum(counts.values()) or 1
    s = _svg_open(w, h, "Répartition des CVE par sévérité (données OT Watch)")
    cx, cy, r, r2 = 90, 110, 70, 40
    import math
    a0 = -90
    for sev, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        a1 = a0 + 360 * n / total
        large = 1 if (a1 - a0) > 180 else 0
        x0, y0 = cx + r * math.cos(math.radians(a0)), cy + r * math.sin(math.radians(a0))
        x1, y1 = cx + r * math.cos(math.radians(a1)), cy + r * math.sin(math.radians(a1))
        s += (f'<path d="M {x0:.1f} {y0:.1f} A {r} {r} 0 {large} 1 {x1:.1f} {y1:.1f} L {cx + r2 * math.cos(math.radians(a1)):.1f} '
              f'{cy + r2 * math.sin(math.radians(a1)):.1f} A {r2} {r2} 0 {large} 0 {cx + r2 * math.cos(math.radians(a0)):.1f} '
              f'{cy + r2 * math.sin(math.radians(a0)):.1f} Z" fill="{colors.get(sev, "#64748b")}"/>\n')
        s += f'<text x="175" y="{60 + 22 * list(sorted(counts, key=lambda k: -counts[k])).index(sev)}" font-size="12" fill="{PALETTE["txt"]}" font-family="sans-serif">{sev} : {n}</text>\n'
        a0 = a1
    s += f'<text x="{cx}" y="{cy + 5}" text-anchor="middle" font-size="20" font-weight="bold" fill="{PALETTE["txt"]}" font-family="sans-serif">{total}</text>\n'
    return s + "</svg>\n"


def risk_hist_svg(cves, w=720, h=180):
    buckets = [0] * 10
    for c in cves:
        r = c.get("risk") or 0
        buckets[min(9, int(r))] += 1
    pad = 40
    bw = (w - 2 * pad) / 10
    mx = max([*buckets, 1])
    s = _svg_open(w, h, "Distribution des scores de risque (CVSS+EPSS+KEV) — données OT Watch")
    for i, n in enumerate(buckets):
        bh = (h - 2 * pad) * n / mx
        color = PALETTE["critical"] if i >= 8 else ("#ea580c" if i >= 6 else PALETTE["total"])
        s += (f'<rect x="{pad + i * bw + 3:.1f}" y="{h - pad - bh:.1f}" width="{bw - 6:.1f}" height="{bh:.1f}" fill="{color}"/>\n'
              f'<text x="{pad + i * bw + bw / 2:.1f}" y="{h - pad + 14}" text-anchor="middle" font-size="10" fill="{PALETTE["txt"]}" font-family="sans-serif">{i}-{i + 1}</text>\n')
    return s + "</svg>\n"


def generate_svgs(brief, img_dir):
    """Génère les SVG data-driven ; renvoie [{file, caption, provenance}]."""
    os.makedirs(img_dir, exist_ok=True)
    out = []
    cves = []
    data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
    p = os.path.join(data_dir, "cves.json")
    if os.path.exists(p):
        import json
        with open(p, encoding="utf-8") as fh:
            cves = json.load(fh)
    jobs = [
        ("sparkline-30j.svg", sparkline_svg(brief.get("trends", {}).get("history", [])), "Tendances 30 j (CVE publiées, nouveaux KEV)"),
        ("severity-donut.svg", severity_donut_svg(cves), "Sévérité des CVE de la fenêtre"),
        ("risk-hist.svg", risk_hist_svg(cves), "Distribution des scores de risque"),
    ]
    for name, svg, caption in jobs:
        if not svg:
            continue
        with open(os.path.join(img_dir, name), "w", encoding="utf-8") as fh:
            fh.write(svg)
        out.append({"file": name, "caption": caption,
                    "provenance": "données OT Watch (data/*.json + otwatch.db) — reproductible",
                    "ai_generated": False})
    return out
