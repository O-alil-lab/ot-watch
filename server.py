#!/usr/bin/env python3
"""
OT Watch — tableau de bord TEMPS RÉEL (données live, pas de démo).

- Sert /            -> dashboard HTML (CSS/JS inline, aucun asset externe)
- Sert /api/data    -> JSON live : meta + cves + avis CISA + KEV + articles
- Sert /api/meta    -> fraicheur (generated_at, collecting, last_run, auto_interval)
- POST /api/refresh -> lance une re-collecte CISA/NVD/KEV en arrière-plan
- Sert /issue       -> dernière newsletter HTML générée (out/issue-*.html)

Lancement :  python3 server.py --port 8000 --host 0.0.0.0
Auto-refresh : variable d'env AUTO_REFRESH_SECONDS (défaut 1800 s = 30 min).
"""
import argparse
import json
import os
import queue
import re
import sys
import threading
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "src"))
import collect  # noqa: E402  (pipeline de collecte réel)
import growth  # noqa: E402  (v1.18 : RSS/sitemap/subscribe/stats/integrations)
import render  # noqa: E402   (parse les articles éditoriaux)
import store  # noqa: E402    (historique SQLite)
import taxii  # noqa: E402    (serveur TAXII 2.1 read-only)

DATA = os.path.join(ROOT, "data")
OUT = os.path.join(ROOT, "out")

AUTO_REFRESH_SECONDS = int(os.environ.get("AUTO_REFRESH_SECONDS", "1800"))
with open(os.path.join(ROOT, "config.json"), encoding="utf-8") as _cfgfh:
    CFG = json.load(_cfgfh)
CFG_STALE_N = float(CFG.get("stale_after_intervals", 2))

_lock = threading.Lock()
_sse_clients = []
_sse_lock = threading.Lock()


def broadcast(event):
    """Pousse un événement JSON à tous les clients SSE connectés."""
    with _sse_lock:
        clients = list(_sse_clients)
    for q in clients:
        try:
            q.put_nowait(event)
        except Exception:  # noqa: BLE001 - client parti entre-temps
            pass
_state = {"collecting": False, "last_run": None, "last_error": None, "runs": 0,
          "last_refresh_start": 0.0, "last_collect_duration": 0.0}
REFRESH_MIN_INTERVAL_S = 60  # rate-limit anti-abus


def load_json(name, default):
    try:
        with open(os.path.join(DATA, name), encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return default


def run_collect():
    """Re-collecte CISA/NVD/KEV en tâche de fond (une seule à la fois)."""
    if not _lock.acquire(blocking=False):
        return False
    _state["collecting"] = True
    t0 = time.time()
    try:
        collect.main()  # vraie collecte réseau
        _state["last_collect_duration"] = round(time.time() - t0, 1)
        _state["last_run"] = datetime.now(UTC).isoformat()
        _state["last_error"] = None
        _state["runs"] += 1
        meta = load_json("meta.json", {})
        broadcast({"type": "collected", "generated_at": meta.get("generated_at"),
                   "diff": meta.get("diff", {}), "counts": meta.get("counts", {}),
                   "validation_ok": (meta.get("validation") or {}).get("ok", True)})
        return True
    except Exception as exc:  # noqa: BLE001 - journalisé et exposé via /api/meta
        _state["last_error"] = str(exc)
        return False
    finally:
        _state["collecting"] = False
        _lock.release()


def auto_refresh_loop():
    while True:
        time.sleep(AUTO_REFRESH_SECONDS)
        run_collect()


def _exposure_re():
    kws = CFG.get("exposure", {}).get("keywords", [])
    return re.compile("|".join(re.escape(k) for k in kws), re.IGNORECASE) if kws else None


def api_payload():
    cves_raw = load_json("cves.json", [])
    exp_re = _exposure_re()
    if exp_re:
        for c in cves_raw:
            if "relevant" not in c:  # données collectées avant le profil d'exposition
                c["relevant"] = bool(exp_re.search(c.get("description") or ""))
    meta = load_json("meta.json", {
        "generated_at": None, "window_days": 14,
        "counts": {"cves": 0, "cisa_advisories": 0, "kev_ot": 0},
    })
    gen = meta.get("generated_at")
    try:
        age_s = (datetime.now(UTC) - datetime.fromisoformat(gen)).total_seconds() if gen else None
    except Exception:  # noqa: BLE001
        age_s = None
    stale = bool(age_s is not None and age_s > AUTO_REFRESH_SECONDS * CFG_STALE_N)
    return {
        "meta": meta,
        "stale": stale,
        "freshness_seconds": age_s,
        "server_time": datetime.now(UTC).isoformat(),
        "collecting": _state["collecting"],
        "last_run": _state["last_run"],
        "last_error": _state["last_error"],
        "collect_runs": _state["runs"],
        "auto_interval_seconds": AUTO_REFRESH_SECONDS,
        "cves": cves_raw,
        "netwatch": load_json("netwatch.json", None),
        "advisories": load_json("cisa_advisories.json", []),
        "kev": load_json("kev.json", []),
        "articles": render.parse_editorial(),
        "agents": agents_status(),
        "assets": load_json("assets.json", []),
        "quality": (load_json("meta.json", {}) or {}).get("quality", {}),
    }


def latest_issue_html():
    try:
        files = sorted(f for f in os.listdir(OUT) if f.startswith("issue-") and f.endswith(".html"))
        if not files:
            return None
        with open(os.path.join(OUT, files[-1]), encoding="utf-8") as fh:
            return fh.read(), files[-1]
    except Exception:
        return None
    return None


def raw_files_count():
    """Nombre de réponses brutes archivées (couche raw rejouable)."""
    raw = os.path.join(DATA, "raw")
    try:
        if not os.path.isdir(raw):
            return 0
        return sum(len([f for f in os.listdir(os.path.join(raw, d)) if f != "manifest.json"])
                   for d in os.listdir(raw) if os.path.isdir(os.path.join(raw, d)))
    except Exception:
        return 0


def agents_status():
    """Dernier brouillon du pipeline agents IA éditoriaux (fact-check + approbation HITL)."""
    drafts = os.path.join(OUT, "drafts")
    try:
        if not os.path.isdir(drafts):
            return None
        names = sorted(d for d in os.listdir(drafts) if d.startswith("draft-"))
        if not names:
            return None
        last = names[-1]
        fc = None
        p = os.path.join(drafts, last, "factcheck.json")
        if os.path.exists(p):
            with open(p, encoding="utf-8") as fh:
                r = json.load(fh)
            fc = {"ok": r.get("ok"), "checked": r.get("checked"), "failed": len(r.get("failed", []))}
        return {"draft": last, "factcheck": fc,
                "approved": os.path.exists(os.path.join(drafts, last + ".approved")),
                "published": os.path.exists(os.path.join(ROOT, "editorial", f"auto-{last[6:]}.md"))}
    except Exception:
        return None


def latest_issue_misp():
    try:
        files = sorted(f for f in os.listdir(OUT) if f.startswith("issue-") and f.endswith(".misp.json"))
        if not files:
            return None
        with open(os.path.join(OUT, files[-1]), "rb") as fh:
            return fh.read(), files[-1]
    except Exception:
        return None
    return None


def latest_issue_stix():
    try:
        files = sorted(f for f in os.listdir(OUT) if f.startswith("issue-") and f.endswith(".stix.json"))
        if not files:
            return None
        with open(os.path.join(OUT, files[-1]), "rb") as fh:
            return fh.read(), files[-1]
    except Exception:
        return None
    return None


def latest_issue_ar():
    try:
        files = sorted(f for f in os.listdir(OUT) if f.startswith("issue-") and f.endswith(".ar.html"))
        if not files:
            return None
        with open(os.path.join(OUT, files[-1]), encoding="utf-8") as fh:
            return fh.read(), files[-1]
    except Exception:
        return None
    return None


def latest_issue_en():
    try:
        files = sorted(f for f in os.listdir(OUT) if f.startswith("issue-") and f.endswith(".en.html"))
        if not files:
            return None
        with open(os.path.join(OUT, files[-1]), encoding="utf-8") as fh:
            return fh.read(), files[-1]
    except Exception:
        return None
    return None


def latest_issue_pdf():
    try:
        files = sorted(f for f in os.listdir(OUT) if f.startswith("issue-") and f.endswith(".pdf"))
        if not files:
            return None
        with open(os.path.join(OUT, files[-1]), "rb") as fh:
            return fh.read(), files[-1]
    except Exception:
        return None
    return None


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OT Watch — Live</title>
<style>
:root{--bg:#0b1220;--panel:#111c33;--panel2:#0f1830;--line:#1e2c4d;--txt:#e2e8f0;--mut:#8ea0c2;--acc:#f59e0b;--red:#ef4444;--org:#f97316;--yel:#eab308;--grn:#22c55e;--blu:#3b82f6;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}
header{background:linear-gradient(90deg,#0b1f3a,#132a4d);padding:18px 26px;display:flex;flex-wrap:wrap;gap:14px;align-items:center;justify-content:space-between;border-bottom:2px solid var(--acc)}
h1{font-size:22px;margin:0}
h1 .dot{color:var(--acc)}
.tag{color:var(--mut);font-size:12.5px}
.live{display:inline-flex;align-items:center;gap:7px;background:#14532d;border:1px solid #22c55e;color:#86efac;font-size:12px;font-weight:700;padding:4px 10px;border-radius:999px}
.live.off{background:#4a1515;border-color:#ef4444;color:#fca5a5}
.pulse{width:8px;height:8px;border-radius:50%;background:#22c55e;animation:p 1.2s infinite}
.live.off .pulse{background:#ef4444}
@keyframes p{0%{box-shadow:0 0 0 0 rgba(34,197,94,.6)}70%{box-shadow:0 0 0 8px rgba(34,197,94,0)}100%{box-shadow:0 0 0 0 rgba(34,197,94,0)}}
.wrap{max-width:1180px;margin:0 auto;padding:20px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:16px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card .n{font-size:26px;font-weight:800}
.card .l{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.6px}
.card.warn .n{color:var(--org)} .card.crit .n{color:var(--red)} .card.ok .n{color:var(--grn)}
.meta{color:var(--mut);font-size:12.5px;margin:6px 0 0;display:flex;flex-wrap:wrap;gap:16px}
button{background:var(--acc);border:none;color:#1a1206;font-weight:700;border-radius:8px;padding:9px 16px;cursor:pointer;font-size:13px}
button:disabled{opacity:.5;cursor:wait}
button.ghost{background:transparent;border:1px solid var(--line);color:var(--txt)}
section{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin:16px 0}
h2{margin:0 0 4px;font-size:17px;border-left:4px solid var(--acc);padding-left:10px}
.sub{color:var(--mut);font-size:12.5px;margin:0 0 14px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:var(--panel2);text-align:left;padding:8px 10px;font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--mut);border-bottom:2px solid var(--line)}
td{padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
tr:hover td{background:#16233f}
a{color:#60a5fa;text-decoration:none} a:hover{text-decoration:underline}
.badge{display:inline-block;color:#fff;border-radius:5px;padding:1px 8px;font-size:11px;font-weight:800;white-space:nowrap}
.b-CRITICAL{background:#b91c1c}.b-HIGH{background:#ea580c}.b-MEDIUM{background:#ca8a04}.b-LOW{background:#65a30d}.b-DEFAULT{background:#475569}
.kev{color:#f87171;font-weight:800;font-size:11px}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px;align-items:center}
.filters input{background:var(--panel2);border:1px solid var(--line);color:var(--txt);border-radius:8px;padding:7px 12px;font-size:13px;min-width:220px}
.filters button{background:var(--panel2);border:1px solid var(--line);color:var(--txt);padding:7px 12px}
.filters button.on{background:var(--acc);color:#1a1206;border-color:var(--acc)}
.article{border:1px solid var(--line);border-radius:10px;padding:14px 18px;margin-bottom:14px;background:var(--panel2)}
.article .k{font-size:11px;font-weight:800;letter-spacing:1px;text-transform:uppercase;color:var(--acc)}
.article h3{margin:4px 0 8px;font-size:16px}
.article p,.article li{font-size:13.5px;line-height:1.65;color:#cbd5e1}
.article ul{margin:0 0 8px 18px;padding:0}
.article code{background:#0b1220;padding:1px 5px;border-radius:4px;font-size:12px}
.article blockquote{border-left:3px solid var(--acc);margin:8px 0;padding:6px 12px;background:#1a2440;color:#fcd34d;font-size:13px}
.article a{color:#60a5fa}
footer{color:var(--mut);font-size:12px;text-align:center;padding:18px}
#toast{position:fixed;bottom:18px;right:18px;background:#14532d;border:1px solid #22c55e;color:#bbf7d0;padding:10px 16px;border-radius:10px;font-size:13px;display:none}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
</style>
</head>
<body>
<header>
  <div>
    <h1>🛡️ OT Watch <span class="dot">● LIVE</span></h1>
    <div class="tag">Tableau de bord temps réel — PLC / CVE / avis CISA / KEV (sources live : CISA · NVD · KEV)</div>
  </div>
  <div>
    <span id="liveBadge" class="live"><span class="pulse"></span><span id="liveTxt">connecté</span></span>
    <span id="staleBadge" class="live off" style="display:none">⚠ DONNÉES STALES</span>
    <button id="btnRefresh">🔄 Re-collecter maintenant</button>
    <a href="/issue" target="_blank"><button class="ghost">📰 Voir la newsletter</button></a>
    <a href="/issue.pdf" target="_blank"><button class="ghost">📄 Télécharger le PDF</button></a>
    <a href="/stix" target="_blank"><button class="ghost">🧬 Export STIX 2.1</button></a>
    <a href="/taxii2/collections" target="_blank"><button class="ghost">🛰 TAXII 2.1</button></a>
    <a href="/misp" target="_blank"><button class="ghost">🕸 Export MISP</button></a>
    <a href="/issue.ar" target="_blank"><button class="ghost">🌍 العربية</button></a>
    <a href="/issue.en" target="_blank"><button class="ghost">🇬🇧 English</button></a>
    <a href="/openapi.json" target="_blank"><button class="ghost">📖 OpenAPI</button></a>
    <a href="/feed.xml" target="_blank"><button class="ghost">📡 RSS</button></a>
    <a href="/integrate" target="_blank"><button class="ghost">🔌 Intégrer</button></a>
    <a href="/stats" target="_blank"><button class="ghost">📊 Stats</button></a>
  </div>
</header>
<div style="margin:0 0 14px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">
  <form id="subForm" style="display:flex;gap:8px;align-items:center">
    <input id="subEmail" type="email" placeholder="votre@email.tld — recevoir l'édition (sans tracking)" style="padding:8px 10px;border-radius:8px;border:1px solid #cbd5e1;background:#0f172a;color:#e2e8f0;font-size:13px;min-width:280px">
    <button class="ghost" type="submit">🔔 S'abonner</button>
  </form>
  <span id="subMsg" class="mono" style="color:#64748b"></span>
</div>
<div class="wrap">
  <div class="cards">
    <div class="card crit"><div class="n" id="nCve">–</div><div class="l">CVE OT (fenêtre)</div></div>
    <div class="card warn"><div class="n" id="nCrit">–</div><div class="l">dont CRITICAL</div></div>
    <div class="card"><div class="n" id="nKev">–</div><div class="l">★ dans le KEV</div></div>
    <div class="card"><div class="n" id="nAdv">–</div><div class="l">avis CISA ICS</div></div>
    <div class="card ok"><div class="n" id="nKevAll">–</div><div class="l">entrées KEV OT</div></div>
  </div>
  <div class="meta">
    <span>🕒 dernière collecte : <b id="mGen">–</b> (<span id="mAgo">–</span>)</span>
    <span>🖥️ serveur : <span id="mSrv" class="mono">–</span></span>
    <span>🔁 auto-refresh toutes les <b id="mInt">–</b> s · <span id="mNext">–</span></span>
    <span>⚙️ collectes effectuées : <b id="mRuns">0</b> <span id="mErr"></span></span>
    <span>🪟 fenêtre : <b id="mWin">–</b> jours</span>
    <span>🆕 nouvelles CVE : <b id="mNew">–</b></span>
  </div>

  <section>
    <h2>📈 Tendances — publications CVE (30 derniers jours, historique SQLite)</h2>
    <p class="sub">Orange = CVE publiées/jour · Rouge = dont CRITICAL · Bleu = entrées KEV ajoutées/jour.</p>
    <div id="cvChart"></div>
  </section>

  <section>
    <h2>🔴 CVE — PLC &amp; OT (live NVD)</h2>
    <p class="sub">Triées par CVSS. ★KEV = exploitation connue (CISA). Mise à jour automatiquement à chaque collecte.</p>
    <div class="filters">
      <input id="q" placeholder="🔍 filtrer (CVE, texte, CWE…)">
      <button data-sev="" class="on">Toutes</button>
      <button data-sev="CRITICAL">CRITICAL</button>
      <button data-sev="HIGH">HIGH</button>
      <button data-sev="MEDIUM">MEDIUM</button>
      <button id="bKev">★ KEV seulement</button>
      <button id="bRel">⭐ Mes actifs OT</button>
    </div>
    <table><thead><tr><th>CVE</th><th>Risque</th><th>OT</th><th>CVSS</th><th>Détail</th><th>Publié</th></tr></thead><tbody id="tCve"></tbody></table>
  </section>

  <section>
    <h2>📋 Avis CISA ICS (live)</h2>
    <p class="sub">Flux CISA, fenêtre de la collecte en cours.</p>
    <table><thead><tr><th>Code</th><th>Avis</th><th>Publié</th></tr></thead><tbody id="tAdv"></tbody></table>
  </section>

  <section>
    <h2>⚠️ KEV — produits OT/ICS exploités</h2>
    <p class="sub">CISA Known Exploited Vulnerabilities — échéances de correction.</p>
    <table><thead><tr><th>CVE</th><th>Produit</th><th>Ajout → échéance</th><th>Action requise</th></tr></thead><tbody id="tKev"></tbody></table>
  </section>

  <section>
    <h2>✍️ Analyses de la rédaction</h2>
    <p class="sub">Articles écrits à partir des sources primaires (voir research/findings).</p>
    <div id="tArt"></div>
  </section>
</div>
<footer>OT Watch Live · données collectées en temps réel depuis CISA (RSS/ICS advisories), NVD API 2.0 et CISA KEV · affichage échappé/anti-XSS · <span id="clock"></span></footer>
<div id="toast">✅ Données mises à jour</div>
<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function safeHref(u){try{const x=new URL(u);return (x.protocol==='http:'||x.protocol==='https:')?x.href:'#';}catch(e){return '#';}}
function ago(iso){if(!iso)return'–';const s=(Date.now()-new Date(iso).getTime())/1000;if(s<60)return Math.floor(s)+' s';if(s<3600)return Math.floor(s/60)+' min';if(s<86400)return Math.floor(s/3600)+' h';return Math.floor(s/86400)+' j';}
function riskBadge(r){if(r==null)return'<span class="badge b-DEFAULT">–</span>';const cls=r>=8?'b-CRITICAL':r>=6?'b-HIGH':r>=4?'b-MEDIUM':'b-LOW';return `<span class="badge ${cls}">${Number(r).toFixed(1)}</span>`;}
function otBadge(r){if(r==null)return'<span class="badge b-DEFAULT" title="Aucun actif OT impacté">–</span>';const cls=r>=8?'b-CRITICAL':r>=6?'b-HIGH':r>=4?'b-MEDIUM':'b-LOW';return `<span class="badge ${cls}" title="Score OT expositionxPurduexcriticité (+KEV/SSVC)">${Number(r).toFixed(1)}</span>`;}
function badge(score,sev){const s=(sev||'').toUpperCase();const cls='b-'+(['CRITICAL','HIGH','MEDIUM','LOW'].includes(s)?s:'DEFAULT');const lab=(typeof score==='number')?score.toFixed(1):(sev||'n/a');return `<span class="badge ${cls}">${esc(lab)}</span>`;}
let state={sev:'',kev:false,q:'',rel:false},lastGen=null;
async function loadData(){
  const r=await fetch('/api/data');const d=await r.json();
  if(d.meta.generated_at!==lastGen){lastGen=d.meta.generated_at;if($('tCve').children.length)toast('✅ Données mises à jour');}
  $('mGen').textContent=d.meta.generated_at?new Date(d.meta.generated_at).toLocaleString('fr-FR'):'jamais';
  $('mAgo').textContent='il y a '+ago(d.meta.generated_at);
  $('mSrv').textContent=new Date(d.server_time).toLocaleTimeString('fr-FR');
  $('mInt').textContent=d.auto_interval_seconds;
  $('mRuns').textContent=d.collect_runs;
  $('mWin').textContent=d.meta.window_days;
  $('staleBadge').style.display=d.stale?'inline-flex':'none';
  $('mNew').textContent=(d.meta.diff&&d.meta.diff.new_cves)?d.meta.diff.new_cves.length:0;
  $('mErr').textContent=d.last_error?('⚠️ '+esc(d.last_error)):'';
  const live=!d.collecting;$('liveBadge').className='live'+(live?'':' off');$('liveTxt').textContent=d.collecting?'collecte en cours…':'connecté';
  const cves=d.cves||[];const crit=cves.filter(c=>c.severity==='CRITICAL').length;
  $('nCve').textContent=cves.length;$('nCrit').textContent=crit;$('nKev').textContent=cves.filter(c=>c.kev).length;
  $('nAdv').textContent=(d.advisories||[]).length;$('nKevAll').textContent=(d.kev||[]).length;
  renderCves(cves);renderAdv(d.advisories||[]);renderKev(d.kev||[]);renderArt(d.articles||[]);
  $('btnRefresh').disabled=d.collecting;
  $('btnRefresh').textContent=d.collecting?'⏳ Collecte en cours…':'🔄 Re-collecter maintenant';
}
function renderCves(cves){
  const q=state.q.toLowerCase();
  cves=[...cves].sort((a,b)=>((b.relevant?1:0)-(a.relevant?1:0))||((b.ot_score??b.risk??b.cvss??0)-(a.ot_score??a.risk??a.cvss??0)));
  const rows=cves.filter(c=>(!state.sev||c.severity===state.sev)&&(!state.kev||c.kev)&&(!state.rel||c.relevant)&&(!q||(c.id+' '+(c.description||'')+' '+(c.cwes||[]).join(' ')).toLowerCase().includes(q)));
  $('tCve').innerHTML=rows.map(c=>`<tr>
    <td class="mono" style="white-space:nowrap"><a href="${safeHref((c.refs&&c.refs[0])||('https://nvd.nist.gov/vuln/detail/'+c.id))}">${esc(c.id)}</a>${c.kev?' <span class="kev">★KEV</span>':''}${c.relevant?' <span style="color:#f59e0b" title="correspond à votre profil">⭐</span>':''}</td>
    <td>${riskBadge(c.risk)}</td>
    <td>${otBadge(c.ot_score)}</td><td>${badge(c.cvss,c.severity)}</td>
    <td style="color:#cbd5e1">${esc((c.description||'').replace(/\s+/g,' ').slice(0,220))}<br><span style="color:#64748b;font-size:11px">${esc((c.cwes||[]).join(', '))}${(c.ssvc||c.attack_ics)?'<br><span style="font-size:10px;color:#a78bfa">'+esc((c.ssvc?('SSVC '+c.ssvc.toUpperCase()):'')+((c.attack_ics&&c.attack_ics.length)?(' · '+c.attack_ics.join(',')):'')+'')+'</span>':''}</span></td>
    <td class="mono" style="white-space:nowrap;color:#8ea0c2">${esc((c.published||'').slice(0,10))}</td></tr>`).join('')||'<tr><td colspan="6" style="color:#8ea0c2">Aucune CVE ne correspond au filtre.</td></tr>';
}
function renderAdv(adv){$('tAdv').innerHTML=adv.map(a=>`<tr>
  <td class="mono" style="white-space:nowrap">${esc(a.code||'ICS')}</td>
  <td><a href="${safeHref(a.link)}">${esc(a.title)}</a><br><span style="color:#8ea0c2;font-size:12px">${esc((a.summary||'').slice(0,150))}</span></td>
  <td class="mono" style="white-space:nowrap;color:#8ea0c2">${esc((a.published||'').slice(0,16))}</td></tr>`).join('')||'<tr><td colspan="3" style="color:#8ea0c2">Aucun avis dans la fenêtre.</td></tr>';}
function renderKev(kev){$('tKev').innerHTML=kev.map(k=>`<tr>
  <td class="mono" style="white-space:nowrap"><b>${esc(k.cveID)}</b></td>
  <td>${esc(k.vendorProject||'')} — ${esc(k.product||'')}<br><span style="color:#8ea0c2;font-size:12px">${esc((k.vulnerabilityName||'').slice(0,110))}${String(k.knownRansomwareCampaignUse).toLowerCase()==='known'?' ⚠ ransomware':''}</span></td>
  <td class="mono" style="white-space:nowrap;color:#8ea0c2">${esc(k.dateAdded||'')} → ${esc(k.dueDate||'')}</td>
  <td style="color:#cbd5e1;font-size:12px">${esc((k.requiredAction||'').slice(0,120))}</td></tr>`).join('')||'<tr><td colspan="4" style="color:#8ea0c2">Aucune entrée KEV OT.</td></tr>';}
function renderArt(arts){$('tArt').innerHTML=arts.map(a=>`<div class="article"><div class="k">${esc(a.kicker)} · ${esc(a.section)}</div><h3>${esc(a.title)}</h3>${a.body_html}</div>`).join('');}
function toast(msg){const t=$('toast');t.textContent=msg;t.style.display='block';setTimeout(()=>t.style.display='none',2500);}
$('q').addEventListener('input',e=>{state.q=e.target.value;loadData();});
document.querySelectorAll('[data-sev]').forEach(b=>b.addEventListener('click',()=>{document.querySelectorAll('[data-sev]').forEach(x=>x.classList.remove('on'));b.classList.add('on');state.sev=b.dataset.sev;loadData();}));
$('bKev').addEventListener('click',()=>{state.kev=!state.kev;$('bKev').classList.toggle('on',state.kev);loadData();});
$('bRel').addEventListener('click',()=>{state.rel=!state.rel;$('bRel').classList.toggle('on',state.rel);loadData();});
$('btnRefresh').addEventListener('click',async()=>{try{await fetch('/api/refresh',{method:'POST'});toast('🔄 Collecte lancée (CISA/NVD/KEV)…');}catch(e){toast('Erreur: '+e);}loadData();});
setInterval(()=>{$('mAgo').textContent='il y a '+ago(lastGen);$('clock').textContent=new Date().toLocaleString('fr-FR');},1000);
function drawChart(id, series){
  const w=760,h=130,pad=8;
  const max=Math.max(1,...series.map(d=>Math.max(d.total,d.critical,d.kev_added)));
  const X=i=>pad+i*(w-2*pad)/Math.max(1,series.length-1);
  const Y=v=>h-pad-(v/max)*(h-2*pad);
  const line=(key)=>'M'+series.map((d,i)=>X(i).toFixed(1)+','+Y(d[key]).toFixed(1)).join(' L');
  const area=line('total')+` L${X(series.length-1).toFixed(1)},${h-pad} L${pad},${h-pad} Z`;
  document.getElementById(id).innerHTML=
    `<svg viewBox="0 0 ${w} ${h}" width="100%" style="background:#0f1830;border-radius:8px">`+
    `<path d="${area}" fill="rgba(245,158,11,.18)" stroke="#f59e0b" stroke-width="2"/>`+
    `<path d="${line('critical')}" fill="none" stroke="#ef4444" stroke-width="2"/>`+
    `<path d="${line('kev_added')}" fill="none" stroke="#3b82f6" stroke-width="2" stroke-dasharray="4 3"/>`+
    `</svg><div style="display:flex;justify-content:space-between;font-size:10px;color:#8ea0c2"><span>${series[0]?series[0].date:''}</span><span>max ${max}/jour</span><span>${series[series.length-1]?series[series.length-1].date:''}</span></div>`;
}
async function loadHistory(){try{const r=await fetch('/api/history');const h=await r.json();if(h.history)drawChart('cvChart',h.history);}catch(e){}}
setInterval(loadData,15000);  // fallback polling
loadData();loadHistory();
if (window.EventSource) {
  const es = new EventSource('/api/stream');
  es.onmessage = (e) => {
    try {
      const ev = JSON.parse(e.data);
      if (ev.type === 'collected') {
        const n = (ev.diff && ev.diff.new_cves) ? ev.diff.new_cves.length : 0;
        toast('🆕 Collecte terminée : +' + n + ' CVE' + (ev.counts ? ' (' + ev.counts.cves + ' au total)' : ''));
        loadData();
      }
    } catch (_) {}
  };
}
</script>
<script>
document.getElementById('subForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('subEmail').value.trim();
  const msg = document.getElementById('subMsg');
  try {
    const r = await fetch('/subscribe', {method: 'POST', headers: {'Content-Type': 'application/json'},
                                        body: JSON.stringify({email})});
    const j = await r.json();
    msg.textContent = j.message + ' (' + j.subscribers + ' abonnés)';
    if (j.ok) document.getElementById('subEmail').value = '';
  } catch (err) { msg.textContent = 'erreur réseau'; }
});
</script>
</body>
</html>"""


def _base_url(headers):
    """URL publique : OTWATCH_BASE_URL env prioritaire, sinon Host de la requête."""
    return (os.environ.get("OTWATCH_BASE_URL")
            or f"http://{headers.get('Host') or 'localhost:8000'}").rstrip("/")


def _with_seo(html_doc, base, lang, route, title, desc, date_iso):
    """Injecte hreflang FR/AR/EN + canonical + OG + JSON-LD si absent (éditions statiques out/)."""
    if "hreflang" in html_doc:
        return html_doc
    block = growth.seo_head(base, lang, route, title, desc, date_iso)
    return re.sub(r"(<head[^>]*>)", lambda m: m.group(1) + block, html_doc, count=1)


class Handler(BaseHTTPRequestHandler):
    server_version = "OTWatch-Live/1.0"

    def log_message(self, fmt, *args):  # logs compacts
        print(f"[http] {self.address_string()} {fmt % args}", flush=True)

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra_headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
        self.end_headers()
        self.wfile.write(body)

    def _sse(self):
        """Flux Server-Sent Events : push instantané à chaque fin de collecte."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self'")
        self.end_headers()
        q = queue.Queue()
        with _sse_lock:
            _sse_clients.append(q)
        try:
            self.wfile.write(b'data: {"type":"connected"}\n\n')
            self.wfile.flush()
            while True:
                try:
                    ev = q.get(timeout=25)
                    self.wfile.write(f"data: {json.dumps(ev, ensure_ascii=False)}\n\n".encode())
                    self.wfile.flush()
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")  # keepalive
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            with _sse_lock:
                if q in _sse_clients:
                    _sse_clients.remove(q)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/" or path == "/index.html":
            self._send(200, DASHBOARD_HTML, "text/html; charset=utf-8")
        elif path == "/api/data":
            self._send(200, json.dumps(api_payload(), ensure_ascii=False))
        elif path == "/api/meta":
            p = api_payload()
            self._send(200, json.dumps({k: p[k] for k in (
                "meta", "server_time", "collecting", "last_run", "last_error",
                "collect_runs", "auto_interval_seconds", "stale", "freshness_seconds")}, ensure_ascii=False))
        elif path == "/api/refresh":
            self._send(200, json.dumps({"hint": "utiliser POST"}), )
        elif path == "/api/history":
            self._send(200, json.dumps({"history": store.history_daily()}, ensure_ascii=False))
        elif path == "/api/stream":
            self._sse()
            return
        elif path == "/metrics":
            p = api_payload()
            m = p["meta"]
            c = m.get("counts", {})
            crit = sum(1 for x in p["cves"] if x.get("severity") == "CRITICAL")
            gen_ts = 0
            if m.get("generated_at"):
                try:
                    gen_ts = datetime.fromisoformat(m["generated_at"]).timestamp()
                except Exception:  # noqa: BLE001
                    gen_ts = 0
            lines = [
                "# HELP otwatch_up Disponibilité du collecteur",
                "# TYPE otwatch_up gauge",
                "otwatch_up 1",
                "# HELP otwatch_last_collect_timestamp_seconds Dernier timestamp de collecte (epoch)",
                "# TYPE otwatch_last_collect_timestamp_seconds gauge",
                f"otwatch_last_collect_timestamp_seconds {gen_ts:.0f}",
                "# HELP otwatch_data_freshness_seconds Âge des données en secondes",
                "# TYPE otwatch_data_freshness_seconds gauge",
                f"otwatch_data_freshness_seconds {int(p['freshness_seconds'] or 0)}",
                "# HELP otwatch_stale 1 si données plus vieilles que le SLO de fraîcheur",
                "# TYPE otwatch_stale gauge",
                f"otwatch_stale {1 if p['stale'] else 0}",
                f"# TYPE otwatch_cves_total gauge\notwatch_cves_total {c.get('cves', 0)}",
                f"# TYPE otwatch_cves_critical_total gauge\notwatch_cves_critical_total {crit}",
                f"# TYPE otwatch_kev_ot_total gauge\notwatch_kev_ot_total {c.get('kev', c.get('kev_ot', 0))}",
                f"# TYPE otwatch_advisories_total gauge\notwatch_advisories_total {c.get('advisories', c.get('cisa_advisories', 0))}",
                f"# TYPE otwatch_collect_runs_total gauge\notwatch_collect_runs_total {p['collect_runs']}",
                f"# TYPE otwatch_last_collect_duration_seconds gauge\notwatch_last_collect_duration_seconds {_state['last_collect_duration']}",
                f"# TYPE otwatch_assets_total gauge\notwatch_assets_total {len(p.get('assets') or [])}",
                f"# TYPE otwatch_cves_impacted_total gauge\notwatch_cves_impacted_total {sum(1 for c in p.get('cves') or [] if c.get('ot_score') is not None)}",
                f"# TYPE otwatch_ot_score_max gauge\notwatch_ot_score_max {max([c.get('ot_score') or 0 for c in p.get('cves') or []] + [0])}",
                f"# TYPE otwatch_netwatch_hosts_ot gauge\notwatch_netwatch_hosts_ot {(p.get('netwatch') or {}).get('stats', {}).get('hosts_OT', 0)}",
                f"# TYPE otwatch_netwatch_anomalies_total gauge\notwatch_netwatch_anomalies_total {len((p.get('netwatch') or {}).get('anomalies', []))}",
                f"# TYPE otwatch_quality_dup_rate gauge\notwatch_quality_dup_rate {(p.get('quality') or {}).get('dup_rate', 0)}",
                f"# TYPE otwatch_quality_sources_total gauge\notwatch_quality_sources_total {(p.get('quality') or {}).get('sources', 0)}",
                f"# TYPE otwatch_raw_files_total gauge\notwatch_raw_files_total {raw_files_count()}",
            ]
            self._send(200, "\n".join(lines) + "\n", "text/plain; version=0.0.4; charset=utf-8")
        elif path == "/issue":
            res = latest_issue_html()
            if res:
                doc = _with_seo(res[0], _base_url(self.headers), "fr", "/issue",
                                f"OT Watch — édition du {res[1][6:16]}",
                                "Veille OT/ICS : CVE prioritaires, KEV, avis CISA, score OT.", res[1][6:16])
                self._send(200, doc, "text/html; charset=utf-8")
            else:
                self._send(404, json.dumps({"error": "aucune édition générée"}))
        elif path == "/misp":
            res = latest_issue_misp()
            if res:
                self._send(200, res[0], "application/json", extra_headers={
                    "Content-Disposition": f'inline; filename="{res[1]}"'})
            else:
                self._send(404, json.dumps({"error": "aucun export MISP généré"}))
        elif path == "/openapi.json":
            spec_path = os.path.join(ROOT, "docs", "openapi.json")
            try:
                with open(spec_path, encoding="utf-8") as fh:
                    self._send(200, fh.read(), "application/json")
            except OSError:
                self._send(404, json.dumps({"error": "spec OpenAPI introuvable"}))
        elif path == "/api/netwatch":
            nw = load_json("netwatch.json", None)
            if nw is None:
                self._send(404, json.dumps({"error": "aucun rapport netwatch — lancez python3 src/netwatch.py (voir runbook collecte passive)"}))
            else:
                self._send(200, json.dumps(nw, ensure_ascii=False))
        elif path == "/api/assets":
            assets = load_json("assets.json", [])
            cves = load_json("cves.json", [])
            impacted = {}
            for c in cves:
                for aid in c.get("asset_impact") or []:
                    impacted.setdefault(aid, []).append({"id": c.get("id"), "ot_score": c.get("ot_score"),
                                                         "severity": c.get("severity"), "kev": bool(c.get("kev"))})
            self._send(200, json.dumps({"assets": assets, "impacted": impacted,
                                        "purdue": {"L0": "processus", "L1": "contrôle PLC/RTU",
                                                   "L2": "supervision HMI/SCADA", "L3": "site MES",
                                                   "L3.5": "DMZ industrielle", "L4": "entreprise IT"}},
                                       ensure_ascii=False))
        elif path.startswith("/taxii2"):
            from urllib.parse import parse_qs, urlparse
            u = urlparse(self.path)
            q = parse_qs(u.query)
            p2 = u.path
            status, body, ctype = taxii.handle(p2, method="GET", query=q, headers=self.headers)
            self._send(status, body, ctype)
        elif path == "/stix":
            res = latest_issue_stix()
            if res:
                self._send(200, res[0], "application/stix+json", extra_headers={
                    "Content-Disposition": f'inline; filename="{res[1]}"',
                })
            else:
                self._send(404, json.dumps({"error": "aucun export STIX généré"}))
        elif path == "/issue.ar":
            res = latest_issue_ar()
            if res:
                doc = _with_seo(res[0], _base_url(self.headers), "ar", "/issue.ar",
                                "نشرة OT Watch — CVE وKEV وأvis CISA (édition arabe)", "Veille OT/ICS en arabe.", res[1][6:16])
                self._send(200, doc, "text/html; charset=utf-8")
            else:
                self._send(404, json.dumps({"error": "aucune édition arabe générée"}))
        elif path == "/issue.en":
            res = latest_issue_en()
            if res:
                doc = _with_seo(res[0], _base_url(self.headers), "en", "/issue.en",
                                f"OT Watch — English edition {res[1][6:16]}", "OT/ICS watch: priority CVEs, KEV, CISA advisories, OT score.", res[1][6:16])
                self._send(200, doc, "text/html; charset=utf-8")
            else:
                self._send(404, json.dumps({"error": "no English edition generated"}))
        elif path == "/issue.pdf":
            res = latest_issue_pdf()
            if res:
                fname = res[1].replace(".pdf", "")
                self._send(200, res[0], "application/pdf", extra_headers={
                    "Content-Disposition": f'inline; filename="{fname}.pdf"',
                })
            else:
                self._send(404, json.dumps({"error": "aucun PDF généré"}))
        elif path == "/feed.xml":
            self._send(200, growth.rss_feed(_base_url(self.headers)), "application/rss+xml; charset=utf-8")
        elif path == "/sitemap.xml":
            self._send(200, growth.sitemap(_base_url(self.headers)), "application/xml; charset=utf-8")
        elif path == "/robots.txt":
            self._send(200, growth.robots(_base_url(self.headers)), "text/plain; charset=utf-8")
        elif path == "/integrate":
            self._send(200, growth.integrate_html(_base_url(self.headers)), "text/html; charset=utf-8")
        elif path == "/stats":
            self._send(200, growth.stats_html(_base_url(self.headers)), "text/html; charset=utf-8")
        elif path == "/api/subscribers":
            self._send(200, json.dumps({"subscribers": growth.subscriber_count()}))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        if self.path.startswith("/taxii2"):
            status, body, ctype = taxii.handle(self.path, method="POST", headers=self.headers)
            self._send(status, body, ctype)
            return
        path = self.path.split("?", 1)[0]
        if path == "/api/refresh":
            # auth admin (prod) : OTWATCH_ADMIN_TOKEN env -> Authorization: Bearer <token>
            token = os.environ.get("OTWATCH_ADMIN_TOKEN")
            if token:
                auth = self.headers.get("Authorization", "")
                if auth != f"Bearer {token}":
                    self._send(401, json.dumps({"error": "unauthorized"}))
                    return
            # rate-limit : 1 refresh / 60 s max
            now = time.time()
            if now - _state["last_refresh_start"] < REFRESH_MIN_INTERVAL_S:
                self._send(429, json.dumps({"error": "rate_limited", "retry_after_s": int(REFRESH_MIN_INTERVAL_S - (now - _state["last_refresh_start"]) )}))
                return
            _state["last_refresh_start"] = now
            if _state["collecting"] or not _lock.acquire(blocking=False):
                self._send(200, json.dumps({"status": "already_running", "collecting": True}))
            else:
                _lock.release()
                threading.Thread(target=run_collect, daemon=True).start()
                self._send(200, json.dumps({"status": "started", "collecting": True}))
        elif path in ("/subscribe", "/unsubscribe"):
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                n = 0
            raw = self.rfile.read(min(n, 8192)) if n else b""
            email = webhook = None
            try:
                payload = json.loads(raw.decode("utf-8")) if raw else {}
                email = payload.get("email")
                webhook = payload.get("webhook")
            except Exception:
                # formulaire url-encoded : email=...&webhook=...
                from urllib.parse import parse_qs
                q = parse_qs(raw.decode("utf-8", "replace"))
                email = (q.get("email") or [None])[0]
                webhook = (q.get("webhook") or [None])[0]
            if path == "/subscribe":
                ok, msg = growth.subscribe(email=email, webhook=webhook)
                broadcast({"type": "subscribe", "n": growth.subscriber_count()})
                self._send(200 if ok else 400, json.dumps({"ok": ok, "message": msg,
                                                            "subscribers": growth.subscriber_count()}))
            else:
                deleted = growth.unsubscribe(email or "")
                self._send(200, json.dumps({"ok": deleted, "subscribers": growth.subscriber_count()}))
        else:
            self._send(404, json.dumps({"error": "not found"}))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()

    if not os.path.exists(os.path.join(DATA, "meta.json")):
        print("[server] aucune donnée — collecte initiale en arrière-plan…", flush=True)
        threading.Thread(target=run_collect, daemon=True).start()
    threading.Thread(target=auto_refresh_loop, daemon=True).start()

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"[server] OT Watch Live sur http://{args.host}:{args.port}  (auto-refresh {AUTO_REFRESH_SECONDS}s)", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
