#!/usr/bin/env python3
"""
OT Watch — Worker Cloudflare (Python Workers, GA 21/09/2026, Pyodide) pour le FREE tier.

Architecture (voir docs/deploy/CLOUDFLARE-FREE-TIER-2026-11-01.md) :
  - fetch()  : sert dashboard + API en lecture depuis D1/KV/R2 (CPU < 10 ms) + SSE /api/stream.
  - scheduled() (cron, 15 min wall max) : collecte légère (RSS CISA + NVD par CVE + KEV + EPSS)
    puis écrit D1 (tables identiques à store.py) + KV (payload /api/data) + R2 (édition courante).
  - Bindings : env.DB (D1), env.KV (KV), env.R2 (R2). Secrets via env (wrangler secret put ...).

Limites free tier à respecter : 100k req/jour (compte), 10 ms CPU/requête, 50 subrequests/requête,
6 connexions sortantes simultanées, 5 crons, KV 1 000 writes/jour, D1 100k writes/jour.
"""
import contextlib
import json
import os
import re

from workers import Response, WorkerEntrypoint  # workers-py SDK (GA 2026)

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self' 'unsafe-inline'",
}

CISA_RSS = "https://www.cisa.gov/rss.xml"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="


def _json(obj, status=200, extra=None):
    headers = {"Content-Type": "application/json; charset=utf-8", **SECURITY_HEADERS}
    if extra:
        headers.update(extra)
    return Response(json.dumps(obj, ensure_ascii=False), status=status, headers=headers)


def _html(body, status=200):
    return Response(body, status=status, headers={"Content-Type": "text/html; charset=utf-8", **SECURITY_HEADERS})


async def _kv_json(env, key, default):
    try:
        val = await env.KV.get(key, type="json")
    except Exception:
        val = None
    return val if val is not None else default


async def _d1_all(env, sql, params=()):
    res = await env.DB.prepare(sql).bind(*params).all()
    return res.results if hasattr(res, "results") else res


class OtwatchWorker(WorkerEntrypoint):
    """API live en lecture (D1/KV/R2) + collecte cron."""

    async def fetch(self, request, env):
        url = request.url
        path = re.sub(r"^https?://[^/]+", "", url).split("?")[0] or "/"
        method = request.method

        if path in ("/", "/index.html"):
            html = await env.R2.get("issue-latest.html")
            if html:
                return _html(await html.text())
            return _html(await _kv_json(env, "dashboard.html", "<h1>OT Watch — aucune édition encore (attendez le 1er cron)</h1>"))

        if path == "/api/data":
            payload = await _kv_json(env, "api:data", None)
            if payload is None:
                cves = await _d1_all(env, "SELECT cve_id AS id, cvss, severity, kev, epss, risk, relevant, attack_ics, ssvc, assets, ot_score, published, description, refs FROM cves ORDER BY ot_score DESC NULLS LAST, risk DESC LIMIT 200")
                meta = await _kv_json(env, "meta.json", {})
                payload = {"meta": meta, "cves": cves, "advisories": await _kv_json(env, "cisa_advisories.json", []),
                           "kev": await _kv_json(env, "kev.json", []), "assets": await _kv_json(env, "assets.json", []),
                           "quality": (meta or {}).get("quality", {}), "server_time": __import__("datetime").datetime.now(__import__("datetime").UTC).isoformat()}
                with contextlib.suppress(Exception):
                    await env.KV.put("api:data", json.dumps(payload, ensure_ascii=False), expiration_ttl=300)
            return _json(payload)

        if path == "/api/history":
            rows = await _d1_all(env, "SELECT id, finished_at, n_cves, n_advisories, n_kev, ok FROM runs ORDER BY id DESC LIMIT 30")
            return _json({"history": rows})

        if path == "/api/assets":
            assets = await _kv_json(env, "assets.json", [])
            cves = await _d1_all(env, "SELECT cve_id AS id, ot_score, severity, kev, assets FROM cves WHERE assets IS NOT NULL AND assets != '[]'")
            impacted = {}
            for c in cves:
                for aid in json.loads(c["assets"] or "[]"):
                    impacted.setdefault(aid, []).append({"id": c["id"], "ot_score": c["ot_score"], "severity": c["severity"], "kev": bool(c["kev"])})
            return _json({"assets": assets, "impacted": impacted})

        if path == "/api/netwatch":
            nw = await _kv_json(env, "netwatch.json", None)
            return _json(nw) if nw else _json({"error": "aucun rapport netwatch"}, status=404)

        if path == "/api/meta":
            meta = await _kv_json(env, "meta.json", {})
            return _json({"meta": meta, "env": getattr(env, "ENV_NAME", "free-tier")})

        if path == "/metrics":
            cves = await _d1_all(env, "SELECT COUNT(*) n, SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) crit FROM cves")
            runs = await _d1_all(env, "SELECT COUNT(*) n FROM runs")
            assets = await _d1_all(env, "SELECT COUNT(*) n FROM assets")
            n = cves[0]["n"] if cves else 0
            body = "\n".join([
                "# TYPE otwatch_up gauge", "otwatch_up 1",
                f"# TYPE otwatch_cves_total gauge\notwatch_cves_total {n}",
                f"# TYPE otwatch_cves_critical_total gauge\notwatch_cves_critical_total {cves[0]['crit'] if cves else 0}",
                f"# TYPE otwatch_collect_runs_total gauge\notwatch_collect_runs_total {runs[0]['n'] if runs else 0}",
                f"# TYPE otwatch_assets_total gauge\notwatch_assets_total {assets[0]['n'] if assets else 0}",
            ])
            return Response(body, headers={"Content-Type": "text/plain; version=0.0.4", **SECURITY_HEADERS})

        # éditions servies depuis R2 (générées par le cron)
        for route, key, ctype in (("/issue", "issue-latest.html", "text/html; charset=utf-8"),
                                  ("/issue.ar", "issue-latest.ar.html", "text/html; charset=utf-8"),
                                  ("/issue.en", "issue-latest.en.html", "text/html; charset=utf-8"),
                                  ("/issue.pdf", "issue-latest.pdf", "application/pdf"),
                                  ("/stix", "issue-latest.stix.json", "application/stix+json"),
                                  ("/misp", "issue-latest.misp.json", "application/json")):
            if path == route:
                obj = await env.R2.get(key)
                if obj is None:
                    return _json({"error": "aucune édition générée (attendre le 1er cron)"}, status=404)
                return Response(await obj.body, headers={"Content-Type": ctype, **SECURITY_HEADERS})

        if path == "/openapi.json":
            spec = await env.R2.get("openapi.json")
            return _json(json.loads(await spec.text())) if spec else _json({"error": "spec absente"}, status=404)

        if path.startswith("/taxii2"):
            stix_key = "issue-latest.stix.json"
            if path.rstrip("/") in ("/taxii2", "/taxii2/"):
                return _json({"versions": ["2.1"], "default": "/taxii2/"}, extra={"Content-Type": "application/taxii+json; charset=utf-8"})
            if path == "/taxii2/collections":
                return _json({"collections": [{"id": "otwatch-ot-cves", "title": "OT Watch OT CVEs", "description": "CVE OT/ICS + avis CISA (TLP:WHITE)", "can_read": True, "can_write": False, "media_types": ["application/stix+json"]}]}, extra={"Content-Type": "application/taxii+json; charset=utf-8"})
            if path.startswith("/taxii2/collections/otwatch-ot-cves/objects"):
                obj = await env.R2.get(stix_key)
                if obj is None:
                    return _json({"error": "aucun bundle"}, status=404)
                return Response(await obj.body, headers={"Content-Type": "application/stix+json", **SECURITY_HEADERS})
            return _json({"title": "Not Found"}, status=404, extra={"Content-Type": "application/taxii+json"})

        # SSE : streaming natif Workers (pas de limite de durée ; ne jamais mettre en cache)
        if path == "/api/stream":
            async def stream():
                yield b"data: {\"type\":\"connected\"}\n\n"
                meta = await _kv_json(env, "meta.json", {})
                yield ("data: " + json.dumps({"type": "meta", "generated_at": meta.get("generated_at")}) + "\n\n").encode()
            return Response(stream(), headers={"Content-Type": "text/event-stream", "Cache-Control": "no-cache", **SECURITY_HEADERS})

        if path == "/api/refresh" and method == "POST":
            token = os.environ.get("OTWATCH_ADMIN_TOKEN") or getattr(env, "OTWATCH_ADMIN_TOKEN", None)
            auth = request.headers.get("Authorization", "")
            if token and auth != f"Bearer {token}":
                return _json({"error": "unauthorized"}, status=401)
            return _json({"started": "via cron Cloudflare (voir [triggers] wrangler.toml) — ré refreshed automatiquement toutes les 6 h"})

        return _json({"error": "not found", "path": path}, status=404)

    async def scheduled(self, event, env, ctx):
        """Cron (15 min wall max, 5 crons gratuits) : collecte légère + écriture D1/KV/R2."""
        import datetime as dt
        t0 = dt.datetime.now(dt.UTC)
        # 1) KEV (1 subrequest)
        kev = await self._get_json(env, KEV_URL)
        kev_ot = [v for v in (kev or {}).get("vulnerabilities", [])][:50]
        # 2) RSS CISA (1 subrequest, ~500 Ko — parsing léger)
        rss = await self._get_text(env, CISA_RSS)
        advisories = self._parse_rss_light(rss)
        # 3) NVD par CVE watchlist (subrequests <= 50 au total) — config via KV
        watchlist = await _kv_json(env, "watchlist.json", ["CVE-2026-110936"])
        cves = []
        for cve_id in watchlist[:20]:
            data = await self._get_json(env, NVD_API + cve_id)
            c = self._nvd_light(data, cve_id)
            if c:
                cves.append(c)
        kev_ids = {v.get("cveID") for v in kev_ot}
        for c in cves:
            c["kev"] = c["id"] in kev_ids
        # 4) persistance : D1 (upsert) + KV (payload) + R2 (édition)
        for c in cves:
            await env.DB.prepare(
                """INSERT INTO cves (cve_id, first_seen_run, last_seen_run, cvss, severity, kev, epss, risk, relevant, attack_ics, ssvc, assets, ot_score, published, description, refs)
                   VALUES (?,1,1,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(cve_id) DO UPDATE SET last_seen_run=last_seen_run+1, cvss=excluded.cvss, severity=excluded.severity, kev=excluded.kev"""
            ).bind(c["id"], c.get("cvss"), c.get("severity"), 1 if c.get("kev") else 0, c.get("epss"), c.get("risk"),
                   0, "[]", "", "[]", c.get("ot_score"), c.get("published"), (c.get("description") or "")[:700], "[]").run()
        meta = {"generated_at": t0.isoformat(), "window_days": 14,
                "counts": {"cves": len(cves), "advisories": len(advisories), "kev": len(kev_ot)},
                "quality": {"sources": 3, "cves_uniques": len(cves), "dup_rate": 0.0, "raw_dir": None},
                "collect_ms": int((dt.datetime.now(dt.UTC) - t0).total_seconds() * 1000), "env": "cloudflare-free"}
        await env.KV.put("meta.json", json.dumps(meta, ensure_ascii=False))
        await env.KV.put("kev.json", json.dumps(kev_ot, ensure_ascii=False))
        await env.KV.put("cisa_advisories.json", json.dumps(advisories, ensure_ascii=False))
        # édition HTML minimale depuis les données (le rendu complet reste côté run_all local/CI)
        html = self._render_min(cves, advisories, meta)
        await env.R2.put("issue-latest.html", html)
        await env.R2.put("issue-latest.ar.html", self._render_min_ar(cves, meta))
        await env.R2.put("issue-latest.en.html", self._render_min_en(cves, meta))
        await env.DB.prepare("INSERT INTO runs (finished_at, n_cves, n_advisories, n_kev, ok) VALUES (?,?,?,?,1)").bind(
            meta["generated_at"], len(cves), len(advisories), len(kev_ot)).run()
        return {"ok": True, "cves": len(cves), "advisories": len(advisories)}

    # ---------------------------------------------------------- helpers collecte (léger)
    async def _get_json(self, env, url):
        r = await env.fetch(url) if hasattr(env, "fetch") else None
        import js  # Pyodide : fetch via js si besoin
        if r is None:
            resp = await js.fetch(url)
            return await resp.json()
        return await r.json()

    async def _get_text(self, env, url):
        r = await env.fetch(url) if hasattr(env, "fetch") else None
        if r is None:
            import js
            resp = await js.fetch(url)
            return await resp.text()
        return await r.text()

    def _parse_rss_light(self, xml):
        items = re.findall(r"<item>(.*?)</item>", xml or "", re.S)[:30]
        out = []
        for it in items:
            title = re.search(r"<title>(.*?)</title>", it, re.S)
            link = re.search(r"<link>(.*?)</link>", it, re.S)
            pub = re.search(r"<pubDate>(.*?)</pubDate>", it, re.S)
            out.append({"code": "ICS", "title": (title.group(1) if title else "")[:200],
                        "link": link.group(1) if link else "", "published": (pub.group(1) if pub else "")[:30], "summary": ""})
        return out

    def _nvd_light(self, data, cve_id):
        try:
            v = data["vulnerabilities"][0]["cve"]
        except Exception:
            return None
        metrics = v.get("metrics", {}).get("cvssMetricV31", []) or v.get("metrics", {}).get("cvssMetricV40", [])
        cvss = metrics[0]["cvssData"]["baseScore"] if metrics else None
        return {"id": cve_id, "cvss": cvss, "severity": (metrics[0]["cvssData"].get("baseSeverity") if metrics else None),
                "published": v.get("published", "")[:10], "description": (v.get("descriptions", [{}])[0].get("value", "") or "")[:300],
                "refs": [r.get("url") for r in v.get("references", [])][:5], "epss": None, "risk": cvss, "ot_score": None}

    def _render_min(self, cves, advisories, meta):
        rows = "".join(f"<tr><td>{c['id']}</td><td>{c.get('severity')}</td><td>{c.get('cvss')}</td><td>{'★KEV' if c.get('kev') else ''}</td></tr>" for c in cves)
        adv = "".join(f"<li>{a['title']}</li>" for a in advisories[:15])
        return f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><title>OT Watch LIVE (Cloudflare free)</title>
<style>body{{font-family:system-ui;max-width:960px;margin:auto;padding:24px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:6px;font-size:13px}}</style></head>
<body><h1>🛰 OT Watch — LIVE Cloudflare Workers (free tier)</h1>
<p>Édition {meta['generated_at'][:10]} · {len(cves)} CVE · {len(advisories)} avis CISA · {meta['counts']['kev']} KEV — <a href="/api/data">/api/data</a> · <a href="/openapi.json">OpenAPI</a> · <a href="/taxii2/collections">TAXII</a> · <a href="/metrics">/metrics</a> · <a href="/api/stream">SSE</a></p>
<table><tr><th>CVE</th><th>Sévérité</th><th>CVSS</th><th>KEV</th></tr>{rows}</table><h2>Avis CISA ICS</h2><ul>{adv}</ul></body></html>"""

    def _render_min_ar(self, cves, meta):
        rows = "".join(
            f"<tr><td dir=\"ltr\"><bdi>{c['id']}</bdi></td><td dir=\"ltr\">{c.get('cvss')}</td></tr>" for c in cves
        )
        style = "body{font-family:'Noto Naskh Arabic','Segoe UI',Tahoma,Arial,sans-serif;line-height:1.6;max-width:960px;margin:auto;padding:24px}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:6px;font-size:13px}"
        return (
            '<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><title>نشرة OT Watch</title>'
            f"<style>{style}</style></head><body><h1>نشرة OT Watch — مباشر (Cloudflare مجاني)</h1>"
            f'<p>إصدار <span dir="ltr">{meta["generated_at"][:10]}</span> · {len(cves)} CVE</p>'
            f"<table><tr><th>CVE</th><th>CVSS</th></tr>{rows}</table></body></html>"
        )

    def _render_min_en(self, cves, meta):
        rows = "".join(
            f"<tr><td><b>{c['id']}</b></td><td>{c.get('severity')}</td><td>{c.get('cvss')}</td>"
            f"<td>{'★KEV' if c.get('kev') else ''}</td></tr>" for c in cves
        )
        return f"""<!DOCTYPE html><html lang="en" dir="ltr"><head><meta charset="utf-8"><title>OT Watch EN</title>
<style>body{{font-family:system-ui;max-width:960px;margin:auto;padding:24px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:6px;font-size:13px}}</style></head>
<body><h1>🛰 OT Watch — English edition (Cloudflare free)</h1>
<p>Edition {meta['generated_at'][:10]} · {len(cves)} CVE · <a href="/api/data">/api/data</a> · <a href="/issue.ar">العربية</a> · <a href="/">FR</a></p>
<table><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>KEV</th></tr>{rows}</table></body></html>"""
