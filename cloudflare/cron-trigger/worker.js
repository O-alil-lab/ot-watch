// OT Watch — Worker Cloudflare : relance la publication GitHub Pages.
// - cron toutes les 6 h (scheduled) ;
// - POST /refresh depuis le site : collecte à la demande, limitée (pas de doublon, 15 min mini entre deux).
// Secret requis (jamais dans le code) : GITHUB_TOKEN = fine-grained token limité au dépôt
// O-alil-lab/ot-watch, permission "Actions: Read and write" uniquement.

const REPO = "O-alil-lab/ot-watch";
const WORKFLOW = "pages.yml";
const REF = "main";
const SITE_ORIGIN = "https://o-alil-lab.github.io";
const MIN_INTERVAL_MS = 15 * 60 * 1000;

function gh(env, path, init) {
  return fetch("https://api.github.com/repos/" + REPO + "/actions/workflows/" + WORKFLOW + path, Object.assign({
    headers: {
      "Authorization": "Bearer " + env.GITHUB_TOKEN,
      "Accept": "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "ot-watch-cron-worker"
    }
  }, init || {}));
}

async function dispatch(env) {
  if (!env.GITHUB_TOKEN) throw new Error("secret GITHUB_TOKEN manquant");
  const res = await gh(env, "/dispatches", { method: "POST", body: JSON.stringify({ ref: REF }) });
  if (res.status !== 204) throw new Error("GitHub a repondu " + res.status + " : " + (await res.text()).slice(0, 200));
  return res.status;
}

// Refuse si une collecte tourne déjà ou si la dernière a démarré il y a moins de 15 min.
async function busyReason(env, now) {
  const res = await gh(env, "/runs?per_page=1&branch=" + REF);
  if (res.status !== 200) return null;
  const last = ((await res.json()).workflow_runs || [])[0];
  if (!last) return null;
  if (last.status !== "completed") return { code: "running", retry_after_s: 300 };
  const age = now - Date.parse(last.created_at);
  if (age < MIN_INTERVAL_MS) return { code: "too_soon", retry_after_s: Math.ceil((MIN_INTERVAL_MS - age) / 1000) };
  return null;
}

function json(body, status, origin) {
  const h = { "content-type": "application/json", "Vary": "Origin" };
  if (origin === SITE_ORIGIN) h["Access-Control-Allow-Origin"] = SITE_ORIGIN;
  return new Response(JSON.stringify(body), { status: status, headers: h });
}

async function handleRefresh(request, env, now) {
  const origin = request.headers.get("Origin") || "";
  if (origin !== SITE_ORIGIN) return json({ ok: false, error: "origine non autorisee" }, 403, origin);
  if (!env.GITHUB_TOKEN) return json({ ok: false, error: "worker non configure" }, 503, origin);
  const busy = await busyReason(env, now);
  if (busy) return json({ ok: false, error: busy.code, retry_after_s: busy.retry_after_s }, 429, origin);
  await dispatch(env);
  return json({ ok: true, message: "collecte lancee", eta_s: 300 }, 202, origin);
}

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(dispatch(env).then(
      (s) => console.log("[ot-watch] workflow relance (" + s + ") cron " + event.cron),
      (e) => console.error("[ot-watch] echec : " + e.message)
    ));
  },
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";
    if (url.pathname === "/refresh") {
      if (request.method === "OPTIONS") {
        if (origin !== SITE_ORIGIN) return new Response(null, { status: 403 });
        return new Response(null, { status: 204, headers: {
          "Access-Control-Allow-Origin": SITE_ORIGIN,
          "Access-Control-Allow-Methods": "POST",
          "Access-Control-Max-Age": "86400"
        } });
      }
      if (request.method !== "POST") return json({ ok: false, error: "POST uniquement" }, 405, origin);
      try {
        return await handleRefresh(request, env, Date.now());
      } catch (e) {
        console.error("[ot-watch] refresh : " + e.message);
        return json({ ok: false, error: "echec du declenchement" }, 502, origin);
      }
    }
    return json({ worker: "ot-watch-cron", repo: REPO, workflow: WORKFLOW, schedule: "17 */6 * * *", refresh: "POST /refresh" }, 200, origin);
  }
};
