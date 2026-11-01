// OT Watch — Cron Trigger Cloudflare qui relance la publication GitHub Pages.
// Toutes les 6 h, il appelle l'API GitHub "workflow_dispatch" sur .github/workflows/pages.yml.
// La collecte Python tourne sur GitHub Actions ; ce Worker ne fait qu'un appel HTTP.
//
// Secret requis (jamais dans le code) : GITHUB_TOKEN = fine-grained token limité au dépôt
// O-alil-lab/ot-watch, permission "Actions: Read and write" uniquement.

const REPO = "O-alil-lab/ot-watch";
const WORKFLOW = "pages.yml";
const REF = "main";

async function dispatch(env) {
  if (!env.GITHUB_TOKEN) throw new Error("secret GITHUB_TOKEN manquant");
  const res = await fetch(
    `https://api.github.com/repos/${REPO}/actions/workflows/${WORKFLOW}/dispatches`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.GITHUB_TOKEN}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "ot-watch-cron-worker",
      },
      body: JSON.stringify({ ref: REF }),
    },
  );
  if (res.status !== 204) {
    throw new Error(`GitHub a répondu ${res.status} : ${(await res.text()).slice(0, 200)}`);
  }
  return res.status;
}

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(dispatch(env).then(
      (s) => console.log(`[ot-watch] workflow ${WORKFLOW} relancé (${s}) — cron ${event.cron}`),
      (e) => console.error(`[ot-watch] échec : ${e.message}`),
    ));
  },
  // GET / : état simple, sans déclencher quoi que ce soit (pas d'appel public au dispatch)
  async fetch() {
    return new Response(JSON.stringify({ worker: "ot-watch-cron", repo: REPO, workflow: WORKFLOW, schedule: "17 */6 * * *" }), {
      headers: { "content-type": "application/json" },
    });
  },
};
