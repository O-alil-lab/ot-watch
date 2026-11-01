#!/usr/bin/env python3
"""
Importe la roadmap OT Watch (research/plans/PLATFORM-IMPROVEMENTS-2026-10-31.md)
dans Linear via l'API GraphQL — 100 % gratuit (intégration GitHub incluse en Free).

  - Dry-run par défaut : imprime les mutations GraphQL sans rien appeler.
  - Réel : LINEAR_API_KEY + LINEAR_TEAM_ID en env (clé perso Linear, header
    Authorization sans préfixe « Bearer »), option --apply.

Usage :
  python3 scripts/linear_import.py                 # dry-run (recommandé d'abord)
  LINEAR_API_KEY=lin_api_... LINEAR_TEAM_ID=... python3 scripts/linear_import.py --apply
"""
import argparse
import json
import os
import re
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLANS = os.path.join(ROOT, "research", "plans", "PLATFORM-IMPROVEMENTS-2026-10-31.md")
API = "https://api.linear.app/graphql"

PRIO = {"P0": 1, "P1": 2, "P2": 4}  # Linear: 0 none, 1 urgent, 2 high, 3 medium, 4 low


def parse_items(path=PLANS):
    """Extrait les items '- **P0/P1/P2 · …** : description' du plan -> [{prio, title, desc, done}]."""
    items = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            m = re.match(r"\s*-\s+\*\*(P[012])[^*]*\*\*\s*:?\s*(.+?)\s*((?:✅|\(fait\)).*)?$", line)
            if m:
                prio, text, done = m.group(1), m.group(2), bool(m.group(3))
                items.append({"prio": prio, "title": text.strip(" :"), "done": done})
    return items


def mutation(item, team_id):
    title = item["title"][:200]
    desc = (f"Priorité {item['prio']} · importé de research/plans/PLATFORM-IMPROVEMENTS-2026-10-31.md"
            + (" · ✅ fait" if item["done"] else ""))
    return {
        "query": "mutation($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id identifier url } } }",
        "variables": {"input": {"teamId": team_id, "title": title, "description": desc,
                                "priority": PRIO.get(item["prio"], 3),
                                "labelIds": []}},
    }


def call(payload, api_key):
    req = urllib.request.Request(
        API, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Authorization": api_key})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="appelle vraiment l'API Linear (sinon dry-run)")
    args = ap.parse_args()

    items = parse_items()
    print(f"[linear_import] {len(items)} items trouvés dans {os.path.relpath(PLANS, ROOT)}")
    key = os.environ.get("LINEAR_API_KEY", "")
    team = os.environ.get("LINEAR_TEAM_ID", "")
    if args.apply and (not key or not team):
        sys.exit("ERREUR: --apply exige LINEAR_API_KEY et LINEAR_TEAM_ID en env")
    for it in items:
        payload = mutation(it, team or "TEAM_ID")
        if not args.apply:
            print(f"[dry-run] {it['prio']} {'✅' if it['done'] else '⬜'} {it['title'][:90]}")
            print("   mutation:", json.dumps(payload, ensure_ascii=False)[:220], "…")
        else:
            res = call(payload, key)
            issue = (res.get("data") or {}).get("issueCreate") or {}
            print(f"[apply] {it['prio']} {it['title'][:60]} -> {issue.get('issue', {}).get('url', res)}")
    if not args.apply:
        print("\n[dry-run] aucune API appelée. Pour appliquer : LINEAR_API_KEY=... LINEAR_TEAM_ID=... python3 scripts/linear_import.py --apply")


if __name__ == "__main__":
    main()
