#!/usr/bin/env python3
"""Importe la roadmap OT Watch (research/plans/PLATFORM-IMPROVEMENTS-*.md) dans Linear.

Dry-run par défaut : affiche les issues qui seraient créées, sans réseau.
Mode réel : --apply avec LINEAR_API_KEY et LINEAR_TEAM_ID en variables d'environnement.
Idempotent : les titres déjà présents dans l'équipe sont ignorés.
Priorités Linear : P0 -> 1 (Urgent), P1 -> 2 (High), P2 -> 3 (Medium).
Plan Free Linear : 250 issues max par workspace -> on refuse d'en créer au-delà de --max.
"""
import argparse
import glob
import json
import os
import re
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API_URL = "https://api.linear.app/graphql"
PRIORITY = {"P0": 1, "P1": 2, "P2": 3}
ITEM_RE = re.compile(r"^- \*\*(P[0-2]) · (.+?)\*\*\s*:?\s*(.*)$")
SECTION_RE = re.compile(r"^## (.+)$")
TIMEOUT_S = 20


def default_roadmap():
    files = sorted(glob.glob(os.path.join(ROOT, "research", "plans", "PLATFORM-IMPROVEMENTS-*.md")))
    return files[-1] if files else None


def parse_roadmap(text):
    """Retourne [{title, priority, label, description}] depuis le markdown de la roadmap."""
    items, section = [], ""
    for line in text.splitlines():
        sec = SECTION_RE.match(line)
        if sec:
            section = sec.group(1).strip()
            continue
        m = ITEM_RE.match(line.strip())
        if not m:
            continue
        prio, title, desc = m.groups()
        items.append({
            "title": f"[{prio}] {title.strip()}"[:250],
            "priority": PRIORITY[prio],
            "label": section,
            "description": f"{desc.strip()}\n\n_Section roadmap : {section}_",
        })
    return items


def _gql(api_key, query, variables=None):
    body = json.dumps({"query": query, "variables": variables or {}}).encode()
    req = urllib.request.Request(API_URL, data=body, method="POST", headers={
        "Content-Type": "application/json", "Authorization": api_key})
    with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
        data = json.load(resp)
    if data.get("errors"):
        raise RuntimeError(f"Linear API : {data['errors'][0].get('message', data['errors'])}")
    return data["data"]


def existing_titles(api_key, team_id):
    q = "query($id:String!){ team(id:$id){ issues(first:250){ nodes{ title } } } }"
    nodes = _gql(api_key, q, {"id": team_id})["team"]["issues"]["nodes"]
    return {n["title"] for n in nodes}


def create_issue(api_key, team_id, item):
    q = ("mutation($input: IssueCreateInput!){ issueCreate(input:$input){ success issue{ identifier url } } }")
    inp = {"teamId": team_id, "title": item["title"], "description": item["description"],
           "priority": item["priority"]}
    return _gql(api_key, q, {"input": inp})["issueCreate"]


def main(argv=None, environ=None):
    environ = os.environ if environ is None else environ
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--roadmap", default=default_roadmap())
    ap.add_argument("--apply", action="store_true", help="crée réellement les issues (sinon dry-run)")
    ap.add_argument("--only", choices=sorted(PRIORITY), help="n'importer qu'une priorité")
    ap.add_argument("--max", type=int, default=200, help="plafond d'issues créées (plan Free : 250)")
    args = ap.parse_args(argv)

    if not args.roadmap or not os.path.exists(args.roadmap):
        print("erreur : roadmap introuvable", file=sys.stderr)
        return 1
    with open(args.roadmap, encoding="utf-8") as fh:
        items = parse_roadmap(fh.read())
    if args.only:
        items = [i for i in items if i["title"].startswith(f"[{args.only}]")]
    if len(items) > args.max:
        print(f"erreur : {len(items)} issues > plafond --max {args.max}", file=sys.stderr)
        return 1

    if not args.apply:
        for it in items:
            print(f"[dry-run] prio={it['priority']} {it['title']}")
        print(f"[dry-run] {len(items)} issue(s) — relancez avec --apply pour créer.")
        return 0

    api_key, team_id = environ.get("LINEAR_API_KEY"), environ.get("LINEAR_TEAM_ID")
    if not api_key or not team_id:
        print("erreur : LINEAR_API_KEY et LINEAR_TEAM_ID requis en variables d'environnement", file=sys.stderr)
        return 1
    seen = existing_titles(api_key, team_id)
    created = 0
    for it in items:
        if it["title"] in seen:
            print(f"= déjà présent : {it['title']}")
            continue
        res = create_issue(api_key, team_id, it)
        if res.get("success"):
            created += 1
            print(f"+ {res['issue']['identifier']} {it['title']}")
    print(f"{created} issue(s) créée(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
