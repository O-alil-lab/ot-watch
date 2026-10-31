#!/usr/bin/env python3
"""Orchestrateur du pipeline agents IA éditoriaux (HITL obligatoire).

Usage :
  python3 -m agents.pipeline draft            # produit out/drafts/draft-<date>/ (brief, article, factcheck, img/)
  python3 -m agents.pipeline status           # dernier brouillon + statut fact-check
  python3 -m agents.pipeline publish <draft> --reviewer "Nom"   # gate HITL : exige draft-<date>.approved

Gate de publication (human-in-the-loop) : publish échoue si
  - le fact-checker a des failures (niveau 1), OU
  - le fichier <draft>.approved (contenant le nom du relecteur) est absent.
La publication copie l'article dans editorial/auto-<date>.md (pris en compte par render.py)
et écrit une ligne d'audit dans logs/agents.jsonl (HOTL : audit après coup).
"""
import argparse
import json
import os
import shutil
import sys
from datetime import UTC, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "src"))

from agents import factcheck, images, rag, writer  # noqa: E402

DATA = os.path.join(ROOT, "data")
DB = os.path.join(DATA, "otwatch.db")
OUT = os.path.join(ROOT, "out")
DRAFTS = os.path.join(OUT, "drafts")
LOGS = os.path.join(ROOT, "logs")
EDITORIAL = os.path.join(ROOT, "editorial")


def _audit(entry):
    os.makedirs(LOGS, exist_ok=True)
    entry["ts"] = datetime.now(UTC).isoformat()
    with open(os.path.join(LOGS, "agents.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def run_draft(date=None, data_dir=DATA, db_path=DB, drafts_dir=DRAFTS):
    date = date or datetime.now(UTC).strftime("%Y-%m-%d")
    brief = rag.build_brief(data_dir, db_path)
    article = writer.write_article(brief)
    report = factcheck.check_draft(article, brief, data_dir)
    ddir = os.path.join(drafts_dir, f"draft-{date}")
    img_dir = os.path.join(ddir, "img")
    os.makedirs(img_dir, exist_ok=True)
    with open(os.path.join(ddir, "brief.json"), "w", encoding="utf-8") as fh:
        json.dump(brief, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(ddir, "article.md"), "w", encoding="utf-8") as fh:
        fh.write(article)
    with open(os.path.join(ddir, "factcheck.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)
    imgs = images.generate_svgs(brief, img_dir)
    with open(os.path.join(ddir, "images.json"), "w", encoding="utf-8") as fh:
        json.dump(imgs, fh, ensure_ascii=False, indent=2)
    _audit({"stage": "draft", "draft": f"draft-{date}", "factcheck_ok": report["ok"],
            "checked": report["checked"], "failed": len(report["failed"]), "images": len(imgs)})
    print(f"[agents] brouillon out/drafts/draft-{date}/ : fact-check {'OK' if report['ok'] else 'KO'} "
          f"({report['passed']}/{report['checked']} vérifiés, {len(report['failed'])} échecs, "
          f"{len(report['human_review'])} points revue humaine) · {len(imgs)} visuels SVG")
    if report["failed"]:
        for f in report["failed"][:10]:
            print("  KO:", f["claim"], "—", f["reason"])
    return ddir, report


def status(drafts_dir=DRAFTS):
    if not os.path.isdir(drafts_dir):
        return None
    names = sorted(d for d in os.listdir(drafts_dir) if d.startswith("draft-"))
    if not names:
        return None
    last = names[-1]
    p = os.path.join(drafts_dir, last, "factcheck.json")
    fc = None
    if os.path.exists(p):
        with open(p, encoding="utf-8") as fh:
            fc = json.load(fh)
    approved = os.path.exists(os.path.join(drafts_dir, last + ".approved"))
    return {"draft": last, "factcheck": fc and {"ok": fc["ok"], "checked": fc["checked"], "failed": len(fc["failed"])},
            "approved": approved, "published": os.path.exists(os.path.join(EDITORIAL, f"auto-{last[6:]}.md"))}


def publish(draft, reviewer, drafts_dir=DRAFTS, editorial_dir=EDITORIAL):
    """Gate HITL : fact-check OK + fichier <draft>.approved requis."""
    ddir = os.path.join(drafts_dir, draft)
    fc_path = os.path.join(ddir, "factcheck.json")
    if not os.path.exists(fc_path):
        raise SystemExit(f"[agents] publish refusé : pas de factcheck pour {draft}")
    with open(fc_path, encoding="utf-8") as fh:
        fc = json.load(fh)
    if not fc.get("ok"):
        raise SystemExit(f"[agents] publish refusé : fact-check KO ({len(fc['failed'])} échecs) — corrige d'abord")
    appr = os.path.join(drafts_dir, draft + ".approved")
    if not os.path.exists(appr):
        raise SystemExit(f"[agents] publish refusé (HITL) : crée {draft}.approved avec le nom du relecteur humain")
    with open(appr, encoding="utf-8") as fh:
        reviewer_file = fh.read().strip() or reviewer
    date = draft[6:]
    os.makedirs(editorial_dir, exist_ok=True)
    dest = os.path.join(editorial_dir, f"auto-{date}.md")
    shutil.copyfile(os.path.join(ddir, "article.md"), dest)
    _audit({"stage": "publish", "draft": draft, "reviewer": reviewer_file, "dest": dest})
    print(f"[agents] publié -> {dest} (relecteur : {reviewer_file}) — pris en compte à la prochaine édition")
    return dest


def main():
    ap = argparse.ArgumentParser(prog="agents.pipeline")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("draft").add_argument("--date", default=None)
    sub.add_parser("status")
    pp = sub.add_parser("publish")
    pp.add_argument("draft")
    pp.add_argument("--reviewer", default="")
    args = ap.parse_args()
    if args.cmd == "draft":
        run_draft(date=args.date)
    elif args.cmd == "status":
        print(json.dumps(status(), ensure_ascii=False, indent=2))
    elif args.cmd == "publish":
        publish(args.draft, args.reviewer)


if __name__ == "__main__":
    main()
