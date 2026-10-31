#!/usr/bin/env python3
"""
OT Watch — alerting.
Déclenché à chaque collecte (cron OU bouton /api/refresh) quand des nouveautés
critiques apparaissent : nouvelles CVE CRITICAL / ★KEV / risque >= seuil, nouveau KEV.
Destinations (via variables d'env, jamais en dur) :
  OTWATCH_WEBHOOK_URL      -> POST JSON générique
  OTWATCH_SLACK_WEBHOOK    -> POST format Slack {"text": ...}
  OTWATCH_SMTP_HOST/PORT/USER/PASS/FROM/TO (+OTWATCH_SMTP_SSL=1) -> e-mail
Sans destination configurée -> dry-run : l'alerte est uniquement loguée (logs/alerts.jsonl).
"""
import json
import os
import smtplib
import urllib.request
from datetime import UTC, datetime
from email.message import EmailMessage

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS = os.path.join(ROOT, "logs")
os.makedirs(LOGS, exist_ok=True)

with open(os.path.join(ROOT, "config.json"), encoding="utf-8") as _fh:
    CFG = json.load(_fh)


def _rules():
    return CFG.get("alerts", {}).get("rules", {"new_critical": True, "new_kev": True, "min_risk": 7.0})


def build_alert(meta, cves):
    """Construit l'alerte si des nouveautés remplissent les règles. Sinon None."""
    rules = _rules()
    diff = meta.get("diff", {})
    by_id = {c["id"]: c for c in cves}
    critical = []
    for cid in diff.get("new_cves", []):
        c = by_id.get(cid)
        if not c:
            continue
        if c.get("severity") == "CRITICAL" or c.get("kev") or (c.get("risk") or 0) >= rules.get("min_risk", 7.0):
            critical.append({
                "id": c["id"], "cvss": c.get("cvss"), "risk": c.get("risk"),
                "epss": c.get("epss"), "kev": bool(c.get("kev")),
                "severity": c.get("severity"), "published": c.get("published"),
                "description": (c.get("description") or "")[:240],
            })
    new_kev = diff.get("new_kev", []) if rules.get("new_kev", True) else []
    if not critical and not new_kev:
        return None
    return {
        "type": "otwatch_alert",
        "at": datetime.now(UTC).isoformat(),
        "generated_at": meta.get("generated_at"),
        "new_critical": critical,
        "new_kev": new_kev,
        "new_advisories": diff.get("new_advisories", []),
        "counts": meta.get("counts", {}),
    }


def _post_json(url, payload, timeout=15):
    req = urllib.request.Request(
        url, data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "ot-watch/1.1"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status


def format_slack(alert):
    lines = [f"🚨 *OT Watch* — {len(alert['new_critical'])} nouvelle(s) CVE critique/KEV (collecte {alert['generated_at']})"]
    for c in alert["new_critical"][:10]:
        kev = " ★KEV" if c["kev"] else ""
        lines.append(f"• `{c['id']}`{kev} CVSS {c['cvss']} · risque {c['risk']} · EPSS {c['epss']} — {(c['description'] or '')[:120]}")
    if alert["new_kev"]:
        lines.append(f"• 🆕 {len(alert['new_kev'])} nouvelle(s) entrée(s) KEV OT : {', '.join(alert['new_kev'][:8])}")
    return "\n".join(lines)


def _send_email(alert):
    host = os.environ.get("OTWATCH_SMTP_HOST")
    port = int(os.environ.get("OTWATCH_SMTP_PORT", "587"))
    user = os.environ.get("OTWATCH_SMTP_USER", "")
    password = os.environ.get("OTWATCH_SMTP_PASS", "")
    frm = os.environ.get("OTWATCH_SMTP_FROM", "otwatch@localhost")
    to = os.environ.get("OTWATCH_SMTP_TO", "")
    if not (host and to):
        return None
    msg = EmailMessage()
    msg["Subject"] = f"[OT Watch] 🚨 {len(alert['new_critical'])} nouvelle(s) CVE critique/KEV"
    msg["From"] = frm
    msg["To"] = to
    msg.set_content(format_slack(alert).replace("*", ""))
    if os.environ.get("OTWATCH_SMTP_SSL", "0") == "1":
        with smtplib.SMTP_SSL(host, port, timeout=20) as s:
            if user:
                s.login(user, password)
            s.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=20) as s:
            s.starttls()
            if user:
                s.login(user, password)
            s.send_message(msg)
    return 250


def send_alert(alert):
    """Logue toujours (JSONL) puis envoie vers les destinations configurées. Retourne les statuts."""
    with open(os.path.join(LOGS, "alerts.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps(alert, ensure_ascii=False) + "\n")
    wh = os.environ.get("OTWATCH_WEBHOOK_URL")
    sl = os.environ.get("OTWATCH_SLACK_WEBHOOK")
    smtp_host = os.environ.get("OTWATCH_SMTP_HOST")
    dry = not (wh or sl or smtp_host)  # aucune destination -> dry-run (log seul)
    results = {"dry_run": dry, "webhook": None, "slack": None, "email": None}
    if dry:
        return results
    if wh:
        results["webhook"] = _post_json(wh, alert)
    if sl:
        results["slack"] = _post_json(sl, {"text": format_slack(alert)})
    if smtp_host:
        results["email"] = _send_email(alert)
    return results


def dispatch(meta, cves):
    """Point d'entrée appelé par collect.main() après chaque collecte réussie."""
    try:
        alert = build_alert(meta, cves)
        if alert:
            res = send_alert(alert)
            print(f"[alerts] alerte envoyée: {len(alert['new_critical'])} CVE critiques/KEV, {len(alert['new_kev'])} KEV -> {res}", flush=True)
    except Exception as e:
        print(f"[alerts] erreur (non bloquante): {e}", flush=True)
