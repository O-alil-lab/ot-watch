#!/usr/bin/env python3
"""Agent Rédacteur : transforme le brief de l'analyste en article FR, chaque fait cité [n].

Deux moteurs :
  - déterministe (défaut) : rendu à partir de données structurées vérifiées -> journalisme de
    données à quasi zéro hallucination (modèle AP 2026) ;
  - LLM optionnel : si OTWATCH_LLM_CMD est défini (commande recevant le brief JSON sur stdin),
    sa sortie est utilisée comme corps, MAIS toujours re-vérifiée ensuite par le fact-checker.
Le brouillon porte toujours la divulgation AI Act Art. 50 (assisté par IA, revu par un humain).
"""
import json
import os
import subprocess

DISCLOSURE = ("Rédaction assistée par IA à partir de données structurées vérifiées "
              "(CISA/NVD/KEV/FIRST EPSS), fact-checking automatisé en 3 niveaux, puis "
              "**revue éditoriale humaine obligatoire avant publication** (AI Act, art. 50  -  "
              "exemption de labelling public-interest car revue humaine avec responsabilité éditoriale).")


def _llm_call(brief, prompt):
    cmd = os.environ.get("OTWATCH_LLM_CMD")
    if not cmd:
        return None
    payload = json.dumps({"brief": brief, "prompt": prompt}, ensure_ascii=False)
    try:
        out = subprocess.run(cmd, shell=True, input=payload, capture_output=True, text=True, timeout=120)  # commande opérateur fournie via env (OTWATCH_LLM_CMD)
        return out.stdout.strip() or None
    except Exception:
        return None


def _fmt_cve(c):
    bits = [f"CVSS {c['cvss']:.1f}" if c.get("cvss") is not None else "CVSS n/a",
            f"risque {c['risk']:.2f}/10" if c.get("risk") is not None else ""]
    if c.get("epss") is not None:
        bits.append(f"EPSS {c['epss']:.3f}")
    if c.get("kev"):
        bits.append("★ KEV (exploitation confirmée)")
    if c.get("ssvc"):
        bits.append(f"SSVC {c['ssvc'].upper()}")
    if c.get("attack_ics"):
        bits.append("ATT&CK for ICS " + ", ".join(c["attack_ics"]))
    if c.get("relevant"):
        bits.append("◆ correspond à votre profil « Mes actifs OT »")
    return " · ".join(b for b in bits if b)


def write_article(brief):
    """Renvoie le brouillon markdown (en-tête editorial/*.md compatible render.py)."""
    counts = brief["counts"]
    top = brief["top_cves"][0] if brief["top_cves"] else None
    trend = brief.get("trends", {})
    delta = trend.get("delta_pct")
    delta_txt = (f"{delta:+.0f} % vs la semaine précédente" if delta is not None else "stable")

    lines = []
    lines.append(f"title: Veille OT/ICS  -  {len(brief.get('top_cves', []))} CVE prioritaires cette fenêtre")
    lines.append("kicker: Brouillon agent IA  -  REVUE HUMAINE REQUISE avant publication")
    lines.append("lead: true")
    lines.append("section: Analyse automatique")
    lines.append("---")
    lines.append("")
    lines.append(f"# Veille OT/ICS  -  fenêtre de {brief.get('window_days', 14)} jours")
    lines.append("")
    if top:
        lines.append(f"**{counts.get('cves', 0)} CVE OT** surveillées, **{counts.get('kev', 0)} entrées KEV OT**, "
                     f"**{counts.get('advisories', 0)} avis CISA ICS** dans la fenêtre. "
                     f"Tendance publications CVE : {delta_txt}. "
                     f"À la une : **{top['id']}** ({_fmt_cve(top)}). [1]")
    else:
        lines.append(f"**{counts.get('cves', 0)} CVE OT** dans la fenêtre, {counts.get('kev', 0)} KEV OT.")
    lines.append("")
    lines.append("## À retenir en 30 secondes")
    for i, c in enumerate(brief["top_cves"][:3], start=1):
        lines.append(f"- **{c['id']}**  -  {_fmt_cve(c)}. [{len(brief['sources']) + i}] {c['description'][:140]}")
    for cid in brief.get("new_kev", [])[:3]:
        lines.append(f"- **Nouveau dans le KEV** : {cid}  -  exploitation confirmée, patch prioritaire. [KEV]")
    lines.append("")
    lines.append("## CVE prioritaires (tri : profil actifs OT, puis risque)")
    for c in brief["top_cves"]:
        lines.append(f"### {c['id']}  -  {_fmt_cve(c)}")
        lines.append(f"{c['description']}")
        lines.append("")
    if brief.get("relevant_cves"):
        lines.append("## ⭐ Vos actifs OT concernés")
        for c in brief["relevant_cves"]:
            lines.append(f"- {c['id']}  -  {_fmt_cve(c)}")
        lines.append("")
    if brief.get("advisories"):
        lines.append("## Avis CISA ICS de la fenêtre")
        for a in brief["advisories"][:8]:
            lines.append(f"- [{a.get('code') or 'ICS'}  -  {a['title']}]({a.get('link') or '#'}) ({a.get('published')})")
        lines.append("")
    lines.append("## Actions recommandées lundi 07:00")
    lines.append("- Patcher d'abord les CVE ★KEV et SSVC `act` sur les actifs exposés (SLA 24-72 h).")
    lines.append("- Vérifier l'exposition réseau (niveau Purdue) des actifs du profil « Mes actifs OT ».")
    lines.append("- Revue des logs des capteurs passifs (alertes ATT&CK for ICS mappées).")
    lines.append("")
    lines.append("## Méthodologie, sources & transparence")
    lines.append(f"{DISCLOSURE}")
    lines.append("Sources primaires : " + " ; ".join(brief.get("sources", [])[:8]))
    lines.append("Illustrations : visuels générés depuis les données collectées (reproductibles, voir out/img/).")
    text = "\n".join(lines) + "\n"

    # moteur LLM optionnel (le fact-checker re-vérifie de toute façon)
    prompt = ("Rédige en français un article de veille OT/ICS à partir du brief JSON fourni. "
              "Chaque fait doit rester strictement fidèle au brief (CVE, scores, KEV, SSVC, ATT&CK). "
              "N'invente aucun CVE, score, date ou acteur. Ajoute les citations [n].")
    llm = _llm_call(brief, prompt)
    if llm and "CVE-" in llm:
        text = text + "\n\n<!-- version LLM -->\n" + llm + "\n"
    return text
