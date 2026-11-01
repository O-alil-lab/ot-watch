#!/usr/bin/env python3
"""Agent Rédacteur : transforme le brief de l'analyste en article (FR par défaut, EN via lang="en").

Règles éditoriales (recommandations ECC 2026-11-01, capability:content + capability:agentic) :
  - rédaction strictement « data-grounded » : chaque fait provient du brief (graphe de faits
    vérifiés) et porte sa citation [n] ; aucune invention de CVE, score, date, acteur ou chiffre ;
  - structure fixe et scannable : chapeau -> « en 30 secondes » -> analyse -> impact OT -> actions ;
  - section « impact OT » calculée depuis les données (ot_score_detail, actifs touchés, KEV,
    SSVC, ATT&CK for ICS) — jamais rédigée à la main sans données ;
  - fallback déterministe par défaut (quasi zéro hallucination, style AP 2026) ; moteur LLM
    optionnel (OTWATCH_LLM_CMD) dont la sortie est TOUJOURS re-vérifiée par le fact-checker ;
  - divulgation AI Act art. 50 + revue humaine obligatoire (HITL) avant publication.
"""
import json
import os
import subprocess

DISCLOSURE = {
    "fr": ("Rédaction assistée par IA à partir de données structurées vérifiées "
           "(CISA/NVD/KEV/FIRST EPSS), fact-checking automatisé en 3 niveaux, puis "
           "**revue éditoriale humaine obligatoire avant publication** (AI Act, art. 50 — "
           "exemption de labelling public-interest car revue humaine avec responsabilité éditoriale)."),
    "en": ("AI-assisted writing from verified structured data (CISA/NVD/KEV/FIRST EPSS), "
           "3-level automated fact-checking, then **mandatory human editorial review before "
           "publication** (EU AI Act, art. 50 — public-interest labelling exemption because of "
           "human review with editorial responsibility)."),
}

STYLE_GUIDE = {
    "fr": ("Style : phrases courtes, voix active, chiffres en tête de phrase quand pertinent, "
           "un seul chiffre clé par paragraphe, titres de section en question ou en impératif d'action."),
    "en": ("Style: short sentences, active voice, key figures up front, one key figure per "
           "paragraph, section titles as questions or action imperatives."),
}

_STR = {
    "fr": {
        "title": "Veille OT/ICS",
        "kicker": "Brouillon agent IA — REVUE HUMAINE REQUISE avant publication",
        "lead_hdr": "À retenir en 30 secondes",
        "prio_hdr": "CVE prioritaires (tri : profil actifs OT, puis risque)",
        "assets_hdr": "⭐ Vos actifs OT concernés",
        "adv_hdr": "Avis CISA ICS de la fenêtre",
        "actions_hdr": "Actions recommandées lundi 07:00",
        "ot_impact_hdr": "Pourquoi cela compte pour l'OT",
        "method_hdr": "Méthodologie, sources & transparence",
        "new_kev": "Nouveau dans le KEV",
        "window": "fenêtre de",
        "days": "jours",
        "cves": "CVE OT",
        "kev_ot": "entrées KEV OT",
        "adv": "avis CISA ICS",
        "trend": "Tendance publications CVE",
        "vs_prev": "vs la semaine précédente",
        "stable": "stable",
        "a_la_une": "À la une",
        "patch_first": "- Patcher d'abord les CVE ★KEV et SSVC `act` sur les actifs exposés (SLA 24-72 h).",
        "check_expo": "- Vérifier l'exposition réseau (niveau Purdue) des actifs du profil « Mes actifs OT ».",
        "check_logs": "- Revue des logs des capteurs passifs (alertes ATT&CK for ICS mappées).",
        "sources": "Sources primaires",
        "illus": "Illustrations : visuels générés depuis les données collectées (reproductibles, voir out/img/).",
        "risk": "risque",
        "kev_tag": "★ KEV (exploitation confirmée)",
        "asset_tag": "◆ correspond à votre profil « Mes actifs OT »",
        "ot_line_kev": "exploitation confirmée dans la nature (CISA KEV)",
        "ot_line_ssvc": "décision SSVC « {v} » (priorité d'action CISA)",
        "ot_line_assets": "actifs de votre profil touchés : {a}",
        "ot_line_purdue": "niveaux Purdue concernés : {l}",
        "ot_line_attck": "techniques ATT&CK for ICS associées : {t}",
        "ot_line_score": "score OT {s}/10 (base CVSS/EPSS {b} x facteur actifs {f}, bonus KEV {k}, bonus SSVC {sv})",
        "ot_line_none": "aucun actif de votre profil n'est directement ciblé, mais la surface OT reste concernée",
        "llm_prompt": ("Rédige en français un article de veille OT/ICS à partir du brief JSON fourni. "
                       "Chaque fait doit rester strictement fidèle au brief (CVE, scores, KEV, SSVC, ATT&CK). "
                       "N'invente aucun CVE, score, date ou acteur. Ajoute les citations [n]."),
        "llm_comment": "<!-- version LLM -->",
    },
    "en": {
        "title": "OT/ICS Threat Watch",
        "kicker": "AI agent draft — HUMAN REVIEW REQUIRED before publication",
        "lead_hdr": "Key takeaways in 30 seconds",
        "prio_hdr": "Priority CVEs (sort: OT asset profile, then risk)",
        "assets_hdr": "⭐ Your OT assets affected",
        "adv_hdr": "CISA ICS advisories this window",
        "actions_hdr": "Recommended actions Monday 07:00",
        "ot_impact_hdr": "Why this matters for OT",
        "method_hdr": "Methodology, sources & transparency",
        "new_kev": "New to the KEV",
        "window": "window of",
        "days": "days",
        "cves": "OT CVEs",
        "kev_ot": "OT KEV entries",
        "adv": "CISA ICS advisories",
        "trend": "CVE publication trend",
        "vs_prev": "vs previous week",
        "stable": "stable",
        "a_la_une": "Top story",
        "patch_first": "- Patch ★KEV CVEs and SSVC `act` on exposed assets first (SLA 24-72 h).",
        "check_expo": "- Check network exposure (Purdue level) of the assets in the 'My OT assets' profile.",
        "check_logs": "- Review passive sensor logs (mapped ATT&CK for ICS alerts).",
        "sources": "Primary sources",
        "illus": "Illustrations: visuals generated from the collected data (reproducible, see out/img/).",
        "risk": "risk",
        "kev_tag": "★ KEV (confirmed exploitation)",
        "asset_tag": "◆ matches your 'My OT assets' profile",
        "ot_line_kev": "confirmed exploitation in the wild (CISA KEV)",
        "ot_line_ssvc": "SSVC decision '{v}' (CISA action priority)",
        "ot_line_assets": "assets from your profile affected: {a}",
        "ot_line_purdue": "Purdue levels affected: {l}",
        "ot_line_attck": "associated ATT&CK for ICS techniques: {t}",
        "ot_line_score": "OT score {s}/10 (CVSS/EPSS base {b} x asset factor {f}, KEV bonus {k}, SSVC bonus {sv})",
        "ot_line_none": "no asset in your profile is directly targeted, but the OT attack surface remains relevant",
        "llm_prompt": ("Write in English an OT/ICS threat-watch article from the provided JSON brief. "
                       "Every fact must stay strictly faithful to the brief (CVEs, scores, KEV, SSVC, ATT&CK). "
                       "Do not invent any CVE, score, date or actor. Add [n] citations."),
        "llm_comment": "<!-- LLM version -->",
    },
}


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


def _fmt_cve(c, T):
    bits = [f"CVSS {c['cvss']:.1f}" if c.get("cvss") is not None else "CVSS n/a",
            f"{T['risk']} {c['risk']:.2f}/10" if c.get("risk") is not None else ""]
    if c.get("epss") is not None:
        bits.append(f"EPSS {c['epss']:.3f}")
    if c.get("kev"):
        bits.append(T["kev_tag"])
    if c.get("ssvc"):
        bits.append(f"SSVC {c['ssvc'].upper()}")
    if c.get("attack_ics"):
        bits.append("ATT&CK for ICS " + ", ".join(c["attack_ics"]))
    if c.get("relevant"):
        bits.append(T["asset_tag"])
    return " · ".join(b for b in bits if b)


def _ot_impact_lines(c, T):
    """Section 'impact OT' 100 % calculée depuis les données du brief — aucune rédaction libre."""
    lines = []
    d = c.get("ot_score_detail") or {}
    assets = c.get("asset_impact") or []
    if c.get("kev"):
        lines.append(f"- {T['ot_line_kev']}.")
    if c.get("ssvc"):
        lines.append(f"- {T['ot_line_ssvc'].format(v=c['ssvc'].upper())}.")
    if assets:
        lines.append(f"- {T['ot_line_assets'].format(a=', '.join(assets))}.")
        levels = sorted({a.get("purdue_level") for a in d.get("assets", []) if isinstance(a, dict) and a.get("purdue_level")})
        if levels:
            lines.append(f"- {T['ot_line_purdue'].format(l=', '.join(levels))}.")
    if c.get("attack_ics"):
        lines.append(f"- {T['ot_line_attck'].format(t=', '.join(c['attack_ics']))}.")
    if c.get("ot_score") is not None:
        score_txt = T["ot_line_score"].format(
            s="{:.1f}".format(c["ot_score"]), b=d.get("base", "n/a"),
            f=d.get("asset_factor", 1.0), k=d.get("kev_bonus", 0.0), sv=d.get("ssvc_bonus", 0.0))
        lines.append(f"- {score_txt}.")
    if not lines:
        lines.append(f"- {T['ot_line_none']}.")
    return lines


def write_article(brief, lang="fr"):
    """Renvoie le brouillon markdown (en-tête editorial/*.md compatible render.py). lang: fr|en."""
    lang = lang if lang in _STR else "fr"
    T = _STR[lang]
    counts = brief["counts"]
    top = brief["top_cves"][0] if brief["top_cves"] else None
    trend = brief.get("trends", {})
    delta = trend.get("delta_pct")
    delta_txt = (f"{delta:+.0f} % {T['vs_prev']}" if delta is not None else T["stable"])

    lines = []
    lines.append(f"title: {T['title']} — {len(brief.get('top_cves', []))} CVE prioritaires cette fenêtre" if lang == "fr"
                 else f"title: {T['title']} — {len(brief.get('top_cves', []))} priority CVEs this window")
    lines.append(f"kicker: {T['kicker']}")
    lines.append("lead: true")
    lines.append("section: Analyse automatique" if lang == "fr" else "section: Automated analysis")
    lines.append("---")
    lines.append("")
    lines.append(f"# {T['title']} — {T['window']} {brief.get('window_days', 14)} {T['days']}")
    lines.append("")
    if top:
        lines.append(f"**{counts.get('cves', 0)} {T['cves']}**, **{counts.get('kev', 0)} {T['kev_ot']}**, "
                     f"**{counts.get('advisories', 0)} {T['adv']}** {T['window']} {brief.get('window_days', 14)} {T['days']}. "
                     f"{T['trend']} : {delta_txt}. "
                     f"{T['a_la_une']} : **{top['id']}** ({_fmt_cve(top, T)}). [1]")
    else:
        lines.append(f"**{counts.get('cves', 0)} {T['cves']}** {T['window']} {brief.get('window_days', 14)} {T['days']}, "
                     f"{counts.get('kev', 0)} {T['kev_ot']}.")
    lines.append("")
    lines.append(f"## {T['lead_hdr']}")
    seen_desc = set()
    for i, c in enumerate(brief["top_cves"][:3], start=1):
        desc = (c.get("description") or "")[:140]
        if desc in seen_desc:  # déduplication des descriptions identiques
            desc = ""
        seen_desc.add(c.get("description") or "")
        lines.append(f"- **{c['id']}** — {_fmt_cve(c, T)}. [{len(brief['sources']) + i}] {desc}")
    for c in brief.get("new_kev_facts", [])[:3] or []:
        lines.append(f"- **{T['new_kev']}** : {c['id']} — {_fmt_cve(c, T)}. [KEV]")
    for cid in brief.get("new_kev", [])[:3]:
        if cid not in {c.get("id") for c in brief.get("new_kev_facts", [])}:
            lines.append(f"- **{T['new_kev']}** : {cid} — exploitation confirmée, patch prioritaire. [KEV]" if lang == "fr"
                         else f"- **{T['new_kev']}** : {cid} — confirmed exploitation, patch first. [KEV]")
    lines.append("")
    lines.append(f"## {T['prio_hdr']}")
    for c in brief["top_cves"]:
        lines.append(f"### {c['id']} — {_fmt_cve(c, T)}")
        lines.append("")
        lines.append(f"#### {T['ot_impact_hdr']}")
        lines.extend(_ot_impact_lines(c, T))
        lines.append("")
        lines.append(c.get("description") or "")
        lines.append("")
    if brief.get("relevant_cves"):
        lines.append(f"## {T['assets_hdr']}")
        for c in brief["relevant_cves"]:
            lines.append(f"- {c['id']} — {_fmt_cve(c, T)}")
        lines.append("")
    if brief.get("advisories"):
        lines.append(f"## {T['adv_hdr']}")
        for a in brief["advisories"][:8]:
            lines.append(f"- [{a.get('code') or 'ICS'} — {a['title']}]({a.get('link') or '#'}) ({a.get('published')})")
        lines.append("")
    lines.append(f"## {T['actions_hdr']}")
    lines.append(T["patch_first"])
    lines.append(T["check_expo"])
    lines.append(T["check_logs"])
    lines.append("")
    lines.append(f"## {T['method_hdr']}")
    lines.append(STYLE_GUIDE[lang])
    lines.append(DISCLOSURE[lang])
    lines.append(f"{T['sources']} : " + " ; ".join(brief.get("sources", [])[:8]))
    lines.append(T["illus"])
    text = "\n".join(lines) + "\n"

    # moteur LLM optionnel (le fact-checker re-vérifie de toute façon)
    llm = _llm_call(brief, T["llm_prompt"])
    if llm and "CVE-" in llm:
        text = text + f"\n\n{T['llm_comment']}\n" + llm + "\n"
    return text
