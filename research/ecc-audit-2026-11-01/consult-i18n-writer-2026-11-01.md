# Consultations ECC v2.2.3 — 2026-11-01 ~21:24 (target claude)

## 1) Bonnes pratiques HTML arabe RTL 2026 en iframe sandbox + édition EN en parallèle
Query : "best practices 2026 Arabic RTL HTML in sandboxed iframes + EN edition alongside FR"
Recommandations : `locale:ar`, skill:coding-standards, capability:agentic.
Points retenus et appliqués (v1.17) :
- `lang="ar" dir="rtl"` sur <html> ; polices système uniquement (pas de ressource externe en iframe sandbox)
  -> pile `'Noto Naskh Arabic','Segoe UI',Tahoma,Arial,sans-serif`, line-height 1.6, pas d'italique ;
- isolation bidi des contenus latins (IDs CVE, dates, CVSS, chiffres, URLs) : `<bdi>` + `dir="ltr"`,
  descriptions embarquées en `dir="auto"` ; les chiffres restent LTR même en contexte RTL ;
- édition EN ajoutée en parallèle : `lang="en" dir="ltr"`, route `/issue.en` (serveur + worker).

Sources web 2026-11-01 : checklist RTL (dir/lang sur <html>, dir="ltr" sur codes/tél/URL, <bdi> pour
contenu incontrôlé, chiffres jamais mirrorés), guides UAE 2026 (wrap en <bdi> corrige l'ordre des
numéros, polices écran arabes, line-height >= 1.5, zéro letter-spacing), W3C : direction de base
posée sur l'élément html.

## 2) Amélioration agent rédacteur LLM 2026 : data-grounded, anti-hallucination, citations, fallback déterministe, guide de style, HITL
Query : "improve LLM writer agent 2026 : data-grounded from structured CVE/KEV/advisory, anti-hallucination, citations, deterministic fallback, style guide, HITL fact-check"
Recommandations : capability:content, capability:agentic, capability:machine-learning, documentation-governance, operator-desk-patterns.
Appliqué (v1.17) dans agents/writer.py + agents/rag.py :
- brief RAG enrichi : ot_score, ot_score_detail (base/facteurs/bonus/assets), asset_impact, ssvc_detail, vector, cwes, new_kev_facts ;
- structure éditoriale fixe (chapeau -> 30 secondes -> priorités -> impact OT -> actions -> méthodologie) ;
- section « Pourquoi cela compte pour l'OT / Why this matters for OT » 100 % calculée depuis les données (KEV, SSVC, actifs, niveaux Purdue, ATT&CK for ICS, score OT) ;
- anti-hallucination : fallback déterministe par défaut, LLM optionnel (OTWATCH_LLM_CMD) toujours re-vérifié par fact-checker 3 niveaux, dédup des descriptions, citations [n] ;
- support lang fr/en (article.md + article.en.md dans le brouillon), divulgation AI Act art. 50 dans les deux langues ;
- HITL inchangé : gate publish exige .approved + fact-check OK.
