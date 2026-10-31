"""OT Watch — pipeline d'agents IA éditoriaux (roadmap « plateforme de référence », 01/11/2026).

Chaîne : analyste RAG (brief structuré depuis data/*.json + SQLite, citations primaires)
  -> rédacteur (article FR, chaque fait cité [n] ; moteur LLM optionnel via OTWATCH_LLM_CMD,
     sinon rendu déterministe à partir de données structurées = journalisme de données vérifiées,
     quasi zéro hallucination)
  -> fact-checker 3 niveaux (auto contre data/, web-vérification à faire, revue humaine)
  -> illustrateur (SVG 100 % data-driven depuis les données = visuels factuels ; images IA
     possibles mais signées C2PA + légende obligatoire)
  -> éditeur humain (gate HITL : publication uniquement après revue + fichier .approved)
Conformité AI Act Art. 50 (en vigueur depuis 02/08/2026) : divulgation « assisté par IA,
revu par un humain » ; aucun deepfake produit. Voir research/REFERENCE-OT-WATCH-2026-11-01.md §4.
"""
