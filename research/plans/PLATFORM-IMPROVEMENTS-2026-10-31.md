# 🚀 Feuille de route d'amélioration — OT Watch (interrogation ECC, 31/10/2026)

Méthode : ECC a été « interrogé » de 3 façons —
1. **Ses outils d'audit** exécutés sur le harnais et la plateforme : `harness-audit.js` (78/80), `observability-readiness.js` (21/21 ✅), `platform-audit.js`, `skills-health.js` (tous stables), `doctor.js` (5/5 OK), AgentShield (0 critical), tests 28/28 OK, couverture 83 %.
2. **Ses agents spécialisés** utilisés comme *lenses de revue* : `security-reviewer`, `performance-optimizer`, `harness-optimizer`, `silent-failure-hunter`, `a11y-architect`, `planner`, `python-reviewer`, `architect`.
3. **Deep-research 2026** (multi-sources) sur les meilleures pratiques des plateformes CTI et des pipelines de données.

Légende : **P0** = à faire cette semaine · **P1** = ce mois-ci · **P2** = ce trimestre · Effort S/M/L.

---

## 1. Sources & couverture des données — P0/P1
- **P0 · NVD par CPE au lieu de regex** : utiliser le dictionnaire CPE officiel de la NVD (`virtualMatchString=cpe:2.3:*:siemens:*:*`) → fini les faux positifs/négatifs du regex `_is_ot`.
- **P0 · Incrémental au lieu de fenêtre fixe** : NVD `lastModStartDate/lastModEndDate`, KEV `lastBuildDate`, RSS `lastBuildDate` → ne récupérer que le delta depuis la dernière collecte (moins de rate-limit, plus rapide).
- **P1 · Plus de sources OT** : CERT-FR/ANSSI (RSS), Siemens ProductCERT, Schneider Electric, Rockwell, ABB, Mitsubishi PSIRT, Dragos/Waterfall, OT-CERT ; option **STIX 2.1/TAXII** (feeds standards) ; flux abuse.ch (ThreatFox/URLhaus) pour les IOC.
- **P1 · Santé par source** : pour chaque source, journaliser succès/latence/erreurs → badge « source OK/dégradée » dans le dashboard (lens `silent-failure-hunter`).
- **P1 · Couche « raw »** : conserver les réponses brutes (`data/raw/<source>/<ts>.json`) → replay, audit, diff entre collectes.

## 2. Qualité des données — P0
- **P0 · Validation schéma à chaque collecte** (data-quality gates) : CVE id match `^CVE-\d{4}-\d{4,}$`, CVSS ∈ [0,10], champs requis non nuls, comptage vs collecte précédente (alerte si -30 % de CVE = source cassée).
- **P0 · Déduplication par clé métier** (id CVE / code avis) avec **lignée multi-sources** (« signalé par NVD + CISA + KEV »).
- **P1 · Schéma versionné** (`schemas/`) + test de non-régression si une source change de format.

## 3. Stockage & historique — P0
- **P0 · SQLite (stdlib `sqlite3`) comme store canonique** : tables `cves`, `advisories`, `kev`, `runs`, avec historique → détecte les **nouvelles CVE depuis la dernière collecte** (base des alertes), tendances, sparklines. Les JSON restent un export pour la newsletter.
- **P1 · Idempotence/replay** : `INSERT OR REPLACE` sur clé CVE, checkpoints par source, rejouable sans doublons.

## 4. Scoring & priorisation — P0/P1
- **P0 · Score de risque composite** : `risk = f(CVSS, KEV, EPSS, âge, pertinence actif)` — **EPSS (FIRST)** en complément du CVSS (probabilité d'exploitation réelle), KEV = priorité max. Tri par défaut sur ce score, pas seulement CVSS.
- **P1 · Profil d'exposition utilisateur** (`config.json` : mes éditeurs/produits OT) → « pertinent pour VOUS » en premier.
- **P1 · Mapping ATT&CK** à partir des CWE/CVE pour la vue tactique.

## 5. Temps réel & fiabilité infra — P1
- **P1 · Push au lieu de polling** : endpoint **SSE (`/api/stream`)** ou WebSocket → le dashboard se met à jour instantanément à la fin d'une collecte.
- **P1 · Circuit breaker par source** : après N échecs, la source passe « degraded » et on sert le cache (KEV/CVE critiques en cache offline — DR).
- **P1 · File d'attente + backoff exponentiel** pour la NVD (déjà amorcé) ; paralléliser les sources indépendantes (threads) avec un token bucket global.
- **P1 · Healthchecks** : `/healthz` (serveur) + statut par source dans `/api/meta`.

## 6. Alerting & notifications — P1
- **P1 · Alertes sur nouveautés** : nouvelle CVE CRITICAL/KEV depuis la dernière collecte → **webhook générique + e-mail + Slack/Teams** (configurable), avec dédup et seuils.
- **P1 · Digest configurable** (quotidien/hebdo, par sévérité).

## 7. Observabilité — P0/P1 (lens harness-optimizer / observability-readiness 21/21 à transposer)
- **P0 · `/metrics` au format Prometheus** : `otwatch_last_success_timestamp`, `otwatch_cves_total`, `otwatch_collect_duration_seconds`, `otwatch_source_errors{source=…}`, `otwatch_data_freshness_seconds`.
- **P0 · Alerte de fraîcheur (SLO)** : si `now - generated_at > 2 × intervalle` → badge « DONNÉES STALES » rouge dans le dashboard + log WARN.
- **P1 · Logs structurés JSONL** (`logs/runs.jsonl`) : run_id, durées par source, nb enregistrements, erreurs — corrélables.

## 8. Sécurité de la plateforme elle-même — P0 (lens security-reviewer + AgentShield)
- **P0 · Authentifier les endpoints admin** : `POST /api/refresh` protégé par token (env `OTWATCH_ADMIN_TOKEN`), lecture seule publique.
- **P0 · En-têtes de sécurité** sur toutes les réponses : `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`.
- **P0 · Rate limiting** sur `/api/refresh` et les API (éviter l'abus), timeouts explicites côté client.
- **P0 · Secrets** : uniquement via env/vault (jamjà en dur) + **pre-commit gitleaks/trufflehog** ; rotation documentée de `NVD_API_KEY`.
- **P1 · `SECURITY.md`** (signalement de vulnérabilités), audit périodique AgentShield du harnais, revue des dépendances (0 dep externe aujourd'hui → rester minimaliste).
- **P1 · Robustesse réseau** : vérifier le Content-Type des réponses, taille max (cap) avant parse JSON/XML, timeouts partout, pas de redirection aveugle (ou cap de redirects).

## 9. Tests & CI — P0 (lens tdd-guide / verification-loop)
- **P0 · Tests de qualité des données** : assertions schéma sur `data/*.json` après chaque collecte (fait partie du pipeline, bloque la publication si KO).
- **P0 · Tests de contrat API** : `/api/data` possède toutes les clés, types, bornes (CVSS 0–10) — déjà amorcé dans `test_server.py`, à compléter.
- **P0 · CI GitHub Actions** (`.github/workflows/ci.yml`) : ruff + 28+ tests + couverture ≥ 80 % (gate) à chaque push — aujourd'hui tout est manuel.
- **P1 · E2E smoke** : démarre le serveur, vérifie `/`, `/api/data`, `/issue` (amorcé).

## 10. UX & accessibilité — P1/P2 (lens a11y-architect, WCAG 2.2)
- **P1 · Historique visuel** : sparklines/graphes (nb CVE/jour, par sévérité) depuis SQLite.
- **P1 · Accessibilité** : rôles ARIA sur le tableau de bord, navigation clavier complète, contrastes WCAG AA, `prefers-reduced-motion`, textes alternatifs.
- **P1 · i18n** : FR + AR (lectorat marocain bilingue) via dictionnaires de chaînes.
- **P2 · État dans l'URL** (filtres partageables), mode clair, **flux RSS/Atom** de la veille, **page d'archives** des éditions.

## 11. Newsletter & diffusion — P1
- **P1 · Envoi e-mail réel** : SMTP/SendGrid avec mode `--dry-run`, templates, liste d'abonnés, gestion des désabonnements.
- **P1 · Variantes de cadence** (quotidienne « alerte » vs hebdo « digest ») + objets A/B.
- **P2 · Export PDF** de l'édition, hébergement statique de `out/`.

## 12. Ops & déploiement — P1/P2
- **P1 · Dockerfile + docker-compose** (server + cron de collecte), `HEALTHCHECK`, image signée.
- **P1 · Runbook ops** dans le README : redémarrer, forcer une collecte, restaurer depuis `data/raw`, diagnostiquer une source en panne.
- **P2 · Backups** du dossier `data/`, rétention (30 j raw, historique SQLite compressé).

## 13. Gouvernance — P2
- **P2 · `LICENSE` (MIT), `CHANGELOG.md`, `CONTRIBUTING.md`**, attribution des sources (CISA/NVD domaine public, licences des feeds) — déjà amorcé dans le pied de page.

---

## ⚡ Quick wins cette semaine (P0, < 1 j cumulé)
1. CPE `virtualMatchString` pour le filtre NVD (tue les faux positifs).
2. Validation schéma des JSON collectés + alerte si chute de volume.
3. SQLite + détection « nouvelles CVE depuis la dernière collecte ».
4. Score composite CVSS+KEV+EPSS (EPSS via API FIRST, gratuit).
5. Token sur `POST /api/refresh` + en-têtes de sécurité (CSP/nosniff/DENY).
6. `/metrics` Prometheus + badge « STALE » si collecte trop vieille.
7. CI GitHub Actions : ruff + tests + gate couverture ≥ 80 %.
8. Gitleaks en pre-commit + `SECURITY.md`.

## 📅 Phasage
- **Semaine 1–2** : tous les P0 (1, 2, 3, 4, 5-sécurité, 6-observabilité, 7-CI, 8-precommit).
- **Mois 1** : P1 (sources additionnelles, SSE, alerting webhook/Slack, profil d'exposition, UX historique + a11y, envoi e-mail, Docker).
- **Trimestre** : P2 (i18n AR, RSS/archives, PDF, backups, gouvernance complète, TAXII/STIX).

## 📚 Sources (deep-research 2026)
- Architecture TIP : ingest → normalize → dedup → enrich → score → diffuser ; métriques (lag d'ingestion, ratio de dédup, fraîcheur) — [ismalicious.com](https://ismalicious.com/posts/threat-intelligence-platforms-data-quality-architecture)
- TIP 2026 (OpenCTI/STIX 2.1, scoring, priorisation, intégration SIEM/SOAR) — [Cyware](https://www.cyware.com/blog/top-threat-intelligence-platforms-and-solutions), [Exabeam](https://www.exabeam.com/explainers/cyber-threat-intelligence/best-threat-intelligence-solutions-top-8-platforms/), [Cyble](https://cyble.com/knowledge-hub/5-essential-threat-intelligence-platforms/) (EPSS/KEV/abuse.ch comme feeds de référence)
- Pipelines data 2026 : validation schéma, fraîcheur SLO, idempotence/replay, couche raw, métriques (freshness/completeness/dup rate) — [chaindesk.ai](https://www.chaindesk.ai/blog/data-ingestion-best-practices-checklist), [datavidhya](https://datavidhya.com/blog/data-engineering-best-practices/), [improvado](https://improvado.io/blog/data-pipeline-automation)
- CI/CD & secrets 2026 : vault/OIDC, rotation, gitleaks/trufflehog, SAST/SCA, gates — [Harness](https://www.harness.io/blog/ci-cd-security-best-practices), [Group-IB](https://www.group-ib.com/resources/knowledge-hub/ci-cd-security/), [decryptiondigest](https://www.decryptiondigest.com/blog/ci-cd-pipeline-security-best-practices)
- Outils ECC exécutés : `harness-audit` 78/80 · `observability-readiness` 21/21 · `doctor` 5/5 · AgentShield 0 critical · tests 28/28, couverture 83 %.

---

# 🔄 Rafraîchissement 01/11/2026 — « plateforme de référence OT » + agents IA éditoriaux

Suite à l'interrogation ECC (harness-audit repo-scoped 16/39 → quick win `AGENTS.md` ajouté) et à une deep-research 2026, voir le rapport complet :
**`research/REFERENCE-OT-WATCH-2026-11-01.md`**.

Nouvelles priorités ajoutées à la roadmap :
- **P0** : `AGENTS.md` ✅ (fait), remote GitHub + PR template.
- **P1 collecte "référence"** : sources vendor CERTs OT + OTX/VulnCheck/abuse.ch/GreyNoise ; export **STIX 2.1** (`/stix`) ✅ (v1.5) ; mapping **MITRE ATT&CK for ICS** (v20) ✅ (v1.5) ; **SSVC/Vulnrichment** dans le score ✅ (v1.5) ; score OT complet (exposition + niveau Purdue + criticité + safety) ✅ (v1.12) ; runbook **collecte réseau passive** (Zeek/Suricata+ICSNPP ou Malcolm sur SPAN, jamais inline) ✅ (v1.13) ; export **OpenAPI 3.1** (`/openapi.json`) ✅ (v1.14) ; e-mail réel ✅ (SMTP env `OTWATCH_SMTP_*`, v1.2) ; **Docker** ✅ (Dockerfile + compose, v1.14).
- **P1 flagship — agents IA éditoriaux** : analyste RAG hybride (KG faits + corpus primaires) → rédacteur (style FR, citations [n]) → fact-checker 3 tiers anti-hallucination → illustrateur (visuels data-driven + images IA **signées C2PA**, légende visible) → **éditeur humain HITL/HOTL** ; conformité **AI Act Art. 50** (depuis 02/08/2026) : divulgation contenu IA d'intérêt public sauf revue humaine éditoriale ; deepfakes jamais ; C2PA/IPTC `trainedAlgorithmicMedia` préservés.
- **P2** : serveur TAXII 2.1 read-only ✅ (v1.8), connecteur MISP/OT-ISAC ✅ (v1.9), inventaire d'actifs + SBOM (CycloneDX) ✅ (v1.9), lignage/dedup/replay raw + métriques qualité ✅ (v1.10), backups/DR 30 j ✅ (v1.10), i18n AR ✅ (v1.11) — 01/11/2026.
- **P2 gouvernance** ✅ (v1.14) : LICENSE MIT, CHANGELOG.md, CONTRIBUTING.md, PR/issue templates, CODEOWNERS, dependabot ; **harness-audit ECC 39/39** ; score OT ✅ (v1.12) ; runbook collecte passive ✅ (v1.13) — 01/11/2026.
