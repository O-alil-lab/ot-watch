#!/usr/bin/env bash
# Restaure les fichiers "dot-dirs" (.claude/, .github/) que le bac à sable efface parfois,
# depuis les copies canoniques de scaffolds/. Idempotent. Usage : bash scripts/restore-sandbox.sh
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .claude/commands .claude/skills/ot-watch-ops .github/ISSUE_TEMPLATE .github/workflows
cp scaffolds/claude/settings.json .claude/settings.json
cp scaffolds/claude/memory.md .claude/memory.md
cp scaffolds/claude/commands/*.md .claude/commands/
cp scaffolds/claude/skills/ot-watch-ops/SKILL.md .claude/skills/ot-watch-ops/SKILL.md
cp scaffolds/mcp.json .mcp.json
cp scaffolds/github/PULL_REQUEST_TEMPLATE.md .github/
cp scaffolds/github/CODEOWNERS scaffolds/github/dependabot.yml .github/
cp scaffolds/github/ISSUE_TEMPLATE/*.md .github/ISSUE_TEMPLATE/
cp scaffolds/github/workflows/*.yml .github/workflows/
chmod +x scripts/claude-hooks/guardrail.sh scripts/github-setup.sh workers/deploy.sh 2>/dev/null || true
# régénère out/ si vide (hors-ligne, depuis data/)
if [ -f data/cves.json ] && [ -z "$(ls -A out 2>/dev/null)" ]; then
  python3 src/render.py >/dev/null 2>&1 || true
  python3 src/render_pdf.py >/dev/null 2>&1 || true
  python3 src/stix.py >/dev/null 2>&1 || true
  python3 src/misp_export.py >/dev/null 2>&1 || true
  python3 src/render_ar.py >/dev/null 2>&1 || true
fi
echo "[restore-sandbox] .claude/ .github/ .mcp.json restaurés ; out/ régénéré si vide"
