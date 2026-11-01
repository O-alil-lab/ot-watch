#!/usr/bin/env bash
# Guardrail PreToolUse (Bash) — bloque les commandes dangereuses avant exécution.
# Appelé via .claude/settings.json. Reçoit le JSON de l'input outil en $1.
set -euo pipefail
input="${1:-}"
cmd=$(printf '%s' "$input" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('tool_input',{}).get('command',''))" 2>/dev/null || printf '%s' "$input")
case "$cmd" in
  *"rm -rf /"*|*"rm -rf ~"*|*"rm -rf \$HOME"*|*"curl "*" | sh"*|*"wget "*" | sh"*|*"git push --force"*|*":(){ :|:& };:"*|*"mkfs."*|*"dd of=/dev/"*)
    echo "[guardrail] commande bloquée (dangereuse) : $cmd" >&2
    exit 2
    ;;
esac
# bloque la lecture de fichiers de secrets par des commandes réseau
if printf '%s' "$cmd" | grep -qE "(cat|grep|rg).*(\.env|\.netrc|id_rsa|credentials)"; then
  echo "[guardrail] lecture de fichier de credentials bloquée" >&2
  exit 2
fi
exit 0
