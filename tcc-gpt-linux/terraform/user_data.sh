#!/bin/bash
# Garante o SSM Agent já incluído nas AMIs Ubuntu oficiais da AWS.
# Não instala pacote adicional, não lê segredo e não abre porta.
set -euo pipefail

if ! command -v snap >/dev/null 2>&1; then
  echo "snap não está disponível nesta AMI." >&2
  exit 1
fi

if snap services amazon-ssm-agent 2>/dev/null | awk 'NR > 1 { print $3 }' | grep -qx "active"; then
  exit 0
fi

snap start amazon-ssm-agent
