#!/usr/bin/env bash
set -euo pipefail

file_path="${1:-}"
api_url="${2:-}"

if [[ -z "$file_path" || -z "$api_url" ]]; then
  echo "Usage: write-runtime-config.sh <file_path> <api_url>" >&2
  exit 1
fi

mkdir -p "$(dirname "$file_path")"

RUNTIME_CONFIG_FILE="$file_path" RUNTIME_CONFIG_API_URL="$api_url" python - <<'PY'
import json
import os
from pathlib import Path

file_path = os.environ["RUNTIME_CONFIG_FILE"]
api_url = os.environ["RUNTIME_CONFIG_API_URL"]
payload = {"apiUrl": api_url}
content = "window.__RUNTIME_CONFIG__ = " + json.dumps(payload, indent=2) + ";\n"
Path(file_path).write_text(content, encoding="utf-8")
PY
