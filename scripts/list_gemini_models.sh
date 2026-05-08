#!/usr/bin/env bash
# List Gemini models (ListModels v1beta) using curl. API key is never stored
# in this file: you are prompted (hidden), or leave empty to use GEMINI_API_KEY
# from the environment.
set -euo pipefail

LIST_URL="https://generativelanguage.googleapis.com/v1beta/models"

echo "Gemini ListModels (v1beta) — curl"
echo "----------------------------------------------"

read -rsp "Enter GEMINI_API_KEY (hidden; leave empty to use \$GEMINI_API_KEY): " _entered
echo
if [[ -n "${_entered}" ]]; then
  GEMINI_API_KEY="${_entered}"
fi
if [[ -z "${GEMINI_API_KEY:-}" ]]; then
  echo "No API key provided." >&2
  exit 1
fi

URL="${LIST_URL}?key=${GEMINI_API_KEY}"

echo ""
echo "Models supporting generateContent:"
curl -sS "${URL}" | python3 -c '
import json, sys
d = json.load(sys.stdin)
rows = []
for m in d.get("models", []):
    methods = m.get("supportedGenerationMethods") or []
    if "generateContent" not in methods:
        continue
    name = m.get("name", "")
    short = name[len("models/"):] if name.startswith("models/") else name
    rows.append((short, ", ".join(methods)))
for short, meth in sorted(rows, key=lambda x: x[0].lower()):
    print(f"  {short}")
    print(f"      methods: {meth}")
'

echo ""
echo "Optional: full JSON (first 120 lines; pipe to a file if large):"
curl -sS "${URL}" | python3 -m json.tool | head -n 120 || true
echo ""
echo "Use a short name with:  export GEMINI_MODEL_ID='<name>'"
echo "Then restart ADK Web / your client."
