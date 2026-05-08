#!/usr/bin/env python3
"""List Gemini models (ListModels v1beta) for your API key.

The API key is never stored in this file. You are prompted to enter it
(hidden). Press Enter without typing to reuse GEMINI_API_KEY from the
environment, if set.

Also prints equivalent curl commands you can run manually.

Shell-only variant: ``scripts/list_gemini_models.sh`` (same prompt semantics).
"""

from __future__ import annotations

import getpass
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

LIST_URL = "https://generativelanguage.googleapis.com/v1beta/models"


def _fetch_models(api_key: str) -> dict:
    url = f"{LIST_URL}?{urllib.parse.urlencode({'key': api_key})}"
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    print("Gemini ListModels (v1beta)")
    print("-" * 44)

    entered = getpass.getpass(
        "Enter GEMINI_API_KEY (hidden; leave empty to use $GEMINI_API_KEY): "
    ).strip()
    key = entered or (os.environ.get("GEMINI_API_KEY") or "").strip()
    if not key:
        print("No API key provided.", file=sys.stderr)
        return 1

    try:
        data = _fetch_models(key)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        print(f"HTTP {exc.code}\n{body[:4000]}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        return 1

    models = data.get("models") or []
    gc_models: list[tuple[str, str]] = []
    for m in models:
        name = m.get("name") or ""
        methods = m.get("supportedGenerationMethods") or []
        if "generateContent" not in methods:
            continue
        short = name[len("models/") :] if name.startswith("models/") else name
        gc_models.append((short, ", ".join(methods)))

    gc_models.sort(key=lambda x: x[0].lower())
    print(f"\nModels supporting generateContent ({len(gc_models)}):\n")
    for short, meth in gc_models:
        print(f"  {short}")
        print(f"      methods: {meth}")

    print(
        "\nUse one of the short names with:\n"
        "  export GEMINI_MODEL_ID='<name>'\n"
        "then restart ADK Web / your client.\n"
    )

    print("--- Equivalent curl (key is NOT in the script; export or type when prompted) ---\n")
    print(
        "  read -sp 'GEMINI_API_KEY: ' GEMINI_API_KEY; echo\n"
        '  curl -sS "https://generativelanguage.googleapis.com/v1beta/models?key=${GEMINI_API_KEY}" \\\n'
        "    | python3 -m json.tool\n"
    )
    print("Filter to models that advertise generateContent:\n")
    print(
        "  read -sp 'GEMINI_API_KEY: ' GEMINI_API_KEY; echo\n"
        '  curl -sS "https://generativelanguage.googleapis.com/v1beta/models?key=${GEMINI_API_KEY}" \\\n'
        "    | python3 -c '\n"
        "import json,sys\n"
        "d=json.load(sys.stdin)\n"
        "for m in d.get(\"models\",[]):\n"
        "  sm=m.get(\"supportedGenerationMethods\")or[]\n"
        "  if \"generateContent\" in sm:\n"
        "    print(m.get(\"name\",\"\"))\n"
        "'\n"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
