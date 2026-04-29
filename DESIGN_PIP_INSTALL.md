# Pip installs — project dependency design

This document lists how Python dependencies for this repository are installed. The canonical list of packages is [`requirements.txt`](requirements.txt).

## Environment

- Use **Python 3.10 or newer**. `google-adk` declares `Requires-Python >=3.10` (newer ADK releases may require 3.11+; check `pip` resolver output if installs fail).
- Prefer an isolated environment so dependency versions stay reproducible.

## Recommended: install from requirements file

Create and activate a virtual environment, upgrade pip, then install everything:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

On Windows:

```bat
python -m venv .venv
.venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Equivalent explicit installs

These commands install the same top-level packages as `requirements.txt` (versions are unconstrained unless you add pins):

```bash
pip install flask google-adk google-genai mcp
```

## Individual packages (install separately when needed)

```bash
pip install flask
pip install google-adk
pip install google-genai
pip install mcp
```

## Optional: editable / development installs

There are no editable local packages in this repo today. If you add a `pyproject.toml` later, document `pip install -e .` here.

## Locking versions (optional)

For repeatable CI or production images, generate a lock file after installing:

```bash
pip freeze > requirements-lock.txt
```

Prefer pinning in `requirements.txt` or using `pip-tools` / Poetry / uv if the team standardizes on one of those.
