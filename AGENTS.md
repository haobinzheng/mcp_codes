# AGENTS.md

## Repository Purpose

This repository contains a small set of Python scripts for running MCP-backed network audit workflows against GFiber / Juniper devices.

There are two main patterns:

- `server.py` + `client.py`: a basic MCP server/client pair for single commands and file access.
- `server_agg.py` + `client_agg.py`: the main concurrent audit flow for running `gnetch.sh` across many devices and then analyzing the saved results with Gemini.

The `.txt` files in this directory are working inputs and outputs, not general documentation.

## Primary Files

- `/Users/haobin/Coding/mcp_codes/server.py`
  Simple MCP server exposing:
  - `run_gnetch(command, hostname)`
  - `read_local_file(file_path)`
  - `write_to_file(filename, content)`

- `/Users/haobin/Coding/mcp_codes/client.py`
  Interactive Gemini client that starts `server_agg.py` over stdio and allows iterative tool use.

- `/Users/haobin/Coding/mcp_codes/server_agg.py`
  Main audit server. Runs `gnetch.sh` concurrently across many devices and writes aggregated results to a local output file.

- `/Users/haobin/Coding/mcp_codes/client_agg.py`
  Interactive Gemini client with a stronger system prompt intended for the aggregated audit workflow.

- `/Users/haobin/Coding/mcp_codes/juniper_devices.txt`
  Large example inventory file of hostnames used as input to `audit_devices`.

- `/Users/haobin/Coding/mcp_codes/audit_results.txt`
  Example aggregated output file produced by `server_agg.py`.

## Runtime Assumptions

- Python 3 is required.
- The code depends on MCP Python packages and Google GenAI packages:
  - `mcp`
  - `google-genai`
- `GEMINI_API_KEY` must be set before running either client.
- The network tooling depends on an external script at:
  - `/usr/local/google/home/mikezh/Coding/gfiber/bin/gnetch.sh`

This repository does not currently include dependency manifests such as `requirements.txt` or `pyproject.toml`.

## How The Code Works

### `server_agg.py`

- Exposes `audit_devices(command, devices, output_file="audit_results.txt")`.
- `devices` may be:
  - a filename in the current working directory, or
  - a comma/space-separated list of hostnames.
- Hostnames are normalized, deduplicated, and processed concurrently.
- Output is intentionally filtered to lines containing hardware inventory markers such as `RE-S`, `SCB`, `MPC`, `FPC`, `Chassis`, and `Model`.
- The server writes a combined text report into the current directory.

### `client_agg.py`

- Starts `server_agg.py` as a stdio MCP server.
- Creates a Gemini chat session with MCP tool access.
- The system instruction explicitly expects this flow:
  1. run `audit_devices`
  2. read the saved file with `read_local_file`
  3. answer follow-up questions from the ingested result set

### Important mismatch

- `/Users/haobin/Coding/mcp_codes/client.py` is labeled like the simple client, but it also points to `server_agg.py`, not `server.py`.
- If you change one of these files, verify whether that coupling is intentional before refactoring.

## Change Guidelines For Agents

- Preserve the current MCP tool names unless the user explicitly asks for a breaking API change.
- Do not remove the output filtering in `server_agg.py` unless the user wants fuller raw output; it exists to reduce model token load.
- Be careful with hardcoded filesystem paths. They are environment-specific and likely the most fragile part of this repo.
- Keep generated audit files in the current repository directory unless the user asks for a different output location.
- Treat the `.txt` files here as real working data. Do not delete or overwrite them casually.
- If adding configuration, prefer small explicit constants or a simple env-var fallback instead of introducing a large framework.
- If adding dependencies, also add a dependency manifest because the repo currently has none.

## Safe Ways To Run

From `/Users/haobin/Coding/mcp_codes`:

```bash
export GEMINI_API_KEY=...
python3 client_agg.py
```

Typical prompt examples inside the client:

- `Audit the devices in juniper_devices.txt using command 'show chassis hardware'`
- `Audit dr01.atl103, dr01.aus121, dr01.cbf101 using command 'show chassis hardware'`
- `Summarize all devices that have RE-S-2X00x6`

## Known Risks / Technical Debt

- Hardcoded path to `gnetch.sh`.
- No dependency manifest.
- No tests.
- Minimal input validation around commands passed to the external script.
- `server.py` and `client.py` are not aligned as cleanly as their names suggest.

## Preferred Next Improvements

- Add `requirements.txt` or `pyproject.toml`.
- Make `GNETCH_PATH` configurable through an environment variable.
- Add a small README with setup and example usage.
- Add basic tests for hostname parsing and output filtering in `server_agg.py`.
