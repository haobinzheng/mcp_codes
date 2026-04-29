# Shell launch scripts

Executable helpers in the repo root for running the GFiber MCP-backed clients. Install Python deps first ([`DESIGN_PIP_INSTALL.md`](DESIGN_PIP_INSTALL.md)).

## Scripts overview

| Script | Purpose |
|--------|---------|
| [`start_ai_tool`](start_ai_tool) | Stdio CLI: `client_inmemory_v2.py` |
| [`start_ai_tool_web`](start_ai_tool_web) | Flask UI: `client_inmemory_v2_web.py` (`WEB_HOST` / `WEB_PORT`) |
| [`start_ai_tool_web_tunnel`](start_ai_tool_web_tunnel) | SSH **local port forward** `-L` so your laptop browser reaches the remote web UI |
| [`start_ai_tool_adk`](start_ai_tool_adk) | ADK CLI: `client_inmemory_v2_adk.py` (`PYTHON` overrides interpreter) |
| [`start_ai_tool_adk_tunnel`](start_ai_tool_adk_tunnel) | Default: interactive SSH + `./start_ai_tool_adk` on remote. **`ADK_TUNNEL_MODE=port-forward`**: same `ssh -N -L` block as [`start_ai_tool_web_tunnel`](start_ai_tool_web_tunnel) (`LOCAL_PORT`, `REMOTE_HOST`, `REMOTE_PORT`) |

## Local / server: `start_ai_tool_adk`

From the repository directory (after `chmod +x` if needed):

```bash
export GEMINI_API_KEY=...   # or GOOGLE_API_KEY
./start_ai_tool_adk
```

Equivalent:

```bash
PYTHON=python3 ./start_ai_tool_adk
```

## Remote interactive session: `start_ai_tool_adk_tunnel`

Default behavior opens **TTY** SSH and runs `./start_ai_tool_adk` on the remote host. The MCP server process is still started **by the ADK client** over stdio (same as locally); you do not run `server_inmemory_v2.py` by itself unless debugging.

1. Edit placeholders at top of the script (`SSH_USER`, `SSH_HOST`) or pass `user@host` as the first argument (same as [`start_ai_tool_web_tunnel`](start_ai_tool_web_tunnel)).
2. Ensure the repo exists on the server and `start_ai_tool_adk` is executable there (`chmod +x start_ai_tool_adk`).
3. Optional: point at the checkout on the server:

```bash
# Directory under the remote user's HOME (default: mcp_codes)
REMOTE_REL=projects/mcp_codes ./start_ai_tool_adk_tunnel user@remote.example.com
```

Or an absolute path on the server:

```bash
REMOTE_ABS=/srv/mcp_codes ./start_ai_tool_adk_tunnel
```

## Port-forward mode (HTTP on remote)

With `ADK_TUNNEL_MODE=port-forward`, the script runs the **same** tunnel command and messages as [`start_ai_tool_web_tunnel`](start_ai_tool_web_tunnel) (`LOCAL_PORT`, `REMOTE_HOST`, `REMOTE_PORT`, `ssh -N -L ...`). Use when something on the remote listens on a TCP port (for example the Flask web UI).

```bash
ADK_TUNNEL_MODE=port-forward LOCAL_PORT=8000 REMOTE_PORT=8000 ./start_ai_tool_adk_tunnel user@remote.example.com
```

Pure ADK **CLI** does not listen on a port; use **interactive** tunnel mode for that case.

## Permissions

```bash
chmod +x start_ai_tool_adk start_ai_tool_adk_tunnel
```

Repeat on the remote host for `start_ai_tool_adk` if you deploy by clone/rsync.
