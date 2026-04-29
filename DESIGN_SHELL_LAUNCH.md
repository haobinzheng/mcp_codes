# Shell launch scripts

Executable helpers in the repo root for running the GFiber MCP-backed clients. Install Python deps first ([`DESIGN_PIP_INSTALL.md`](DESIGN_PIP_INSTALL.md)).

## Why SSH port forwarding?

Remote servers often have **no graphical web browser** (or no easy way to use one). You run the Flask UI on the server and open an **SSH local forward** (`*-tunnel` scripts: `ssh -N -L`) so **`http://127.0.0.1:PORT` on your laptop** reaches the app bound on the remote host. The server never needs a browser; only your Mac (or other local machine) does.

## Scripts overview

| Script | Purpose |
|--------|---------|
| [`start_ai_tool`](start_ai_tool) | Stdio CLI: `client_inmemory_v2.py` |
| [`start_ai_tool_web`](start_ai_tool_web) | Flask UI: `client_inmemory_v2_web.py` (`WEB_HOST` / `WEB_PORT`) |
| [`start_ai_tool_web_tunnel`](start_ai_tool_web_tunnel) | SSH **local port forward** `-L` so your laptop browser reaches the remote web UI |
| [`start_ai_tool_adk`](start_ai_tool_adk) | **ADK Web** (`adk web`): FastAPI + ADK Web UI; agents from [`adk_agents/`](adk_agents/) (default `ADK_WEB_PORT=8000`) |
| [`start_ai_tool_adk_tunnel`](start_ai_tool_adk_tunnel) | Same as [`start_ai_tool_web_tunnel`](start_ai_tool_web_tunnel): **SSH local port forward only** (`ssh -N -L`; `LOCAL_PORT`, `REMOTE_HOST`, `REMOTE_PORT`) — point at the same port as `ADK_WEB_PORT` on the server |

## ADK Web: `start_ai_tool_adk`

[`start_ai_tool_adk`](start_ai_tool_adk) runs **`python -m google.adk.cli web`** against [`adk_agents/`](adk_agents/) (the `gfiber_network` agent in [`adk_agents/gfiber_network/agent.py`](adk_agents/gfiber_network/agent.py) defines `root_agent` with the same MCP `McpToolset` + `server_inmemory_v2.py` wiring as the standalone ADK client).

From the repository directory (after `chmod +x` if needed):

```bash
export GEMINI_API_KEY=...   # or GOOGLE_API_KEY
./start_ai_tool_adk
```

Environment variables:

- **`ADK_WEB_HOST`** — bind address (default `127.0.0.1`).
- **`ADK_WEB_PORT`** — port (default `8000`). Use the **same** value for **`REMOTE_PORT`** when using [`start_ai_tool_adk_tunnel`](start_ai_tool_adk_tunnel).
- **`AGENTS_DIR`** — override agents directory (default `<repo>/adk_agents`).
- **`PYTHON`** — interpreter (default `python3`).

**Interactive terminal CLI** (no browser UI): run `python3 client_inmemory_v2_adk.py` directly instead of this script.

## Port forwarding: `start_ai_tool_web_tunnel` and `start_ai_tool_adk_tunnel`

Both tunnel scripts only run **`ssh -N -L`**: traffic to `127.0.0.1:LOCAL_PORT` on **your laptop** is forwarded to `REMOTE_HOST:REMOTE_PORT` on the **remote** host. Typical use: the Flask app ([`start_ai_tool_web`](start_ai_tool_web)) listens on the server; you browse from your machine because the server has no browser (see [Why SSH port forwarding?](#why-ssh-port-forwarding) above).

[`start_ai_tool_adk_tunnel`](start_ai_tool_adk_tunnel) is the same tunnel helper as [`start_ai_tool_web_tunnel`](start_ai_tool_web_tunnel) if you prefer a separate name for documentation or automation.

```bash
./start_ai_tool_adk_tunnel user@remote.example.com
# Optional: LOCAL_PORT=9000 REMOTE_PORT=9000 ./start_ai_tool_adk_tunnel user@remote.example.com
```

On the remote host, run `./start_ai_tool_adk` so ADK Web listens on `127.0.0.1:ADK_WEB_PORT`; the tunnel forwards your laptop’s `LOCAL_PORT` to that listener so you can use the ADK Web UI in a local browser.

## Permissions

```bash
chmod +x start_ai_tool_adk start_ai_tool_adk_tunnel
```

Repeat on the remote host for `start_ai_tool_adk` if you deploy by clone/rsync.
