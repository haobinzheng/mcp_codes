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
| [`start_ai_tool_adk`](start_ai_tool_adk) | ADK CLI: `client_inmemory_v2_adk.py` (`PYTHON` overrides interpreter) |
| [`start_ai_tool_adk_tunnel`](start_ai_tool_adk_tunnel) | Same as [`start_ai_tool_web_tunnel`](start_ai_tool_web_tunnel): **SSH local port forward only** (`ssh -N -L`; `LOCAL_PORT`, `REMOTE_HOST`, `REMOTE_PORT`) |

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

## Port forwarding: `start_ai_tool_web_tunnel` and `start_ai_tool_adk_tunnel`

Both tunnel scripts only run **`ssh -N -L`**: traffic to `127.0.0.1:LOCAL_PORT` on **your laptop** is forwarded to `REMOTE_HOST:REMOTE_PORT` on the **remote** host. Typical use: the Flask app ([`start_ai_tool_web`](start_ai_tool_web)) listens on the server; you browse from your machine because the server has no browser (see [Why SSH port forwarding?](#why-ssh-port-forwarding) above).

[`start_ai_tool_adk_tunnel`](start_ai_tool_adk_tunnel) is the same tunnel helper as [`start_ai_tool_web_tunnel`](start_ai_tool_web_tunnel) if you prefer a separate name for documentation or automation.

```bash
./start_ai_tool_adk_tunnel user@remote.example.com
# Optional: LOCAL_PORT=9000 REMOTE_PORT=9000 ./start_ai_tool_adk_tunnel user@remote.example.com
```

The ADK **CLI** (`./start_ai_tool_adk`) does not open a TCP port by itself; run it directly on the machine where you want it (for example `ssh -t user@host 'cd ~/path/to/mcp_codes && ./start_ai_tool_adk'`).

## Permissions

```bash
chmod +x start_ai_tool_adk start_ai_tool_adk_tunnel
```

Repeat on the remote host for `start_ai_tool_adk` if you deploy by clone/rsync.
