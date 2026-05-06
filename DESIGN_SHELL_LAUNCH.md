# Shell launch scripts

Executable helpers in the repo root for running the GFiber MCP-backed clients. Install Python deps first ([`DESIGN_PIP_INSTALL.md`](DESIGN_PIP_INSTALL.md)).

## Why SSH port forwarding?

Remote servers often have **no graphical web browser** (or no easy way to use one). You run the Flask UI on the server and open an **SSH local forward** (`*-tunnel` scripts: `ssh -N -L`) so **`http://127.0.0.1:PORT` on your laptop** reaches the app bound on the remote host. The server never needs a browser; only your Mac (or other local machine) does.

## Scripts overview

| Script | Purpose |
|--------|---------|
| [`start_ai_tool`](start_ai_tool) | Stdio CLI: `client_inmemory_v2.py` |
| [`start_ai_tool_web`](start_ai_tool_web) | Flask UI: `client_inmemory_v2_web.py` (`WEB_HOST` / `WEB_PORT`) |
| [`start_ai_tool_web_tunnel`](start_ai_tool_web_tunnel) | SSH **local port forward** `-L` (defaults port **8000**, same as Flask `WEB_PORT` in `start_ai_tool_web`) |
| [`start_ai_tool_adk`](start_ai_tool_adk) | **ADK Web** (`adk web`): agents only under [`adk_agents/`](adk_agents/); default **`ADK_WEB_PORT=8787`** to avoid clashing with Flask / other `adk web` on `8000` |
| [`start_ai_tool_adk_tunnel`](start_ai_tool_adk_tunnel) | Same `-L` pattern; defaults **`LOCAL_PORT`/`REMOTE_PORT=8787`** to match [`start_ai_tool_adk`](start_ai_tool_adk) (override if you set `ADK_WEB_PORT`) |

## Logging (`start_ai_tool_adk`, `start_ai_tool_adk_tunnel`)

Both scripts append **session headers** (timestamp, PID, key settings) and **tee all stdout/stderr** into log files under **`logs/`** by default.

| Variable | Purpose |
|----------|---------|
| **`START_AI_TOOL_LOG_DIR`** | Directory for default log paths (default `<repo>/logs`; created automatically). |
| **`ADK_LOG_FILE`** | Full path for ADK Web logs (default **`${START_AI_TOOL_LOG_DIR}/adk_web.log`**). |
| **`ADK_TUNNEL_LOG_FILE`** | Full path for tunnel logs (default **`${START_AI_TOOL_LOG_DIR}/adk_tunnel.log`**). |
| **`START_AI_TOOL_LOG_DISABLE`** | Set to **`1`** or **`true`** to disable file logging (terminal output unchanged). |

Shared helpers live in [`start_ai_tool_logging.sh`](start_ai_tool_logging.sh).

## ADK Web: `start_ai_tool_adk`

[`start_ai_tool_adk`](start_ai_tool_adk) runs **`python -m google.adk.cli web`** with an explicit **`AGENTS_DIR`** of [`adk_agents/`](adk_agents/) only (the `gfiber_network` agent in [`adk_agents/gfiber_network/agent.py`](adk_agents/gfiber_network/agent.py)). Always pass this directory — do **not** run bare `adk web` from `$HOME` or a multi-project folder, or ADK will treat every subdirectory as a separate agent and collide with other projects.

### Avoiding conflicts with other ADK / web apps

- **Port:** default **`8787`** (not `8000`) so this repo does not fight [`start_ai_tool_web`](start_ai_tool_web), other Flask apps, or another `adk web` on the same host.
- **Sessions:** **`memory://`** via **`--session_service_uri`** (no SQLite in this launcher). Chat state is per process and not persisted. Set **`ADK_SESSION_SERVICE_URI`** if you need a different ADK-supported backend.
- **Reload:** **`--no-reload`** by default (set **`ADK_WEB_RELOAD=true`** to enable). Reload watches files and is easy to misconfigure when several agent trees exist on one machine.
- **UI logo:** Custom branding is passed only when **both** **`ADK_LOGO_TEXT`** and **`ADK_LOGO_IMAGE_URL`** are set (newer ADK rejects **`--logo-text`** alone).

From the repository directory (after `chmod +x` if needed):

```bash
export GEMINI_API_KEY=...
./start_ai_tool_adk
```

Environment variables:

- **`ADK_WEB_HOST`** — bind address (default `127.0.0.1`).
- **`ADK_WEB_PORT`** — port (default **`8787`**). Use the **same** value for **`REMOTE_PORT`** / **`LOCAL_PORT`** when tunneling (see [`start_ai_tool_adk_tunnel`](start_ai_tool_adk_tunnel)).
- **`AGENTS_DIR`** — override agents directory (default `<repo>/adk_agents`).
- **`ADK_SESSION_SERVICE_URI`** — session backend URI (default **`memory://`**). Set explicitly only if you need something other than in-memory sessions.
- **`ADK_WEB_RELOAD`** — `true` / `1` to enable `--reload`.
- **`ADK_LOGO_TEXT`** / **`ADK_LOGO_IMAGE_URL`** — optional pair for custom Web UI logo (both required together).
- **`PYTHON`** — interpreter (default `python3`).

**Interactive terminal CLI** (no browser UI): run `python3 client_inmemory_v2_adk.py` directly instead of this script.

## Port forwarding: `start_ai_tool_web_tunnel` and `start_ai_tool_adk_tunnel`

Both tunnel scripts only run **`ssh -N -L`**: traffic to `127.0.0.1:LOCAL_PORT` on **your laptop** is forwarded to `REMOTE_HOST:REMOTE_PORT` on the **remote** host (see [Why SSH port forwarding?](#why-ssh-port-forwarding)).

- **[`start_ai_tool_web_tunnel`](start_ai_tool_web_tunnel)** defaults **`8000`** → matches Flask **`WEB_PORT`** / **`start_ai_tool_web`**.
- **[`start_ai_tool_adk_tunnel`](start_ai_tool_adk_tunnel)** defaults **`8787`** → matches **`ADK_WEB_PORT`** / **`start_ai_tool_adk`**.

```bash
./start_ai_tool_web_tunnel user@remote.example.com
./start_ai_tool_adk_tunnel user@remote.example.com
# If you changed ADK_WEB_PORT on the server:
# REMOTE_PORT=9999 LOCAL_PORT=9999 ./start_ai_tool_adk_tunnel user@remote.example.com
```

**ADK Web from a Mac while the server is Linux:** run `./start_ai_tool_adk` on the Linux host first, then on the Mac run `./start_ai_tool_adk_tunnel user@linux-host` (no hardcoded SSH user/host in the script—pass **`user@host`** or set **`REMOTE_SSH_TARGET`**). Open **`http://127.0.0.1:8787`** locally and choose app **`gfiber_network`**. Optional: **`START_AI_TOOL_TUNNEL_OPEN_BROWSER=1`** runs **`open`** on macOS after the tunnel command starts (still keep the terminal open for **`ssh -N`**).

On the remote host, ADK Web must be listening on **`REMOTE_HOST`:`REMOTE_PORT`** (defaults **`127.0.0.1:8787`**); the tunnel forwards your Mac’s **`LOCAL_PORT`** to that listener.

## Permissions

```bash
chmod +x start_ai_tool_adk start_ai_tool_adk_tunnel
```

Repeat on the remote host for `start_ai_tool_adk` if you deploy by clone/rsync.
