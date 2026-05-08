"""Root agent for ADK Web: same model/prompt/MCP env as the stdio ADK client (``gfiber_adk_shared``).

Run from repo root: ``./start_ai_tool_adk`` (or ``python -m google.adk.cli web … adk_agents``).
In the UI, open app **gfiber_network**. ADK Web cannot load ``client_inmemory_v2_google_adk.py`` directly.

Session logging (JSONL + ``.log``) is enabled via ``App`` plugins — see ``gfiber_adk_web_session_logging`` module.
Files: ``session_logs/adk_web_session_<adk_session_id>.jsonl``. Disable with ``GFIBER_ADK_WEB_SESSION_LOG_DISABLE=1``.
"""

from __future__ import annotations

import os

# google-genai prefers GOOGLE_API_KEY over GEMINI_API_KEY when both are set.
# Manual `python -m google.adk.cli web` skips start_ai_tool_adk's `unset`; match that here.
os.environ.pop("GOOGLE_API_KEY", None)

import sys
from pathlib import Path

from google.adk.agents import LlmAgent
from google.adk.apps.app import App
from google.adk.tools.mcp_tool import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
from mcp import StdioServerParameters

# Repo root (…/mcp_codes): agent path is adk_agents/gfiber_network/agent.py
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from gfiber_adk_shared import MODEL_ID, SYSTEM_INSTRUCTION, mcp_stdio_server_env
from gfiber_adk_web_session_logging import GfiberAdkWebSessionLogPlugin

_SERVER_PATH = str(_REPO_ROOT / "server_inmemory_v2.py")

root_agent = LlmAgent(
    model=MODEL_ID,
    name="gfiber_network_agent",
    instruction=SYSTEM_INSTRUCTION,
    tools=[
        McpToolset(
            connection_params=StdioConnectionParams(
                server_params=StdioServerParameters(
                    command="python3",
                    args=[_SERVER_PATH],
                    env=mcp_stdio_server_env(),
                ),
            ),
        )
    ],
)

app = App(
    name="gfiber_network",
    root_agent=root_agent,
    plugins=[GfiberAdkWebSessionLogPlugin()],
)
