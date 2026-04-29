"""Root agent for ADK Web: GFiber MCP tools via server_inmemory_v2.py."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from google.adk.agents import LlmAgent
from google.adk.tools.mcp_tool import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
from mcp import StdioServerParameters

# Repo root (…/mcp_codes): agent path is adk_agents/gfiber_network/agent.py
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from client_inmemory_v2_adk import MODEL_ID, SYSTEM_INSTRUCTION

_SERVER_PATH = str(_REPO_ROOT / "server_inmemory_v2.py")

root_agent = LlmAgent(
    model=os.environ.get("GEMINI_MODEL_ID", MODEL_ID),
    name="gfiber_network_agent",
    instruction=SYSTEM_INSTRUCTION,
    tools=[
        McpToolset(
            connection_params=StdioConnectionParams(
                server_params=StdioServerParameters(
                    command="python3",
                    args=[_SERVER_PATH],
                    env=os.environ.copy(),
                ),
            ),
        )
    ],
)
