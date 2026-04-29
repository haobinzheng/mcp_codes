"""GFiber in-memory network agent (v2) using Google ADK + MCP.

This is the **ADK** CLI entrypoint: ``LlmAgent``, ``Runner``, ``McpTool``, and
``InMemorySessionService``. The original stdio client with the google-genai chat
loop lives in ``client_inmemory_v2.py`` (unchanged).

Run: ``python client_inmemory_v2_google_adk.py`` (or ``python client_inmemory_v2_adk.py``).

Logging (per session): by default under this repo's ``session_logs/`` (same folder tree as
this file), files ``session_<id>.jsonl`` and ``session_<id>.log``. Override with ``SESSION_LOG_DIR``.
That directory is tracked in git so you can ``git add`` / push logs from a remote host when sharing runs.
Env: ``GFIBER_SESSION_LOG_LEVEL`` (default INFO), ``GFIBER_LOG_CONSOLE=1`` to mirror the text log to stderr.
"""

import asyncio
import json
import logging
import os
import re
import time
import uuid
from typing import Any

from google import genai
from google.genai import types
from google.adk.agents import LlmAgent
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.runners import Runner
from google.adk.sessions.in_memory_session_service import InMemorySessionService
from google.adk.tools.mcp_tool.mcp_session_manager import MCPSessionManager
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
from google.adk.tools.mcp_tool.mcp_tool import McpTool
from mcp import StdioServerParameters


SERVER_PATH = os.path.join(os.getcwd(), "server_inmemory_v2.py")
# Default when GEMINI_MODEL_ID is unset (Gemini 2.5 Pro).
DEFAULT_GEMINI_MODEL_ID = "gemini-2.5-pro"
MODEL_ID = os.environ.get("GEMINI_MODEL_ID", DEFAULT_GEMINI_MODEL_ID)
CLIENT_VERSION = "v2-google-adk"
SERVER_VERSION = "v2"
MAX_MEMORY_HOSTS = 8
MAX_MEMORY_COMMANDS = 6
GFIBER_BOOKMARKS_VERSION = 1
# Default logs dir is always this repo's ``session_logs/`` (not cwd), so paths are stable for tooling.
_REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
SESSION_LOG_DIR = os.environ.get(
    "SESSION_LOG_DIR", os.path.join(_REPO_ROOT, "session_logs")
)


class SessionRecorder:
    """Append-only JSONL (machine-readable) plus a plain-text ``.log`` for running sessions."""

    def __init__(self, session_id: str, jsonl_path: str) -> None:
        self.session_id = session_id
        self.jsonl_path = jsonl_path
        self.text_log_path = (
            jsonl_path[:-6] + ".log" if jsonl_path.endswith(".jsonl") else jsonl_path + ".log"
        )
        level_name = os.environ.get("GFIBER_SESSION_LOG_LEVEL", "INFO").upper()
        level = getattr(logging, level_name, logging.INFO)
        self._logger = logging.getLogger(f"gfiber.adk.session.{session_id}")
        self._logger.handlers.clear()
        self._logger.setLevel(level)
        self._logger.propagate = False
        fmt = logging.Formatter(
            fmt="%(asctime)s | %(levelname)s | %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        fh = logging.FileHandler(self.text_log_path, encoding="utf-8")
        fh.setLevel(level)
        fh.setFormatter(fmt)
        self._logger.addHandler(fh)
        if os.environ.get("GFIBER_LOG_CONSOLE", "").lower() in ("1", "true", "yes"):
            ch = logging.StreamHandler()
            ch.setLevel(level)
            ch.setFormatter(fmt)
            self._logger.addHandler(ch)

    @staticmethod
    def _truncate(s: str, max_len: int) -> str:
        s = s.replace("\r\n", "\n")
        if len(s) <= max_len:
            return s
        return s[:max_len] + f"... ({len(s)} chars total)"

    def _format_text_row(self, row: dict[str, Any]) -> str:
        ev = row.get("event", "?")
        bits: list[str] = [str(ev)]
        for key in (
            "turn_id",
            "tool_name",
            "route",
            "duration_ms",
            "author",
            "invocation_id",
            "error",
            "reason",
            "event_count",
            "adk_tool_activity_events",
            "user_text_len",
            "response_len",
            "route",
        ):
            if key in row and row[key] is not None:
                bits.append(f"{key}={row[key]}")
        if "prompt" in row:
            p = str(row["prompt"])
            bits.append(f"prompt_len={len(p)}")
            bits.append(f"prompt_preview={self._truncate(p, 200)!r}")
        if "response" in row:
            r = str(row["response"])
            bits.append(f"response_len={len(r)}")
            bits.append(f"response_preview={self._truncate(r, 400)!r}")
        if "args" in row and row["args"] is not None:
            bits.append(f"args={self._truncate(json.dumps(row['args'], default=str), 600)}")
        if "result" in row and row["result"] is not None:
            r = str(row["result"])
            bits.append(f"result_len={len(r)}")
            bits.append(f"result_preview={self._truncate(r, 500)!r}")
        if "function_calls" in row and row["function_calls"] is not None:
            bits.append(f"function_calls={row['function_calls']}")
        if "function_responses" in row and row["function_responses"] is not None:
            bits.append(f"function_responses={row['function_responses']}")
        if "result_keys" in row:
            bits.append(f"result_keys={row['result_keys']}")
        if "result_size" in row:
            bits.append(f"result_size={row['result_size']}")
        return " | ".join(bits)

    def record(self, **fields: Any) -> None:
        if "event" not in fields:
            raise ValueError("SessionRecorder.record() requires event=...")
        row = {"session_id": self.session_id, "timestamp": time.time(), **fields}
        with open(self.jsonl_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, sort_keys=True, default=str) + "\n")
        self._logger.info(self._format_text_row(row))

SYSTEM_INSTRUCTION = """
You are the GFiber Network Intelligence Agent.

Use the MCP tools with this workflow:
1. Start audits with start_audit_run.
2. Check progress with get_audit_run_status when needed.
3. Read compact results with get_audit_run_summary before requesting detailed outputs.
4. Fetch host- or command-level details only when needed to support a conclusion.
4a. If the user asks to ping a device, never assume ping runs from the local server.
    Use ping_from_device with both source_hostname and target_hostname.
    If the user does not specify the source device, ask a short follow-up question asking where to run the ping from.
    When ping results are available, report the raw output plus the average latency. If asked, highlight the longest latency.
4b. If the user asks to collect BNG configuration, use collect_bng_configuration.
    That tool collects 'admin display-config' through gnetch, saves the original config, and rootifies it into the flat output directory.
    Report the saved original and flat file paths plus any tool errors.
4c. If the user asks to convert hierarchical SR OS configuration into flat format, use flatten_sros_config.
    If the pasted text includes [gl:/configure ...] or /configure ..., use that hierarchy automatically.
    If no hierarchy is present, ask the user for the current /configure hierarchy.
5. For hardware component questions and totals, use count_components or list_components instead of reasoning from raw text.
6. Default to exact matching for component names. Only use prefix or contains matching if the user explicitly asks for variants, prefixes, or fuzzy matches.
7. When you need evidence for a host or command, prefer get_analysis_context. It returns structured data when a parser exists and raw output otherwise.
8. For commands without structured parsing, use list_run_commands and get_raw_analysis_context to retrieve raw evidence before answering.
9. Use list_audit_log_runs, get_audit_log_summary, and get_audit_log_host_details when the user asks about prior runs.
10. Do not ask the server to use local files for state exchange; the server stores audit data in memory and persists audit logs for later analysis.

When the user asks for analysis over multiple commands, prefer:
- summary first
- then targeted lookups for specific hosts, commands, failures, or anomalies

When a run is still in progress, tell the user that the audit is still running and continue polling only if needed.
For arithmetic, totals, or per-device counts, do not calculate in free text if a server tool can compute the answer.
If no structured parser exists for a command, use the raw output returned by get_analysis_context and answer from that evidence.
"""

PASTE_MODE_HELP = (
    "Block prompt commands:\n"
    "- `:paste` or `:prompt` starts multi-line capture and submits when you enter `:end`.\n"
    "- `:paste flat-sros` or `:prompt flat-sros` starts multi-line SR OS capture and submits when you enter `:end`.\n"
    "- `:cancel` aborts the current block capture without sending anything.\n"
    "- `Ctrl-D` still ends block capture if needed, but `:end` is the preferred delimiter."
)


def _ensure_session_log_dir() -> None:
    os.makedirs(SESSION_LOG_DIR, exist_ok=True)


def _tool_result_text(result) -> str:
    if hasattr(result, "content") and result.content:
        texts = [getattr(item, "text", "") for item in result.content if getattr(item, "text", "")]
        if texts:
            return "\n".join(texts)
    return str(result)


def _tool_result_json(result) -> dict:
    text = _tool_result_text(result)
    return json.loads(text)


def _read_block_prompt() -> str | None:
    print("[*] Block prompt active. Paste or type the message body. Enter ':end' on its own line to submit.")
    print("[*] Enter ':cancel' on its own line to abort.")
    lines: list[str] = []
    while True:
        try:
            line = input()
        except EOFError:
            print("[*] Block prompt finished with Ctrl-D.")
            return "\n".join(lines).strip()
        if line.strip() == ":cancel":
            print("[*] Block prompt canceled.")
            return None
        if line.strip() == ":end":
            print("[*] Block prompt submitted.")
            return "\n".join(lines).strip()
        lines.append(line)


def _extract_hosts_from_text(text: str) -> list[str]:
    pattern = r"\b[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*\d+\b"
    hosts = re.findall(pattern, text.lower())
    return sorted(set(hosts))


def _extract_commands_from_text(text: str) -> list[str]:
    commands = re.findall(r'"(show[^"]+)"', text, flags=re.IGNORECASE)
    if commands:
        return [command.strip() for command in commands]
    commands = re.findall(r"\bshow\s+[a-z0-9 _/-]+", text, flags=re.IGNORECASE)
    return [command.strip(" .,") for command in commands[:3]]


def _new_gfiber_bookmarks() -> dict:
    return {
        "v": GFIBER_BOOKMARKS_VERSION,
        "run_id": "",
        "focus": {"hosts": [], "commands": []},
        "picks": {"hosts": [], "destinations": []},
        "evidence": {"structured_summary": {}, "raw": {}},
        "ping": {"last_source": "", "last_target": ""},
        "pending": {"flat_sros": {"active": False, "hierarchy": ""}},
    }


def _pick_set(bookmarks: dict, kind: str, items: list) -> None:
    """Remember one explicit batch for follow-ups ('hosts' / 'destinations')."""
    normalized = [x for x in items if isinstance(x, str) and x.strip()]
    if not normalized:
        return
    picks = bookmarks.setdefault("picks", {})
    if kind == "hosts":
        picks["hosts"] = normalized[-MAX_MEMORY_HOSTS:]
    else:
        picks[kind] = normalized[-8:]


def _merge_tool_into_gfiber_bookmarks(bookmarks: dict, tool_name: str, data: dict) -> None:
    """Merge domain fields from any tool JSON; avoids per-tool caches elsewhere."""
    if not isinstance(data, dict):
        return
    focus = bookmarks.setdefault("focus", {"hosts": [], "commands": []})
    evidence = bookmarks.setdefault("evidence", {"structured_summary": {}, "raw": {}})
    ping_meta = bookmarks.setdefault("ping", {"last_source": "", "last_target": ""})

    run_id = data.get("run_id")
    if run_id:
        bookmarks["run_id"] = run_id

    hosts: list[str] = []
    if isinstance(data.get("hostname"), str) and data.get("hostname"):
        hosts.append(data["hostname"])
    if isinstance(data.get("hosts"), list):
        hosts.extend([host for host in data["hosts"] if isinstance(host, str)])
    if isinstance(data.get("per_host"), dict):
        hosts.extend(list(data["per_host"].keys()))
    if isinstance(data.get("items"), list):
        for item in data["items"]:
            if isinstance(item, dict) and isinstance(item.get("hostname"), str):
                hosts.append(item["hostname"])
    if hosts:
        merged_hosts = list(dict.fromkeys(focus["hosts"] + hosts))
        focus["hosts"] = merged_hosts[-MAX_MEMORY_HOSTS:]
    if data.get("hosts"):
        _pick_set(bookmarks, "hosts", [host for host in data["hosts"] if isinstance(host, str)])

    if tool_name == "ping_from_device":
        if data.get("source_hostname"):
            _pick_set(bookmarks, "hosts", [data["source_hostname"]])
            ping_meta["last_source"] = data["source_hostname"]
        if data.get("target_hostname"):
            _pick_set(bookmarks, "destinations", [data["target_hostname"]])
            ping_meta["last_target"] = data["target_hostname"]

    commands: list[str] = []
    command_value = data.get("command")
    if isinstance(command_value, str) and command_value:
        commands.append(command_value)
    if isinstance(data.get("commands"), list):
        commands.extend([command for command in data["commands"] if isinstance(command, str)])
    if isinstance(data.get("items"), list):
        for item in data["items"]:
            if isinstance(item, dict) and isinstance(item.get("command"), str) and item.get("command"):
                commands.append(item["command"])
    if commands:
        merged_commands = list(dict.fromkeys(focus["commands"] + commands))
        focus["commands"] = merged_commands[-MAX_MEMORY_COMMANDS:]

    if tool_name == "summarize_components" and data.get("summary"):
        evidence["structured_summary"] = data["summary"]
    elif tool_name == "get_raw_analysis_context" and data.get("items"):
        evidence["raw"] = {
            "run_id": data.get("run_id", ""),
            "command": data.get("command", ""),
            "question": data.get("question", ""),
            "truncated": data.get("truncated", False),
            "items": data.get("items", [])[:4],
        }


def _apply_prompt_to_gfiber_bookmarks(bookmarks: dict, prompt: str) -> None:
    focus = bookmarks.setdefault("focus", {"hosts": [], "commands": []})
    hosts = _extract_hosts_from_text(prompt)
    if hosts:
        merged_hosts = list(dict.fromkeys(focus["hosts"] + hosts))
        focus["hosts"] = merged_hosts[-MAX_MEMORY_HOSTS:]
        _pick_set(bookmarks, "hosts", hosts[-MAX_MEMORY_HOSTS:])
    commands = _extract_commands_from_text(prompt)
    if commands:
        merged_commands = list(dict.fromkeys(focus["commands"] + commands))
        focus["commands"] = merged_commands[-MAX_MEMORY_COMMANDS:]
    ping_target = _extract_ping_target(prompt)
    if ping_target:
        _pick_set(bookmarks, "destinations", [ping_target])


def _prompt_refers_to_previous_selection(prompt: str) -> bool:
    lower_prompt = prompt.lower()
    return any(
        term in lower_prompt
        for term in (
            "same ",
            "above",
            "those",
            "that list",
            "previous",
            "following",
            "same format",
        )
    )


def _resolve_host_pick(bookmarks: dict, prompt: str) -> list[str] | None:
    if not _prompt_refers_to_previous_selection(prompt):
        return None
    hosts = bookmarks.get("picks", {}).get("hosts", [])
    return hosts if hosts else None


def _latest_host_pick(bookmarks: dict) -> list[str]:
    return list(bookmarks.get("picks", {}).get("hosts", []))


def _format_gfiber_bookmarks_for_prompt(bookmarks: dict) -> str:
    lines = ["Session bookmark:"]
    if bookmarks.get("run_id"):
        lines.append(f'- Last run id: {bookmarks["run_id"]}')
    focus = bookmarks.get("focus", {})
    fh = focus.get("hosts", [])
    if fh:
        lines.append("- Focus hosts: " + ", ".join(fh[-MAX_MEMORY_HOSTS:]))
    fc = focus.get("commands", [])
    if fc:
        lines.append("- Focus commands: " + ", ".join(fc[-MAX_MEMORY_COMMANDS:]))
    structured_summary = bookmarks.get("evidence", {}).get("structured_summary") or {}
    if structured_summary:
        categories = []
        for component_type, descriptions in structured_summary.items():
            categories.extend(f"{component_type}:{name}" for name in list(descriptions.keys())[:3])
        if categories:
            lines.append("- Structured categories: " + ", ".join(categories[:8]))
    raw_context = bookmarks.get("evidence", {}).get("raw") or {}
    if raw_context:
        summary = [f'run={raw_context.get("run_id", "")}']
        if raw_context.get("command"):
            summary.append(f'command={raw_context["command"]}')
        summary.append(f'items={len(raw_context.get("items", []))}')
        if raw_context.get("truncated"):
            summary.append("truncated=true")
        lines.append("- Last raw evidence: " + ", ".join(summary))
    return "\n".join(lines)


def _gfiber_bookmark_one_liner(bookmarks: dict) -> str:
    parts: list[str] = []
    if bookmarks.get("run_id"):
        parts.append(f"run={bookmarks['run_id']}")
    fh = bookmarks.get("focus", {}).get("hosts", [])
    if fh:
        parts.append(f'hosts={",".join(fh[-4:])}')
    fc = bookmarks.get("focus", {}).get("commands", [])
    if fc:
        parts.append(f"cmds={len(fc)}")
    return "; ".join(parts) if parts else "(empty)"


class GfiberBookmarkPlugin(BasePlugin):
    """Merge MCP tool JSON into shared bookmarks; mirror a one-liner into session.state."""

    def __init__(self, bookmarks: dict, session_log: SessionRecorder | None = None) -> None:
        super().__init__()
        self._bookmarks = bookmarks
        self._session_log = session_log

    async def after_tool_callback(
        self,
        *,
        tool,
        tool_args: dict,
        tool_context,
        result: dict,
    ):
        if not isinstance(result, dict):
            return None
        tool_name = getattr(tool, "name", "") or ""
        _merge_tool_into_gfiber_bookmarks(self._bookmarks, tool_name, result)
        state = getattr(tool_context, "state", None)
        if state is not None:
            state["app:gfiber_bookmark"] = _gfiber_bookmark_one_liner(self._bookmarks)
        if self._session_log is not None:
            try:
                payload = json.dumps(result, default=str)
            except TypeError:
                payload = str(result)
            self._session_log.record(
                event="adk_mcp_tool_callback",
                tool_name=tool_name,
                result_keys=sorted(result.keys()),
                result_size=len(payload),
            )
        return None


async def _call_tool_logged(
    session, session_log: SessionRecorder, session_id: str, turn_id: str, tool_name: str, args: dict
):
    session_log.record(
        event="tool_call",
        turn_id=turn_id,
        tool_name=tool_name,
        args=args,
    )
    result = await session.call_tool(tool_name, args)
    result_text = _tool_result_text(result)
    session_log.record(
        event="tool_result",
        turn_id=turn_id,
        tool_name=tool_name,
        result=result_text,
    )
    return result


async def _get_latest_run_id(session, session_log: SessionRecorder, session_id: str, turn_id: str) -> str | None:
    result = await _call_tool_logged(session, session_log, session_id, turn_id, "list_audit_runs", {})
    data = _tool_result_json(result)
    runs = data.get("runs", [])
    if runs:
        runs = sorted(
            runs,
            key=lambda item: item.get("created_at") or item.get("completed_at") or 0,
            reverse=True,
        )
        return runs[0].get("run_id")

    result = await _call_tool_logged(session, session_log, session_id, turn_id, "list_audit_log_runs", {})
    data = _tool_result_json(result)
    runs = data.get("runs", [])
    if runs:
        runs = sorted(
            runs,
            key=lambda item: item.get("created_at") or item.get("completed_at") or 0,
            reverse=True,
        )
        return runs[0].get("run_id")
    return None


def _extract_component_name(prompt: str) -> str:
    quoted = re.findall(r'"([^"]+)"', prompt)
    if quoted:
        return quoted[-1]

    patterns = [
        r"total number of\s+([A-Za-z0-9\-\+ ]+)",
        r"count\s+([A-Za-z0-9\-\+ ]+)",
        r"how many\s+([A-Za-z0-9\-\+ ]+)",
    ]
    lower_prompt = prompt.lower()
    for pattern in patterns:
        match = re.search(pattern, lower_prompt)
        if match:
            return prompt[match.start(1):match.end(1)].strip(" .,:")
    return ""


def _detect_component_type(prompt: str) -> str:
    lower_prompt = prompt.lower()
    if "routing engine" in lower_prompt or "re-s-" in lower_prompt:
        return "routing_engine"
    if "line card" in lower_prompt or "mpc" in lower_prompt or "fpc" in lower_prompt:
        return "line_card"
    if "control board" in lower_prompt or "scb" in lower_prompt:
        return "control_board"
    if "chassis" in lower_prompt:
        return "chassis"
    return ""


def _looks_like_hardware_count_prompt(prompt: str) -> bool:
    lower_prompt = prompt.lower()
    count_terms = ("count", "total", "how many", "calculate", "number of", "double check")
    hardware_terms = (
        "hardware",
        "component",
        "chassis",
        "routing engine",
        "re-s-",
        "scb",
        "control board",
        "line card",
        "mpc",
        "mpce",
        "mrate",
        "fpc",
    )
    return any(term in lower_prompt for term in count_terms) and any(
        term in lower_prompt for term in hardware_terms
    )


def _looks_like_audit_start_prompt(prompt: str) -> bool:
    lower_prompt = prompt.lower()
    audit_terms = (
        "audit ",
        "audit the",
        "run audit",
        "using command",
        "based on file",
        "device ",
        "devices ",
        ".txt",
    )
    return "audit" in lower_prompt and any(term in lower_prompt for term in audit_terms)


def _looks_like_audit_summary_prompt(prompt: str) -> bool:
    lower_prompt = prompt.lower()
    summary_terms = (
        "each category",
        "hardware category",
        "total number",
        "total count",
        "print out total",
        "summary",
    )
    return _looks_like_audit_start_prompt(prompt) and any(term in lower_prompt for term in summary_terms)


def _format_component_summary(summary: dict) -> str:
    lines = ["Here is the verified component summary from the server-side structured counts:"]
    type_labels = {
        "chassis": "Chassis",
        "routing_engine": "Routing Engine",
        "control_board": "Control Board",
        "line_card": "Line Card",
    }
    for component_type, descriptions in summary.items():
        lines.append("")
        lines.append(f"{type_labels.get(component_type, component_type)}:")
        for description, count in descriptions.items():
            lines.append(f"- {description}: {count}")
    return "\n".join(lines)


def _flatten_summary_categories(summary: dict) -> list[tuple[str, str]]:
    items = []
    for component_type, descriptions in summary.items():
        for description in descriptions.keys():
            items.append((component_type, description))
    return items


def _looks_like_followup_category_prompt(prompt: str) -> bool:
    lower_prompt = prompt.lower()
    followup_terms = (
        "these categories",
        "same categories",
        "each category",
        "for each device",
        "per device",
        "device by device",
        "host by host",
        "counts for each device",
        "print out these categories",
        "same format",
        "break down",
        "breakdown",
    )
    return any(term in lower_prompt for term in followup_terms)


def _format_per_device_category_counts(results: list[dict]) -> str:
    lines = ["Here are the per-device counts for the requested categories:"]
    for item in results:
        lines.append("")
        lines.append(f'{item["component_type"]}: {item["name"]}')
        per_host = item.get("per_host", {})
        for hostname, count in per_host.items():
            lines.append(f"- {hostname}: {count}")
    return "\n".join(lines)


def _format_host_component_summary(per_host: dict) -> str:
    lines = ["Here is the hardware summary for each selected device:"]
    type_labels = {
        "chassis": "Chassis",
        "routing_engine": "Routing Engines",
        "control_board": "Control Boards",
        "line_card": "Line Cards",
    }
    for hostname, component_map in per_host.items():
        lines.append("")
        lines.append(f"**{hostname}**")
        for component_type, descriptions in component_map.items():
            label = type_labels.get(component_type, component_type)
            if len(descriptions) == 1 and component_type != "line_card":
                name, count = next(iter(descriptions.items()))
                lines.append(f"- {label}: {count}x {name}")
                continue
            lines.append(f"- {label}:")
            for name, count in descriptions.items():
                lines.append(f"  - {count}x {name}")
    return "\n".join(lines)


def _extract_ping_target(prompt: str) -> str:
    match = re.search(r"\bping\s+([A-Za-z0-9._:-]+)", prompt, flags=re.IGNORECASE)
    if not match:
        return ""
    return match.group(1).strip(" ,.")


def _extract_ping_sources(prompt: str) -> list[str]:
    lower_prompt = prompt.lower()
    source_text = ""
    if " from " in lower_prompt:
        source_text = prompt[lower_prompt.rfind(" from ") + 6 :]
    elif lower_prompt.startswith("from "):
        ping_index = lower_prompt.find(", ping ")
        if ping_index == -1:
            ping_index = lower_prompt.find(" ping ")
        if ping_index != -1:
            source_text = prompt[5:ping_index]
    if not source_text:
        return []
    return _extract_hosts_from_text(source_text)


def _looks_like_ping_prompt(prompt: str) -> bool:
    return "ping " in prompt.lower() or prompt.lower().startswith("ping")


def _looks_like_flat_sros_prompt(prompt: str) -> bool:
    lower_prompt = prompt.lower()
    has_sros_shape = (
        "[gl:/configure" in lower_prompt
        or "\n/configure" in lower_prompt
        or lower_prompt.startswith("/configure")
        or "# info" in lower_prompt
    )
    has_flatten_intent = any(
        term in lower_prompt
        for term in (
            "flat format",
            "flatten",
            "flat sros",
            "convert sros",
            "sros configuration into flat",
        )
    )
    return has_sros_shape and has_flatten_intent


def _has_flat_sros_intent(prompt: str) -> bool:
    lower_prompt = prompt.lower()
    return any(
        term in lower_prompt
        for term in (
            "flat format",
            "flatten",
            "flat sros",
            "convert sros",
            "convert sors",
            "sros configuration into flat",
            "sr os configuration into flat",
        )
    )


def _looks_like_sros_config_payload(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    lower_text = stripped.lower()
    if "# info" in lower_text:
        return True
    if "{" in stripped or "}" in stripped:
        return True
    config_markers = (
        '\n    ',
        '\n\t',
        'ies "',
        'vprn ',
        'interface "',
        "sap ",
        "admin-state ",
        "service-id ",
        "customer ",
        "address ",
        "prefix-length ",
        "ping-reply ",
    )
    return any(marker in lower_text for marker in config_markers)


def _extract_flat_sros_payload(prompt: str) -> str:
    text = prompt.strip()
    if not text:
        return ""

    marker_patterns = (
        r"here\s+is\s+the\s+configuration\s*:\s*",
        r"here\s+is\s+the\s+sros\s+configuration\s*:\s*",
        r"configuration\s*:\s*",
        r"config\s*:\s*",
        r"following\s+sros\s+configuration\s*:\s*",
        r"following\s+configuration\s*:\s*",
    )
    for pattern in marker_patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL)
        if match:
            return text[match.end() :].strip()

    if "\n" in text:
        first_line, remainder = text.split("\n", 1)
        if _has_flat_sros_intent(first_line):
            return remainder.strip()

    if _looks_like_sros_config_payload(text):
        return text
    return ""


def _extract_explicit_hierarchy(prompt: str) -> str:
    match = re.search(r"(\[gl:(/configure[^\]]*)\])", prompt, flags=re.IGNORECASE)
    if match:
        return match.group(2).strip()
    match = re.search(r"(^|\s)(/configure[^\n\r]*)", prompt, flags=re.IGNORECASE)
    if match:
        return match.group(2).strip()
    return ""


def _format_flat_sros_result(data: dict) -> str:
    if data.get("error"):
        return f"Unable to flatten the SR OS configuration.\n\n{data['error']}"

    lines = [
        f'Flattened SR OS configuration using hierarchy `{data.get("hierarchy", "")}`.',
        f'- Flat lines: {data.get("line_count", 0)}',
        "",
        "Flat configuration:",
        "```",
        data.get("flat_text", ""),
        "```",
    ]
    return "\n".join(lines)


async def _handle_deterministic_flat_sros(
    session,
    session_log: SessionRecorder,
    session_id: str,
    turn_id: str,
    prompt: str,
    gfiber_bookmarks: dict,
) -> str | None:
    pending_flat_sros = gfiber_bookmarks.setdefault("pending", {}).setdefault(
        "flat_sros",
        {"active": False, "hierarchy": ""},
    )
    explicit_hierarchy = _extract_explicit_hierarchy(prompt)
    if explicit_hierarchy:
        pending_flat_sros["hierarchy"] = explicit_hierarchy

    has_intent = _has_flat_sros_intent(prompt)
    payload = _extract_flat_sros_payload(prompt)
    payload_looks_like_config = _looks_like_sros_config_payload(payload)
    should_continue_pending = pending_flat_sros.get("active", False) and _looks_like_sros_config_payload(prompt)

    if not has_intent and not should_continue_pending and not _looks_like_flat_sros_prompt(prompt):
        return None

    if has_intent and not payload_looks_like_config:
        pending_flat_sros["active"] = True
        hierarchy = pending_flat_sros.get("hierarchy", "")
        if hierarchy:
            return (
                f"I have the SR OS hierarchy `{hierarchy}`. "
                "Paste the configuration block next, and I will flatten it."
            )
        return (
            "Paste the SR OS configuration block next. "
            "If it does not include `[gl:/configure ...]` or `/configure ...`, include the current hierarchy too."
        )

    if should_continue_pending and not payload_looks_like_config:
        payload = prompt.strip()
        payload_looks_like_config = _looks_like_sros_config_payload(payload)

    if not payload_looks_like_config:
        return None

    hierarchy = pending_flat_sros.get("hierarchy", "") or explicit_hierarchy
    result = await _call_tool_logged(
        session,
        session_log,
        session_id,
        turn_id,
        "flatten_sros_config",
        {
            "raw_text": payload,
            "hierarchy": hierarchy,
        },
    )
    data = _tool_result_json(result)
    _merge_tool_into_gfiber_bookmarks(gfiber_bookmarks, "flatten_sros_config", data)
    pending_flat_sros["active"] = False
    pending_flat_sros["hierarchy"] = ""
    return _format_flat_sros_result(data)


def _looks_like_bng_config_prompt(prompt: str) -> bool:
    lower_prompt = prompt.lower()
    has_host = bool(_extract_hosts_from_text(prompt))
    has_bng_term = "bng" in lower_prompt or "bgn" in lower_prompt
    has_config_term = any(
        term in lower_prompt
        for term in (
            "collect configuration",
            "collect config",
            "collection configuration",
            "collection config",
            "collect the configuration",
            "collect the config",
            "configuration",
            "config",
            "display-config",
        )
    )
    has_collect_term = any(
        term in lower_prompt
        for term in (
            "collect",
            "collection",
            "get",
            "grab",
            "pull",
            "save",
        )
    )
    return has_host and has_bng_term and has_config_term and has_collect_term


def _looks_ambiguous_bng_prompt(prompt: str) -> bool:
    lower_prompt = prompt.lower()
    if not bool(_extract_hosts_from_text(prompt)):
        return False
    suspicious_terms = ("gnb", "bgnn", "bngg")
    has_suspicious_term = any(term in lower_prompt for term in suspicious_terms)
    has_config_term = "config" in lower_prompt or "configuration" in lower_prompt
    has_collect_term = any(
        term in lower_prompt for term in ("collect", "collection", "get", "grab", "pull", "save")
    )
    return has_suspicious_term and has_config_term and has_collect_term


def _format_bng_collection_result(data: dict) -> str:
    if data.get("error") or data.get("exit_code") not in (0, None):
        details = data.get("stderr") or data.get("error") or "Collection failed."
        return (
            f'Failed to collect configuration from `{data.get("hostname", "")}`.\n\n'
            f"{details}"
        )

    lines = [f'Collected configuration from `{data.get("hostname", "")}`.']
    lines.append(f'- Original config: `{data.get("original_path", "")}`')
    lines.append(f'- Flat config: `{data.get("flat_path", "")}`')
    lines.append(f'- Lines collected: {data.get("lines_collected", 0)}')
    lines.append(f'- Bytes collected: {data.get("bytes_collected", 0)}')
    if data.get("rootifier_exit_code") not in (0, None):
        lines.append("")
        lines.append(
            f'Rootifier failed with exit code {data.get("rootifier_exit_code")}: '
            f'{data.get("rootifier_stderr", "")}'
        )
    elif data.get("rootifier_stderr"):
        lines.append("")
        lines.append(f'Rootifier note: {data.get("rootifier_stderr")}')
    return "\n".join(lines)


async def _handle_deterministic_bng_config_collection(
    session,
    session_log: SessionRecorder,
    session_id: str,
    turn_id: str,
    prompt: str,
    gfiber_bookmarks: dict,
) -> str | None:
    if _looks_ambiguous_bng_prompt(prompt):
        hosts = _extract_hosts_from_text(prompt)
        hostname = hosts[0] if hosts else "that device"
        return f"Did you mean collect BNG configuration on `{hostname}`?"

    if not _looks_like_bng_config_prompt(prompt):
        return None

    hosts = _extract_hosts_from_text(prompt)
    if not hosts:
        return "Which BNG should I collect the configuration from?"

    hostname = hosts[0]
    result = await _call_tool_logged(
        session,
        session_log,
        session_id,
        turn_id,
        "collect_bng_configuration",
        {"hostname": hostname},
    )
    data = _tool_result_json(result)
    _merge_tool_into_gfiber_bookmarks(gfiber_bookmarks, "collect_bng_configuration", data)
    return _format_bng_collection_result(data)


def _format_ping_result(data: dict, highlight_longest: bool) -> str:
    source = data.get("source_hostname", "")
    target = data.get("target_hostname", "")
    stderr = data.get("stderr", "")
    raw_output = data.get("raw_output", "").strip()
    latencies = [value for value in data.get("latencies_ms", []) if isinstance(value, (int, float))]
    average = data.get("average_latency_ms")
    packet_loss = data.get("packet_loss_percent")
    exit_code = data.get("exit_code")
    packets_received = data.get("packets_received")

    if exit_code != 0 or stderr or packets_received == 0 or packet_loss == 100.0:
        detail = stderr or "Ping failed."
        if raw_output:
            detail = f"{detail}\n\n```\n{raw_output}\n```"
        return f'The ping from `{source}` to `{target}` failed.\n\n{detail}'

    lines = [f"The ping from `{source}` to `{target}` was successful."]
    if average is not None:
        lines.append(f"- Average latency: {average:.3f} ms")
    if packet_loss is not None:
        lines.append(f"- Packet loss: {packet_loss}%")
    if highlight_longest and latencies:
        lines.append(f"- Longest latency: {max(latencies):.3f} ms")
    if raw_output:
        lines.append("")
        lines.append("Raw output:")
        lines.append("```")
        lines.append(raw_output)
        lines.append("```")
    return "\n".join(lines)


async def _handle_deterministic_ping(
    session,
    session_log: SessionRecorder,
    session_id: str,
    turn_id: str,
    prompt: str,
    gfiber_bookmarks: dict,
) -> str | None:
    if not _looks_like_ping_prompt(prompt):
        return None

    target = _extract_ping_target(prompt)
    source_hosts = _extract_ping_sources(prompt)
    if not source_hosts:
        picked = _resolve_host_pick(gfiber_bookmarks, prompt)
        if picked:
            source_hosts = picked[:MAX_MEMORY_HOSTS]
    if not target:
        return None
    if not source_hosts:
        return f"Where should I run the ping from for `{target}`?"

    highlight_longest = "longest latency" in prompt.lower() or "highlight" in prompt.lower()
    results = []
    for source in source_hosts:
        result = await _call_tool_logged(
            session,
            session_log,
            session_id,
            turn_id,
            "ping_from_device",
            {
                "source_hostname": source,
                "target_hostname": target,
            },
        )
        data = _tool_result_json(result)
        _merge_tool_into_gfiber_bookmarks(gfiber_bookmarks, "ping_from_device", data)
        results.append(_format_ping_result(data, highlight_longest))

    return "\n\n".join(results)


async def _answer_from_raw_context(
    genai_client: genai.Client,
    model_id: str,
    prompt: str,
    raw_context: dict,
) -> str:
    grounded_prompt = (
        "Answer the user's request using only the raw command evidence below.\n\n"
        f"User request:\n{prompt}\n\n"
        "Raw evidence context:\n"
        f"{json.dumps(raw_context, indent=2, sort_keys=True)}\n\n"
        "Rules:\n"
        "- Do not invent data that is not present in the evidence.\n"
        "- If the evidence is partial or truncated, say so.\n"
        "- If an exact count cannot be determined from the provided evidence, say that clearly.\n"
        "- Keep the answer concise and cite hostnames when useful.\n"
    )
    chat = genai_client.aio.chats.create(
        model=model_id,
        config=types.GenerateContentConfig(),
    )
    response = await chat.send_message(grounded_prompt)
    return response.text or "No answer was generated from the raw evidence."


async def _handle_deterministic_hardware_count(
    session,
    session_log: SessionRecorder,
    session_id: str,
    turn_id: str,
    prompt: str,
    deterministic_state: dict,
    gfiber_bookmarks: dict,
) -> str | None:
    if not _looks_like_hardware_count_prompt(prompt) and not (
        deterministic_state.get("last_summary") and _looks_like_followup_category_prompt(prompt)
    ):
        return None
    if _looks_like_audit_start_prompt(prompt):
        return None

    run_id = await _get_latest_run_id(session, session_log, session_id, turn_id)
    if not run_id:
        return "No audit run is available to count against."

    lower_prompt = prompt.lower()
    picked = _resolve_host_pick(gfiber_bookmarks, prompt)
    if not picked and (
        "for each device" in lower_prompt
        or "per device" in lower_prompt
        or "device by device" in lower_prompt
        or "host by host" in lower_prompt
        or "same format" in lower_prompt
        or "all hardware summary for each device" in lower_prompt
    ):
        picked = _latest_host_pick(gfiber_bookmarks)
    selected_hosts = picked[:MAX_MEMORY_HOSTS] if picked else []

    if selected_hosts and (
        "for each device" in lower_prompt
        or "per device" in lower_prompt
        or "device by device" in lower_prompt
        or "host by host" in lower_prompt
        or "same format" in lower_prompt
        or "all hardware summary for each device" in lower_prompt
    ):
        result = await _call_tool_logged(
            session,
            session_log,
            session_id,
            turn_id,
            "get_host_component_summary",
            {
                "run_id": run_id,
                "hosts": ",".join(selected_hosts),
            },
        )
        data = _tool_result_json(result)
        per_host = data.get("per_host", {})
        if not per_host:
            return "No structured component data was found for the selected hosts."
        _merge_tool_into_gfiber_bookmarks(gfiber_bookmarks, "get_host_component_summary", data)
        deterministic_state["last_run_id"] = run_id
        return _format_host_component_summary(per_host)

    if "all the hard" in lower_prompt or "all hardware" in lower_prompt or "each category" in lower_prompt:
        result = await _call_tool_logged(
            session,
            session_log,
            session_id,
            turn_id,
            "summarize_components",
            {
                "run_id": run_id,
                "hosts": ",".join(selected_hosts) if selected_hosts else "",
            },
        )
        data = _tool_result_json(result)
        summary = data.get("summary", {})
        if not summary:
            return (
                "The selected audit run does not contain structured component data yet. "
                "Please run a fresh audit or use the normal analysis path."
            )
        deterministic_state["last_summary"] = summary
        deterministic_state["last_run_id"] = run_id
        _merge_tool_into_gfiber_bookmarks(gfiber_bookmarks, "summarize_components", data)
        return _format_component_summary(summary)

    if deterministic_state.get("last_summary") and _looks_like_followup_category_prompt(prompt):
        results = []
        for component_type, name in _flatten_summary_categories(deterministic_state["last_summary"]):
            result = await _call_tool_logged(
                session,
                session_log,
                session_id,
                turn_id,
                "count_components",
                {
                    "run_id": deterministic_state.get("last_run_id", run_id),
                    "name": name,
                    "component_type": component_type,
                    "match_mode": "exact",
                    "hosts": ",".join(selected_hosts) if selected_hosts else "",
                },
            )
            data = _tool_result_json(result)
            if data.get("error"):
                continue
            _merge_tool_into_gfiber_bookmarks(gfiber_bookmarks, "count_components", data)
            results.append(
                {
                    "component_type": component_type,
                    "name": name,
                    "per_host": data.get("per_host", {}),
                }
            )
        return _format_per_device_category_counts(results)

    name = _extract_component_name(prompt)
    component_type = _detect_component_type(prompt)
    if not name:
        return None

    result = await _call_tool_logged(
        session,
        session_log,
        session_id,
        turn_id,
        "count_components",
        {
                    "run_id": run_id,
                    "name": name,
                    "component_type": component_type,
                    "match_mode": "exact",
                    "hosts": ",".join(selected_hosts) if selected_hosts else "",
                },
    )
    data = _tool_result_json(result)
    if data.get("error"):
        return f"Error: {data['error']}"

    total_count = data.get("total_count", 0)
    host_count = data.get("host_count", 0)
    per_host = data.get("per_host", {})
    _merge_tool_into_gfiber_bookmarks(gfiber_bookmarks, "count_components", data)
    deterministic_state["last_summary"] = {
        component_type or "unknown": {
            name: total_count,
        }
    }
    deterministic_state["last_run_id"] = run_id
    response_lines = [
        f'The verified total number of "{name}" is {total_count} across {host_count} devices.'
    ]
    if "list" in lower_prompt or "each device" in lower_prompt or "per device" in lower_prompt:
        response_lines.append("")
        response_lines.append("Per-device counts:")
        for hostname, count in per_host.items():
            response_lines.append(f"- {hostname}: {count}")
    return "\n".join(response_lines)


async def _wait_for_run_completion(
    session, session_log: SessionRecorder, session_id: str, turn_id: str, run_id: str
) -> dict:
    for _ in range(60):
        result = await _call_tool_logged(
            session,
            session_log,
            session_id,
            turn_id,
            "get_audit_run_status",
            {"run_id": run_id},
        )
        data = _tool_result_json(result)
        state = data.get("state")
        if state in {"completed", "failed"}:
            return data
        await asyncio.sleep(1)
    return {"error": f"Timed out waiting for audit run {run_id} to complete."}


def _extract_audit_inputs(prompt: str) -> tuple[str, str] | tuple[None, None]:
    quoted = re.findall(r'"([^"]+)"', prompt)
    command = quoted[0].strip() if quoted else ""

    file_match = re.search(r"\b([\w.\-]+\.txt)\b", prompt)
    devices = file_match.group(1) if file_match else ""

    if command and devices:
        return devices, command
    return None, None


async def _handle_deterministic_audit_summary(
    session,
    genai_client: genai.Client,
    session_log: SessionRecorder,
    session_id: str,
    turn_id: str,
    prompt: str,
    deterministic_state: dict,
    gfiber_bookmarks: dict,
) -> str | None:
    if not _looks_like_audit_summary_prompt(prompt):
        return None

    devices, command = _extract_audit_inputs(prompt)
    if not devices or not command:
        return None

    result = await _call_tool_logged(
        session,
        session_log,
        session_id,
        turn_id,
        "start_audit_run",
        {"devices": devices, "commands": command},
    )
    data = _tool_result_json(result)
    run_id = data.get("run_id")
    if not run_id:
        return "Unable to start the audit run."

    status = await _wait_for_run_completion(session, session_log, session_id, turn_id, run_id)
    if status.get("error"):
        return f"Error: {status['error']}"
    if status.get("state") != "completed":
        return f'Audit run {run_id} ended with state: {status.get("state")}.'
    _merge_tool_into_gfiber_bookmarks(gfiber_bookmarks, "start_audit_run", data)

    result = await _call_tool_logged(
        session,
        session_log,
        session_id,
        turn_id,
        "summarize_components",
        {"run_id": run_id},
    )
    data = _tool_result_json(result)
    summary = data.get("summary", {})
    if not summary:
        raw_result = await _call_tool_logged(
            session,
            session_log,
            session_id,
            turn_id,
            "get_raw_analysis_context",
            {
                "run_id": run_id,
                "question": prompt,
                "command": command,
            },
        )
        raw_data = _tool_result_json(raw_result)
        if raw_data.get("error"):
            return (
                "The completed audit run did not produce structured component data, "
                f"and raw evidence lookup failed: {raw_data['error']}"
            )
        _merge_tool_into_gfiber_bookmarks(gfiber_bookmarks, "get_raw_analysis_context", raw_data)
        deterministic_state["last_run_id"] = run_id
        deterministic_state["last_summary"] = {}
        return await _answer_from_raw_context(genai_client, MODEL_ID, prompt, raw_data)

    _merge_tool_into_gfiber_bookmarks(gfiber_bookmarks, "summarize_components", data)
    deterministic_state["last_summary"] = summary
    deterministic_state["last_run_id"] = run_id
    return _format_component_summary(summary)


async def _run_adk_turn(
    runner: Runner,
    *,
    user_id: str,
    session_id: str,
    user_text: str,
    session_log: SessionRecorder,
    turn_id: str,
) -> str:
    """Runs one user turn through ADK; MCP tool calls are handled by the agent runtime."""
    session_log.record(event="adk_turn_start", turn_id=turn_id, user_text_len=len(user_text))
    t0 = time.time()
    new_message = types.Content(role="user", parts=[types.Part(text=user_text)])
    last_text = ""
    activity_events = 0
    async for event in runner.run_async(
        user_id=user_id,
        session_id=session_id,
        new_message=new_message,
    ):
        calls = event.get_function_calls()
        responses = event.get_function_responses()
        call_names = [c.name for c in calls if getattr(c, "name", None)]
        resp_names = [r.name for r in responses if getattr(r, "name", None)]
        if call_names or resp_names:
            activity_events += 1
            session_log.record(
                event="adk_tool_activity",
                turn_id=turn_id,
                author=getattr(event, "author", ""),
                function_calls=call_names,
                function_responses=resp_names,
            )
        if not event.content or not event.content.parts:
            continue
        if event.is_final_response():
            last_text = "".join(
                part.text
                for part in event.content.parts
                if part.text and not getattr(part, "thought", False)
            )
    elapsed_ms = int((time.time() - t0) * 1000)
    last_text = last_text.strip() or "No model text returned."
    session_log.record(
        event="adk_turn_complete",
        turn_id=turn_id,
        duration_ms=elapsed_ms,
        adk_tool_activity_events=activity_events,
        response_len=len(last_text),
    )
    return last_text


ADK_APP_NAME = "gfiber_inmemory_v2_adk"
ADK_USER_ID = "local"


async def run_intelligent_agent() -> None:
    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        print("Error: Set GEMINI_API_KEY or GOOGLE_API_KEY.")
        return
    if not os.environ.get("GOOGLE_API_KEY"):
        os.environ["GOOGLE_API_KEY"] = api_key

    if not os.path.exists(SERVER_PATH):
        print(f"Error: Server not found at {SERVER_PATH}")
        return

    genai_client = genai.Client(api_key=api_key)
    connection_params = StdioConnectionParams(
        server_params=StdioServerParameters(
            command="python3",
            args=[SERVER_PATH],
            env=os.environ.copy(),
        ),
    )
    mcp_manager = MCPSessionManager(connection_params)
    _ensure_session_log_dir()
    session_id = uuid.uuid4().hex[:12]
    session_log_file = os.path.join(SESSION_LOG_DIR, f"session_{session_id}.jsonl")
    session_log = SessionRecorder(session_id, session_log_file)

    try:
        mcp_session = await mcp_manager.create_session()
        tools_response = await mcp_session.list_tools()
        mcp_tools = [
            McpTool(
                mcp_tool=t,
                mcp_session_manager=mcp_manager,
            )
            for t in tools_response.tools
        ]

        gfiber_bookmarks = _new_gfiber_bookmarks()
        bookmark_plugin = GfiberBookmarkPlugin(gfiber_bookmarks, session_log)

        root_agent = LlmAgent(
            model=MODEL_ID,
            name="gfiber_network_agent",
            instruction=SYSTEM_INSTRUCTION,
            tools=mcp_tools,
        )
        session_service = InMemorySessionService()
        runner = Runner(
            app_name=ADK_APP_NAME,
            agent=root_agent,
            session_service=session_service,
            auto_create_session=True,
            plugins=[bookmark_plugin],
        )

        print("\n" + "=" * 60)
        print(f" GFIBER IN-MEMORY AGENT (ADK): {MODEL_ID}")
        print(" Type 'exit' or 'quit' to end the session.")
        print(f" Session JSONL: {session_log.jsonl_path}")
        print(f" Session text log: {session_log.text_log_path}")
        print("=" * 60)

        session_log.record(
            event="session_started",
            client_version=CLIENT_VERSION,
            framework="google-adk",
            model_id=MODEL_ID,
            server_path=SERVER_PATH,
            server_version=SERVER_VERSION,
        )

        deterministic_state: dict = {}

        while True:
            prompt = input("\n[USER]: ").strip()
            if prompt.lower() in [":help", "help paste", ":help paste"]:
                print(PASTE_MODE_HELP)
                continue
            if prompt.lower() in [":paste", ":prompt", ":paste flat-sros", ":prompt flat-sros"]:
                pasted_block = _read_block_prompt()
                if pasted_block is None:
                    continue
                if not pasted_block:
                    print("[*] No pasted text captured.")
                    continue
                if prompt.lower() in [":paste flat-sros", ":prompt flat-sros"]:
                    prompt = f"convert sros configuration into flat format\n{pasted_block}"
                else:
                    prompt = pasted_block
            if prompt.lower() in ["exit", "quit", "goodbye", "bye"]:
                session_log.record(event="session_ended", reason="user_exit")
                print("\n[*] Closing session. Goodbye!\n")
                break
            if not prompt:
                continue

            try:
                turn_id = uuid.uuid4().hex[:12]
                session_log.record(event="user_prompt", turn_id=turn_id, prompt=prompt)
                _apply_prompt_to_gfiber_bookmarks(gfiber_bookmarks, prompt)

                route = "adk"
                deterministic_response = await _handle_deterministic_audit_summary(
                    mcp_session,
                    genai_client,
                    session_log,
                    session_id,
                    turn_id,
                    prompt,
                    deterministic_state,
                    gfiber_bookmarks,
                )
                if deterministic_response is not None:
                    route = "deterministic_audit_summary"
                else:
                    deterministic_response = await _handle_deterministic_bng_config_collection(
                        mcp_session,
                        session_log,
                        session_id,
                        turn_id,
                        prompt,
                        gfiber_bookmarks,
                    )
                    if deterministic_response is not None:
                        route = "deterministic_bng"
                if deterministic_response is None:
                    deterministic_response = await _handle_deterministic_flat_sros(
                        mcp_session,
                        session_log,
                        session_id,
                        turn_id,
                        prompt,
                        gfiber_bookmarks,
                    )
                    if deterministic_response is not None:
                        route = "deterministic_flat_sros"
                if deterministic_response is None:
                    deterministic_response = await _handle_deterministic_ping(
                        mcp_session,
                        session_log,
                        session_id,
                        turn_id,
                        prompt,
                        gfiber_bookmarks,
                    )
                    if deterministic_response is not None:
                        route = "deterministic_ping"
                if deterministic_response is None:
                    deterministic_response = await _handle_deterministic_hardware_count(
                        mcp_session,
                        session_log,
                        session_id,
                        turn_id,
                        prompt,
                        deterministic_state,
                        gfiber_bookmarks,
                    )
                    if deterministic_response is not None:
                        route = "deterministic_hardware_count"

                if deterministic_response is not None:
                    session_log.record(
                        event="model_answer",
                        turn_id=turn_id,
                        route=route,
                        response=deterministic_response,
                    )
                    print(f"\n[AI]: {deterministic_response}")
                    continue

                enriched_prompt = (
                    f"{_format_gfiber_bookmarks_for_prompt(gfiber_bookmarks)}\n\n"
                    f"Current user request:\n{prompt}"
                )
                answer_text = await _run_adk_turn(
                    runner,
                    user_id=ADK_USER_ID,
                    session_id=session_id,
                    user_text=enriched_prompt,
                    session_log=session_log,
                    turn_id=turn_id,
                )
                session_log.record(
                    event="model_answer",
                    turn_id=turn_id,
                    route=route,
                    response=answer_text,
                )
                print(f"\n[AI]: {answer_text}")

            except KeyboardInterrupt:
                session_log.record(event="session_ended", reason="keyboard_interrupt")
                print("\n[*] Interrupted by user. Goodbye!\n")
                break
            except Exception as exc:
                session_log.record(
                    event="turn_error",
                    turn_id=turn_id if "turn_id" in locals() else None,
                    error=str(exc),
                )
                print(f"\n[!] Error: {exc}")
    finally:
        await mcp_manager.close()


if __name__ == "__main__":
    try:
        asyncio.run(run_intelligent_agent())
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user. Exiting...")
