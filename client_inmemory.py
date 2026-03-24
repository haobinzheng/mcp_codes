import asyncio
import json
import os
import re
import time
import uuid

from google import genai
from google.genai import types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


SERVER_PATH = os.path.join(os.getcwd(), "server_inmemory.py")
MODEL_ID = os.environ.get("GEMINI_MODEL_ID", "gemini-2.5-pro")
MAX_TOOL_LOOPS = 20
MAX_MEMORY_PROMPTS = 6
MAX_MEMORY_HOSTS = 8
MAX_MEMORY_COMMANDS = 6
MAX_INLINE_HOSTS = 12
MAX_MODEL_ANSWER_CHARS = 12000
RAW_CHUNK_CHARS = 4_000_000
MAX_DIRECT_RAW_MODEL_CHARS = 200_000
RAW_ANALYSIS_MAX_CHUNKS = 24
SESSION_LOG_DIR = os.environ.get(
    "SESSION_LOG_DIR", os.path.join(os.getcwd(), "session_logs")
)

SYSTEM_INSTRUCTION = """
You are the GFiber Network Intelligence Agent.

Use the MCP tools with this workflow:
1. Start audits with start_audit_run.
2. Check progress with get_audit_run_status when needed.
3. Read compact results with get_audit_run_summary before requesting detailed outputs.
4. Fetch host- or command-level details only when needed to support a conclusion.
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


def _ensure_session_log_dir() -> None:
    os.makedirs(SESSION_LOG_DIR, exist_ok=True)


def _write_session_log(log_file: str, event: dict) -> None:
    with open(log_file, "a") as f:
        f.write(json.dumps(event, sort_keys=True) + "\n")


def _tool_result_text(result) -> str:
    if hasattr(result, "content") and result.content:
        texts = [getattr(item, "text", "") for item in result.content if getattr(item, "text", "")]
        if texts:
            return "\n".join(texts)
    return str(result)


def _tool_result_json(result) -> dict:
    text = _tool_result_text(result)
    return json.loads(text)


def _limit_list(items: list, max_items: int) -> list:
    if len(items) <= max_items:
        return items
    return items[-max_items:]


def _extract_hosts_from_text(text: str) -> list[str]:
    pattern = r"\b[a-z]{2,}\d{2}\.[a-z]{3}\d{3}\b"
    hosts = re.findall(pattern, text.lower())
    return sorted(set(hosts))


def _extract_commands_from_text(text: str) -> list[str]:
    commands = re.findall(r'"(show[^"]+)"', text, flags=re.IGNORECASE)
    if commands:
        return [command.strip() for command in commands]
    commands = re.findall(r"\bshow\s+[a-z0-9 _/-]+", text, flags=re.IGNORECASE)
    return [command.strip(" .,") for command in commands[:3]]


def _new_session_memory() -> dict:
    return {
        "last_run_id": "",
        "last_hosts": [],
        "last_commands": [],
        "last_structured_summary": {},
        "last_raw_context": {},
        "last_active_raw_request": {},
        "recent_user_prompts": [],
    }


def _remember_user_prompt(session_memory: dict, prompt: str) -> None:
    session_memory["recent_user_prompts"] = _limit_list(
        session_memory.get("recent_user_prompts", []) + [prompt],
        MAX_MEMORY_PROMPTS,
    )
    hosts = _extract_hosts_from_text(prompt)
    if hosts:
        merged_hosts = list(dict.fromkeys(session_memory.get("last_hosts", []) + hosts))
        session_memory["last_hosts"] = merged_hosts[-MAX_MEMORY_HOSTS:]
    commands = _extract_commands_from_text(prompt)
    if commands:
        merged_commands = list(dict.fromkeys(session_memory.get("last_commands", []) + commands))
        session_memory["last_commands"] = merged_commands[-MAX_MEMORY_COMMANDS:]


def _remember_tool_data(session_memory: dict, tool_name: str, data: dict) -> None:
    run_id = data.get("run_id")
    if run_id:
        session_memory["last_run_id"] = run_id

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
        merged_hosts = list(dict.fromkeys(session_memory.get("last_hosts", []) + hosts))
        session_memory["last_hosts"] = merged_hosts[-MAX_MEMORY_HOSTS:]

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
        merged_commands = list(dict.fromkeys(session_memory.get("last_commands", []) + commands))
        session_memory["last_commands"] = merged_commands[-MAX_MEMORY_COMMANDS:]

    if tool_name == "summarize_components" and data.get("summary"):
        session_memory["last_structured_summary"] = data["summary"]
    elif tool_name == "get_raw_analysis_context" and data.get("items"):
        session_memory["last_raw_context"] = {
            "run_id": data.get("run_id", ""),
            "command": data.get("command", ""),
            "question": data.get("question", ""),
            "truncated": data.get("truncated", False),
            "items": data.get("items", [])[:4],
        }


def _build_memory_context(session_memory: dict) -> str:
    lines = ["Session memory:"]
    if session_memory.get("last_run_id"):
        lines.append(f'- Last run id: {session_memory["last_run_id"]}')
    if session_memory.get("last_hosts"):
        lines.append(
            "- Recent hosts: " + ", ".join(session_memory["last_hosts"][-MAX_MEMORY_HOSTS:])
        )
    if session_memory.get("last_commands"):
        lines.append(
            "- Recent commands: " + ", ".join(session_memory["last_commands"][-MAX_MEMORY_COMMANDS:])
        )
    structured_summary = session_memory.get("last_structured_summary", {})
    if structured_summary:
        categories = []
        for component_type, descriptions in structured_summary.items():
            categories.extend(f"{component_type}:{name}" for name in list(descriptions.keys())[:3])
        if categories:
            lines.append("- Last structured categories: " + ", ".join(categories[:8]))
    raw_context = session_memory.get("last_raw_context", {})
    if raw_context:
        summary = [f'run={raw_context.get("run_id", "")}']
        if raw_context.get("command"):
            summary.append(f'command={raw_context["command"]}')
        summary.append(f'items={len(raw_context.get("items", []))}')
        if raw_context.get("truncated"):
            summary.append("truncated=true")
        lines.append("- Last raw evidence: " + ", ".join(summary))
    active_raw = session_memory.get("last_active_raw_request", {})
    if active_raw:
        parts = [f'run={active_raw.get("run_id", "")}']
        if active_raw.get("hostname"):
            parts.append(f'host={active_raw["hostname"]}')
        if active_raw.get("command"):
            parts.append(f'command={active_raw["command"]}')
        if active_raw.get("chunked"):
            parts.append("chunked=true")
        lines.append("- Last active raw request: " + ", ".join(parts))
    prompts = session_memory.get("recent_user_prompts", [])
    if prompts:
        lines.append("- Recent user intents:")
        for item in prompts[-3:]:
            lines.append(f"  - {item}")
    return "\n".join(lines)


def _extract_specific_hostname(prompt: str) -> str:
    hosts = _extract_hosts_from_text(prompt)
    return hosts[0] if hosts else ""


def _extract_first_quoted_command(prompt: str) -> str:
    quoted = re.findall(r'"([^"]+)"', prompt)
    for item in quoted:
        if item.lower().startswith("show "):
            return item.strip()
    return ""


def _looks_like_device_scoped_hardware_prompt(prompt: str) -> bool:
    lower_prompt = prompt.lower()
    return (
        bool(_extract_specific_hostname(prompt))
        and any(term in lower_prompt for term in ("hardware", "category", "component", "tally", "count"))
    )


def _format_single_host_component_summary(hostname: str, components: list[dict]) -> str:
    grouped: dict[str, dict[str, int]] = {}
    for component in components:
        component_type = component.get("component_type", "unknown")
        description = component.get("description", "")
        if not description:
            continue
        grouped.setdefault(component_type, {})
        grouped[component_type][description] = grouped[component_type].get(description, 0) + 1

    type_labels = {
        "chassis": "Chassis",
        "routing_engine": "Routing Engine",
        "control_board": "Control Board",
        "line_card": "Line Card",
    }
    lines = [f"Here is the hardware category tally for device {hostname}:"]
    for component_type, descriptions in sorted(grouped.items()):
        lines.append("")
        lines.append(f"{type_labels.get(component_type, component_type)}:")
        for description, count in sorted(descriptions.items()):
            lines.append(f"- {description}: {count}")
    return "\n".join(lines)


def _needs_compaction(response_text: str) -> bool:
    return len(response_text) > MAX_MODEL_ANSWER_CHARS or response_text.count("\n") > 220


def _looks_like_single_host_command_prompt(prompt: str) -> bool:
    return bool(_extract_specific_hostname(prompt) and _extract_first_quoted_command(prompt))


def _looks_like_raw_followup_prompt(prompt: str, session_memory: dict) -> bool:
    active = session_memory.get("last_active_raw_request", {})
    if not active:
        return False
    if _extract_first_quoted_command(prompt):
        return False
    explicit_host = _extract_specific_hostname(prompt)
    if explicit_host and explicit_host != active.get("hostname"):
        return False
    if _looks_like_audit_start_prompt(prompt):
        return False
    return True


def _looks_like_structured_hardware_host_prompt(prompt: str, deterministic_state: dict) -> bool:
    hostname = _extract_specific_hostname(prompt)
    if not hostname:
        return False
    lower_prompt = prompt.lower()
    quoted_command = _extract_first_quoted_command(prompt).lower()
    if quoted_command == "show chassis hardware":
        return True
    if not deterministic_state.get("last_summary"):
        return False
    return any(
        term in lower_prompt
        for term in (
            "audit result",
            "hardware result",
            "hardware",
            "component",
            "category",
            "count",
            "tally",
            "show result",
            "print result",
        )
    )


def _make_chat(client, session):
    return client.aio.chats.create(
        model=MODEL_ID,
        config=types.GenerateContentConfig(
            tools=[session],
            system_instruction=SYSTEM_INSTRUCTION,
        ),
    )


def _format_large_output_requires_tool(run_id: str, hostname: str, command: str, total_chars: int) -> str:
    return (
        f'The output for `{command}` on `{hostname}` is too large to send to the model safely '
        f"({total_chars} characters). I am not going to pass that raw output through the model.\n\n"
        "This command needs a dedicated server-side parser/tool first. "
        "Please develop a tool for this command, or narrow the request to a smaller subset that can be processed deterministically.\n\n"
        f"Run id: {run_id}"
    )


async def _handle_single_host_raw_command(
    chat,
    session,
    log_file: str,
    session_id: str,
    turn_id: str,
    prompt: str,
    session_memory: dict,
) -> str | None:
    hostname = _extract_specific_hostname(prompt)
    command = _extract_first_quoted_command(prompt)
    if not hostname or not command:
        return None

    result = await _call_tool_logged(
        session,
        log_file,
        session_id,
        turn_id,
        "start_audit_run",
        {"devices": hostname, "commands": command},
    )
    data = _tool_result_json(result)
    run_id = data.get("run_id")
    if not run_id:
        return "Unable to start the command run."

    status = await _wait_for_run_completion(session, log_file, session_id, turn_id, run_id)
    if status.get("error"):
        return f"Error: {status['error']}"

    preview_result = await _call_tool_logged(
        session,
        log_file,
        session_id,
        turn_id,
        "get_raw_command_outputs",
        {
            "run_id": run_id,
            "command": command,
            "hosts": hostname,
            "max_chars_per_output": RAW_CHUNK_CHARS,
            "max_results": 1,
        },
    )
    preview_data = _tool_result_json(preview_result)
    items = preview_data.get("items", [])
    if not items:
        return f"No raw output was found for {hostname} {command}."

    session_memory["last_active_raw_request"] = {
        "run_id": run_id,
        "hostname": hostname,
        "command": command,
        "chunked": not items[0].get("raw_output_complete", True),
    }
    session_memory["last_run_id"] = run_id

    if items[0].get("raw_output_complete", True):
        if items[0].get("raw_output_length", 0) > MAX_DIRECT_RAW_MODEL_CHARS:
            raw_result = await _call_tool_logged(
                session,
                log_file,
                session_id,
                turn_id,
                "get_raw_analysis_context",
                {
                    "run_id": run_id,
                    "question": prompt,
                    "command": command,
                    "hosts": hostname,
                    "max_hosts": 1,
                    "max_chars_per_host": 12000,
                },
            )
            raw_data = _tool_result_json(raw_result)
            _remember_tool_data(session_memory, "get_raw_analysis_context", raw_data)
            session_memory["last_raw_context"] = raw_data
            return await _answer_from_raw_context(chat, prompt, raw_data)
        _remember_tool_data(session_memory, "get_raw_command_outputs", preview_data)
        session_memory["last_raw_context"] = preview_data
        return await _answer_from_raw_context(chat, prompt, preview_data)

    return _format_large_output_requires_tool(
        run_id,
        hostname,
        command,
        items[0].get("raw_output_length", 0),
    )


async def _handle_raw_followup_from_memory(
    chat,
    session,
    log_file: str,
    session_id: str,
    turn_id: str,
    prompt: str,
    session_memory: dict,
) -> str | None:
    active = session_memory.get("last_active_raw_request", {})
    run_id = active.get("run_id")
    hostname = active.get("hostname")
    command = active.get("command")
    if not run_id or not hostname or not command:
        return None
    if not active.get("chunked", False):
        raw_result = await _call_tool_logged(
            session,
            log_file,
            session_id,
            turn_id,
            "get_raw_command_outputs",
            {
                "run_id": run_id,
                "command": command,
                "hosts": hostname,
                "max_chars_per_output": RAW_CHUNK_CHARS,
                "max_results": 1,
            },
        )
        raw_data = _tool_result_json(raw_result)
        items = raw_data.get("items", [])
        if items and items[0].get("raw_output_length", 0) > MAX_DIRECT_RAW_MODEL_CHARS:
            bounded_result = await _call_tool_logged(
                session,
                log_file,
                session_id,
                turn_id,
                "get_raw_analysis_context",
                {
                    "run_id": run_id,
                    "question": prompt,
                    "command": command,
                    "hosts": hostname,
                    "max_hosts": 1,
                    "max_chars_per_host": 12000,
                },
            )
            bounded_data = _tool_result_json(bounded_result)
            _remember_tool_data(session_memory, "get_raw_analysis_context", bounded_data)
            session_memory["last_raw_context"] = bounded_data
            return await _answer_from_raw_context(chat, prompt, bounded_data)
        _remember_tool_data(session_memory, "get_raw_command_outputs", raw_data)
        session_memory["last_raw_context"] = raw_data
        return await _answer_from_raw_context(chat, prompt, raw_data)
    return (
        f'Your follow-up refers to `{command}` on `{hostname}` from run `{run_id}`.\n\n'
        "That command still needs a dedicated server-side parser/tool before I can answer follow-up questions reliably. "
        "I am not sending the large raw output through the model."
    )


async def _call_tool_logged(session, log_file: str, session_id: str, turn_id: str, tool_name: str, args: dict):
    _write_session_log(
        log_file,
        {
            "args": args,
            "event": "tool_call",
            "session_id": session_id,
            "timestamp": time.time(),
            "tool_name": tool_name,
            "turn_id": turn_id,
        },
    )
    result = await session.call_tool(tool_name, args)
    result_text = _tool_result_text(result)
    _write_session_log(
        log_file,
        {
            "event": "tool_result",
            "result": result_text,
            "session_id": session_id,
            "timestamp": time.time(),
            "tool_name": tool_name,
            "turn_id": turn_id,
        },
    )
    return result


async def _get_latest_run_id(session, log_file: str, session_id: str, turn_id: str) -> str | None:
    result = await _call_tool_logged(session, log_file, session_id, turn_id, "list_audit_runs", {})
    data = _tool_result_json(result)
    runs = data.get("runs", [])
    if runs:
        runs = sorted(
            runs,
            key=lambda item: item.get("created_at") or item.get("completed_at") or 0,
            reverse=True,
        )
        return runs[0].get("run_id")

    result = await _call_tool_logged(session, log_file, session_id, turn_id, "list_audit_log_runs", {})
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
        "break down",
        "breakdown",
        "category breakdown",
        "per-device",
        "counts for each device",
        "print out these categories",
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


def _is_per_device_hardware_prompt(prompt: str) -> bool:
    lower_prompt = prompt.lower()
    return (
        any(
            term in lower_prompt
            for term in (
                "for each device",
                "per device",
                "device by device",
                "host by host",
                "per-device",
            )
        )
        and any(
            term in lower_prompt
            for term in (
                "hardware",
                "category",
                "component",
                "count",
                "tally",
                "break down",
                "breakdown",
            )
        )
    )


async def _answer_from_raw_context(
    chat,
    prompt: str,
    raw_context: dict,
) -> str:
    def _format_raw_context(context: dict) -> str:
        lines = []
        if context.get("run_id"):
            lines.append(f'Run id: {context["run_id"]}')
        if context.get("command"):
            lines.append(f'Command: {context["command"]}')
        if context.get("question"):
            lines.append(f'Question hint: {context["question"]}')
        if context.get("truncated"):
            lines.append("Context truncated: true")

        for item in context.get("items", []):
            lines.append("")
            lines.append(f'Host: {item.get("hostname", "")}')
            lines.append(f'Command: {item.get("command", "")}')
            if "raw_output_length" in item:
                lines.append(f'Raw output length: {item.get("raw_output_length")}')
            if "raw_output_complete" in item:
                lines.append(f'Raw output complete: {item.get("raw_output_complete")}')
            body = item.get("raw_output") or item.get("excerpt") or ""
            if body:
                lines.append("Evidence:")
                lines.append(body)

        for match in context.get("matches", []):
            lines.append("")
            lines.append(f'Match host: {match.get("hostname", "")}')
            lines.append(f'Match command: {match.get("command", "")}')
            excerpt = match.get("excerpt", "")
            if excerpt:
                lines.append("Excerpt:")
                lines.append(excerpt)

        return "\n".join(lines).strip()

    grounded_prompt = (
        "Answer the user's request using only the raw command evidence below.\n\n"
        f"User request:\n{prompt}\n\n"
        "Raw evidence context:\n"
        f"{_format_raw_context(raw_context)}\n\n"
        "Rules:\n"
        "- Do not invent data that is not present in the evidence.\n"
        "- If the evidence is partial or truncated, say so.\n"
        "- If an exact count cannot be determined from the provided evidence, say that clearly.\n"
        "- Keep the answer concise and cite hostnames when useful.\n"
    )
    response = await chat.send_message(grounded_prompt)
    return response.text or "No answer was generated from the raw evidence."


async def _handle_deterministic_hardware_count(
    session,
    log_file: str,
    session_id: str,
    turn_id: str,
    prompt: str,
    deterministic_state: dict,
    session_memory: dict,
) -> str | None:
    permissive_followup = (
        deterministic_state.get("last_summary")
        and (
            _looks_like_followup_category_prompt(prompt)
            or (
                any(
                    term in prompt.lower()
                    for term in ("for each device", "per device", "device by device", "host by host")
                )
            )
        )
    )
    if not (
        _looks_like_hardware_count_prompt(prompt)
        or _looks_like_structured_hardware_host_prompt(prompt, deterministic_state)
        or permissive_followup
    ):
        return None
    if _looks_like_audit_start_prompt(prompt):
        return None

    run_id = deterministic_state.get("last_run_id") or await _get_latest_run_id(
        session, log_file, session_id, turn_id
    )
    if not run_id:
        return "No audit run is available to count against."

    lower_prompt = prompt.lower()
    if _looks_like_device_scoped_hardware_prompt(prompt) or _looks_like_structured_hardware_host_prompt(
        prompt, deterministic_state
    ):
        hostname = _extract_specific_hostname(prompt)
        result = await _call_tool_logged(
            session,
            log_file,
            session_id,
            turn_id,
            "get_analysis_context",
            {
                "run_id": run_id,
                "hostname": hostname,
                "command": "show chassis hardware",
            },
        )
        data = _tool_result_json(result)
        items = data.get("items", [])
        if not items:
            return f"No structured chassis hardware data was found for {hostname}."
        first_item = items[0]
        components = first_item.get("components", [])
        if not components:
            return f"No structured chassis hardware data was found for {hostname}."
        _remember_tool_data(
            session_memory,
            "get_analysis_context",
            {
                "run_id": run_id,
                "hostname": hostname,
                "command": "show chassis hardware",
                "items": items,
            },
        )
        deterministic_state["last_run_id"] = run_id
        return _format_single_host_component_summary(hostname, components)

    if permissive_followup and (
        _is_per_device_hardware_prompt(prompt)
        or _looks_like_followup_category_prompt(prompt)
    ):
        results = []
        for component_type, name in _flatten_summary_categories(deterministic_state["last_summary"]):
            result = await _call_tool_logged(
                session,
                log_file,
                session_id,
                turn_id,
                "count_components",
                {
                    "run_id": deterministic_state.get("last_run_id", run_id),
                    "name": name,
                    "component_type": component_type,
                    "match_mode": "exact",
                },
            )
            data = _tool_result_json(result)
            if data.get("error"):
                continue
            _remember_tool_data(session_memory, "count_components", data)
            results.append(
                {
                    "component_type": component_type,
                    "name": name,
                    "per_host": data.get("per_host", {}),
                }
            )
        total_hosts = len({host for item in results for host in item.get("per_host", {}).keys()})
        if total_hosts > MAX_INLINE_HOSTS:
            return (
                f"The full per-device tally spans {total_hosts} devices, which is too large to print in one reply "
                "without bloating the session. I can provide a host slice such as the first 10 devices, a specific "
                "list of hosts, or one device at a time."
            )
        return _format_per_device_category_counts(results)

    if "all the hard" in lower_prompt or "all hardware" in lower_prompt or "each category" in lower_prompt:
        result = await _call_tool_logged(
            session,
            log_file,
            session_id,
            turn_id,
            "summarize_components",
            {"run_id": run_id},
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
        _remember_tool_data(session_memory, "summarize_components", data)
        return _format_component_summary(summary)

    name = _extract_component_name(prompt)
    component_type = _detect_component_type(prompt)
    if not name:
        return None

    result = await _call_tool_logged(
        session,
        log_file,
        session_id,
        turn_id,
        "count_components",
        {
            "run_id": run_id,
            "name": name,
            "component_type": component_type,
            "match_mode": "exact",
        },
    )
    data = _tool_result_json(result)
    if data.get("error"):
        return f"Error: {data['error']}"

    total_count = data.get("total_count", 0)
    host_count = data.get("host_count", 0)
    per_host = data.get("per_host", {})
    _remember_tool_data(session_memory, "count_components", data)
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
    session, log_file: str, session_id: str, turn_id: str, run_id: str
) -> dict:
    for _ in range(60):
        result = await _call_tool_logged(
            session,
            log_file,
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
    chat,
    log_file: str,
    session_id: str,
    turn_id: str,
    prompt: str,
    deterministic_state: dict,
    session_memory: dict,
) -> str | None:
    if not _looks_like_audit_summary_prompt(prompt):
        return None

    devices, command = _extract_audit_inputs(prompt)
    if not devices or not command:
        return None

    result = await _call_tool_logged(
        session,
        log_file,
        session_id,
        turn_id,
        "start_audit_run",
        {"devices": devices, "commands": command},
    )
    data = _tool_result_json(result)
    run_id = data.get("run_id")
    if not run_id:
        return "Unable to start the audit run."

    status = await _wait_for_run_completion(session, log_file, session_id, turn_id, run_id)
    if status.get("error"):
        return f"Error: {status['error']}"
    if status.get("state") != "completed":
        return f'Audit run {run_id} ended with state: {status.get("state")}.'
    _remember_tool_data(session_memory, "start_audit_run", data)

    result = await _call_tool_logged(
        session,
        log_file,
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
            log_file,
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
        _remember_tool_data(session_memory, "get_raw_analysis_context", raw_data)
        deterministic_state["last_run_id"] = run_id
        deterministic_state["last_summary"] = {}
        return await _answer_from_raw_context(chat, prompt, raw_data)

    _remember_tool_data(session_memory, "summarize_components", data)
    deterministic_state["last_summary"] = summary
    deterministic_state["last_run_id"] = run_id
    return _format_component_summary(summary)


async def run_intelligent_agent() -> None:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("Error: Set your GEMINI_API_KEY environment variable.")
        return

    if not os.path.exists(SERVER_PATH):
        print(f"Error: Server not found at {SERVER_PATH}")
        return

    client = genai.Client(api_key=api_key)
    params = StdioServerParameters(command="python3", args=[SERVER_PATH], env=os.environ.copy())
    _ensure_session_log_dir()
    session_id = uuid.uuid4().hex[:12]
    session_log_file = os.path.join(SESSION_LOG_DIR, f"session_{session_id}.jsonl")

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            print("\n" + "=" * 60)
            print(f" GFIBER IN-MEMORY AGENT: {MODEL_ID}")
            print(" Type 'exit' or 'quit' to end the session.")
            print(f" Session log: {session_log_file}")
            print("=" * 60)

            _write_session_log(
                session_log_file,
                {
                    "event": "session_started",
                    "model_id": MODEL_ID,
                    "server_path": SERVER_PATH,
                    "session_id": session_id,
                    "timestamp": time.time(),
                },
            )

            chat = _make_chat(client, session)
            deterministic_state: dict = {}
            session_memory = _new_session_memory()

            while True:
                prompt = input("\n[USER]: ").strip()
                if prompt.lower() in ["exit", "quit", "goodbye", "bye"]:
                    _write_session_log(
                        session_log_file,
                        {
                            "event": "session_ended",
                            "reason": "user_exit",
                            "session_id": session_id,
                            "timestamp": time.time(),
                        },
                    )
                    print("\n[*] Closing session. Goodbye!\n")
                    break
                if not prompt:
                    continue

                try:
                    turn_id = uuid.uuid4().hex[:12]
                    _write_session_log(
                        session_log_file,
                        {
                            "event": "user_prompt",
                            "prompt": prompt,
                            "session_id": session_id,
                            "timestamp": time.time(),
                            "turn_id": turn_id,
                        },
                    )
                    _remember_user_prompt(session_memory, prompt)

                    deterministic_response = await _handle_deterministic_audit_summary(
                        session,
                        chat,
                        session_log_file,
                        session_id,
                        turn_id,
                        prompt,
                        deterministic_state,
                        session_memory,
                    )
                    if deterministic_response is None:
                        deterministic_response = await _handle_deterministic_hardware_count(
                            session,
                            session_log_file,
                            session_id,
                            turn_id,
                            prompt,
                            deterministic_state,
                            session_memory,
                        )
                    if deterministic_response is None and _looks_like_single_host_command_prompt(prompt):
                        deterministic_response = await _handle_single_host_raw_command(
                            chat,
                            session,
                            session_log_file,
                            session_id,
                            turn_id,
                            prompt,
                            session_memory,
                        )
                    if deterministic_response is None and _looks_like_raw_followup_prompt(prompt, session_memory):
                        deterministic_response = await _handle_raw_followup_from_memory(
                            chat,
                            session,
                            session_log_file,
                            session_id,
                            turn_id,
                            prompt,
                            session_memory,
                        )
                    if deterministic_response is not None:
                        _write_session_log(
                            session_log_file,
                            {
                                "event": "model_answer",
                                "response": deterministic_response,
                                "session_id": session_id,
                                "timestamp": time.time(),
                                "turn_id": turn_id,
                            },
                        )
                        print(f"\n[AI]: {deterministic_response}")
                        continue

                    enriched_prompt = (
                        f"{_build_memory_context(session_memory)}\n\n"
                        f"Current user request:\n{prompt}"
                    )
                    response = await chat.send_message(enriched_prompt)

                    for _ in range(MAX_TOOL_LOOPS):
                        if not response.candidates or not response.candidates[0].content:
                            break

                        parts = response.candidates[0].content.parts
                        if not parts:
                            break

                        tool_calls = [part.function_call for part in parts if part.function_call]
                        if not tool_calls:
                            break

                        tool_responses = []
                        for call in tool_calls:
                            print(f"[*] Server executing: {call.name}...")
                            result = await _call_tool_logged(
                                session,
                                session_log_file,
                                session_id,
                                turn_id,
                                call.name,
                                dict(call.args),
                            )
                            result_text = _tool_result_text(result)
                            try:
                                _remember_tool_data(session_memory, call.name, json.loads(result_text))
                            except Exception:
                                pass
                            tool_responses.append(
                                types.Part.from_function_response(
                                    name=call.name,
                                    response={"result": result_text},
                                )
                            )

                        response = await chat.send_message(tool_responses)
                    else:
                        _write_session_log(
                            session_log_file,
                            {
                                "event": "tool_loop_limit_reached",
                                "max_tool_loops": MAX_TOOL_LOOPS,
                                "session_id": session_id,
                                "timestamp": time.time(),
                                "turn_id": turn_id,
                            },
                        )
                        print("\n[!] Stopped after too many consecutive tool loops.")

                    if response.text:
                        if _needs_compaction(response.text):
                            chat = _make_chat(client, session)
                            _write_session_log(
                                session_log_file,
                                {
                                    "event": "chat_reset",
                                    "reason": "large_model_answer",
                                    "session_id": session_id,
                                    "timestamp": time.time(),
                                    "turn_id": turn_id,
                                },
                            )
                        _write_session_log(
                            session_log_file,
                            {
                                "event": "model_answer",
                                "response": response.text,
                                "session_id": session_id,
                                "timestamp": time.time(),
                                "turn_id": turn_id,
                            },
                        )
                        print(f"\n[AI]: {response.text}")

                except Exception as exc:
                    error_text = str(exc)
                    if "maximum number of tokens" in error_text or "input token count exceeds" in error_text:
                        chat = _make_chat(client, session)
                        _write_session_log(
                            session_log_file,
                            {
                                "event": "chat_reset",
                                "reason": "token_limit_error",
                                "session_id": session_id,
                                "timestamp": time.time(),
                                "turn_id": turn_id if "turn_id" in locals() else None,
                            },
                        )
                    _write_session_log(
                        session_log_file,
                        {
                            "error": error_text,
                            "event": "turn_error",
                            "session_id": session_id,
                            "timestamp": time.time(),
                            "turn_id": turn_id if "turn_id" in locals() else None,
                        },
                    )
                    print(f"\n[!] Error: {exc}")


if __name__ == "__main__":
    try:
        asyncio.run(run_intelligent_agent())
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user. Exiting...")
