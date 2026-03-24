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
8. Use list_audit_log_runs, get_audit_log_summary, and get_audit_log_host_details when the user asks about prior runs.
9. Do not ask the server to use local files for state exchange; the server stores audit data in memory and persists audit logs for later analysis.

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
        return runs[0].get("run_id")

    result = await _call_tool_logged(session, log_file, session_id, turn_id, "list_audit_log_runs", {})
    data = _tool_result_json(result)
    runs = data.get("runs", [])
    if runs:
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


async def _handle_deterministic_hardware_count(
    session, log_file: str, session_id: str, turn_id: str, prompt: str
) -> str | None:
    if not _looks_like_hardware_count_prompt(prompt):
        return None

    run_id = await _get_latest_run_id(session, log_file, session_id, turn_id)
    if not run_id:
        return "No audit run is available to count against."

    lower_prompt = prompt.lower()
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
        return _format_component_summary(data.get("summary", {}))

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
    response_lines = [
        f'The verified total number of "{name}" is {total_count} across {host_count} devices.'
    ]
    if "list" in lower_prompt or "each device" in lower_prompt or "per device" in lower_prompt:
        response_lines.append("")
        response_lines.append("Per-device counts:")
        for hostname, count in per_host.items():
            response_lines.append(f"- {hostname}: {count}")
    return "\n".join(response_lines)


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

            chat = client.aio.chats.create(
                model=MODEL_ID,
                config=types.GenerateContentConfig(
                    tools=[session],
                    system_instruction=SYSTEM_INSTRUCTION,
                ),
            )

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

                    deterministic_response = await _handle_deterministic_hardware_count(
                        session, session_log_file, session_id, turn_id, prompt
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

                    response = await chat.send_message(prompt)

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
                    _write_session_log(
                        session_log_file,
                        {
                            "error": str(exc),
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
