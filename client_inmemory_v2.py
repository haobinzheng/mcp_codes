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


SERVER_PATH = os.path.join(os.getcwd(), "server_inmemory_v2.py")
MODEL_ID = os.environ.get("GEMINI_MODEL_ID", "gemini-2.5-pro")
MAX_TOOL_LOOPS = 20
MAX_MEMORY_PROMPTS = 6
MAX_MEMORY_HOSTS = 10
MAX_MEMORY_COMMANDS = 8
MAX_MODEL_ANSWER_CHARS = 4_000_000
MAX_RAW_TOOL_CHARS = 4_000_000
SESSION_LOG_DIR = os.environ.get(
    "SESSION_LOG_DIR", os.path.join(os.getcwd(), "session_logs")
)

SYSTEM_INSTRUCTION = """
You are the GFiber Network Intelligence Agent v2.

General workflow:
1. Use MCP tools to fetch evidence before answering operational questions.
2. Prefer structured tools when available:
   - summarize_components
   - count_components
   - get_host_component_summary
   - compare_host_components
   - get_analysis_context
3. For unsupported commands, use bounded raw-evidence tools:
   - list_run_commands
   - get_raw_analysis_context
   - get_raw_command_outputs only for targeted small outputs
4. Do not rely on free-text math when a tool can compute the answer.
5. Use exact component matching by default unless the user explicitly asks for fuzzy matching.
6. If evidence is partial or truncated, say so clearly.
7. Keep answers concise by default. Summaries first, details on demand.
8. Use prior session memory for follow-up questions. If the user refers to "same host", "same command", or "that run", resolve it from memory before asking for clarification.
9. If the needed evidence is still missing, ask a short follow-up question instead of guessing.
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


def _limit_list(items: list[str], max_items: int) -> list[str]:
    if len(items) <= max_items:
        return items
    return items[-max_items:]


def _extract_hosts_from_text(text: str) -> list[str]:
    pattern = r"\b[a-z]{2,}\d{2}\.[a-z]{3}\d{3}\b"
    return sorted(set(re.findall(pattern, text.lower())))


def _extract_commands_from_text(text: str) -> list[str]:
    commands = re.findall(r'"(show[^"]+)"', text, flags=re.IGNORECASE)
    if commands:
        return [command.strip() for command in commands]
    return [item.strip(" .,") for item in re.findall(r"\bshow\s+[a-z0-9 _/-]+", text, flags=re.IGNORECASE)[:3]]


def _new_session_memory() -> dict:
    return {
        "last_run_id": "",
        "last_hosts": [],
        "last_commands": [],
        "last_structured_summary": {},
        "last_raw_context": {},
        "recent_user_prompts": [],
    }


def _remember_user_prompt(session_memory: dict, prompt: str) -> None:
    session_memory["recent_user_prompts"] = _limit_list(
        session_memory.get("recent_user_prompts", []) + [prompt],
        MAX_MEMORY_PROMPTS,
    )
    hosts = _extract_hosts_from_text(prompt)
    if hosts:
        session_memory["last_hosts"] = _limit_list(
            list(dict.fromkeys(session_memory.get("last_hosts", []) + hosts)),
            MAX_MEMORY_HOSTS,
        )
    commands = _extract_commands_from_text(prompt)
    if commands:
        session_memory["last_commands"] = _limit_list(
            list(dict.fromkeys(session_memory.get("last_commands", []) + commands)),
            MAX_MEMORY_COMMANDS,
        )


def _remember_tool_data(session_memory: dict, tool_name: str, payload: dict) -> None:
    run_id = payload.get("run_id")
    if isinstance(run_id, str) and run_id:
        session_memory["last_run_id"] = run_id

    hosts: list[str] = []
    if isinstance(payload.get("hostname"), str) and payload.get("hostname"):
        hosts.append(payload["hostname"])
    if isinstance(payload.get("host_a"), str) and payload.get("host_a"):
        hosts.append(payload["host_a"])
    if isinstance(payload.get("host_b"), str) and payload.get("host_b"):
        hosts.append(payload["host_b"])
    if isinstance(payload.get("hosts"), list):
        hosts.extend([item for item in payload["hosts"] if isinstance(item, str)])
    if isinstance(payload.get("items"), list):
        for item in payload["items"]:
            if isinstance(item, dict) and isinstance(item.get("hostname"), str):
                hosts.append(item["hostname"])
    if hosts:
        session_memory["last_hosts"] = _limit_list(
            list(dict.fromkeys(session_memory.get("last_hosts", []) + hosts)),
            MAX_MEMORY_HOSTS,
        )

    commands: list[str] = []
    if isinstance(payload.get("command"), str) and payload.get("command"):
        commands.append(payload["command"])
    if isinstance(payload.get("commands"), list):
        commands.extend([item for item in payload["commands"] if isinstance(item, str)])
    if isinstance(payload.get("items"), list):
        for item in payload["items"]:
            if isinstance(item, dict) and isinstance(item.get("command"), str) and item.get("command"):
                commands.append(item["command"])
    if commands:
        session_memory["last_commands"] = _limit_list(
            list(dict.fromkeys(session_memory.get("last_commands", []) + commands)),
            MAX_MEMORY_COMMANDS,
        )

    if tool_name == "summarize_components" and payload.get("summary"):
        session_memory["last_structured_summary"] = payload["summary"]
    if tool_name == "get_raw_analysis_context" and payload.get("items"):
        session_memory["last_raw_context"] = {
            "run_id": payload.get("run_id", ""),
            "command": payload.get("command", ""),
            "truncated": payload.get("truncated", False),
            "items": payload.get("items", [])[:4],
        }


def _build_memory_context(session_memory: dict) -> str:
    lines = ["Session memory:"]
    if session_memory.get("last_run_id"):
        lines.append(f'- Last run id: {session_memory["last_run_id"]}')
    if session_memory.get("last_hosts"):
        lines.append("- Recent hosts: " + ", ".join(session_memory["last_hosts"]))
    if session_memory.get("last_commands"):
        lines.append("- Recent commands: " + ", ".join(session_memory["last_commands"]))
    if session_memory.get("last_structured_summary"):
        preview = []
        for component_type, descriptions in session_memory["last_structured_summary"].items():
            for name in list(descriptions.keys())[:2]:
                preview.append(f"{component_type}:{name}")
        if preview:
            lines.append("- Last structured categories: " + ", ".join(preview[:8]))
    if session_memory.get("last_raw_context"):
        raw_context = session_memory["last_raw_context"]
        lines.append(
            "- Last raw context: "
            f'run={raw_context.get("run_id", "")}, '
            f'command={raw_context.get("command", "")}, '
            f'items={len(raw_context.get("items", []))}, '
            f'truncated={raw_context.get("truncated", False)}'
        )
    prompts = session_memory.get("recent_user_prompts", [])
    if prompts:
        lines.append("- Recent prompts:")
        for item in prompts[-3:]:
            lines.append(f"  - {item}")
    return "\n".join(lines)


def _make_chat(client, session):
    return client.aio.chats.create(
        model=MODEL_ID,
        config=types.GenerateContentConfig(
            tools=[session],
            system_instruction=SYSTEM_INSTRUCTION,
        ),
    )


async def _call_tool_logged(session, log_file: str, session_id: str, turn_id: str, tool_name: str, args: dict):
    safe_args = dict(args)
    if tool_name == "get_raw_command_outputs":
        safe_args["max_chars_per_output"] = min(
            int(safe_args.get("max_chars_per_output", MAX_RAW_TOOL_CHARS)),
            MAX_RAW_TOOL_CHARS,
        )
    if tool_name == "get_raw_command_chunk":
        safe_args["max_chars"] = min(int(safe_args.get("max_chars", MAX_RAW_TOOL_CHARS)), MAX_RAW_TOOL_CHARS)
    _write_session_log(
        log_file,
        {
            "event": "tool_call",
            "session_id": session_id,
            "timestamp": time.time(),
            "tool_name": tool_name,
            "turn_id": turn_id,
            "args": safe_args,
        },
    )
    result = await session.call_tool(tool_name, safe_args)
    result_text = _tool_result_text(result)
    _write_session_log(
        log_file,
        {
            "event": "tool_result",
            "session_id": session_id,
            "timestamp": time.time(),
            "tool_name": tool_name,
            "turn_id": turn_id,
            "result": result_text,
        },
    )
    try:
        payload = json.loads(result_text)
        _remember_tool_data(session_memory=_CURRENT_SESSION_MEMORY.get(), tool_name=tool_name, payload=payload)
    except Exception:
        pass
    return result


class _SessionMemoryRef:
    def __init__(self) -> None:
        self.value = _new_session_memory()

    def get(self) -> dict:
        return self.value

    def reset(self) -> None:
        self.value = _new_session_memory()


_CURRENT_SESSION_MEMORY = _SessionMemoryRef()


def _needs_compaction(response_text: str) -> bool:
    return len(response_text) > MAX_MODEL_ANSWER_CHARS


async def run_intelligent_agent_v2() -> None:
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
            chat = _make_chat(client, session)
            _CURRENT_SESSION_MEMORY.reset()

            print("\n" + "=" * 60)
            print(f" GFIBER IN-MEMORY AGENT V2: {MODEL_ID}")
            print(" Type 'exit' or 'quit' to end the session.")
            print(f" Server: {SERVER_PATH}")
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

            while True:
                prompt = input("\n[USER]: ").strip()
                if prompt.lower() in {"exit", "quit", "bye", "goodbye"}:
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
                    session_memory = _CURRENT_SESSION_MEMORY.get()
                    _remember_user_prompt(session_memory, prompt)

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
                            tool_responses.append(
                                types.Part.from_function_response(
                                    name=call.name,
                                    response={"result": _tool_result_text(result)},
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

                    answer = response.text or "No answer returned."
                    if _needs_compaction(answer):
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
                            "response": answer,
                            "session_id": session_id,
                            "timestamp": time.time(),
                            "turn_id": turn_id,
                        },
                    )
                    print(f"\n[AI]: {answer}")

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
                            "event": "turn_error",
                            "error": error_text,
                            "session_id": session_id,
                            "timestamp": time.time(),
                            "turn_id": turn_id if "turn_id" in locals() else None,
                        },
                    )
                    print(f"\n[!] Error: {exc}")


if __name__ == "__main__":
    try:
        asyncio.run(run_intelligent_agent_v2())
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user. Exiting...")
