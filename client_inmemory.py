import asyncio
import json
import os
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
5. Use list_audit_log_runs, get_audit_log_summary, and get_audit_log_host_details when the user asks about prior runs.
6. Do not ask the server to use local files for state exchange; the server stores audit data in memory and persists audit logs for later analysis.

When the user asks for analysis over multiple commands, prefer:
- summary first
- then targeted lookups for specific hosts, commands, failures, or anomalies

When a run is still in progress, tell the user that the audit is still running and continue polling only if needed.
"""


def _ensure_session_log_dir() -> None:
    os.makedirs(SESSION_LOG_DIR, exist_ok=True)


def _write_session_log(log_file: str, event: dict) -> None:
    with open(log_file, "a") as f:
        f.write(json.dumps(event, sort_keys=True) + "\n")


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
                            _write_session_log(
                                session_log_file,
                                {
                                    "args": dict(call.args),
                                    "event": "tool_call",
                                    "session_id": session_id,
                                    "timestamp": time.time(),
                                    "tool_name": call.name,
                                    "turn_id": turn_id,
                                },
                            )
                            result = await session.call_tool(call.name, call.args)
                            result_text = str(result)
                            _write_session_log(
                                session_log_file,
                                {
                                    "event": "tool_result",
                                    "result": result_text,
                                    "session_id": session_id,
                                    "timestamp": time.time(),
                                    "tool_name": call.name,
                                    "turn_id": turn_id,
                                },
                            )
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
