import asyncio
import os

from google import genai
from google.genai import types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


SERVER_PATH = os.path.join(os.getcwd(), "server_inmemory.py")
MODEL_ID = os.environ.get("GEMINI_MODEL_ID", "gemini-2.5-pro")
MAX_TOOL_LOOPS = 20

SYSTEM_INSTRUCTION = """
You are the GFiber Network Intelligence Agent.

Use the MCP tools with this workflow:
1. Start audits with start_audit_run.
2. Check progress with get_audit_run_status when needed.
3. Read compact results with get_audit_run_summary before requesting detailed outputs.
4. Fetch host- or command-level details only when needed to support a conclusion.
5. Do not ask the server to use local files for state exchange; the server stores audit data in memory.

When the user asks for analysis over multiple commands, prefer:
- summary first
- then targeted lookups for specific hosts, commands, failures, or anomalies

When a run is still in progress, tell the user that the audit is still running and continue polling only if needed.
"""


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

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            print("\n" + "=" * 60)
            print(f" GFIBER IN-MEMORY AGENT: {MODEL_ID}")
            print(" Type 'exit' or 'quit' to end the session.")
            print("=" * 60)

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
                    print("\n[*] Closing session. Goodbye!\n")
                    break
                if not prompt:
                    continue

                try:
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
                            result = await session.call_tool(call.name, call.args)
                            tool_responses.append(
                                types.Part.from_function_response(
                                    name=call.name,
                                    response={"result": str(result)},
                                )
                            )

                        response = await chat.send_message(tool_responses)
                    else:
                        print("\n[!] Stopped after too many consecutive tool loops.")

                    if response.text:
                        print(f"\n[AI]: {response.text}")

                except Exception as exc:
                    print(f"\n[!] Error: {exc}")


if __name__ == "__main__":
    try:
        asyncio.run(run_intelligent_agent())
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user. Exiting...")
