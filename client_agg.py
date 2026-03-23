import asyncio
import os
import sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from google import genai
from google.genai import types

# --- Configuration ---
SERVER_PATH = os.path.join(os.getcwd(), "server_agg.py")
MODEL_ID = "gemini-2.5-pro"

server_params = StdioServerParameters(
    command="python3",
    args=[SERVER_PATH],
    env=os.environ.copy()
)

SYSTEM_INSTRUCTION = """
You are the GFiber Network Intelligence Agent.
1. Use 'audit_devices' for BOTH files and manual lists of hostnames.
2. If the user provides specific names, pass them as a string to the 'devices' parameter.
3. After an audit, ALWAYS follow up by using 'read_local_file' to load the data into your memory.
4. Once data is loaded into your context, DO NOT use tools to read the file again; answer from memory.
5. You are an expert engineer. Be precise in your tallies and breakdowns.
"""

async def run_intelligent_agent():
    client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            print("\n" + "="*60 + "\n GFIBER AGENT: PERSISTENT CONTEXT & CONFIRMATION MODE\n" + "="*60)

            chat = client.aio.chats.create(
                model=MODEL_ID,
                config=types.GenerateContentConfig(
                    tools=[session], 
                    system_instruction=SYSTEM_INSTRUCTION
                )
            )

            while True:
                prompt = input("\n[USER]: ").strip()
                if prompt.lower() in ['exit', 'quit']: break
                if not prompt: continue

                try:
                    response = await chat.send_message(prompt)
                    
                    while True:
                        if not response.candidates or not response.candidates[0].content: break
                        parts = response.candidates[0].content.parts
                        if not parts: break
                        tool_calls = [p.function_call for p in parts if p.function_call]
                        if not tool_calls: break

                        tool_responses = []
                        for call in tool_calls:
                            # --- INTERACTIVE CONFIRMATION ---
                            if call.name == "audit_devices":
                                print(f"\n[?] PROPOSED ACTION: Run '{call.args['command']}' on devices:")
                                print(f"    {call.args['devices']}")
                                confirm = input("    Proceed? (y/n): ").strip().lower()
                                if confirm != 'y':
                                    print("[!] Audit aborted.")
                                    tool_responses.append(types.Part.from_function_response(
                                        name=call.name, response={'result': "Error: User cancelled audit."}
                                    ))
                                    continue
                            
                            print(f"[*] Executing tool: {call.name}...")
                            res = await session.call_tool(call.name, call.args)
                            tool_responses.append(types.Part.from_function_response(
                                name=call.name, response={'result': str(res)}
                            ))

                        if tool_responses:
                            response = await chat.send_message(tool_responses)
                        else:
                            break

                    if response.text:
                        print(f"\n[AI]: {response.text}")

                except Exception as e:
                    print(f"\n[!] Error: {e}")

if __name__ == "__main__":
    if "GEMINI_API_KEY" not in os.environ:
        print("Error: Set GEMINI_API_KEY environment variable.")
    else:
        asyncio.run(run_intelligent_agent())