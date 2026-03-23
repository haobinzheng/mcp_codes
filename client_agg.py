import asyncio, os, sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from google import genai
from google.genai import types

SERVER_PATH = os.path.join(os.getcwd(), "server_agg.py")
MODEL_ID = "gemini-2.5-pro"

SYSTEM_INSTRUCTION = """
You are the GFiber Network Intelligence Agent.
1. Use 'audit_devices' for BOTH files and manual lists of hostnames.
2. After an audit, ALWAYS use 'read_local_file' to ingest the data.
3. Once data is in your memory, answer follow-up questions LOCALLY.
4. If the user provides a manual list of hosts, pass them exactly as a string to the 'devices' parameter.
"""

async def run_intelligent_agent():
    client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))
    params = StdioServerParameters(command="python3", args=[SERVER_PATH], env=os.environ.copy())

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            print("\n" + "="*60 + "\n GFIBER INTELLIGENT AGENT: MANUAL & FILE MODE\n" + "="*60)

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
                    # We send the message and handle tool loops
                    response = await chat.send_message(prompt)
                    
                    while True:
                        if not response.candidates or not response.candidates[0].content: break
                        parts = response.candidates[0].content.parts
                        if not parts: break
                        tool_calls = [p.function_call for p in parts if p.function_call]
                        if not tool_calls: break

                        tool_responses = []
                        for call in tool_calls:
                            print(f"[*] Server executing: {call.name}...")
                            res = await session.call_tool(call.name, call.args)
                            tool_responses.append(types.Part.from_function_response(name=call.name, response={'result': str(res)}))
                        
                        response = await chat.send_message(tool_responses)

                    if response.text:
                        print(f"\n[AI]: {response.text}")

                except Exception as e:
                    print(f"\n[!] Error: {e}")

if __name__ == "__main__":
    asyncio.run(run_intelligent_agent())