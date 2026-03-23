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

async def run_persistent_agent():
    client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            print("\n" + "="*60)
            print(f" GFIBER AGENT: {MODEL_ID} PERSISTENT SESSION")
            print(" Type 'exit', 'quit', or 'goodbye' to end the session.")
            print("="*60)

            # Initialize chat with tool access
            chat = client.aio.chats.create(
                model=MODEL_ID,
                config=types.GenerateContentConfig(tools=[session])
            )

            while True:
                prompt = input("\n[USER]: ").strip()
                
                # Check for exit keywords
                if prompt.lower() in ['exit', 'quit', 'goodbye', 'bye']:
                    print("\n[*] Closing session. Goodbye!\n")
                    break

                if not prompt:
                    continue

                try:
                    response = await chat.send_message(prompt)
                    
                    # Tool Execution Loop (The "Thinking" Loop)
                    while True:
                        if not response.candidates or not response.candidates[0].content:
                            break
                        
                        parts = response.candidates[0].content.parts
                        if not parts:
                            break

                        tool_calls = [p.function_call for p in parts if p.function_call]
                        if not tool_calls:
                            # If no more tools, Gemini has finished its thought
                            break

                        tool_responses = []
                        for call in tool_calls:
                            print(f"[*] AI requesting tool: {call.name}...")
                            res = await session.call_tool(call.name, call.args)
                            
                            tool_responses.append(types.Part.from_function_response(
                                name=call.name, 
                                response={'result': str(res)}
                            ))

                        # Send tool results back to the SAME chat object to maintain context
                        response = await chat.send_message(tool_responses)

                    if response.text:
                        print(f"\n[AI]: {response.text}")

                except Exception as e:
                    print(f"\n[!] Error: {e}")

if __name__ == "__main__":
    if "GEMINI_API_KEY" not in os.environ:
        print("Error: Set your GEMINI_API_KEY environment variable.")
    else:
        try:
            asyncio.run(run_persistent_agent())
        except KeyboardInterrupt:
            print("\n[*] Interrupted by user. Exiting...")