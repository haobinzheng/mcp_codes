import subprocess
import os
import asyncio
import re
from mcp.server.fastmcp import FastMCP

# Initialize the High-Speed Universal Aggregator
mcp = FastMCP("GFiber-Net-Power-Server")

# --- Configuration ---
GNETCH_PATH = "/usr/local/google/home/mikezh/Coding/gfiber/bin/gnetch.sh"
CURRENT_DIR = os.getcwd()
SEMAPHORE_LIMIT = 30  # Max concurrent SSH sessions

async def run_single_gnetch(command: str, hostname: str, semaphore: asyncio.Semaphore):
    """Executes ANY command on a host and returns RAW output (no hardcoded filters)."""
    async with semaphore:
        try:
            proc = await asyncio.create_subprocess_exec(
                GNETCH_PATH, command, hostname,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode().strip()
            
            # Remove empty lines to keep the AI context window lean
            clean_lines = [line for line in output.splitlines() if line.strip()]
            final_output = "\n".join(clean_lines)
            
            return f"\n--- HOST: {hostname} ---\n{final_output}\n"
        except Exception as e:
            return f"\n--- HOST: {hostname} ---\nERROR: {str(e)}\n"

@mcp.tool()
async def audit_devices(command: str, devices: str, output_file: str = "audit_results.txt") -> str:
    """
    UNIVERSAL AUDITOR: 
    - command: Any shell/Junos command.
    - devices: A filename (e.g. 'mx960.txt') OR a raw list of hostnames (e.g. 'pr01, pr02').
    - output_file: Path to save the aggregated raw data.
    """
    potential_path = os.path.join(CURRENT_DIR, devices)
    
    # Identify if input is a File or a Manual String
    if os.path.exists(potential_path) and os.path.isfile(potential_path):
        with open(potential_path, "r") as f:
            raw_input = f.read().strip().splitlines()
    else:
        # Split by comma, space, or newline
        raw_input = re.split(r'[,\s\n]+', devices)

    # Clean hostnames (handles 'host:# Model' format and duplicates)
    hosts = []
    for line in raw_input:
        host = re.split(r'[:\s]', line.strip())[0].strip()
        if host:
            hosts.append(host)
    
    hosts = sorted(list(set(hosts)))
    if not hosts:
        return "Error: No valid hostnames identified."

    print(f"[*] Starting audit for {len(hosts)} devices...")
    sem = asyncio.Semaphore(SEMAPHORE_LIMIT)
    results = await asyncio.gather(*(run_single_gnetch(command, h, sem) for h in hosts))

    # Save RAW data to disk
    with open(os.path.join(CURRENT_DIR, output_file), "w") as f:
        f.write("".join(results))
        
    return f"SUCCESS: Audit complete for {len(hosts)} devices. Data saved to {output_file}."

@mcp.tool()
def read_local_file(file_name: str) -> str:
    """Reads a file from the current directory into the AI's memory."""
    path = os.path.join(CURRENT_DIR, file_name)
    with open(path, "r") as f:
        return f.read()

@mcp.tool()
def write_to_file(filename: str, content: str) -> str:
    """Saves final analyzed results or reports to a file."""
    path = os.path.join(CURRENT_DIR, filename)
    with open(path, "w") as f:
        f.write(content)
    return f"File saved to {path}"

if __name__ == "__main__":
    mcp.run()