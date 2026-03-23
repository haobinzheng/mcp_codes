import subprocess, os, asyncio, re
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("GFiber-Net-Power-Server")
GNETCH_PATH = "/usr/local/google/home/mikezh/Coding/gfiber/bin/gnetch.sh"
CURRENT_DIR = os.getcwd()
SEMAPHORE_LIMIT = 30 

async def run_single_gnetch(command: str, hostname: str, semaphore: asyncio.Semaphore):
    async with semaphore:
        try:
            proc = await asyncio.create_subprocess_exec(
                GNETCH_PATH, command, hostname,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode().strip()
            
            # --- SPEED ENHANCEMENT ---
            # Filter output: only keep lines with actual data to reduce token load
            filtered = [l for l in output.splitlines() if any(x in l for x in ["RE-S", "SCB", "MPC", "FPC", "Chassis", "Model"])]
            clean_output = "\n".join(filtered)
            
            return f"\n--- HOST: {hostname} ---\n{clean_output}\n"
        except Exception as e:
            return f"\n--- HOST: {hostname} ---\nERROR: {str(e)}\n"

@mcp.tool()
async def audit_devices(command: str, devices: str, output_file: str = "audit_results.txt") -> str:
    """
    UNIVERSAL AUDIT: Accepts a filename OR a comma-separated list of hostnames.
    Runs 'command' concurrently and saves to 'output_file'.
    """
    # Determine if 'devices' is a file or a list
    if os.path.exists(os.path.join(CURRENT_DIR, devices)):
        with open(os.path.join(CURRENT_DIR, devices), "r") as f:
            raw_hosts = f.read().strip().splitlines()
    else:
        # It's a manual list (comma or space separated)
        raw_hosts = re.split(r'[,\s]+', devices)

    # Clean the host list
    hosts = [re.split(r'[:\s]', l)[0].strip() for l in raw_hosts if l]
    hosts = sorted(list(set(hosts)))

    print(f"[*] Starting server-side audit on {len(hosts)} devices...")
    sem = asyncio.Semaphore(SEMAPHORE_LIMIT)
    results = await asyncio.gather(*(run_single_gnetch(command, h, sem) for h in hosts))

    with open(os.path.join(CURRENT_DIR, output_file), "w") as f:
        f.write("".join(results))
        
    return f"SUCCESS: Audit complete for {len(hosts)} devices. Data saved to {output_file}."

@mcp.tool()
def read_local_file(file_name: str) -> str:
    """Reads a file from the current directory."""
    with open(os.path.join(CURRENT_DIR, file_name), "r") as f:
        return f.read()

if __name__ == "__main__":
    mcp.run()