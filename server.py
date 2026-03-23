import subprocess
import os
import logging
from mcp.server.fastmcp import FastMCP

# Initialize the MCP server
mcp = FastMCP("GFiber-Net-Tools")

# --- Configuration ---
GNETCH_PATH = "/usr/local/google/home/mikezh/Coding/gfiber/bin/gnetch.sh"
SAFE_DIRECTORY = "/usr/local/google/home/mikezh/Coding/gfiber/"

@mcp.tool()
def run_gnetch(command: str, hostname: str) -> str:
    """Executes gnetch.sh 'command' 'hostname' on the network."""
    if not os.path.exists(GNETCH_PATH):
        return f"Error: Script not found at {GNETCH_PATH}"
    try:
        result = subprocess.run(
            [GNETCH_PATH, command, hostname],
            capture_output=True, text=True, check=True
        )
        return result.stdout or "Success."
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool()
def read_local_file(file_path: str) -> str:
    """Reads a local text file within the safe directory."""
    norm_path = os.path.abspath(file_path)
    if not norm_path.startswith(os.path.abspath(SAFE_DIRECTORY)):
        return "Access Denied."
    try:
        with open(norm_path, "r") as f:
            return f.read()
    except Exception as e:
        return str(e)

@mcp.tool()
def write_to_file(filename: str, content: str) -> str:
    """Saves the final report to the project directory."""
    full_path = os.path.join(SAFE_DIRECTORY, filename)
    try:
        with open(full_path, "w") as f:
            f.write(content)
        return f"SUCCESS: File saved to {full_path}"
    except Exception as e:
        return f"ERROR: {str(e)}"

if __name__ == "__main__":
    mcp.run()