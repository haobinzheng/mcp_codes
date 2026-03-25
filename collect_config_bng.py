import os
import sys
import re
import json
import asyncio
from functools import partial
import time
from openpyxl import Workbook, load_workbook
from datetime import datetime
 

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils_gfiber import *
from device_class import *
from juniper_lib import *

DEBUG = False
RATE_LIMIT = 2  # seconds between commands for the same device
rate_limiters = {}

def dprint(msg):
    if DEBUG:
        if isinstance(msg, list):
            for m in msg:
                print(f"Debug: {m}")
        else:
            print(f"Debug: {msg}")

async def async_gnetch_command(cmd, target):
    """
    Asynchronously execute a gnetch command using asyncio subprocess.
    """
    gnetch_cmd = f"stubby --proto2 call blade:gnetch-frontend Gnetch2.Command 'command: \"{cmd}\" target: \"{target}\"'"
    process = await asyncio.create_subprocess_shell(
        gnetch_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, _ = await process.communicate()
    output = stdout.decode().lstrip("data: ").strip('"').split("\\n")
    return output[:-1]

async def rate_limited_gnetch_command(cmd, target):
    """
    Execute gnetch_command with rate limiting for the target device.
    """
    if target not in rate_limiters:
        rate_limiters[target] = asyncio.Semaphore(1)

    async with rate_limiters[target]:
        output = await async_gnetch_command(cmd, target)
        await asyncio.sleep(RATE_LIMIT)  # Enforce the rate limit
        return output

async def collect_bng_config(device, folder_name, regex_site):
    """
    Process a single device asynchronously and log outputs to separate log files.
    """
    host = device.hostname
    local_device_site = host.split(".")[1]
    matched = re.search(regex_site, local_device_site)
    local_site = matched.group(1).strip() if matched else "Unknown"

    bundle_dict = {}
    device_log_file = os.path.join(folder_name, f"{host}_config.txt")

    try:
        print(f"Processing device: {host}\n")

        # Fetch 'show version'
        config_result = await rate_limited_gnetch_command("show config | display set", host)
        with open(device_log_file, 'a') as log_file:
            log_file.write("\n".join(config_result) + "\n")

    except Exception as e:
        # Log errors
        with open(device_log_file, 'a') as log_file:
            log_file.write(f"\nError processing device {host}: {e}\n")

    return {host: bundle_dict}



async def main():
    yaml_file = "rancid_juniper_dr.yaml"
    setup = setup_db(yaml_file)
    folder_name = setup.setupdb.Log_folder
    #os.makedirs(folder_name, exist_ok=True)
    create_or_recreate_folder(folder_name)

    # Prepare tasks for all devices
    regex_site = r"([a-zA-Z]+)[0-9]+"

    async_start = time.time()
    tasks = [collect_bng_config(device, folder_name, regex_site) for device in setup.setupdb.Device_list]
    # Run tasks concurrently
    results = await asyncio.gather(*tasks)

    # Aggregate results
    audit_result = {host: data for device_result in results for host, data in device_result.items()}
    print(f"Total number of devices: {len(audit_result)}")

    async_duration = time.time() - async_start
    print(f"Asynchronous execution time: {async_duration:.2f} seconds\n")



if __name__ == "__main__":
    asyncio.run(main())
