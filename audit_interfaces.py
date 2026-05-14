import os
import sys
import re
import json
import asyncio
from functools import partial
import time
from openpyxl import Workbook, load_workbook
from datetime import datetime
from zoneinfo import ZoneInfo
import argparse

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../gfiber')))

from utils_gfiber import *
from device_class import *
from juniper_lib import *
from linux_message import *

DEBUG = False
RATE_LIMIT = 2  # seconds between commands for the same device
rate_limiters = {}

def convert_speed_human(speed_bps):
    """ Converts raw speed in bps to human-readable format (K, M, G, T). """
    units = [("T", 10**12), ("G", 10**9), ("M", 10**6), ("K", 10**3)]
    
    for unit, factor in units:
        if speed_bps >= factor:
            return f"{speed_bps / factor:.1f}{unit}" if speed_bps % factor else f"{speed_bps // factor}{unit}"
    
    return f"{speed_bps}bps"

def extract_metro(device_name):
    """
    Extracts the metro name from a device name.
    Expected format examples:
    - "cr01.aus122" → "aus"
    - "dr01.slc103" → "slc"
    - "core1.nyc" → "nyc"  (Allows non-numeric suffix)
    - "router.sfo" → "sfo"
    - Fallback: "unknown" if not found.
    """
    match = re.search(r"\.(\D{3})\d*", device_name)  # Matches a 3-letter metro code
    return match.group(1) if match else "unknown"

def get_pacific_timestamp() -> str:
    """
    Return the current Pacific Time timestamp in format YYYY-MM-DD HH:MM:SS.
    Automatically adjusts for daylight savings (PST/PDT).
    """
    # Get UTC time with timezone
    utc_now = datetime.now(tz=ZoneInfo("UTC"))
    
    # Convert to Pacific (America/Los_Angeles)
    pacific_time = utc_now.astimezone(ZoneInfo("America/Los_Angeles"))
    
    # Format as string
    return pacific_time.strftime("%Y-%m-%d %H:%M:%S")

def save_high_interfaces_core(audit_result, json_file_path):
    """
    Processes network utilization data, identifying high-utilization interfaces (>50%).
    Stores data in:
    {
        metro: {
            device: {
                interface: [
                    {neighbor, input_percent, output_percent, speed, timestamp},
                    {neighbor, input_percent, output_percent, speed, timestamp}
                ]
            }
        }
    }
    Loads existing JSON data, updates it, saves to file, and returns the updated dictionary.

    :param audit_result: Dictionary containing device utilization data.
    :param json_file_path: Path to the JSON file for storing high-utilization interfaces.
    :return: Updated high_utilization_data dictionary.
    """
    high_utilization_data = {}

    # Load existing data from JSON file
    if os.path.exists(json_file_path):
        with open(json_file_path, "r") as json_file:
            try:
                high_utilization_data = json.load(json_file)
            except json.JSONDecodeError:
                print(f"Warning: {json_file_path} contains invalid JSON. Starting with an empty dictionary.")

    high_devices_existed = False
    high_devices_header = False
   
    for device, interfaces in audit_result.items():
        metro = extract_metro(device)  # Extract metro from device name

        # Retrieve existing device data if it exists; otherwise, create a new dictionary
        device_data = high_utilization_data.get(metro, {}).get(device, {})

        for key, details in interfaces.items():
            if key in ["role", "year"]:
                continue  # Skip non-interface keys

            interface = key
            input_bps = round(details.get("input_bps", 0))
            input_percent = round(details.get("input_bps_percent", 0))
            output_bps = round(details.get("output_bps", 0))
            output_percent = round(details.get("output_bps_percent", 0))
            neighbor = details.get("neighbor", "Unknown")

            # Convert speed to human-readable format
            raw_speed = details.get("speed_human", 0)
            speed = convert_speed_human(raw_speed) if isinstance(raw_speed, (int, float)) else "Unknown"

            timestamp = get_pacific_timestamp()

            if input_percent > 50 or output_percent > 50:
                high_devices_existed = True
                if not high_devices_header:
                    print("\nDevices with high utilization (>50%):")
                    high_devices_header = True

                print(f"Device: {device}, Interface: {interface}, Metro: {metro}, Speed: {speed}, "
                      f"Neighbor: {neighbor}, Input: {input_percent}%, Output: {output_percent}%, Timestamp: {timestamp}")
                text_message_body = f"Device: {device}, Interface: {interface}, Metro: {metro}, Speed: {speed}, " + \
                            f"Neighbor: {neighbor}, Input: {input_percent}%, Output: {output_percent}%, Timestamp: {timestamp}"
                text_message_subject = text_message_body

                if interface not in device_data:
                    device_data[interface] = []

                device_data[interface].append({
                    "neighbor": neighbor,
                    "input_util": input_bps,
                    "input_percent": input_percent,
                    "output_util": output_bps,
                    "output_percent": output_percent,
                    "speed": speed,
                    "timestamp": timestamp
                })

        if device_data:
            if metro not in high_utilization_data:
                high_utilization_data[metro] = {}  # Create metro if needed
            high_utilization_data[metro][device] = device_data  # Update device data

    # Save the updated data back to the JSON file
    if not high_utilization_data or not high_devices_existed:
        print(f"No high utilization interfaces at core")
        text_message_subject = text_message_body = "No high utilization interfaces at core"
    else:
        with open(json_file_path, "w") as json_file:
            json.dump(high_utilization_data, json_file, indent=4)

        print(f"\nHigh utilization data saved to {json_file_path}")

    return high_utilization_data

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

async def process_device_interfaces(hostname, folder_name, regex_site):
    """
    Process a single device asynchronously, find all active interfaces,
    and log outputs to separate log files.
    """
    host = hostname
    role = "backbone" if host.startswith("cr") or "core" in host else "metro"
    year = 2024 
    local_device_site = host.split(".")[1] if "." in host else host
    matched = re.search(regex_site, local_device_site)
    local_site = matched.group(1).strip() if matched else "Unknown"

    bundle_dict = {}
    bundle_dict["role"] = role 
    bundle_dict["year"] = year
    device_log_file = os.path.join(folder_name, f"{host}.log")

    try:
        print(f"Collecting data on {host}...")
        # Log start of processing
        with open(device_log_file, 'a') as log_file:
            log_file.write(f"Processing device: {host}\n")

        # Fetch 'show version'
        version_result = await rate_limited_gnetch_command("show version", host)
        with open(device_log_file, 'a') as log_file:
            log_file.write("\n--- show version ---\n")
            log_file.write("\n".join(version_result) + "\n")

        # Fetch 'show interfaces terse' to discover all active interfaces
        terse_result = await rate_limited_gnetch_command("show interfaces terse", host)
        with open(device_log_file, 'a') as log_file:
            log_file.write("\n--- show interfaces terse ---\n")
            log_file.write("\n".join(terse_result) + "\n")

        active_intfs = []
        for line in terse_result:
            parts = line.strip().split()
            if len(parts) >= 3:
                intf_name = parts[0]
                admin = parts[1].lower()
                link = parts[2].lower()
                # Match physical or bundle interfaces (no subinterfaces like .0)
                if admin == "up" and link == "up" and "." not in intf_name:
                    if intf_name.startswith(("ae", "et-", "xe-", "ge-")):
                        active_intfs.append(intf_name)

        for intf in active_intfs:
            agg_members = []
            neighbor = "Unknown"
            bundle_dict.setdefault(intf, {"neighbor": neighbor, "Circuit": "Unknown"})

            # Fetch 'show interfaces extensive'
            intf_result = await rate_limited_gnetch_command(f"show interfaces {intf} extensive", host)
            with open(device_log_file, 'a') as log_file:
                log_file.write(f"\n--- show interfaces {intf} extensive ---\n")
                log_file.write("\n".join(intf_result) + "\n")

            speed_in_bps = 100_000_000_000
            speed_str = "100Gbps"
            description = ""
            input_bps = 0
            input_bps_percent = 0.0
            output_bps = 0
            output_bps_percent = 0.0
            input_pps = 0
            output_pps = 0
            agg_member_links = 0

            # Parse interface details
            for line in intf_result:
                if "Description: " in line:
                    description = line
                    bundle_dict[intf]["description"] = description
                    match_r = re.search(r"\[R=([^\]]+)\]", line, flags=re.IGNORECASE)
                    if match_r:
                        neighbor = match_r.group(1).strip()
                        bundle_dict[intf]["neighbor"] = neighbor
                        remote_device_site = neighbor.split(".")[1] if "." in neighbor else neighbor
                        matched_rem = re.search(regex_site, remote_device_site)
                        remote_site = matched_rem.group(1).strip() if matched_rem else "Unknown"
                        bundle_dict[intf]["Circuit"] = "SR" if local_site.upper() == remote_site.upper() else "LR"
                elif "Link-level type: Ethernet, MTU" in line or "Speed:" in line:
                    regex_speed = r"Speed: ([0-9]+Gbps)"
                    matched_sp = re.search(regex_speed, line)
                    if matched_sp:
                        speed_str = matched_sp.group(1)
                        bundle_dict[intf]["speed"] = speed_str
                        try:
                            speed_in_bps = int(speed_str.replace("Gbps", "")) * 1_000_000_000
                            bundle_dict[intf]["speed_human"] = speed_in_bps
                        except ValueError:
                            pass
                elif "Traffic statistics:" in line:
                    try:
                        index = intf_result.index(line)
                        input_bytes = intf_result[index + 1]
                        input_bps = int(input_bytes.split(":")[1].split()[1].strip())

                        output_bytes = intf_result[index + 2]
                        output_bps = int(output_bytes.split(":")[1].split()[1].strip())

                        input_packets = intf_result[index + 3]
                        input_pps = int(input_packets.split(":")[1].split()[1].strip())

                        output_packets = intf_result[index + 4]
                        output_pps = int(output_packets.split(":")[1].split()[1].strip())

                        bundle_dict[intf]["input_bps"] = input_bps
                        bundle_dict[intf]["input_bps_percent"] = (input_bps / speed_in_bps) * 100
                        bundle_dict[intf]["output_bps"] = output_bps
                        bundle_dict[intf]["output_bps_percent"] = (output_bps / speed_in_bps) * 100
                        bundle_dict[intf]["input_pps"] = input_pps
                        bundle_dict[intf]["output_pps"] = output_pps
                    except Exception:
                        pass

                elif "Aggregate member links:" in line:
                    try:
                        agg_member_links = int(line.split(":")[1].strip())
                    except Exception:
                        pass
                    break

            agg_link_found = False
            for i in range(len(intf_result)):
                if "Link:" in intf_result[i] or "Members:" in intf_result[i]:
                    num = 0
                    agg_link_found = True
                    continue
                if agg_link_found and intf_result[i].strip().startswith(("et-", "xe-", "ge-")):
                    agg_members.append(intf_result[i].strip().split()[0])
                    num += 1
                    if agg_member_links > 0 and num == agg_member_links:
                        break

            debug(agg_members)
            member_speeds = {}
            for member in agg_members:
                member_result = await rate_limited_gnetch_command(f"show interfaces {member}", host)
                with open(device_log_file, 'a') as log_file:
                    log_file.write(f"\n--- show interfaces {member} ---\n")
                    log_file.write("\n".join(member_result) + "\n")

                member_speed = "Unknown"
                for m_line in member_result:
                    if "Speed:" in m_line or "Link-level type: Ethernet, MTU" in m_line:
                        matched_m = re.search(r"Speed: ([0-9]+Gbps)", m_line)
                        if matched_m:
                            member_speed = matched_m.group(1)
                            break
                member_speeds[member] = member_speed

            bundle_dict[intf]["ae_list"] = agg_members
            bundle_dict[intf]["member_speeds"] = member_speeds
            is_400g = any("400g" in sp.lower() for sp in member_speeds.values())
            bundle_dict[intf]["is_400g_upgraded"] = is_400g
            bundle_dict[intf]["upgrade_status"] = "400G upgraded" if is_400g else "Not upgraded"

        # Log the completed dictionary
        with open(device_log_file, 'a') as log_file:
            log_file.write("\n--- Processed Data ---\n")
            log_file.write(json.dumps(bundle_dict, indent=4) + "\n")

    except Exception as e:
        # Log errors
        with open(device_log_file, 'a') as log_file:
            log_file.write(f"\nError processing device {host}: {e}\n")

    return {host: bundle_dict}

class CustomArgumentParser(argparse.ArgumentParser):
    def print_help(self):
        super().print_help()
        print("Note #1: Make sure dr yaml file exist, otherwise, you need to build it with -f augument ")
        print("Note #2: if you want to collect LSP data, you need to run it with -d")
        print("Note #3: If you don't provide any arugment in CLI, by default you are using SSH to access devices")

async def process_device_interfaces_with_sem(hostname, folder_name, regex_site, semaphore):
    """
    Wrapper to limit the number of concurrent devices being processed, preventing
    subprocess/network bottlenecking when auditing many devices at once.
    """
    async with semaphore:
        return await process_device_interfaces(hostname, folder_name, regex_site)

async def main():
    parser = CustomArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose debug output')
    parser.add_argument('-d', '--data', action='store_true', help='Collect network configuration data')
    parser.add_argument('-f', '--yaml_file', action='store_true', help='Build DR yaml database')
    parser.add_argument('-a', '--analyze', action='store_true', help='Convert data into excel file')
    parser.add_argument("-m", "--metro", required=False, help="Specify the metro name")
    parser.add_argument("--device", required=False, help="Specify device prefixes to filter from rancid (e.g., '[cr,pr]' or 'cr,pr')")

    parser.add_argument(
        "-j", "--json_folder",
        nargs="?",  # Makes the argument optional
        default=None,  # Default value when not provided
        help="Specify the json folder name (optional). If used, a folder name must be provided."
    )

    args = parser.parse_args()

    # Checking if -j was used but no folder name was provided
    if args.json_folder is None and "-j" in vars(args):
        parser.error("-j requires a folder name when specified.")
        exit(-1)

    folder_name = "audit_logs_interfaces"
    os.makedirs(folder_name, exist_ok=True)

    # Prepare tasks for all devices
    regex_site = r"([a-zA-Z]+)[0-9]+"

    # Dynamically collect routers from rancid folder
    rancid_folder = "/google/src/head/depot/ops/network/rancid/gfiber/juniper"
    all_devices = []

    if os.path.isdir(rancid_folder):
        print(f"Collecting routers from live Rancid depot: {rancid_folder}")
        all_entries = os.listdir(rancid_folder)
        for entry in all_entries:
            base = entry.strip()
            if base.endswith(",v"):
                base = base[:-2]
            if base.startswith(".") or base.endswith((".md", ".html", ".pdf")):
                continue
            all_devices.append(base)
    else:
        sample_file = os.path.join(os.path.dirname(__file__), "rancid_samples", "juniper", "ls_output_sample.txt")
        print(f"Live Rancid depot unreachable; falling back to sample inventory: {sample_file}")
        if os.path.isfile(sample_file):
            with open(sample_file, "r", encoding="utf-8") as f:
                for line in f:
                    item = line.strip()
                    if item and not item.startswith("#"):
                        all_devices.append(item)
        else:
            print("Error: Neither live Rancid depot nor sample inventory file could be loaded.")
            exit(-1)

    all_devices = sorted(set(all_devices))

    if args.metro:
        all_devices = [d for d in all_devices if args.metro in d]

    if args.device:
        cleaned = args.device.strip("[]")
        prefixes = tuple(p.strip().lower() for p in cleaned.split(",") if p.strip())
        device_list = [
            d for d in all_devices
            if d.lower().startswith(prefixes)
        ]
    else:
        device_list = [d for d in all_devices if d.lower().startswith(("cr", "pr", "dr", "mar", "core", "metro"))]

    async_start = time.time()
    # Limit concurrent device audits to 10 to prevent stubby/network bottlenecking
    sem = asyncio.Semaphore(10)
    tasks = [process_device_interfaces_with_sem(device, folder_name, regex_site, sem) for device in device_list]
    # Run tasks concurrently
    results = await asyncio.gather(*tasks)

    # Aggregate results
    audit_result = {host: data for device_result in results for host, data in device_result.items()}
    print(f"Total number of devices: {len(audit_result)}")

    json_file_path = "high_utilization_interfaces_history.json"
    save_high_interfaces_core(audit_result, json_file_path)
    print("You can run 'python convert_core_high_interfaces_excel.py' to convert json to excel file")

    # Get the current date and time
    now = datetime.now()
    date_string = now.strftime("%Y_%m_%d_%H_%M")

    output_file = f'interfaces_high_{date_string}.json'
    if args.json_folder:
        json_folder_name = args.json_folder
    else:
        json_folder_name = "Json_interfaces_folder"
    dump_json_file(json_folder_name, output_file, audit_result)
     
    async_duration = time.time() - async_start
    print(f"Asynchronous execution time: {async_duration:.2f} seconds\n")


if __name__ == "__main__":
    asyncio.run(main())
