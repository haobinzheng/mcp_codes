#!/usr/bin/env python3
import os
import sys
import re
import json
import asyncio
import time
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
RATE_LIMIT = 2.0  # seconds between commands for the same device
rate_limiters = {}

def get_device_type(hostname):
    """ Determines if a device is a Nokia BNG (SROS) or a Juniper device. """
    name = hostname.lower()
    if name.startswith("bng"):
        return "bng"
    return "juniper"

def convert_speed_human(speed_bps):
    """ Converts raw speed in bps to human-readable format (K, M, G, T). """
    units = [("T", 10**12), ("G", 10**9), ("M", 10**6), ("K", 10**3)]
    for unit, factor in units:
        if speed_bps >= factor:
            return f"{speed_bps / factor:.1f}{unit}" if speed_bps % factor else f"{speed_bps // factor}{unit}"
    return f"{speed_bps}bps"

def extract_metro(device_name):
    """ Extracts the 3-letter metro code from the device hostname. """
    match = re.search(r"\.(\D{3})\d*", device_name)
    return match.group(1) if match else "unknown"

def get_pacific_timestamp() -> str:
    """ Returns current Pacific Time timestamp in format YYYY-MM-DD HH:MM:SS. """
    utc_now = datetime.now(tz=ZoneInfo("UTC"))
    pacific_time = utc_now.astimezone(ZoneInfo("America/Los_Angeles"))
    return pacific_time.strftime("%Y-%m-%d %H:%M:%S")

def save_high_interfaces_core(audit_result, json_file_path):
    """ Identifies high utilization interfaces (>50%) and saves to historical record. """
    high_utilization_data = {}

    if os.path.exists(json_file_path):
        with open(json_file_path, "r") as json_file:
            try:
                high_utilization_data = json.load(json_file)
            except json.JSONDecodeError:
                print(f"Warning: {json_file_path} contains invalid JSON. Starting with an empty dictionary.")

    high_devices_existed = False
    high_devices_header = False
   
    for device, interfaces in audit_result.items():
        metro = extract_metro(device)
        device_data = high_utilization_data.get(metro, {}).get(device, {})

        for key, details in interfaces.items():
            if key in ["role", "year", "audit_timestamp"]:
                continue

            interface = key
            input_bps = round(details.get("input_bps", 0))
            input_percent = round(details.get("input_bps_percent", 0))
            output_bps = round(details.get("output_bps", 0))
            output_percent = round(details.get("output_bps_percent", 0))
            neighbor = details.get("neighbor", "Unknown")

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
                high_utilization_data[metro] = {}
            high_utilization_data[metro][device] = device_data

    if not high_utilization_data or not high_devices_existed:
        print(f"No high utilization interfaces found.")
    else:
        with open(json_file_path, "w") as json_file:
            json.dump(high_utilization_data, json_file, indent=4)
        print(f"\nHigh utilization data saved to {json_file_path}")

    return high_utilization_data

async def async_gnetch_command(cmd, target):
    """ Asynchronously execute a gnetch command using asyncio subprocess. """
    gnetch_cmd = f"stubby --proto2 call blade:gnetch-frontend Gnetch2.Command 'command: \"{cmd}\" target: \"{target}\"'"
    process = await asyncio.create_subprocess_shell(
        gnetch_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, _ = await process.communicate()
    raw_out = stdout.decode()
    match = re.search(r'data:\s*"(.*)"', raw_out, re.DOTALL)
    if match:
        content = match.group(1)
        content = content.replace('\\"', '"')
        return content.split("\\n")
    return []

async def rate_limited_gnetch_command(cmd, target):
    """ Execute gnetch_command with rate limiting. """
    if target not in rate_limiters:
        rate_limiters[target] = asyncio.Semaphore(1)

    async with rate_limiters[target]:
        output = await async_gnetch_command(cmd, target)
        await asyncio.sleep(RATE_LIMIT)
        return output

# SROS BNG Specific Parsers
def parse_isis_adjacencies(lines):
    adjacencies = []
    for line in lines:
        match = re.search(r"\b(\S+)\s+\S+\s+(Up)\s+\d+\s+(ae\d+)\b", line, re.IGNORECASE)
        if match:
            adjacencies.append({
                "system_id": match.group(1),
                "interface": match.group(3)
            })
    return adjacencies

def parse_router_interface(lines, interface_name):
    for line in lines:
        match = re.search(rf"\b({interface_name})\b\s+\S+\s+\S+\s+\S+\s+(\S+)", line)
        if match:
            return match.group(2)
    return None

def parse_lag_ports(lines, lag_id):
    ports = []
    for line in lines:
        if "up" in line.lower() or "active" in line.lower():
            match = re.search(r"\b\d+/\d+/[a-zA-Z0-9]+(?:/[a-zA-Z0-9]+)*\b", line)
            if match:
                ports.append(match.group(0))
    return ports

def parse_port_speed(lines):
    for line in lines:
        if "Oper Speed" in line:
            parts = line.split(":")
            if len(parts) >= 3:
                speed_str = parts[2].strip()
                match = re.match(r"^(\d+)\s*(Gbps|Mbps|kbps|Gb|Mb|Kb)", speed_str, re.IGNORECASE)
                if match:
                    val = int(match.group(1))
                    unit = match.group(2).lower()
                    if "g" in unit:
                        return val * 1_000_000_000
                    elif "m" in unit:
                        return val * 1_000_000
                    elif "k" in unit:
                        return val * 1_000
                return 0
    return 0

def parse_monitor_lag_totals(lines):
    for i in range(len(lines) - 1, -1, -1):
        if lines[i].strip().startswith("Totals"):
            if i + 1 < len(lines):
                parts = lines[i+1].split()
                if len(parts) >= 2:
                    return int(parts[0]), int(parts[1])
    return 0, 0

async def process_device_interfaces(hostname, folder_name, regex_site):
    """ Process a single device (either SROS BNG or Juniper) and return results dictionary. """
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

    device_type = get_device_type(host)

    if device_type == "juniper":
        try:
            print(f"Collecting data on Juniper host {host}...")
            with open(device_log_file, 'a') as log_file:
                log_file.write(f"Processing Juniper device: {host}\n")

            version_result = await rate_limited_gnetch_command("show version", host)
            with open(device_log_file, 'a') as log_file:
                log_file.write("\n--- show version ---\n")
                log_file.write("\n".join(version_result) + "\n")

            active_intfs = []
            isis_neighbors = {}

            if host.startswith("cr") or "core" in host:
                adj_result = await rate_limited_gnetch_command("show isis adjacency", host)
                with open(device_log_file, 'a') as log_file:
                    log_file.write("\n--- show isis adjacency ---\n")
                    log_file.write("\n".join(adj_result) + "\n")

                adj_list = parse_isis_adj(adj_result)
                for adj in adj_list:
                    if "dr" in adj["System"] or "cr" in adj["System"] or "pr" in adj["System"]:
                        if adj["State"] == "Up":
                            intf = adj['Interface'].split(".")[0]
                            if intf not in active_intfs:
                                active_intfs.append(intf)
                            isis_neighbors[intf] = adj["System"]
            else:
                terse_result = await rate_limited_gnetch_command("show interfaces terse", host)
                with open(device_log_file, 'a') as log_file:
                    log_file.write("\n--- show interfaces terse ---\n")
                    log_file.write("\n".join(terse_result) + "\n")

                for line in terse_result:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        intf_name = parts[0]
                        admin = parts[1].lower()
                        link = parts[2].lower()
                        if admin == "up" and link == "up" and "." not in intf_name:
                            if intf_name.startswith("ae"):
                                active_intfs.append(intf_name)

            for intf in active_intfs:
                agg_members = []
                neighbor = "Unknown"
                circuit = "Unknown"
                if (host.startswith("cr") or "core" in host) and intf in isis_neighbors:
                    neighbor = isis_neighbors[intf]
                    remote_device_site = neighbor.split(".")[1] if "." in neighbor else neighbor
                    matched_rem = re.search(regex_site, remote_device_site)
                    remote_site = matched_rem.group(1).strip() if matched_rem else "Unknown"
                    circuit = "SR" if local_site.upper() == remote_site.upper() else "LR"

                bundle_dict.setdefault(intf, {"neighbor": neighbor, "Circuit": circuit})

                intf_result = await rate_limited_gnetch_command(f"show interfaces {intf} extensive", host)
                with open(device_log_file, 'a') as log_file:
                    log_file.write(f"\n--- show interfaces {intf} extensive ---\n")
                    log_file.write("\n".join(intf_result) + "\n")

                speed_in_bps = 100_000_000_000
                speed_str = "100Gbps"
                description = ""
                input_bps = 0
                output_bps = 0
                agg_member_links = 0

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

                            bundle_dict[intf]["input_bps"] = input_bps
                            bundle_dict[intf]["input_bps_percent"] = (input_bps / speed_in_bps) * 100
                            bundle_dict[intf]["output_bps"] = output_bps
                            bundle_dict[intf]["output_bps_percent"] = (output_bps / speed_in_bps) * 100
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

            with open(device_log_file, 'a') as log_file:
                log_file.write("\n--- Processed Juniper Data ---\n")
                log_file.write(json.dumps(bundle_dict, indent=4) + "\n")

        except Exception as e:
            with open(device_log_file, 'a') as log_file:
                log_file.write(f"\nError processing Juniper device {host}: {e}\n")

    elif device_type == "bng":
        try:
            print(f"Collecting data on Nokia BNG host {host}...")
            with open(device_log_file, 'a') as log_file:
                log_file.write(f"Processing BNG SROS device: {host}\n")

            isis_output = await rate_limited_gnetch_command("show router isis adjacency", host)
            with open(device_log_file, 'a') as log_file:
                log_file.write("\n--- show router isis adjacency ---\n")
                log_file.write("\n".join(isis_output) + "\n")
            
            adjacencies = parse_isis_adjacencies(isis_output)
            
            for adj in adjacencies:
                intf = adj["interface"]
                system_id = adj["system_id"]
                
                remote_device_site = system_id.split(".")[1] if "." in system_id else system_id
                matched_rem = re.search(regex_site, remote_device_site)
                remote_site = matched_rem.group(1).strip() if matched_rem else "Unknown"
                circuit = "SR" if local_site.upper() == remote_site.upper() else "LR"
                
                bundle_dict.setdefault(intf, {
                    "neighbor": system_id,
                    "Circuit": circuit,
                    "description": "BNG LAG interface"
                })
                
                intf_output = await rate_limited_gnetch_command(f'show router interface {intf}', host)
                with open(device_log_file, 'a') as log_file:
                    log_file.write(f"\n--- show router interface {intf} ---\n")
                    log_file.write("\n".join(intf_output) + "\n")
                
                lag_id = parse_router_interface(intf_output, intf)
                if not lag_id:
                    continue
                    
                lag_output = await rate_limited_gnetch_command(f'show lag {lag_id} port', host)
                with open(device_log_file, 'a') as log_file:
                    log_file.write(f"\n--- show lag {lag_id} port ---\n")
                    log_file.write("\n".join(lag_output) + "\n")
                
                ports = parse_lag_ports(lag_output, lag_id)
                if not ports:
                    continue
                    
                total_lag_speed = 0
                port_speeds = {}
                
                for port in ports:
                    port_output = await rate_limited_gnetch_command(f"show port {port}", host)
                    with open(device_log_file, 'a') as log_file:
                        log_file.write(f"\n--- show port {port} ---\n")
                        log_file.write("\n".join(port_output) + "\n")
                    
                    speed = parse_port_speed(port_output)
                    port_speeds[port] = convert_speed_human(speed) if speed > 0 else "Unknown"
                    total_lag_speed += speed
                    
                if total_lag_speed == 0:
                    continue
                    
                bundle_dict[intf]["ae_list"] = ports
                bundle_dict[intf]["member_speeds"] = port_speeds
                bundle_dict[intf]["speed"] = convert_speed_human(total_lag_speed)
                bundle_dict[intf]["speed_human"] = total_lag_speed
                
                is_400g = any("400g" in sp.lower() for sp in port_speeds.values())
                bundle_dict[intf]["is_400g_upgraded"] = is_400g
                bundle_dict[intf]["upgrade_status"] = "400G upgraded" if is_400g else "Not upgraded"
                
                # 5) use monitor lag to fetch traffic snapshots
                lag_num_match = re.search(r"\d+", lag_id)
                if not lag_num_match:
                    continue
                lag_num = lag_num_match.group(0)
                
                monitor_output = await rate_limited_gnetch_command(f"monitor lag {lag_num} interval 3 repeat 3", host)
                with open(device_log_file, 'a') as log_file:
                    log_file.write(f"\n--- monitor lag {lag_id} ---\n")
                    log_file.write("\n".join(monitor_output) + "\n")
                
                in_bytes, out_bytes = parse_monitor_lag_totals(monitor_output)
                
                in_bps = (in_bytes * 8) / 3.0
                out_bps = (out_bytes * 8) / 3.0
                
                bundle_dict[intf]["input_bps"] = in_bps
                bundle_dict[intf]["input_bps_percent"] = (in_bps / total_lag_speed) * 100
                bundle_dict[intf]["output_bps"] = out_bps
                bundle_dict[intf]["output_bps_percent"] = (out_bps / total_lag_speed) * 100
                bundle_dict[intf]["input_pps"] = 0
                bundle_dict[intf]["output_pps"] = 0

            with open(device_log_file, 'a') as log_file:
                log_file.write("\n--- Processed BNG SROS Data ---\n")
                log_file.write(json.dumps(bundle_dict, indent=4) + "\n")

        except Exception as e:
            with open(device_log_file, 'a') as log_file:
                log_file.write(f"\nError processing BNG SROS device {host}: {e}\n")

    return {host: bundle_dict}

async def run_audit_cycle(device_list, folder_name, regex_site, args):
    async_start = time.time()
    tasks = [process_device_interfaces(device, folder_name, regex_site) for device in device_list]
    results = await asyncio.gather(*tasks)

    audit_result = {host: data for device_result in results for host, data in device_result.items()}
    print(f"Total number of audited devices: {len(audit_result)}")

    json_file_path = "high_utilization_interfaces_history.json"
    save_high_interfaces_core(audit_result, json_file_path)
    print("You can run 'python convert_core_high_interfaces_excel.py' to convert json to excel file")

    root_folder = args.json_folder if args.json_folder else "Audit_interfaces_data"
    pt_now = datetime.now(tz=ZoneInfo("America/Los_Angeles"))
    date_folder = pt_now.strftime("%Y-%m-%d")
    time_stamp = pt_now.strftime("%Y_%m_%d_%H_%M")

    for host, data in audit_result.items():
        host_folder = os.path.join(root_folder, date_folder, host)
        os.makedirs(host_folder, exist_ok=True)
        json_filename = f"{host}_{time_stamp}.json"
        data["audit_timestamp"] = pt_now.strftime("%Y-%m-%d %H:%M:%S")
        dump_json_file(host_folder, json_filename, data)
     
    async_duration = time.time() - async_start
    print(f"Asynchronous execution time: {async_duration:.2f} seconds\n")

async def main():
    parser = argparse.ArgumentParser(description="Audit Juniper and Nokia BNG interfaces utilization asynchronously.")
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose debug output')
    parser.add_argument("-m", "--metro", required=False, help="Specify the metro name to filter")
    parser.add_argument("--device", required=False, help="Specify device prefixes to filter from rancid (e.g., 'cr,bng' or '[cr,bng]')")
    parser.add_argument("-j", "--json_folder", default=None, help="Specify output json root folder (optional)")
    parser.add_argument("--duration", required=False, help="Run continuously for specified duration (e.g. '5h', '30m')")

    args = parser.parse_args()

    folder_name = "audit_logs_interfaces"
    os.makedirs(folder_name, exist_ok=True)

    regex_site = r"([a-zA-Z]+)[0-9]+"

    # Dynamically collect routers from rancid folders
    juniper_rancid = "/google/src/head/depot/ops/network/rancid/gfiber/juniper"
    bng_rancid = "/google/src/head/depot/ops/network/rancid/gfiber/alcatellucentsr"
    all_devices = []

    # 1) Collect Juniper
    if os.path.isdir(juniper_rancid):
        print(f"Collecting Juniper routers from live Rancid depot: {juniper_rancid}")
        for entry in os.listdir(juniper_rancid):
            base = entry.strip()
            if base.endswith(",v"):
                base = base[:-2]
            if base.startswith(".") or base.endswith((".md", ".html", ".pdf")):
                continue
            all_devices.append(base)
            
    # 2) Collect BNG
    if os.path.isdir(bng_rancid):
        print(f"Collecting BNG SROS routers from live Rancid depot: {bng_rancid}")
        for entry in os.listdir(bng_rancid):
            base = entry.strip()
            if base.endswith(",v"):
                base = base[:-2]
            if base.startswith(".") or base.endswith((".md", ".html", ".pdf")):
                continue
            all_devices.append(base)

    if not all_devices:
        # Fallback sample setup if rancid not present
        sample_file = os.path.join(os.path.dirname(__file__), "rancid_samples", "juniper", "ls_output_sample.txt")
        if os.path.isfile(sample_file):
            print(f"Rancid unreachable; falling back to sample inventory: {sample_file}")
            with open(sample_file, "r", encoding="utf-8") as f:
                for line in f:
                    item = line.strip()
                    if item and not item.startswith("#"):
                        all_devices.append(item)
        else:
            print("Error: No devices found and sample inventory file unreachable.")
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
        # Default: Audit all Juniper and BNG SROS devices
        device_list = [d for d in all_devices if d.lower().startswith(("cr", "bng", "pr", "dr", "mpr"))]

    if not device_list:
        print("No devices matched your filters.")
        return

    print(f"Matched {len(device_list)} total devices to audit: {device_list}")

    if args.duration:
        # Parse duration
        val = float(re.match(r"^\d+", args.duration).group(0))
        unit = re.search(r"[a-zA-Z]+$", args.duration)
        unit_str = unit.group(0).lower() if unit else "s"
        multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
        total_duration = val * multipliers.get(unit_str, 1)
    else:
        total_duration = 0.0

    if total_duration > 0:
        start_time = time.time()
        sleep_interval = 300.0
        print(f"Starting continuous auditing every 5 minutes for duration: {args.duration}")
        while True:
            elapsed = time.time() - start_time
            if elapsed >= total_duration:
                print("Continuous audit duration completed.")
                break

            print(f"\n=== Starting audit cycle at {get_pacific_timestamp()} ===")
            await run_audit_cycle(device_list, folder_name, regex_site, args)

            sleep_needed = sleep_interval
            if (time.time() - start_time + sleep_needed) >= total_duration:
                sleep_needed = total_duration - (time.time() - start_time)

            if sleep_needed > 0:
                print(f"Waiting {sleep_needed:.1f} seconds before next cycle...")
                await asyncio.sleep(sleep_needed)
    else:
        await run_audit_cycle(device_list, folder_name, regex_site, args)

if __name__ == "__main__":
    asyncio.run(main())
