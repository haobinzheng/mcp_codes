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
RATE_LIMIT = 0.5  # seconds between commands for the same device
rate_limiters = {}

def get_device_type(hostname):
    name = hostname.lower()
    if name.startswith("bng"):
        return "bng"
    return "juniper"

def get_device_role(hostname):
    name = hostname.lower()
    if name.startswith("cr"):
        return "cr"
    elif name.startswith("pr"):
        return "pr"
    elif name.startswith("bng"):
        return "bng"
    return "unknown"

def convert_speed_human(speed_bps):
    units = [("T", 10**12), ("G", 10**9), ("M", 10**6), ("K", 10**3)]
    for unit, factor in units:
        if speed_bps >= factor:
            return f"{speed_bps / factor:.1f}{unit}" if speed_bps % factor else f"{speed_bps // factor}{unit}"
    return f"{speed_bps}bps"

def normalize_system_name(name):
    name = name.lower()
    if name.endswith(".googlefiber.net"):
        name = name[:-16]
    name = re.sub(r"^re[01]-", "", name)
    return name.strip()

async def async_gnetch_command(cmd, target):
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
    if target not in rate_limiters:
        rate_limiters[target] = asyncio.Semaphore(1)

    async with rate_limiters[target]:
        output = await async_gnetch_command(cmd, target)
        await asyncio.sleep(RATE_LIMIT)
        return output

async def discover_cr_topology(host, device_log_file):
    try:
        print(f"Discovering topology for CR router: {host}...")
        with open(device_log_file, 'a') as log_file:
            log_file.write(f"Discovering topology on CR: {host}\n")

        # show lldp neighbors
        lldp_output = await rate_limited_gnetch_command("show lldp neighbors", host)
        with open(device_log_file, 'a') as log_file:
            log_file.write("\n--- show lldp neighbors ---\n")
            log_file.write("\n".join(lldp_output) + "\n")

        neighbors = []
        for line in lldp_output:
            line = line.strip()
            if not line or line.startswith("Local Interface") or line.startswith("---"):
                continue
            parts = line.split()
            if len(parts) >= 5:
                local_int = parts[0]
                parent_int = parts[1]
                chassis_id = parts[2]
                system_name = parts[-1]
                
                if parent_int == "-":
                    parent_int = None
                
                neighbors.append({
                    "local_interface": local_int,
                    "parent_interface": parent_int,
                    "chassis_id": chassis_id,
                    "system_name": system_name
                })

        # Filter out management and dr neighbors, and require parent interface (ae bundle)
        filtered_neighbors = []
        for n in neighbors:
            sys_name = n["system_name"].lower()
            local_int = n["local_interface"].lower()
            parent_int = n["parent_interface"]
            
            if "mgt" in sys_name or "mgmt" in sys_name or "dr" in sys_name:
                continue
            if "mgmt" in local_int or "mgt" in local_int:
                continue
            if not parent_int or not parent_int.lower().startswith("ae"):
                continue
                
            filtered_neighbors.append(n)

        # Group by parent interface and peer system
        bundle_peers = {}
        for n in filtered_neighbors:
            parent = n["parent_interface"]
            peer = normalize_system_name(n["system_name"])
            bundle_peers.setdefault(parent, {"peer": peer, "members": []})
            bundle_peers[parent]["members"].append(n["local_interface"])

        # Now fetch speeds for each bundle
        topology_data = {}
        for bundle, info in bundle_peers.items():
            intf_output = await rate_limited_gnetch_command(f"show interfaces {bundle}", host)
            with open(device_log_file, 'a') as log_file:
                log_file.write(f"\n--- show interfaces {bundle} ---\n")
                log_file.write("\n".join(intf_output) + "\n")

            speed_bps = 0
            for line in intf_output:
                if "Speed:" in line:
                    match = re.search(r"Speed:\s*([0-9]+)(Gbps|Mbps|Gb|Mb)", line, re.IGNORECASE)
                    if match:
                        val = int(match.group(1))
                        unit = match.group(2).lower()
                        if "g" in unit:
                            speed_bps = val * 1_000_000_000
                        elif "m" in unit:
                            speed_bps = val * 1_000_000
                    break

            topology_data[bundle] = {
                "local_interface": bundle,
                "remote_device": info["peer"],
                "capacity_bps": speed_bps,
                "capacity_human": convert_speed_human(speed_bps),
                "members": info["members"]
            }

        with open(device_log_file, 'a') as log_file:
            log_file.write("\n--- Discovered CR Topology ---\n")
            log_file.write(json.dumps(topology_data, indent=4) + "\n")

        return topology_data

    except Exception as e:
        with open(device_log_file, 'a') as log_file:
            log_file.write(f"\nError discovering topology on CR {host}: {e}\n")
        return {}

async def discover_pr_topology(host, device_log_file):
    try:
        print(f"Discovering topology for PR router: {host}...")
        with open(device_log_file, 'a') as log_file:
            log_file.write(f"Discovering topology on PR: {host}\n")

        # show interfaces descriptions
        desc_output = await rate_limited_gnetch_command("show interfaces descriptions", host)
        with open(device_log_file, 'a') as log_file:
            log_file.write("\n--- show interfaces descriptions ---\n")
            log_file.write("\n".join(desc_output) + "\n")

        # Filter for core-connected ae interfaces
        core_ae_interfaces = set()
        for line in desc_output:
            line = line.strip()
            if line.startswith("ae"):
                parts = line.split()
                ae_name = parts[0]
                desc_str = " ".join(parts[1:])
                if re.search(r"\[R=[^\]]*cr[^\]]*\]", desc_str, re.IGNORECASE) and "CORE" in desc_str:
                    core_ae_interfaces.add(ae_name)

        if not core_ae_interfaces:
            with open(device_log_file, 'a') as log_file:
                log_file.write("No core-connected ae interfaces found via show interfaces descriptions.\n")
            return {}

        # show lldp neighbors
        lldp_output = await rate_limited_gnetch_command("show lldp neighbors", host)
        with open(device_log_file, 'a') as log_file:
            log_file.write("\n--- show lldp neighbors ---\n")
            log_file.write("\n".join(lldp_output) + "\n")

        neighbors = []
        for line in lldp_output:
            line = line.strip()
            if not line or line.startswith("Local Interface") or line.startswith("---"):
                continue
            parts = line.split()
            if len(parts) >= 5:
                local_int = parts[0]
                parent_int = parts[1]
                chassis_id = parts[2]
                system_name = parts[-1]
                
                if parent_int == "-":
                    parent_int = None
                
                neighbors.append({
                    "local_interface": local_int,
                    "parent_interface": parent_int,
                    "chassis_id": chassis_id,
                    "system_name": system_name
                })

        # Group by parent interface and remote peer
        bundle_peers = {}
        for n in neighbors:
            parent = n["parent_interface"]
            if parent in core_ae_interfaces:
                peer = normalize_system_name(n["system_name"])
                bundle_peers.setdefault(parent, {"peer": peer, "members": []})
                bundle_peers[parent]["members"].append(n["local_interface"])

        # Fetch speeds for core-connected bundles
        topology_data = {}
        for bundle, info in bundle_peers.items():
            intf_output = await rate_limited_gnetch_command(f"show interfaces {bundle}", host)
            with open(device_log_file, 'a') as log_file:
                log_file.write(f"\n--- show interfaces {bundle} ---\n")
                log_file.write("\n".join(intf_output) + "\n")

            speed_bps = 0
            for line in intf_output:
                if "Speed:" in line:
                    match = re.search(r"Speed:\s*([0-9]+)(Gbps|Mbps|Gb|Mb)", line, re.IGNORECASE)
                    if match:
                        val = int(match.group(1))
                        unit = match.group(2).lower()
                        if "g" in unit:
                            speed_bps = val * 1_000_000_000
                        elif "m" in unit:
                            speed_bps = val * 1_000_000
                    break

            topology_data[bundle] = {
                "local_interface": bundle,
                "remote_device": info["peer"],
                "capacity_bps": speed_bps,
                "capacity_human": convert_speed_human(speed_bps),
                "members": info["members"]
            }

        with open(device_log_file, 'a') as log_file:
            log_file.write("\n--- Discovered PR Topology ---\n")
            log_file.write(json.dumps(topology_data, indent=4) + "\n")

        return topology_data

    except Exception as e:
        with open(device_log_file, 'a') as log_file:
            log_file.write(f"\nError discovering topology on PR {host}: {e}\n")
        return {}

async def discover_bng_topology(host, device_log_file):
    try:
        print(f"Discovering topology for BNG router: {host}...")
        with open(device_log_file, 'a') as log_file:
            log_file.write(f"Discovering topology on BNG SROS: {host}\n")

        # show system lldp neighbor
        lldp_output = await rate_limited_gnetch_command("show system lldp neighbor", host)
        with open(device_log_file, 'a') as log_file:
            log_file.write("\n--- show system lldp neighbor ---\n")
            log_file.write("\n".join(lldp_output) + "\n")

        # Filter for CR neighbors
        cr_neighbors = []
        for line in lldp_output:
            line = line.strip()
            if not line or line.startswith("="):
                continue
            parts = line.split()
            if len(parts) >= 6:
                port = parts[0]
                peer_system = parts[-1].replace("*", "")
                peer_port = parts[-2]
                
                if "cr0" in peer_system.lower() or "cr" in peer_system.lower():
                    cr_neighbors.append({
                        "local_port": port,
                        "peer_system": normalize_system_name(peer_system),
                        "peer_port": peer_port
                    })

        if not cr_neighbors:
            with open(device_log_file, 'a') as log_file:
                log_file.write("No CR neighbors found via show system lldp neighbor.\n")
            return {}

        # Collect port details (LAG mapping and speed) in parallel for CR neighbors
        async def get_port_details(n):
            port = n["local_port"]
            port_output = await rate_limited_gnetch_command(f"show port {port}", host)
            with open(device_log_file, 'a') as log_file:
                log_file.write(f"\n--- show port {port} ---\n")
                log_file.write("\n".join(port_output) + "\n")

            lag_id = None
            speed_bps = 0

            for line in port_output:
                if "Description" in line:
                    lag_match = re.search(r"\[A=([^\]]+)\]", line, re.IGNORECASE)
                    if lag_match:
                        lag_id = lag_match.group(1).strip().lower()
                elif "Oper Speed" in line:
                    parts = line.split(":")
                    if len(parts) >= 3:
                        speed_str = parts[2].strip()
                        match = re.match(r"^(\d+)\s*(Gbps|Mbps|kbps|Gb|Mb|Kb)", speed_str, re.IGNORECASE)
                        if match:
                            val = int(match.group(1))
                            unit = match.group(2).lower()
                            if "g" in unit:
                                speed_bps = val * 1_000_000_000
                            elif "m" in unit:
                                speed_bps = val * 1_000_000

            return {
                "local_port": port,
                "peer_system": n["peer_system"],
                "peer_port": n["peer_port"],
                "lag_id": lag_id,
                "speed_bps": speed_bps
            }

        port_tasks = [get_port_details(n) for n in cr_neighbors]
        port_details_list = await asyncio.gather(*port_tasks)

        lag_groups = {}
        for pd in port_details_list:
            lag_id = pd["lag_id"]
            if not lag_id:
                continue
            peer = pd["peer_system"]
            key = (lag_id, peer)
            lag_groups.setdefault(key, {"ports": [], "total_speed_bps": 0})
            lag_groups[key]["ports"].append(pd["local_port"])
            lag_groups[key]["total_speed_bps"] += pd["speed_bps"]

        topology_data = {}
        for (lag_id, peer), info in lag_groups.items():
            lag_num_match = re.search(r"lag-(\d+)", lag_id, re.IGNORECASE)
            ae_interface = f"ae{lag_num_match.group(1)}" if lag_num_match else lag_id

            topology_data[ae_interface] = {
                "local_interface": ae_interface,
                "remote_device": peer,
                "capacity_bps": info["total_speed_bps"],
                "capacity_human": convert_speed_human(info["total_speed_bps"]),
                "members": info["ports"]
            }

        with open(device_log_file, 'a') as log_file:
            log_file.write("\n--- Discovered BNG Topology ---\n")
            log_file.write(json.dumps(topology_data, indent=4) + "\n")

        return topology_data

    except Exception as e:
        with open(device_log_file, 'a') as log_file:
            log_file.write(f"\nError discovering topology on BNG {host}: {e}\n")
        return {}

async def process_device(device, folder_name):
    device_log_file = os.path.join(folder_name, f"{device}.log")
    role = get_device_role(device)
    
    if role == "cr":
        topology = await discover_cr_topology(device, device_log_file)
    elif role == "pr":
        topology = await discover_pr_topology(device, device_log_file)
    elif role == "bng":
        topology = await discover_bng_topology(device, device_log_file)
    else:
        topology = {}
        
    return device, topology

def get_pacific_timestamp() -> str:
    utc_now = datetime.now(tz=ZoneInfo("UTC"))
    pacific_time = utc_now.astimezone(ZoneInfo("America/Los_Angeles"))
    return pacific_time.strftime("%Y-%m-%d %H:%M:%S")

async def main():
    parser = argparse.ArgumentParser(description="Discover network topology for CR, PR, and BNG routers.")
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose debug output')
    parser.add_argument("-m", "--metro", required=False, help="Specify the metro name to filter")
    parser.add_argument("--device", required=False, help="Specify device prefixes or hostnames to filter (e.g., 'cr,pr' or 'cr01.atl101')")
    parser.add_argument("-j", "--json_file", default="topology_discovery.json", help="Specify output JSON file path")

    args = parser.parse_args()

    folder_name = "topology_discovery_logs"
    create_or_recreate_folder(folder_name)

    juniper_rancid = "/google/src/head/depot/ops/network/rancid/gfiber/juniper"
    bng_rancid = "/google/src/head/depot/ops/network/rancid/gfiber/alcatellucentsr"
    all_devices = []

    if os.path.isdir(juniper_rancid):
        print(f"Collecting Juniper routers from live Rancid depot: {juniper_rancid}")
        for entry in os.listdir(juniper_rancid):
            base = entry.strip()
            if base.endswith(",v"):
                base = base[:-2]
            if base.startswith(".") or base.endswith((".md", ".html", ".pdf")):
                continue
            all_devices.append(base)
            
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
            if d.lower().startswith(prefixes) or d.lower() in prefixes
        ]
    else:
        device_list = [d for d in all_devices if d.lower().startswith(("cr", "pr", "bng"))]

    if not device_list:
        print("No devices matched your filters.")
        return

    print(f"Matched {len(device_list)} total devices to discover topology: {device_list}")

    sem = asyncio.Semaphore(20)

    async def sem_process(device):
        async with sem:
            return await process_device(device, folder_name)

    start_time = time.time()
    tasks = [sem_process(device) for device in device_list]
    results = await asyncio.gather(*tasks)

    topology_report = {}
    for device, topology in results:
        if topology:
            topology_report[device] = topology

    print("\n" + "="*80)
    print(f" DISCOVERED TOPOLOGY REPORT - {get_pacific_timestamp()} ")
    print("="*80)
    print(f"{'Local Device':<20} | {'Local Int':<10} | {'Remote Device':<20} | {'Capacity':<8} | {'Members'}")
    print("-"*80)
    for local_dev, intfs in sorted(topology_report.items()):
        for intf_name, details in sorted(intfs.items()):
            members_str = ", ".join(details["members"])
            print(f"{local_dev:<20} | {intf_name:<10} | {details['remote_device']:<20} | {details['capacity_human']:<8} | {members_str}")
    print("="*80)

    with open(args.json_file, "w") as f:
        json.dump(topology_report, f, indent=4)
    print(f"\nTopology report successfully saved to {args.json_file}")
    
    duration = time.time() - start_time
    print(f"Total discovery time: {duration:.2f} seconds\n")

if __name__ == "__main__":
    asyncio.run(main())
