#!/usr/bin/env python3
"""
discover_topology_mpls.py

Discovers MPLS core and peering network topology excluding BNG routers.
Collects:
1. LLDP neighbor adjacencies and member ports.
2. Link bandwidth speed and capacity (capacity_bps, capacity_human).
3. Loopback IP address for each router (lo0.0 / Router ID).
4. Local IPv4 address and remote IPv4 address for each interface link.

Outputs: topology_discovery_mpls.json (by default).
"""

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

DEBUG = False
RATE_LIMIT = 0.5  # seconds between commands for the same device
rate_limiters = {}

def get_device_role(hostname):
    name = hostname.lower()
    if name.startswith("bng") or name.startswith("rr"):
        return "bng"  # Excluded role
    elif name.startswith("cr"):
        return "cr"
    elif name.startswith("pr") or name.startswith("mpr"):
        return "pr"
    return "unknown"

def convert_speed_human(speed_bps):
    units = [("T", 10**12), ("G", 10**9), ("M", 10**6), ("K", 10**3)]
    for unit, factor in units:
        if speed_bps >= factor:
            return f"{speed_bps / factor:.1f}{unit}" if speed_bps % factor else f"{speed_bps // factor}{unit}"
    return f"{speed_bps}bps"

def normalize_system_name(name):
    name = name.lower().strip()
    if name.endswith(".googlefiber.net"):
        name = name[:-16]
    name = re.sub(r"^re[01]-", "", name)
    return name.strip()

def derive_peer_ip_point_to_point(ip_str):
    if not ip_str or "/" not in ip_str:
        return ""
    parts = ip_str.split("/")
    ip_part, mask = parts[0], parts[1]
    if mask not in ("30", "31"):
        return ""
    try:
        octets = [int(o) for o in ip_part.split(".")]
        if len(octets) != 4:
            return ""
        octets[3] = octets[3] ^ 1
        peer_ip = ".".join(str(o) for o in octets)
        return f"{peer_ip}/{mask}"
    except Exception:
        return ""

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

async def fetch_interface_ip_table(host, device_log_file):
    """
    Executes 'show interfaces terse' on JunOS devices and returns:
    1) loopback_ip (IPv4 of lo0.0 / lo0)
    2) interface_ips dict mapping base interface name (e.g. 'ae10') -> local IPv4 string
    """
    terse_output = await rate_limited_gnetch_command("show interfaces terse", host)
    with open(device_log_file, 'a') as log_file:
        log_file.write("\n--- show interfaces terse ---\n")
        log_file.write("\n".join(terse_output) + "\n")

    loopback_ip = ""
    interface_ips = {}
    current_intf = ""

    for line in terse_output:
        line_str = line.strip()
        if not line_str or line_str.startswith("Interface") or line_str.startswith("---"):
            continue

        parts = line_str.split()
        if len(parts) >= 1:
            if "." in parts[0] or parts[0].startswith(("ae", "et", "ge", "xe", "lo")):
                current_intf = parts[0]

        # Check for inet IPv4 address line
        if "inet" in line_str:
            tokens = line_str.split()
            try:
                inet_idx = tokens.index("inet")
                if len(tokens) > inet_idx + 1:
                    ip_candidate = tokens[inet_idx + 1]
                    # Match IPv4 pattern like 10.100.1.2/30 or 10.0.0.1
                    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$", ip_candidate):
                        intf_name = current_intf if current_intf else (tokens[0] if tokens[0] != "inet" else "")
                        base_intf = intf_name.split(".")[0] if intf_name else ""

                        if intf_name.startswith("lo0") or base_intf == "lo0":
                            if not loopback_ip:
                                loopback_ip = ip_candidate.split("/")[0]
                        elif base_intf:
                            interface_ips[base_intf] = ip_candidate
                            interface_ips[intf_name] = ip_candidate
            except ValueError:
                pass

    return loopback_ip, interface_ips

async def discover_mpls_router_topology(host, device_log_file):
    """
    Discovers LLDP topology and interface IP addresses for a JunOS CR/PR/RR router.
    Excludes BNG routers.
    """
    role = get_device_role(host)
    if role == "bng":
        print(f"Skipping BNG router: {host}")
        return {}

    try:
        print(f"Discovering MPLS topology & IPs for {role.upper()} router: {host}...")
        with open(device_log_file, 'a') as log_file:
            log_file.write(f"Discovering MPLS topology on {role.upper()}: {host}\n")

        # 1. Fetch Loopback IP & Interface IPv4 table
        loopback_ip, interface_ips = await fetch_interface_ip_table(host, device_log_file)

        # 2. Query LLDP Neighbors
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

        # 3. Filter neighbors: strictly allow internal GFiber Core (cr) and Peering (pr/mpr) routers (exclude BNG and RR)
        filtered_neighbors = []
        for n in neighbors:
            sys_name = n["system_name"].lower()
            peer_norm = normalize_system_name(n["system_name"]).lower()
            local_int = n["local_interface"].lower()
            parent_int = n["parent_interface"]

            if "mgt" in sys_name or "mgmt" in sys_name or "dr" in sys_name or "bng" in sys_name or "rr" in sys_name:
                continue
            if "mgmt" in local_int or "mgt" in local_int:
                continue

            # Must be internal GFiber Core or Peering router (cr, pr, mpr)
            if not peer_norm.startswith(("cr", "pr", "mpr")):
                continue

            filtered_neighbors.append(n)

        # Group by effective interface (parent ae bundle or standalone local interface)
        bundle_peers = {}
        for n in filtered_neighbors:
            parent = n["parent_interface"]
            if parent and parent.lower().startswith("ae"):
                effective_intf = parent.lower()
            else:
                effective_intf = n["local_interface"].lower()

            peer = normalize_system_name(n["system_name"])
            bundle_peers.setdefault(effective_intf, {"peer": peer, "members": []})
            bundle_peers[effective_intf]["members"].append(n["local_interface"])

        # 4. Fetch interface speed & details for each bundle / interface
        topology_data = {}
        for intf_name, info in bundle_peers.items():
            intf_output = await rate_limited_gnetch_command(f"show interfaces {intf_name}", host)
            with open(device_log_file, 'a') as log_file:
                log_file.write(f"\n--- show interfaces {intf_name} ---\n")
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

            local_ip = interface_ips.get(intf_name, interface_ips.get(f"{intf_name}.0", ""))
            remote_ip = derive_peer_ip_point_to_point(local_ip)

            topology_data[intf_name] = {
                "local_interface": intf_name,
                "local_ip": local_ip,
                "remote_device": info["peer"],
                "remote_ip": remote_ip,
                "capacity_bps": speed_bps,
                "capacity_human": convert_speed_human(speed_bps),
                "members": info["members"]
            }

        result_node = {
            "device_name": host,
            "device_role": role,
            "loopback_ip": loopback_ip,
            "interfaces": topology_data
        }

        with open(device_log_file, 'a') as log_file:
            log_file.write("\n--- Discovered MPLS Topology Node ---\n")
            log_file.write(json.dumps(result_node, indent=4) + "\n")

        return result_node

    except Exception as e:
        with open(device_log_file, 'a') as log_file:
            log_file.write(f"\nError discovering MPLS topology on {host}: {e}\n")
        return {}

async def process_device(device, folder_name):
    device_log_file = os.path.join(folder_name, f"{device}.log")
    role = get_device_role(device)

    if role == "bng":
        return device, {}

    topology_node = await discover_mpls_router_topology(device, device_log_file)
    return device, topology_node

def get_pacific_timestamp() -> str:
    utc_now = datetime.now(tz=ZoneInfo("UTC"))
    pacific_time = utc_now.astimezone(ZoneInfo("America/Los_Angeles"))
    return pacific_time.strftime("%Y-%m-%d %H:%M:%S")

def resolve_cross_device_remote_ips(topology_report):
    """
    Cross-references discovered devices to resolve exact remote_interface and remote_ip
    between peer routers, supporting multiple connections and IP subnet matching.
    """
    for dev, node_data in topology_report.items():
        if not node_data or "interfaces" not in node_data:
            continue
        for intf_name, details in node_data["interfaces"].items():
            remote_dev = details.get("remote_device", "")
            if not remote_dev or remote_dev not in topology_report:
                continue

            local_ip = details.get("local_ip", "")
            clean_local_ip = defCleanIP(local_ip)
            clean_remote_ip = defCleanIP(details.get("remote_ip", ""))

            remote_node = topology_report[remote_dev]
            remote_intfs = remote_node.get("interfaces", {})

            matched_r_intf = None
            matched_r_details = None

            # 1. Match by exact IP address or peer IP (/31 or /30)
            for r_intf, r_details in remote_intfs.items():
                r_local_ip = defCleanIP(r_details.get("local_ip", ""))
                r_remote_ip = defCleanIP(r_details.get("remote_ip", ""))

                if clean_remote_ip and r_local_ip == clean_remote_ip:
                    matched_r_intf = r_intf
                    matched_r_details = r_details
                    break
                if clean_local_ip and r_remote_ip == clean_local_ip:
                    matched_r_intf = r_intf
                    matched_r_details = r_details
                    break

            # 2. Fallback: match by member interface name or exact interface match
            if not matched_r_intf:
                for r_intf, r_details in remote_intfs.items():
                    if r_details.get("remote_device") == dev:
                        if r_intf == intf_name:
                            matched_r_intf = r_intf
                            matched_r_details = r_details
                            break

            # 3. Fallback: match if only one peer link exists to this dev
            if not matched_r_intf:
                matching_peer_intfs = [
                    (r_intf, r_details) for r_intf, r_details in remote_intfs.items()
                    if r_details.get("remote_device") == dev
                ]
                if len(matching_peer_intfs) == 1:
                    matched_r_intf, matched_r_details = matching_peer_intfs[0]

            if matched_r_intf and matched_r_details:
                details["remote_interface"] = matched_r_intf
                if not details.get("remote_ip") and matched_r_details.get("local_ip"):
                    details["remote_ip"] = matched_r_details.get("local_ip")

async def main():
    parser = argparse.ArgumentParser(description="Discover MPLS network topology excluding BNG routers.")
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose debug output')
    parser.add_argument("-m", "--metro", required=False, help="Specify the metro name to filter (e.g. 'atl')")
    parser.add_argument("--device", required=False, help="Specify device prefixes or hostnames to filter (e.g. 'cr' or 'cr01.atl101')")
    parser.add_argument("-j", "--json_file", default="topology_discovery_mpls.json", help="Specify output JSON file path")

    args = parser.parse_args()

    folder_name = "topology_discovery_mpls_logs"
    create_or_recreate_folder(folder_name)

    juniper_rancid = "/google/src/head/depot/ops/network/rancid/gfiber/juniper"
    all_devices = []

    if os.path.isdir(juniper_rancid):
        print(f"Collecting Juniper routers from live Rancid depot: {juniper_rancid}")
        for entry in os.listdir(juniper_rancid):
            base = entry.strip()
            if base.endswith(",v"):
                base = base[:-2]
            if base.startswith(".") or base.endswith((".md", ".html", ".pdf")):
                continue
            # EXCLUDE BNG routers
            if not base.lower().startswith(("bng", "rr")):
                all_devices.append(base)

    if not all_devices:
        inventory_files = [
            os.path.join(os.path.dirname(__file__), "juniper_devices.txt"),
            os.path.join(os.path.dirname(__file__), "rancid_samples", "juniper", "ls_output_sample.txt")
        ]
        for inv_file in inventory_files:
            if os.path.isfile(inv_file):
                print(f"Rancid unreachable; falling back to device inventory: {inv_file}")
                with open(inv_file, "r", encoding="utf-8") as f:
                    for line in f:
                        for item in line.strip().split():
                            item = item.strip()
                            if item and not item.startswith("#") and not item.lower().startswith(("bng", "rr")):
                                all_devices.append(item)
                if all_devices:
                    break
        else:
            print("Error: No non-BNG devices found.")
            exit(-1)

    all_devices = sorted(set(all_devices))

    if args.metro:
        all_devices = [d for d in all_devices if args.metro in d]

    if args.device:
        cleaned = args.device.strip("[]")
        prefixes = tuple(p.strip().lower() for p in cleaned.split(",") if p.strip())
        device_list = [
            d for d in all_devices
            if (d.lower().startswith(prefixes) or d.lower() in prefixes) and not d.lower().startswith(("bng", "rr"))
        ]
    else:
        # Exclude BNG and RR routers: only select CR, PR, MPR core/peering routers
        device_list = [d for d in all_devices if d.lower().startswith(("cr", "pr", "mpr")) and not d.lower().startswith(("bng", "rr"))]

    if not device_list:
        print("No non-BNG devices matched your filters.")
        return

    print(f"Matched {len(device_list)} total non-BNG devices to discover MPLS topology: {device_list}")

    sem = asyncio.Semaphore(20)

    async def sem_process(device):
        async with sem:
            return await process_device(device, folder_name)

    start_time = time.time()
    tasks = [sem_process(device) for device in device_list]
    results = await asyncio.gather(*tasks)

    # Reconstruct flat topology dictionary for output matching view_topology format
    topology_report = {}
    for device, node_data in results:
        if node_data and "interfaces" in node_data and node_data["interfaces"]:
            # Format: device -> dict of interfaces (with loopback_ip and local_ip embedded)
            dev_interfaces = {}
            for intf_name, details in node_data["interfaces"].items():
                details["loopback_ip"] = node_data.get("loopback_ip", "")
                dev_interfaces[intf_name] = details
            topology_report[device] = dev_interfaces

    resolve_cross_device_remote_ips(topology_report)

    print("\n" + "="*95)
    print(f" DISCOVERED MPLS TOPOLOGY REPORT (EXCLUDING BNG) - {get_pacific_timestamp()} ")
    print("="*95)
    print(f"{'Local Device':<18} | {'Loopback IP':<15} | {'Intf':<8} | {'Local IP':<18} | {'Remote Device':<18} | {'Capacity'}")
    print("-"*95)
    for local_dev, intfs in sorted(topology_report.items()):
        for intf_name, details in sorted(intfs.items()):
            loopback = details.get("loopback_ip", "-")
            local_ip = details.get("local_ip", "-")
            remote_dev = details.get("remote_device", "-")
            cap = details.get("capacity_human", "-")
            print(f"{local_dev:<18} | {loopback:<15} | {intf_name:<8} | {local_ip:<18} | {remote_dev:<18} | {cap}")
    print("="*95)

    with open(args.json_file, "w") as f:
        json.dump(topology_report, f, indent=4)
    print(f"\nMPLS topology report successfully saved to {args.json_file}")

    duration = time.time() - start_time
    print(f"Total MPLS discovery time: {duration:.2f} seconds\n")

if __name__ == "__main__":
    asyncio.run(main())
