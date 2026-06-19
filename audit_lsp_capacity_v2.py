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
from collections import defaultdict


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../gfiber')))
from utils_gfiber import *
from device_class import *
from juniper_lib import *


DEBUG = False
RATE_LIMIT = 1  # seconds between commands for the same device
rate_limiters = {}

DEBUG = False


def dprint(msg):
    if DEBUG:
        if isinstance(msg, list):
            for m in msg:
                print(f"Debug: {m}")
        else:
            print(f"Debug: {msg}")


def parse_rro_line_prod(line):
    """
    Parse a line containing tokens in the following format:
      IP((flag=flag_value [Label=label_value]) | (Label=label_value))
      
    - IP: an IPv4 address.
    - The flag and Label pairs are optional.
    - If both are present, flag appears first.
    
    This function returns a list of dictionaries.
    """
    pattern = (
        r'(\d+\.\d+\.\d+\.\d+)\('
        r'(?:(?:flag=([^\s\)]+)(?:\s+Label=([^\)]+))?)|(?:Label=([^\)]+)))'
        r'\)'
    )
    matches = re.findall(pattern, line)
    
    results = []
    for ip, flag, label_from_flag, label_alone in matches:
        token = {"ip": ip}
        label = label_from_flag if flag else label_alone
        
        if flag:
            token["flag"] = flag
        if label:
            token["Label"] = label
            
        # Parse flags
        try:
            if flag:
                if flag.lower().startswith("0x"):
                    flag_val = int(flag, 16)
                else:
                    flag_val = int(flag)
            else:
                flag_val = 0
        except ValueError:
            flag_val = 0
            
        meanings = []
        if flag_val & 0x20:
            meanings.append("Node-ID flag")
            rro_type = "Router ID"
        else:
            rro_type = "Downstream Int."
            if label == "0":
                rro_type = "Final Egress Int."
                meanings.append("Label IPv4 Explicit Null (Confirms PHP behavior)")

        if flag_val & 0x10:
            meanings.append("SoftPreempt")
        if flag_val & 0x08:
            meanings.append("Node protection available")
        if flag_val & 0x04:
            meanings.append("Bandwidth protection available")
        if flag_val & 0x02:
            meanings.append("In-use")
        if flag_val & 0x01:
            meanings.append("Link protection available")
            
        if not meanings and not flag:
            meanings.append("No flags (Protection not available/requested on this segment)")
            
        token["Type"] = rro_type
        token["Meaning"] = ", ".join(meanings)
        
        results.append(token)
    
    return results

def parse_show_lsp_ingress(show_result):
    """
    Parses LSP data from a list of strings and returns a dictionary organized by egress metro.

    Args:
        show_result: A list of strings containing the output of the "show lsp" command.

    Returns:
        A dictionary where keys are egress metro names and values are dictionaries
        containing LSP details (from, to, ingress_router, egress_router, lsp_number).
        Returns an empty dictionary if no matching LSP data is found.
    """

    parsed_data = {}

    for line in show_result[2:]:
        parts = line.split()
        if len(parts) >= 6 and parts[2] == "Up":
            to_ip = parts[0]
            from_ip = parts[1]
            lsp_name = parts[5]

            match = re.match(r"([A-Z]{2,3}\d+)([A-Z]{3}\d+)-([A-Z]{2,3}\d+)([A-Z]{3}\d+)-(HSD-\d+)", lsp_name)
            if match:
                in_role, in_site, eg_role, eg_site, lsp_number = match.groups()

                ingress_router = f"{in_role.lower()}.{in_site.lower()}"
                ingress_metro = in_site[:3].lower()
                egress_router = f"{eg_role.lower()}.{eg_site.lower()}"
                egress_metro = eg_site[:3].lower()

                if egress_metro not in parsed_data:
                    parsed_data[egress_metro] = {}

                parsed_data[egress_metro][lsp_name] = {
                    "from": from_ip,
                    "to": to_ip,
                    "ingress_router": ingress_router,
                    "egress_router": egress_router,
                    "lsp_number": lsp_number
                }
    return parsed_data  # Return the dictionary


def consolidate_lsp_data(device_data):
    """Consolidates LSP data and sums max_avg_bw_util for each metro.

    Args:
        device_data: A dictionary where keys are device names and values are
                     dictionaries of metro names and LSP details.

    Returns:
        A dictionary where keys are metro names and values are dictionaries
        containing 'total_util' (sum of max_avg_bw_util) and LSP details.
    """

    metro_data = {}

    for device_name, metro_info in device_data.items():
        for metro_name, lsp_info in metro_info.items():
            if metro_name == "audit_timestamp":
                continue
            if metro_name not in metro_data:
                metro_data[metro_name] = {"total_util": 0, "lsps": {}}

            for lsp_name, lsp_details in lsp_info.items():
                try:
                    # Extract and convert max_avg_bw_util to bps
                    util_str = lsp_details["details"]["max_avg_bw_util"]
 
                    util_value = convert_to_bps(util_str)
                    metro_data[metro_name]["total_util"] += util_value
                    metro_data[metro_name]["lsps"][lsp_name] = lsp_details

                except (KeyError, ValueError) as e:
                    print(f"Error processing LSP '{lsp_name}': {e}")
    for metro, metro_info in metro_data.items():
        metro_info["total_util_human"] = human_readable_format(metro_info["total_util"])
    return metro_data


def parse_traceroute(traceroute_data):
    path = []
    if not traceroute_data:
        return path
    for line in traceroute_data:
        match = re.search(r"^\s*\d+\s+.*?\(([\d\.]+)\)", line)
        if match:
            path.append(match.group(1))
    return path


TRACEROUTE_CACHE_FILE = "traceroute_cache.json"
CACHE_EXPIRY_SECONDS = 86400  # 24 hours

def get_cached_traceroute(host, ip):
    if not os.path.exists(TRACEROUTE_CACHE_FILE):
        return None
    try:
        with open(TRACEROUTE_CACHE_FILE, "r") as f:
            cache = json.load(f)
            cache_key = f"{host}_{ip}"
            if cache_key in cache:
                entry = cache[cache_key]
                if time.time() - entry.get("timestamp", 0) < CACHE_EXPIRY_SECONDS:
                    return entry.get("path")
    except Exception as e:
        print(f"Error reading cache: {e}")
    return None

def set_cached_traceroute(host, ip, path):
    cache = {}
    if os.path.exists(TRACEROUTE_CACHE_FILE):
        try:
            with open(TRACEROUTE_CACHE_FILE, "r") as f:
                cache = json.load(f)
        except Exception:
            pass
            
    cache_key = f"{host}_{ip}"
    cache[cache_key] = {
        "timestamp": time.time(),
        "path": path
    }
    
    try:
        with open(TRACEROUTE_CACHE_FILE, "w") as f:
            json.dump(cache, f, indent=2)
    except Exception as e:
        print(f"Error writing cache: {e}")



def parse_lsp_details(lsp_data):
    lsp_details = {}
    rro_found = False 
    lsp_name = None

    for line in lsp_data:
        # LSP Name
        match = re.search(r"LSPname: ([\w-]+)", line)
        if match:
            lsp_name = match.group(1)
            lsp_details.setdefault(lsp_name, {})
            rro_found = False

        # Max AvgBW util
        match = re.search(r"Bandwidth: ([\d.]+[kKmMgGtT]?bps)", line)
        if match and lsp_name:
            lsp_details[lsp_name]["max_avg_bw_util"] = match.group(1)

        # Received RRO
        if "Received RRO" in line:
            rro_found = True 
            if lsp_name:
                lsp_details[lsp_name]["rro_list"] = []
            continue 
        elif rro_found: 
            if not line.strip():
                continue
            if "Total" in line or "displayed" in line or "State:" in line or "LSPname:" in line or "Computed ERO" in line:
                rro_found = False
            else:
                result = parse_rro_line_prod(line)
                if result and lsp_name:
                    lsp_details[lsp_name]["rro_list"].extend(result)
                    
    # Post-process to organize path lists
    for name, details in lsp_details.items():
        if "rro_list" in details:
            router_id_list = []
            interface_list = []
            
            for hop in details["rro_list"]:
                if hop.get("Type") == "Router ID":
                    router_id_list.append(hop["ip"])
                elif hop.get("Type") in ("Downstream Int.", "Final Egress Int."):
                    interface_list.append(hop["ip"])
                    
            interface_plus_last_router = list(interface_list)
            if router_id_list and interface_plus_last_router:
                interface_plus_last_router[-1] = router_id_list[-1]
                
            details["router_id_list"] = router_id_list
            details["interface_list"] = interface_list
            details["interface_plus_last_router_list"] = interface_plus_last_router

    return lsp_details if lsp_details else None



async def collect_lsp_data_v2(device, folder_name, regex_site,metro=None):
    """
    Process a single device asynchronously and log outputs to separate log files.
    """
    host = device
    local_device_site = host.split(".")[1]
    matched = re.search(regex_site, local_device_site)
    local_site = matched.group(1).strip() if matched else "Unknown"

    bgp_dict = {}
    device_log_file = os.path.join(folder_name, f"{host}_lsp_log.txt")

    try:
        ######## configuration for interface lo0
        cmd = "show mpls lsp ingress"
        show_result = await rate_limited_gnetch_command(cmd,host)
        lsp_dict = parse_show_lsp_ingress(show_result)
        lsp_dict_audit = {}
        #now metro is a list
        if metro:
            for m,content in lsp_dict.items():
                if m in metro:
                    lsp_dict_audit[m] = content
        else:
            lsp_dict_audit = lsp_dict 
        audit_metros = []
        for m, c in lsp_dict_audit.items():
            audit_metros.append(m)
        print(f"Processing device: {host}\n")
        dprint(lsp_dict_audit)
        dprint(f"lsp dicts that need to be audit = {lsp_dict_audit}")
        for metro,l_dict in lsp_dict_audit.items():
            for name, content in l_dict.items():
                dprint(name)
                cmd = f"show mpls lsp ingress name {name} detail"
                show_result = await rate_limited_gnetch_command(cmd,host)
                lsp_infor = parse_lsp_details(show_result)
                dprint(json.dumps(lsp_infor, indent=4))
                for lsp_name, lsp_details in lsp_infor.items():
                    dprint(lsp_name)
                    dprint(lsp_details)
                    l_dict[lsp_name]["details"] = lsp_details

            unique_egress_ips = set()
            for name, content in l_dict.items():
                if "to" in content:
                    unique_egress_ips.add(content["to"])

            traceroute_results = {}
            for ip in unique_egress_ips:
                cached_path = get_cached_traceroute(host, ip)
                if cached_path is not None:
                    traceroute_results[ip] = cached_path
                    dprint(f"Using cached traceroute for {host} to {ip}")
                else:
                    cmd = f"traceroute {ip}"
                    trace_output = await rate_limited_gnetch_command(cmd, host)
                    path = parse_traceroute(trace_output)
                    traceroute_results[ip] = path
                    set_cached_traceroute(host, ip, path)

            # Now compare for each LSP
            for name, content in l_dict.items():
                details = content.get("details", {})
                interface_plus_last_router_list = details.get("interface_plus_last_router_list", [])
                
                to_ip = content.get("to")
                if to_ip in traceroute_results:
                    trace_path = traceroute_results[to_ip]
                    details["traceroute_path"] = trace_path
                    details["path_match"] = (interface_plus_last_router_list == trace_path)

    except Exception as e:
        print(f"\nError processing device {host}: {e}\n")
        with open(device_log_file, 'a') as log_file:
            log_file.write(f"\nError processing device {host}: {e}\n")
    #print_dict(lsp_dict)
    return {host:lsp_dict_audit}

class CustomArgumentParser(argparse.ArgumentParser):
    def print_help(self):
        super().print_help()
        print("Note #1: Make sure dr yaml file exist, otherwise, you need to build it with -f augument ")
        print("Note #2: if you want to collect LSP data, you need to run it with -d")
        print("Note #3: If you don't provide any arugment in CLI, by default you are using SSH to access devices")

async def main():
    parser = CustomArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose debug output')
    parser.add_argument('-a', '--analyze', action='store_true', help='Convert data into excel file')
    parser.add_argument("-p", "--path", action="store_true", help="Print out all unmatched LSP paths to traceroute paths")
    parser.add_argument("-m", "--metro", required=False, help="Specify the metro name")
    parser.add_argument("--device", required=False, help="Specify device prefixes to filter (e.g., 'cr,mpr' or '[cr,mpr]')")

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

    if args.metro:
        metro_name_list = args.metro.split(",")
        dprint(metro_name_list)
    else:
        metro_name_list = []

    # Dynamically collect routers from rancid folders
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

    if metro_name_list:
        all_devices = [d for d in all_devices if any(m in d for m in metro_name_list)]

    if args.device:
        cleaned = args.device.strip("[]")
        prefixes = tuple(p.strip().lower() for p in cleaned.split(",") if p.strip())
        device_list = [d for d in all_devices if d.lower().startswith(prefixes)]
    else:
        device_list = [d for d in all_devices if d.lower().startswith(("dr", "pr", "mpr"))]

    if not device_list:
        print("No devices matched your filters.")
        return

    print(f"Matched {len(device_list)} total devices to audit: {device_list}")

    log_folder="Log_lsp"


    # Prepare tasks for all devices
    regex_site = r"([a-zA-Z]+)[0-9]+"

    folder_name = log_folder
    create_or_recreate_folder(folder_name)
    async_start = time.time()
    tasks = [collect_lsp_data_v2(device, folder_name, regex_site,metro=metro_name_list) for device in device_list]
    # Run tasks concurrently
    results = await asyncio.gather(*tasks)

    # Aggregate results
    audit_result = {host: data for device_result in results for host, data in device_result.items()}
    print(f"Total number of devices: {len(audit_result)}")

    root_folder = args.json_folder if args.json_folder else "Audit_lsp_data"
    pt_now = datetime.now(tz=ZoneInfo("America/Los_Angeles"))
    date_folder = pt_now.strftime("%Y-%m-%d")
    time_stamp = pt_now.strftime("%Y_%m_%d_%H_%M")

    for host, data in audit_result.items():
        host_folder = os.path.join(root_folder, date_folder, host)
        os.makedirs(host_folder, exist_ok=True)
        json_filename = f"{host}_{time_stamp}.json"
        data["audit_timestamp"] = pt_now.strftime("%Y-%m-%d %H:%M:%S")
        dump_json_file(host_folder, json_filename, data)

    consolidate_audit = consolidate_lsp_data(audit_result)
    output_file = f'lsp_metro_all_{time_stamp}.json'
    json_folder_name_consolidated = f"{root_folder}_consolidated"
    os.makedirs(json_folder_name_consolidated, exist_ok=True)
    dump_json_file(json_folder_name_consolidated, output_file, consolidate_audit)
    async_duration = time.time() - async_start
    print(f"Asynchronous execution time: {async_duration:.2f} seconds\n")

    if args.path:
        print("\n--- Unmatched LSP Paths ---")
        unmatched_found = False
        for host, metros in audit_result.items():
            for metro, lsps in metros.items():
                if metro == "audit_timestamp":
                    continue
                if isinstance(lsps, dict):
                    for lsp_name, content in lsps.items():
                        details = content.get("details", {})
                        if details and "path_match" in details and not details["path_match"]:
                            unmatched_found = True
                            print(f"\n[Mismatch] Device: {host} | LSP: {lsp_name}")
                            print(f"  RRO Path        : {details.get('interface_plus_last_router_list')}")
                            print(f"  Traceroute Path : {details.get('traceroute_path')}")
        if not unmatched_found:
            print("All LSPs matched their traceroute paths successfully!")
        print("---------------------------\n")

    if args.analyze:
        # Example usage:
        import runpy
        print("Start running another python code to analyze the data....")
        # Execute the script as if it were the __main__ module.
        subprocess.run(["python3", "convert_lsp_excel.py"])
       
        # filename = 'config.txt'  # Adjust to your file name if needed.
        # parsed_results = parse_ipfix_config(filename)
        # print_dict(parsed_results)

if __name__ == "__main__":
    asyncio.run(main())



