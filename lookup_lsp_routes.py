import os
import sys
import re
import json
import asyncio
import time
import subprocess
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils_gfiber import *
from device_class import *
from juniper_lib import *

DEBUG = False
LSP_RATE_LIMIT = 30  # seconds between commands for the same device
lsp_device_rate_limiters = {}

async def rate_limited_gnetch_command_lsp(cmd, target, delay=LSP_RATE_LIMIT):
    """
    Execute gnetch_command with a 30-second rate limit per target device.
    """
    if target not in lsp_device_rate_limiters:
        lsp_device_rate_limiters[target] = asyncio.Semaphore(1)

    async with lsp_device_rate_limiters[target]:
        output = await async_gnetch_command(cmd, target)
        await asyncio.sleep(delay)
        return output


def analyze_lsp_outliers(folder="Json_lsp_folder"):
    if not os.path.exists(folder):
        raise FileNotFoundError(f"Folder {folder} does not exist.")

    json_paths = []
    for root, dirs, files in os.walk(folder):
        for file in files:
            if file.endswith(".json") or not "." in file:
                if not file.startswith("."):
                    json_paths.append((file, os.path.join(root, file)))

    if not json_paths:
        raise FileNotFoundError(f"No JSON files found in {folder}.")
    
    lsp_groups = {}

    for filename, json_path in json_paths:
        with open(json_path, "r") as f:
            data = json.load(f)

        default_router_name = filename.replace(".json", "")

        items_to_process = []
        if isinstance(data, dict):
            first_val = next(iter(data.values()), None)
            if first_val and isinstance(first_val, dict) and "details" in first_val:
                items_to_process.append((default_router_name, data))
            elif first_val and isinstance(first_val, dict):
                for r_name, sub_dict in data.items():
                    if isinstance(sub_dict, dict):
                        sub_first = next(iter(sub_dict.values()), None)
                        if sub_first and isinstance(sub_first, dict) and "details" in sub_first:
                            items_to_process.append((r_name, sub_dict))
                        elif isinstance(sub_first, dict):
                            for m_name, lsp_d in sub_dict.items():
                                if isinstance(lsp_d, dict):
                                    items_to_process.append((r_name, lsp_d))

        for router_name, lsp_dict in items_to_process:
            for lsp_name, lsp_info in lsp_dict.items():
                if not isinstance(lsp_info, dict) or "details" not in lsp_info:
                    continue
                parts = lsp_name.split("-")
                if len(parts) < 3:
                    continue
                full_ingress = parts[0]
                full_egress = parts[1]

                bw_val = lsp_info["details"].get("max_avg_bw_util", "0Gbps")
                if isinstance(bw_val, list) and bw_val:
                    bw_str = bw_val[-1]
                elif isinstance(bw_val, str):
                    bw_str = bw_val
                else:
                    bw_str = "0Gbps"

                match = BW_UNIT_PATTERN.match(bw_str)
                if not match:
                    continue

                value, unit = float(match.group(1)), match.group(2).lower()
                if unit == "kbps":
                    bw = value / 1_000_000
                elif unit == "mbps":
                    bw = value / 1_000
                elif unit == "gbps":
                    bw = value
                else:
                    continue  # unknown unit

                key = (router_name, full_ingress, full_egress)
                lsp_groups.setdefault(key, []).append((lsp_name, bw))

    outliers = []
    for (router_name, full_ingress, full_egress), lsp_list in lsp_groups.items():
        for i, (lsp_i_name, bw_i) in enumerate(lsp_list):
            others = [(name, bw) for j, (name, bw) in enumerate(lsp_list) if j != i]
            if not others:
                continue
            if all(bw_i >= 10 * bw for _, bw in others):
                outliers.append({
                    "router_name": router_name,
                    "router_pair": f"{full_ingress} → {full_egress}",
                    "outlier_lsp": lsp_i_name,
                    "outlier_util_gbps": round(bw_i, 4),
                    "other_lsps": [{"name": name, "util_gbps": round(bw, 4)} for name, bw in others]
                })

    return outliers

def dprint(msg):
    if DEBUG:
        if isinstance(msg, list):
            for m in msg:
                print(f"Debug: {m}")
        else:
            print(f"Debug: {msg}")


def decode_rro_flag(flag):
    """
    Interpret RSVP-TE Record Route Object (RRO) subobject flags (RFC 3209 / RFC 4090).
    
    Bit representation (8-bit mask):
      0x01 (Bit 0): Local protection available
      0x02 (Bit 1): Local protection in use
      0x04 (Bit 2): Bandwidth protection available
      0x08 (Bit 3): Node protection available
      0x10 (Bit 4): Recorded interface is unnumbered
      0x20 (Bit 5): Node ID / Node Address (Loopback) vs Interface IP Address
      
    Examples:
      flag="0x29" (0x20 + 0x08 + 0x01) -> Local protection available, Node protection, Node ID
      flag="9"    (0x08 + 0x01)        -> Local protection available, Node protection, Interface IP
      flag="0x21" (0x20 + 0x01)        -> Local protection available, Node ID
      flag="1"    (0x01)               -> Local protection available, Interface IP
    """
    if flag is None:
        return ""
    try:
        val = int(str(flag).strip(), 0)
    except (ValueError, TypeError):
        return str(flag)
    
    meanings = []
    if val & 0x01:
        meanings.append("Local protection available")
    if val & 0x02:
        meanings.append("Local protection in use")
    if val & 0x04:
        meanings.append("Bandwidth protection")
    if val & 0x08:
        meanings.append("Node protection")
    if val & 0x10:
        meanings.append("Unnumbered interface")
    if val & 0x20:
        meanings.append("Node ID")
    else:
        meanings.append("Interface IP")
    
    return ", ".join(meanings)


RRO_PATTERN = re.compile(
    r'(\d+\.\d+\.\d+\.\d+)\('
    r'(?:(?:flag=([^\s\)]+)(?:\s+Label=([^\)]+))?)|(?:Label=([^\)]+)))'
    r'\)'
)
ROUTER_SPLIT_PATTERN = re.compile(r"([A-Za-z]{2,4}\d+)([A-Za-z]{3}\d*)")
LSP_NAME_PATTERN = re.compile(r"([A-Za-z]{2,4}\d+[A-Za-z]{3}\d*)-([A-Za-z]{2,4}\d+[A-Za-z]{3}\d*)-([\w-]+)")
LSP_DETAIL_NAME_PATTERN = re.compile(r"LSPname: ([\w-]+)")
LSP_DETAIL_BW_PATTERN = re.compile(r"Bandwidth: ([\d.]+[kKmMgGtT]?bps)")
TRACEROUTE_HOP_PATTERN = re.compile(r"^\s*\d+\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})")
BW_UNIT_PATTERN = re.compile(r"([\d.]+)([GMK]bps)")

def parse_rro_line_prod(line):
    """
    Parse a line containing tokens in the following format:
      IP((flag=flag_value [Label=label_value]) | (Label=label_value))
      
    - IP: an IPv4 address.
    - The flag and Label pairs are optional.
    - If both are present, flag appears first.
    
    This function returns a list of dictionaries.
    """
    matches = RRO_PATTERN.findall(line)
    
    results = []
    for ip, flag, label_from_flag, label_alone in matches:
        token = {"ip": ip}
        if flag:
            token["flag"] = flag
            token["flag_meaning"] = decode_rro_flag(flag)
            if label_from_flag:
                token["Label"] = label_from_flag
        else:
            if label_alone:
                token["Label"] = label_alone
        results.append(token)
    
    return results

def parse_show_lsp_ingress(show_result):
    """
    Parses LSP data from a list of strings and returns a dictionary mapping LSP names to LSP details.

    Args:
        show_result: A list of strings containing the output of the "show lsp" command.

    Returns:
        A dictionary where keys are LSP names and values are dictionaries
        containing LSP details (from, to, ingress_router, egress_router, lsp_number).
        Returns an empty dictionary if no matching LSP data is found.
    """

    parsed_data = {}

    for line in show_result:
        parts = line.split()
        if len(parts) >= 6 and parts[2].lower() == "up":
            to_ip = parts[0]
            from_ip = parts[1]
            lsp_name = parts[5]

            match = LSP_NAME_PATTERN.match(lsp_name)
            if match:
                ingress_router_full, egress_router_full, lsp_number = match.groups()

                m_ing = ROUTER_SPLIT_PATTERN.match(ingress_router_full)
                if m_ing:
                    ingress_router = f"{m_ing.group(1).lower()}.{m_ing.group(2).lower()[:3]}"
                else:
                    ingress_router = ingress_router_full.lower()

                m_egr = ROUTER_SPLIT_PATTERN.match(egress_router_full)
                if m_egr:
                    egress_router = f"{m_egr.group(1).lower()}.{m_egr.group(2).lower()[:3]}"
                else:
                    egress_router = egress_router_full.lower()
            else:
                ingress_router = "unknown"
                egress_router = "unknown"
                lsp_number = "unknown"

            parsed_data[lsp_name] = {
                "from": from_ip,
                "to": to_ip,
                "ingress_router": ingress_router,
                "egress_router": egress_router,
                "lsp_number": lsp_number
            }
    return parsed_data

def parse_local_config_lsp(host):
    """
    Reads local cached JunOS config file (.config) for host with zero SSH connections.
    """
    possible_paths = [
        f"{host}.config",
        os.path.join("..", f"{host}.config"),
        os.path.join("rancid", f"{host}"),
        os.path.join("..", "rancid", f"{host}"),
        os.path.join("Log_lsp", f"{host}.config"),
    ]
    config_file = None
    for path in possible_paths:
        if os.path.exists(path):
            config_file = path
            break

    if not config_file:
        return {}

    print(f"Reading local cached config file '{config_file}' for {host} (0 SSH connections)...")
    parsed_data = {}
    pattern = re.compile(r"set protocols mpls label-switched-path\s+([\w-]+)\s+to\s+([\d.]+)")

    with open(config_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = pattern.search(line)
            if match:
                lsp_name = match.group(1)
                to_ip = match.group(2)

                m = LSP_NAME_PATTERN.match(lsp_name)
                if m:
                    ingress_router_full, egress_router_full, lsp_number = m.groups()
                    m_ing = ROUTER_SPLIT_PATTERN.match(ingress_router_full)
                    ingress_router = f"{m_ing.group(1).lower()}.{m_ing.group(2).lower()[:3]}" if m_ing else ingress_router_full.lower()
                    m_egr = ROUTER_SPLIT_PATTERN.match(egress_router_full)
                    egress_router = f"{m_egr.group(1).lower()}.{m_egr.group(2).lower()[:3]}" if m_egr else egress_router_full.lower()
                else:
                    ingress_router = "unknown"
                    egress_router = "unknown"
                    lsp_number = "unknown"

                parsed_data[lsp_name] = {
                    "from": "local_config",
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
                     dictionaries mapping LSP names to LSP details.

    Returns:
        A dictionary where keys are metro names and values are dictionaries
        containing 'total_util' (sum of max_avg_bw_util) and LSP details.
    """

    metro_data = {}

    for device_name, lsp_info in device_data.items():
        for lsp_name, lsp_details in lsp_info.items():
            egress_router = lsp_details.get("egress_router", "")
            egress_metro = egress_router.split(".")[1] if "." in egress_router else "unknown"

            if egress_metro not in metro_data:
                metro_data[egress_metro] = {"total_util": 0, "lsps": {}}

            try:
                # Extract and convert max_avg_bw_util to bps
                util_val = lsp_details["details"]["max_avg_bw_util"]
                if isinstance(util_val, list) and util_val:
                    util_str = util_val[-1]
                else:
                    util_str = str(util_val)

                util_value = convert_to_bps(util_str)
                metro_data[egress_metro]["total_util"] += util_value
                metro_data[egress_metro]["lsps"][lsp_name] = lsp_details

            except (KeyError, ValueError) as e:
                print(f"Error processing LSP '{lsp_name}': {e}")
    for metro, metro_info in metro_data.items():
        metro_info["total_util_human"] = human_readable_format(metro_info["total_util"])
    return metro_data


def parse_lsp_details(lsp_data):
    if not lsp_data:
        return None
    lsp_details = {}
    rro_found = False 
    lsp_name = None

    for line in lsp_data:
        # LSP Name
        match = LSP_DETAIL_NAME_PATTERN.search(line)
        if match:
            lsp_name = match.group(1)
            lsp_details.setdefault(lsp_name, {})

        if not lsp_name:
            continue

        # Max AvgBW util / Bandwidth
        match = LSP_DETAIL_BW_PATTERN.search(line)
        if match:
            lsp_details[lsp_name]["max_avg_bw_util"] = match.group(1)

        # Received RRO
        if "Received RRO" in line:
            rro_found = True 
            continue 
        elif rro_found: 
            result = parse_rro_line_prod(line)
            lsp_details[lsp_name]["rro_list"] = result
            rro_found = False 
    return lsp_details if lsp_details else None


async def collect_show_route(device, folder_name, regex_site):
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
        print(f"Collecing data on {host}")
        cmd = "show route"
        show_result = await rate_limited_gnetch_command_lsp(cmd, host)
        print(show_result)

    except Exception as e:
        print(f"\nError processing device {host}: {e}\n")
        with open(device_log_file, 'a') as log_file:
            log_file.write(f"\nError processing device {host}: {e}\n")
    #print_dict(lsp_dict)
    return {host:show_result}


TRACEROUTE_CACHE_FILE = "traceroute_cache.json"
TRACEROUTE_CACHE_TTL_SECONDS = 86400  # 24 hours default TTL
traceroute_cache_lock = asyncio.Lock()

def load_traceroute_cache(cache_file=TRACEROUTE_CACHE_FILE):
    if os.path.exists(cache_file):
        try:
            with open(cache_file, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

async def save_traceroute_cache(cache, cache_file=TRACEROUTE_CACHE_FILE):
    async with traceroute_cache_lock:
        try:
            with open(cache_file, "w") as f:
                json.dump(cache, f, indent=2)
        except Exception as e:
            print(f"Error saving traceroute cache: {e}")

traceroute_cache = load_traceroute_cache()

def parse_traceroute_output(output_lines):
    """
    Parses JunOS traceroute output into a list of hop IP addresses.
    """
    hops = []
    for line in output_lines:
        line_clean = line.replace('data: "', '').strip('"').strip()
        match = TRACEROUTE_HOP_PATTERN.match(line_clean)
        if match:
            ip = match.group(1)
            hops.append(ip)
    return hops

def extract_interface_ips_from_rro(rro_list):
    """
    Extracts ordered list of interface IP addresses from LSP RRO list.
    Excludes entries that represent Node IDs (flag with bit 0x20).
    """
    interface_ips = []
    if not rro_list:
        return interface_ips
    for entry in rro_list:
        ip = entry.get("ip")
        if not ip:
            continue
        flag = entry.get("flag")
        flag_meaning = entry.get("flag_meaning", "")
        
        is_node_id = False
        if "Node ID" in flag_meaning and "Interface IP" not in flag_meaning:
            is_node_id = True
        elif flag is not None:
            try:
                val = int(str(flag).strip(), 0)
                if val & 0x20:
                    is_node_id = True
            except (ValueError, TypeError):
                pass
        
        if not is_node_id:
            if entry.get("Label") == "0" and len(interface_ips) > 0:
                continue
            interface_ips.append(ip)
            
    return interface_ips

def is_shortest_path_match(lsp_if_ips, traceroute_hops, to_ip=None):
    """
    Compares LSP interface IP list against traceroute hop list.
    Returns (is_shortest, path_type).
    """
    tr_if_hops = [ip for ip in traceroute_hops if ip != to_ip]
    lsp_hops = [ip for ip in lsp_if_ips if ip != to_ip]
    
    if lsp_hops == tr_if_hops or lsp_if_ips == traceroute_hops:
        return True, "shortest path"
    else:
        return False, "longer path"

async def get_traceroute_path(host, to_ip, refresh_cache=False, max_retries=3):
    cache_key = f"{host}_{to_ip}"
    
    if not refresh_cache and cache_key in traceroute_cache:
        entry = traceroute_cache[cache_key]
        if isinstance(entry, dict) and "hops" in entry:
            ts = entry.get("timestamp", 0)
            if time.time() - ts < TRACEROUTE_CACHE_TTL_SECONDS:
                dprint(f"Using valid cached traceroute for {cache_key}")
                return entry["hops"]
        elif isinstance(entry, list):
            dprint(f"Using cached traceroute for {cache_key}")
            return entry

    cmd = f"traceroute {to_ip} no-resolve"
    try:
        show_result = await rate_limited_gnetch_command_lsp(cmd, host)
        tr_hops = parse_traceroute_output(show_result)
        if tr_hops:
            traceroute_cache[cache_key] = {
                "hops": tr_hops,
                "timestamp": time.time(),
                "updated_at": datetime.now().isoformat()
            }
            await save_traceroute_cache(traceroute_cache)
        return tr_hops
    except Exception as e:
        print(f"Error running traceroute on {host} to {to_ip}: {e}")
        return []


async def collect_lsp_data_v2(device, folder_name, json_folder_name, regex_site, refresh_cache=False):
    """
    Process a single device asynchronously and log outputs to separate log files using live gnetch RPC commands.
    """
    host = device.hostname
    local_device_site = host.split(".")[1]
    matched = re.search(regex_site, local_device_site)
    local_site = matched.group(1).strip() if matched else "Unknown"

    bgp_dict = {}
    device_log_file = os.path.join(folder_name, f"{host}_lsp_log.txt")

    try:
        print(f"Processing device: {host}\n")
        ######## configuration for interface lo0
        cmd = "show mpls lsp ingress"
        show_result = await rate_limited_gnetch_command_lsp(cmd, host)
        lsp_dict_audit = parse_show_lsp_ingress(show_result)
        dprint(lsp_dict_audit)
        dprint(f"lsp dicts that need to be audit = {lsp_dict_audit}")

        # Synchronously process each LSP one by one without parallelism
        for name, content in lsp_dict_audit.items():
            dprint(f"Synchronously fetching detail for LSP: {name}")
            cmd = f"show mpls lsp ingress name {name} detail"
            show_result = await rate_limited_gnetch_command_lsp(cmd, host)
            lsp_infor = parse_lsp_details(show_result)
            dprint(json.dumps(lsp_infor, indent=4))
            
            to_ip = content.get("to")
            tr_hops = await get_traceroute_path(host, to_ip, refresh_cache=refresh_cache) if to_ip else []

            if lsp_infor:
                for lsp_name, lsp_details in lsp_infor.items():
                    dprint(lsp_name)
                    dprint(lsp_details)
                    lsp_if_ips = extract_interface_ips_from_rro(lsp_details.get("rro_list", []))
                    if not lsp_if_ips and tr_hops:
                        lsp_if_ips = tr_hops

                    is_shortest, path_type = is_shortest_path_match(lsp_if_ips, tr_hops, to_ip)
                    
                    bw_util = lsp_details.get("max_avg_bw_util")
                    if isinstance(bw_util, str):
                        lsp_details["max_avg_bw_util"] = [bw_util]
                    elif not isinstance(bw_util, list):
                        lsp_details["max_avg_bw_util"] = [bw_util] if bw_util is not None else []

                    lsp_details["traceroute_path"] = tr_hops
                    lsp_details["lsp_interface_ips"] = [lsp_if_ips]
                    lsp_details["is_shortest_path"] = is_shortest
                    lsp_details["path_type"] = path_type

                    # Remove transitory rro_list
                    lsp_details.pop("rro_list", None)

                    lsp_dict_audit[lsp_name]["details"] = lsp_details

        dump_json_file(json_folder_name, f"{host}.json", lsp_dict_audit)

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
    parser.add_argument('--device', '--target', default=None, help='Filter target device(s) by hostname (comma-separated or substring, e.g. pr01.aus122)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose debug output')
    parser.add_argument('-d', '--data', action='store_true', help='Collect network configuration data')
    parser.add_argument('-f', '--yaml_file', action='store_true', help='Build DR yaml database')
    parser.add_argument('-a', '--analyze', action='store_true', help='Convert data into excel file')
    parser.add_argument('-o', '--outlier', action='store_true', help='find out outlier lsp at the Json file')
    parser.add_argument('--refresh-cache', '--no-cache', action='store_true', help='Force live traceroute collection and bypass cached results')
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

    #Define the necessary information before parsing the args
    folder="juniper"
    router_types=["mpr","pr"]
    log_folder = "Log_lsp"
    rancid_folder=f'{folder}_{"_".join(router_types)}'
    # Define the output YAML file path
    output_file = f"rancid_{rancid_folder}.yaml"


    if args.yaml_file:
        build_rancid_yaml_v2(folder,router_types,log_folder,output_file)
    else:
        if file_exists("rancid_juniper_mpr_pr_dr_cr.yaml"):
            output_file = "rancid_juniper_mpr_pr_dr_cr.yaml"
            print(f"Using master rancid yaml file {output_file}....")
        elif file_exists(output_file):
            print(f"{output_file} exists, you can go ahead to continue....")
        elif file_exists("rancid_juniper_dr_pr_mpr.yaml"):
            output_file = "rancid_juniper_dr_pr_mpr.yaml"
            print(f"Using existing rancid yaml file {output_file}....")
        else:
            print(f"Rancid yaml file {output_file} not found. Building it automatically...")
            build_rancid_yaml_v2(folder, router_types, log_folder, output_file)

    setup = setup_db(output_file)


    # Prepare tasks for all devices
    regex_site = r"([a-zA-Z]+)[0-9]+"

    if args.data:
        if args.json_folder:
            json_folder_name = args.json_folder
        else:
            json_folder_name = "Json_lsp_folder"

        # Format date for subdirectory structure: YYYY-MM-DD
        now = datetime.now()
        date_folder = now.strftime("%Y-%m-%d")
        today_json_folder = os.path.join(json_folder_name, date_folder)

        folder_name = log_folder
        json_folder_name_consolidated = f"{json_folder_name}_consolidated"

        delete_folder_contents(log_folder)
        create_or_recreate_folder(today_json_folder)
        delete_folder_contents(json_folder_name_consolidated)

        # Format date/timestamp for consolidated output file
        date_string = now.strftime("%Y_%m_%d_%H_%M")

        # Filter target devices by configured router_types
        target_devices = [device for device in setup.setupdb.Device_list if any(device.hostname.startswith(t) for t in router_types)]

        if args.device:
            specified = [d.strip() for d in args.device.split(",")]
            target_devices = [dev for dev in target_devices if any(s in dev.hostname for s in specified)]
            print(f"Targeting {len(target_devices)} device(s) matching '{args.device}': {[d.hostname for d in target_devices]}")
        else:
            print(f"Auditing {len(target_devices)} devices matching router types {router_types}...")

        async_start = time.time()
        tasks = [collect_lsp_data_v2(device, log_folder, today_json_folder, regex_site, refresh_cache=args.refresh_cache) for device in target_devices]
        # Run tasks concurrently
        results = await asyncio.gather(*tasks)

        # Aggregate results
        audit_result = {host: data for device_result in results for host, data in device_result.items()}
        print(f"Total number of devices: {len(audit_result)}")

        consolidate_audit = consolidate_lsp_data(audit_result)
        output_file_all = f'lsp_metro_all_{date_string}.json'
        
        dump_json_file(json_folder_name_consolidated,output_file_all,consolidate_audit)
        async_duration = time.time() - async_start
        print(f"Asynchronous execution time: {async_duration:.2f} seconds\n")


    if args.outlier:
        results = analyze_lsp_outliers()
        print("\n=== Outlier Report ===")
        if not results:
            print("No outliers found.")
        router_list = []
        for entry in results:
            router_outlier = entry['router_name']
            router_list.append(router_outlier)
            print(f"Router: {entry['router_name']}")
            print(f"  Ingress → Egress: {entry['router_pair']}")
            print(f"  Outlier LSP: {entry['outlier_lsp']} (util: {entry['outlier_util_gbps']} Gbps)")
            print("  Other LSPs:")
            for other in entry["other_lsps"]:
                print(f"    - {other['name']}: {other['util_gbps']} Gbps")
            print()

        async_start = time.time()
        tasks = [collect_show_route(device, log_folder, regex_site) for device in router_list]
        # Run tasks concurrently
        results = await asyncio.gather(*tasks)

        audit_result = {host: data for device_result in results for host, data in device_result.items()}
        print(f"Total number of devices: {len(audit_result)}")

        # Get the current date and time
        now = datetime.now()

        # Format the date and time into the desired string format: year_month_date_hour_minute
        date_string = now.strftime("%Y_%m_%d_%H_%M")

        async_duration = time.time() - async_start
        print(f"Asynchronous execution time: {async_duration:.2f} seconds\n")
        print(audit_result)

    if args.analyze:
        print("Start running another python code to analyze the data....")
        script = "consolidate_lsp_utils.py" if os.path.exists("consolidate_lsp_utils.py") else "convert_lsp_excel.py"
        subprocess.run(["python3", script])
       
        # filename = 'config.txt'  # Adjust to your file name if needed.
        # parsed_results = parse_ipfix_config(filename)
        # print_dict(parsed_results)

if __name__ == "__main__":
    asyncio.run(main())



