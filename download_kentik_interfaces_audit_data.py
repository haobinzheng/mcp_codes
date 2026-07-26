#!/usr/bin/env python3
"""
Download Kentik Interfaces Statistics for View Interfaces Dashboards
----------------------------------------------------------------------
Downloads interface traffic & utilization from Kentik API and formats it into
the exact JSON schema expected in `Audit_interfaces_data/YYYY-MM-DD/router/router_YYYY_MM_DD_HH_MM.json`.

This allows `view_interfaces_fastapi.py`, `main.go`, and `index.html` to consume
Kentik interface data natively without modifying any dashboard code.

Usage:
    python3 download_kentik_interfaces_audit_data.py --start 6/1/2026 --end 7/21/2026 --device "[mpr,pr,cr,bng]"
"""

import os
import sys
import re
import json
import time
import argparse
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List

try:
    from dotenv import load_dotenv
    load_dotenv(override=True)
except ImportError:
    pass

try:
    from kentik_api import (
        KentikAPI,
        Query,
        QueryArrayItem,
        QueryObject,
        MetricType,
        DimensionType,
        FastDataType
    )
    from kentik_api.public.errors import RateLimitExceededError
except ImportError:
    print("ERROR: kentik-api package is not installed. Run: pip install kentik-api", file=sys.stderr)
    sys.exit(1)

KENTIK_EMAIL = os.environ.get("KENTIK_EMAIL", "")
KENTIK_API_TOKEN = os.environ.get("KENTIK_API_TOKEN", "")

def get_client() -> KentikAPI:
    """Initialize the KentikAPI client."""
    if not KENTIK_EMAIL or not KENTIK_API_TOKEN:
        print("ERROR: KENTIK_EMAIL and KENTIK_API_TOKEN environment variables must be set.", file=sys.stderr)
        sys.exit(1)
    return KentikAPI(KENTIK_EMAIL, KENTIK_API_TOKEN)

def parse_interface_meta(intf_full_str: str) -> Dict[str, Any]:
    """
    Parses Kentik interface string like:
    'ae1.0 : [R=BNG01.BNA111][I=AE3][S=ACTIVE][U=CORE] (inherited from physical) (640)'
    """
    intf_name = intf_full_str.split(":")[0].strip() if ":" in intf_full_str else intf_full_str.strip()
    clean_name = intf_name.split(".")[0] if "." in intf_name and intf_name.startswith("ae") else intf_name

    neighbor = "Unknown"
    neighbor_match = re.search(r"\[R=([^\]]+)\]", intf_full_str)
    if neighbor_match:
        neighbor = neighbor_match.group(1)

    usage = "CORE"
    usage_match = re.search(r"\[U=([^\]]+)\]", intf_full_str)
    if usage_match:
        usage = usage_match.group(1)

    circuit = "LR" if "LR" in intf_full_str else ("SR" if "SR" in intf_full_str else usage)
    description = f"    Description: {intf_full_str}"

    speed_human = 100000000000  # Default 100Gbps
    speed_str = "100Gbps"

    if "400G" in intf_full_str:
        speed_human = 400000000000
        speed_str = "400Gbps"
    elif "40G" in intf_full_str:
        speed_human = 40000000000
        speed_str = "40Gbps"
    elif "10G" in intf_full_str or "xe-" in clean_name:
        speed_human = 10000000000
        speed_str = "10Gbps"
    elif "600G" in intf_full_str:
        speed_human = 600000000000
        speed_str = "600Gbps"

    return {
        "clean_name": clean_name,
        "neighbor": neighbor,
        "circuit": circuit,
        "description": description,
        "speed": speed_str,
        "speed_human": speed_human
    }

def execute_query_with_retry(client: KentikAPI, query_item: QueryArrayItem, max_retries: int = 8, pace_delay: float = 0.8):
    """Executes a Kentik query with automatic exponential backoff retry on HTTP 429 Rate Limits."""
    for attempt in range(max_retries):
        try:
            if pace_delay > 0:
                time.sleep(pace_delay)
            res = client.query.data(QueryObject(queries=[query_item]))
            return res
        except Exception as e:
            err_type_str = type(e).__name__
            err_msg_str = str(e).lower()
            if isinstance(e, RateLimitExceededError) or "ratelimit" in err_type_str.lower() or "429" in err_msg_str or "too many" in err_msg_str or "rate limit" in err_msg_str:
                delays = [5.0, 10.0, 20.0, 30.0, 45.0, 60.0, 90.0, 120.0]
                wait_time = delays[min(attempt, len(delays) - 1)]
                print(f"Rate limited by Kentik API (HTTP 429). Waiting {wait_time:.0f}s for API quota cooldown (Attempt {attempt + 1}/{max_retries})...")
                time.sleep(wait_time)
            else:
                raise e
    raise RuntimeError("Max retries exceeded for Kentik API query.")

def fetch_batch_kentik_devices_traffic(
    client: KentikAPI,
    device_list: List[str],
    start_time: str,
    end_time: str,
    device_obj_map: Dict[str, Any] = None,
    device_detail_cache: Dict[str, Any] = None
) -> Dict[str, Dict[str, Any]]:
    """
    Fetch inbound and outbound interface traffic & SNMP interface inventory for a batch of devices.
    Returns: { device_name: { interface_key: interface_details } }
    """
    if device_obj_map is None:
        device_obj_map = {}
    if device_detail_cache is None:
        device_detail_cache = {}

    topx_count = max(200, len(device_list) * 25)

    # 1. Batch Inbound Query (Flow Data)
    q_in = Query(
        starting_time=start_time,
        ending_time=end_time,
        device_name=device_list,
        metric=[MetricType.bytes],
        dimension=[DimensionType.InterfaceID_src],
        topx=topx_count,
        fastData=FastDataType.auto
    )

    # 2. Batch Outbound Query (Flow Data)
    q_out = Query(
        starting_time=start_time,
        ending_time=end_time,
        device_name=device_list,
        metric=[MetricType.bytes],
        dimension=[DimensionType.InterfaceID_dst],
        topx=topx_count,
        fastData=FastDataType.auto
    )

    # Maps: dev_name -> port_str -> bps
    in_map = {}
    out_map = {}

    try:
        res_in = execute_query_with_retry(client, QueryArrayItem(query=q_in, bucket="Left +Y Axis"))
        if res_in and res_in.results and "data" in res_in.results[0]:
            for item in res_in.results[0]["data"]:
                dev = item.get("i_device_name") or item.get("device_name") or ""
                port = item.get("input_port", "")
                if dev and port:
                    in_map.setdefault(dev, {})[port] = item.get("avg_bits_per_sec", 0.0)
    except Exception as e:
        print(f"Warning: Batch inbound traffic query error: {e}")

    try:
        res_out = execute_query_with_retry(client, QueryArrayItem(query=q_out, bucket="Left +Y Axis"))
        if res_out and res_out.results and "data" in res_out.results[0]:
            for item in res_out.results[0]["data"]:
                dev = item.get("i_device_name") or item.get("device_name") or ""
                port = item.get("output_port", "")
                if dev and port:
                    out_map.setdefault(dev, {})[port] = item.get("avg_bits_per_sec", 0.0)
    except Exception as e:
        print(f"Warning: Batch outbound traffic query error: {e}")

    device_results = {}
    flow_devs = set(list(in_map.keys()) + list(out_map.keys()))

    # Process devices with flow traffic data
    for dev in flow_devs:
        dev_in = in_map.get(dev, {})
        dev_out = out_map.get(dev, {})
        all_ports = set(list(dev_in.keys()) + list(dev_out.keys()))

        interfaces_dict = {}
        for port_str in all_ports:
            meta = parse_interface_meta(port_str)
            key = meta["clean_name"]

            in_bps = dev_in.get(port_str, 0.0)
            out_bps = dev_out.get(port_str, 0.0)
            speed_h = meta["speed_human"]

            in_pct = (in_bps / speed_h) * 100.0 if speed_h > 0 else 0.0
            out_pct = (out_bps / speed_h) * 100.0 if speed_h > 0 else 0.0

            interfaces_dict[key] = {
                "neighbor": meta["neighbor"],
                "Circuit": meta["circuit"],
                "description": meta["description"],
                "speed": meta["speed"],
                "speed_human": speed_h,
                "input_bps": round(in_bps, 2),
                "input_bps_percent": round(in_pct, 4),
                "output_bps": round(out_bps, 2),
                "output_bps_percent": round(out_pct, 4),
                "input_pps": int(in_bps / 1200),
                "output_pps": int(out_bps / 1200),
                "ae_list": [],
                "member_speeds": {},
                "is_400g_upgraded": False,
                "upgrade_status": "Not upgraded"
            }
        if interfaces_dict:
            device_results[dev] = interfaces_dict

    # Process devices without flow traffic data (e.g. CR and BNG routers exporting SNMP metrics/inventory only)
    missing_devs = [d for d in device_list if d not in device_results]
    for dev_name in missing_devs:
        d_obj = device_obj_map.get(dev_name)
        if not d_obj:
            continue
        try:
            if dev_name not in device_detail_cache:
                dev_detail = client.devices.get(d_obj.id)
                device_detail_cache[dev_name] = dev_detail
            else:
                dev_detail = device_detail_cache[dev_name]

            if not hasattr(dev_detail, "interfaces") or not dev_detail.interfaces:
                continue

            interfaces_dict = {}
            for item in dev_detail.interfaces:
                full_str = getattr(item, "interface_description", "") or getattr(item, "name", "") or ""
                if not full_str or full_str.startswith(("null", "lo0", "bme", "dsc", "tap", "gre", "re0", "re1", "lsi")):
                    continue

                meta = parse_interface_meta(full_str)
                key = meta["clean_name"]

                speed_h = item.speed if (getattr(item, "speed", None) and item.speed > 0) else meta["speed_human"]
                speed_str = f"{int(speed_h / 1e9)}Gbps" if speed_h >= 1e9 else meta["speed"]

                interfaces_dict[key] = {
                    "neighbor": meta["neighbor"],
                    "Circuit": meta["circuit"],
                    "description": meta["description"],
                    "speed": speed_str,
                    "speed_human": int(speed_h),
                    "input_bps": 0.0,
                    "input_bps_percent": 0.0,
                    "output_bps": 0.0,
                    "output_bps_percent": 0.0,
                    "input_pps": 0,
                    "output_pps": 0,
                    "ae_list": [],
                    "member_speeds": {},
                    "is_400g_upgraded": False,
                    "upgrade_status": "Not upgraded"
                }

            if interfaces_dict:
                device_results[dev_name] = interfaces_dict
        except Exception as e:
            print(f"Warning: Could not fetch SNMP interfaces for {dev_name}: {e}")

    return device_results

def process_batch_interval(
    client: KentikAPI,
    device_list: List[str],
    date_str: str,
    start_time: str,
    end_time: str,
    file_ts_str: str,
    audit_ts: str,
    target_dir: str,
    device_obj_map: Dict[str, Any] = None,
    device_detail_cache: Dict[str, Any] = None
) -> int:
    """Processes a single batch time window across all devices and writes JSON files."""
    batch_data = fetch_batch_kentik_devices_traffic(
        client, device_list, start_time, end_time, device_obj_map, device_detail_cache
    )
    saved_files = 0
    year_val = int(date_str.split("-")[0])

    for dev_name, intf_dict in batch_data.items():
        role = "backbone"
        if dev_name.startswith("bng"):
            role = "bng"
        elif dev_name.startswith("cr"):
            role = "core"
        elif dev_name.startswith("dr"):
            role = "distribution"
        elif dev_name.startswith("pr"):
            role = "peering"

        record = {
            "role": role,
            "year": year_val,
            "audit_timestamp": audit_ts
        }
        record.update(intf_dict)

        device_folder = os.path.join(target_dir, date_str, dev_name)
        os.makedirs(device_folder, exist_ok=True)

        json_filename = f"{dev_name}_{file_ts_str}.json"
        full_path = os.path.join(device_folder, json_filename)

        with open(full_path, "w") as f:
            json.dump(record, f, indent=4)
        saved_files += 1

    return saved_files

def parse_date(date_str: str) -> datetime:
    """Parse flexible date strings (YYYY-MM-DD or MM/DD/YYYY or M/D/YYYY)."""
    if not date_str:
        return datetime.now()
    clean_str = date_str.strip()
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%n/%d/%Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(clean_str, fmt)
        except ValueError:
            pass
    parts = re.split(r"[/-]", clean_str)
    if len(parts) == 3:
        if len(parts[0]) == 4:
            return datetime(int(parts[0]), int(parts[1]), int(parts[2]))
        else:
            return datetime(int(parts[2]), int(parts[0]), int(parts[1]))
    raise ValueError(f"Invalid date format: '{date_str}'. Expected YYYY-MM-DD or MM/DD/YYYY.")

def main():
    parser = argparse.ArgumentParser(description="Download Kentik Interfaces Statistics for Audit_interfaces_data")
    parser.add_argument("--date", type=str, default="", help="Single Target Date YYYY-MM-DD or MM/DD/YYYY (default: today)")
    parser.add_argument("--start", "--start-date", dest="start_date", type=str, default="", help="Start Date YYYY-MM-DD or MM/DD/YYYY (e.g. '5/20/2026')")
    parser.add_argument("--end", "--end-date", dest="end_date", type=str, default="", help="End Date YYYY-MM-DD or MM/DD/YYYY (e.g. '6/20/2026')")
    parser.add_argument("--device", "--devices", dest="device", type=str, default="", help="Specify device prefixes or names (e.g., '[cr,pr,mpr,bng]' or 'bng01.mci121')")
    parser.add_argument("-m", "--metro", type=str, default="", help="Specify metro name filter (e.g. 'atl', 'mci', 'lax')")
    parser.add_argument("--step", "--interval", dest="step", type=str, default="15m", help="Sampling interval: '15m' (default: 15-minute snapshots), '5m', '30m', '1h', or 'summary'")
    parser.add_argument("--outdir", type=str, default="Audit_interfaces_data_kentik", help="Target output directory (default: Audit_interfaces_data_kentik)")

    args = parser.parse_args()

    default_date_str = datetime.now().strftime("%Y-%m-%d")
    raw_start = args.start_date or args.date or default_date_str
    raw_end = args.end_date or (args.start_date if not args.date else args.date) or raw_start

    try:
        start_dt = parse_date(raw_start)
        end_dt = parse_date(raw_end)
    except ValueError as err:
        print(f"ERROR: {err}", file=sys.stderr)
        sys.exit(1)

    if start_dt > end_dt:
        print(f"ERROR: Start date {start_dt.strftime('%Y-%m-%d')} is after end date {end_dt.strftime('%Y-%m-%d')}.", file=sys.stderr)
        sys.exit(1)

    client = get_client()

    print("Fetching device inventory from Kentik API...")
    device_obj_map = {}
    try:
        inventory = client.devices.get_all()
        for d in inventory:
            if getattr(d, 'device_name', None):
                device_obj_map[d.device_name] = d
        all_devices = list(device_obj_map.keys())
        print(f"Retrieved {len(all_devices)} total registered devices from Kentik.")
    except Exception as e:
        print(f"Error fetching device inventory from Kentik: {e}")
        all_devices = ["sar01.bna103", "dr02.lax103", "bng01.mci121", "cr01.atl101", "pr01.iad101"]

    if args.metro:
        all_devices = [d for d in all_devices if args.metro.lower() in d.lower()]

    if args.device:
        cleaned = args.device.strip("[]")
        prefixes = tuple(p.strip().lower() for p in cleaned.split(",") if p.strip())
        device_list = [
            d for d in all_devices
            if d.lower().startswith(prefixes)
        ]
    else:
        device_list = [
            d for d in all_devices
            if d.lower().startswith(("cr", "bng", "pr", "dr", "mpr", "sar"))
        ]

    if not device_list:
        print("No devices matched your filters.")
        return

    device_detail_cache = {}

    step_mins = 15
    step_str = args.step.lower()
    if step_str in ("summary", "day", "daily", "0"):
        step_mins = 0
    elif "5" in step_str and "15" not in step_str:
        step_mins = 5
    elif "30" in step_str:
        step_mins = 30
    elif "60" in step_str or "1h" in step_str or "hour" in step_str:
        step_mins = 60
    elif "15" in step_str:
        step_mins = 15

    date_list = []
    curr = start_dt
    while curr <= end_dt:
        date_list.append(curr.strftime("%Y-%m-%d"))
        curr += timedelta(days=1)

    print(f"\nMatched {len(device_list)} devices across {len(date_list)} date(s) ({date_list[0]} to {date_list[-1]}).")
    print(f"Target Directory: {os.path.abspath(args.outdir)}/")
    print(f"Mode: {'Fast Batch Multi-Device 15-Minute Snapshots' if step_mins > 0 else 'Fast Batch Multi-Device Summary'}\n")

    for d_str in date_list:
        print(f"=== Processing Date: {d_str} ===")
        if step_mins > 0:
            saved_total = 0
            for h in range(24):
                for m in range(0, 60, step_mins):
                    h_end = h
                    m_end = m + step_mins
                    if m_end >= 60:
                        m_end -= 60
                        h_end += 1

                    if h_end >= 24:
                        start_time = f"{d_str} {h:02d}:{m:02d}:00"
                        end_time = f"{d_str} 23:59:59"
                        file_ts_str = f"{d_str.replace('-', '_')}_{h:02d}_{m:02d}"
                        audit_ts = f"{d_str} 23:59:59"
                    else:
                        start_time = f"{d_str} {h:02d}:{m:02d}:00"
                        end_time = f"{d_str} {h_end:02d}:{m_end:02d}:00"
                        file_ts_str = f"{d_str.replace('-', '_')}_{h_end:02d}_{m_end:02d}"
                        audit_ts = f"{d_str} {h_end:02d}:{m_end:02d}:00"

                    saved = process_batch_interval(
                        client, device_list, d_str, start_time, end_time, file_ts_str, audit_ts, args.outdir,
                        device_obj_map, device_detail_cache
                    )
                    saved_total += saved
            print(f" -> Completed date {d_str}: Saved {saved_total} snapshot files across matched devices.")
        else:
            start_time = f"{d_str} 00:00:00"
            end_time = f"{d_str} 23:59:59"
            file_ts_str = f"{d_str.replace('-', '_')}_23_59"
            audit_ts = f"{d_str} 23:59:59"

            saved = process_batch_interval(
                client, device_list, d_str, start_time, end_time, file_ts_str, audit_ts, args.outdir,
                device_obj_map, device_detail_cache
            )
            print(f" -> Completed date {d_str}: Saved summary files for {saved} active devices.")

    print("\nDownload complete! Data formatted for view_interfaces applications.")

if __name__ == "__main__":
    main()

