#!/usr/bin/env python3
"""
Audit Kentik Interface Utilization Script
------------------------------------------
Collects interface traffic utilization metrics (Avg bps, 95th Percentile bps, Max Peak bps)
for network devices over a specified historical date range (e.g. 2026-06-01 to 2026-07-20).

Usage:
    python3 audit_kentik_interface_utilization.py --start 2026-06-01 --end 2026-07-20 --topx 20
    python3 audit_kentik_interface_utilization.py --device bng01.mci121 --start 2026-06-01 --end 2026-07-20
"""

import os
import sys
import json
import argparse
from datetime import datetime
from typing import List, Dict, Any

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
        FastDataType,
        Aggregate,
        AggregateFunctionType
    )
except ImportError:
    print("ERROR: kentik-api package is not installed. Run: pip install kentik-api", file=sys.stderr)
    sys.exit(1)

# Kentik Credentials
KENTIK_EMAIL = os.environ.get("KENTIK_EMAIL", "")
KENTIK_API_TOKEN = os.environ.get("KENTIK_API_TOKEN", "")

def get_client() -> KentikAPI:
    """Initialize the KentikAPI client."""
    if not KENTIK_EMAIL or not KENTIK_API_TOKEN:
        print("ERROR: KENTIK_EMAIL and KENTIK_API_TOKEN environment variables must be set.", file=sys.stderr)
        sys.exit(1)
    return KentikAPI(KENTIK_EMAIL, KENTIK_API_TOKEN)

def format_bps(bps: float) -> str:
    """Format bits per second into readable Gbps/Mbps units."""
    if bps is None:
        return "N/A"
    if bps >= 1e9:
        return f"{bps / 1e9:.2f} Gbps"
    elif bps >= 1e6:
        return f"{bps / 1e6:.2f} Mbps"
    elif bps >= 1e3:
        return f"{bps / 1e3:.2f} Kbps"
    return f"{bps:.2f} bps"

def collect_interface_utilization(
    client: KentikAPI,
    device_names: List[str],
    start_date: str,
    end_date: str,
    topx: int = 20
) -> List[Dict[str, Any]]:
    """
    Execute Kentik Query API to fetch interface utilization for specified devices & date window.
    """
    start_str = f"{start_date} 00:00:00"
    end_str = f"{end_date} 23:59:59"

    print(f"Querying Kentik Interface Traffic Metrics...")
    print(f" - Time Window: {start_str} to {end_str}")
    print(f" - Target Devices: {', '.join(device_names) if device_names else 'All Devices'}")
    print(f" - Top X Interfaces: {topx}\n")

    # Custom aggregates for Avg, 95th Percentile, and Max Peak Traffic
    agg_avg = Aggregate(
        name="avg_bits_per_sec",
        column="f_sum_both_bytes",
        fn=AggregateFunctionType.average,
        raw=True
    )
    agg_p95 = Aggregate(
        name="p95th_bits_per_sec",
        column="f_sum_both_bytes",
        fn=AggregateFunctionType.percentile,
        rank=95
    )
    agg_max = Aggregate(
        name="max_bits_per_sec",
        column="f_sum_both_bytes",
        fn=AggregateFunctionType.max
    )

    query_kwargs = {
        "starting_time": start_str,
        "ending_time": end_str,
        "metric": [MetricType.bytes],
        "dimension": [DimensionType.InterfaceID_src],
        "topx": topx,
        "depth": 75,
        "fastData": FastDataType.auto,
        "aggregates": [agg_avg, agg_p95, agg_max]
    }

    if device_names:
        query_kwargs["device_name"] = device_names
    else:
        query_kwargs["all_selected"] = True

    query = Query(**query_kwargs)
    query_item = QueryArrayItem(query=query, bucket="Left +Y Axis")
    query_object = QueryObject(queries=[query_item])

    try:
        res = client.query.data(query_object)
        if not res.results or "data" not in res.results[0]:
            print("No traffic data returned for the specified criteria.")
            return []
        
        raw_data = res.results[0]["data"]
        results = []
        for item in raw_data:
            interface_name = item.get("input_port", "Unknown")
            device_name = item.get("i_device_name", "Unknown")
            device_id = item.get("i_device_id", 0)
            avg_bps = item.get("avg_bits_per_sec", 0.0)
            p95_bps = item.get("p95th_bits_per_sec", 0.0)
            max_bps = item.get("max_bits_per_sec", 0.0)

            results.append({
                "device_name": device_name,
                "device_id": device_id,
                "interface": interface_name,
                "avg_bps": avg_bps,
                "avg_human": format_bps(avg_bps),
                "p95_bps": p95_bps,
                "p95_human": format_bps(p95_bps),
                "max_bps": max_bps,
                "max_human": format_bps(max_bps)
            })
        
        return results

    except Exception as e:
        print(f"Error querying Kentik traffic data: {e}", file=sys.stderr)
        return []

def main():
    parser = argparse.ArgumentParser(description="Audit Kentik Interface Traffic & Utilization over Date Range")
    parser.add_argument("--start", type=str, default="2026-06-01", help="Start Date (YYYY-MM-DD), default: 2026-06-01")
    parser.add_argument("--end", type=str, default="2026-07-20", help="End Date (YYYY-MM-DD), default: 2026-07-20")
    parser.add_argument("--device", type=str, default="", help="Optional single device name or comma-separated device list")
    parser.add_argument("--topx", type=int, default=20, help="Top X interfaces to return (default: 20)")
    parser.add_argument("--output", type=str, default="kentik_interface_utilization_results.json", help="Output JSON results filename")

    args = parser.parse_args()

    client = get_client()

    device_list = [d.strip() for d in args.device.split(",") if d.strip()] if args.device else []

    # If no specific device passed, get top devices sample from inventory
    if not device_list:
        try:
            inventory = client.devices.get_all()
            if inventory:
                # Select first few router device names for focused report if all isn't passed
                sample_devices = [d.device_name for d in inventory if getattr(d, 'device_name', None)][:3]
                print(f"Retrieved {len(inventory)} total devices in Kentik inventory.")
                print(f"Querying sample devices: {', '.join(sample_devices)}\n")
                device_list = sample_devices
        except Exception as e:
            print(f"Warning: Could not fetch device inventory list: {e}")

    results = collect_interface_utilization(
        client=client,
        device_names=device_list,
        start_date=args.start,
        end_date=args.end,
        topx=args.topx
    )

    if results:
        print("=" * 110)
        print(f"{'DEVICE NAME':<20} | {'INTERFACE':<45} | {'AVG BPS':<12} | {'95TH BPS':<12} | {'MAX PEAK':<12}")
        print("=" * 110)
        for r in results:
            intf = (r['interface'][:42] + "...") if len(r['interface']) > 45 else r['interface']
            print(f"{r['device_name']:<20} | {intf:<45} | {r['avg_human']:<12} | {r['p95_human']:<12} | {r['max_human']:<12}")
        print("=" * 110)

        with open(args.output, "w") as f:
            json.dump({
                "time_window": {"start": args.start, "end": args.end},
                "total_interfaces": len(results),
                "results": results
            }, f, indent=2)
        print(f"\nSaved detailed JSON metrics report to: {args.output}")

if __name__ == "__main__":
    main()
