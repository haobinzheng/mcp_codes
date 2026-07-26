#!/usr/bin/env python3
"""
poc_explore_kentik_ingress_lsp.py
---------------------------------
Explores and analyzes what ingress LSP & MPLS-related data are stored at the Kentik server
for PR and MPR routers versus what is stored in JunOS control plane (via gnetch.sh).

Findings Summary:
1. Kentik Server Stores (Flow & Telemetry Level):
   - Ingress & Egress Inter-Metro Traffic Flow Matrices (c_src_metro -> c_dst_metro).
   - Core LSP Interconnect Interface Telemetry ([U=CORE] interfaces to CR01/CR02 routers).
   - Traffic volume by Destination Type (Customer Subnets, Cache Servers, Webpass).
   - Device & Interface SNMP metadata (speed, status, neighbor router tag [R=...]).

2. JunOS Router Control Plane Stores (CLI / gnetch.sh Level):
   - Named Ingress RSVP LSPs (e.g. PR01ATL101-AR01NUQ102-HSD-1).
   - Explicit Route Object (RRO) Hop-by-Hop paths and MPLS Label Stacks (e.g. Label 406184, PHP Explicit Null Label 0).
   - RSVP reservation state & signaled bandwidth.
"""

import os
import sys
import json
from datetime import datetime, timedelta
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
except ImportError:
    print("ERROR: kentik-api package is not installed. Run: pip install kentik-api", file=sys.stderr)
    sys.exit(1)

KENTIK_EMAIL = os.environ.get("KENTIK_EMAIL", "")
KENTIK_API_TOKEN = os.environ.get("KENTIK_API_TOKEN", "")

def get_client() -> KentikAPI:
    if not KENTIK_EMAIL or not KENTIK_API_TOKEN:
        print("ERROR: KENTIK_EMAIL and KENTIK_API_TOKEN environment variables must be set.", file=sys.stderr)
        sys.exit(1)
    return KentikAPI(KENTIK_EMAIL, KENTIK_API_TOKEN)

def main():
    client = get_client()
    print("================================================================================")
    print("           KENTIK SERVER INGRESS LSP DATA DISCOVERY & POC ANALYSIS               ")
    print("================================================================================")

    # 1. Fetch PR and MPR devices
    all_devices = client.devices.get_all()
    pr_mpr_devices = [d for d in all_devices if d.device_name.startswith(("pr", "mpr"))]
    print(f"\n1. PR & MPR Routers Registered in Kentik Inventory ({len(pr_mpr_devices)} routers):")
    for d in sorted(pr_mpr_devices, key=lambda x: x.device_name):
        print(f"   - {d.device_name:20s} (ID: {d.id}, Subtype: {d.device_subtype})")

    pr_mpr_names = [d.device_name for d in pr_mpr_devices]

    end_str = (datetime.now() - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
    start_str = (datetime.now() - timedelta(hours=6)).strftime("%Y-%m-%d %H:%M:%S")

    # 2. Query Inter-Metro Ingress Flow Matrix (c_src_metro -> c_dst_metro)
    print("\n2. Ingress Inter-Metro Traffic Flow Matrix (c_src_metro -> c_dst_metro):")
    print(f"   Window: {start_str} to {end_str}")
    q_metro = Query(
        starting_time=start_str,
        ending_time=end_str,
        device_name=pr_mpr_names,
        metric=[MetricType.bytes],
        dimension=["c_src_metro", "c_dst_metro"],
        topx=50,
        fastData=FastDataType.auto
    )

    try:
        res = client.query.data(QueryObject(queries=[QueryArrayItem(query=q_metro, bucket="Left +Y Axis")]))
        if res and res.results and "data" in res.results[0]:
            rows = res.results[0]["data"]
            print(f"   Found {len(rows)} inter-metro ingress flow paths:")
            for r in rows[:12]:
                src_m = r.get("c_src_metro", "Unknown")
                dst_m = r.get("c_dst_metro", "Unknown")
                bps = r.get("avg_bits_per_sec", 0.0)
                p95 = r.get("p95th_bits_per_sec", 0.0)
                print(f"     Ingress Metro: {src_m:5s} ---> Egress Metro: {dst_m:5s} | Avg: {bps/1e9:8.2f} Gbps | 95th: {p95/1e9:8.2f} Gbps")
        else:
            print("   No inter-metro flow data found.")
    except Exception as e:
        print(f"   Query error: {e}")

    # 3. Query Core Interconnect Interfaces ([U=CORE]) Carrying Ingress LSP Traffic
    print("\n3. Core Interconnect Interfaces ([U=CORE]) Carrying Ingress LSP Traffic on PR/MPR Routers:")
    q_core_out = Query(
        starting_time=start_str,
        ending_time=end_str,
        device_name=pr_mpr_names,
        metric=[MetricType.bytes],
        dimension=[DimensionType.InterfaceID_dst],
        topx=100,
        fastData=FastDataType.auto
    )

    try:
        res_core = client.query.data(QueryObject(queries=[QueryArrayItem(query=q_core_out, bucket="Left +Y Axis")]))
        if res_core and res_core.results and "data" in res_core.results[0]:
            rows = res_core.results[0]["data"]
            core_rows = [r for r in rows if "[U=CORE]" in r.get("output_port", "")]
            print(f"   Found {len(core_rows)} active Core LSP interconnect interfaces:")
            for r in core_rows[:10]:
                dev = r.get("i_device_name") or r.get("device_name") or "Unknown"
                port = r.get("output_port", "")
                bps = r.get("avg_bits_per_sec", 0.0)
                print(f"     Router: {dev:15s} | Port: {port} | Outbound: {bps/1e9:6.2f} Gbps")
        else:
            print("   No core interface flow data found.")
    except Exception as e:
        print(f"   Query error: {e}")

    # 4. Summary Matrix comparing Kentik Flow Telemetry vs JunOS Control Plane
    print("\n================================================================================")
    print("                    DATA SOURCES COMPARISON MATRIX                              ")
    print("================================================================================")
    print(" Data Field                       | Stored at Kentik? | Stored at Router Control Plane?")
    print(" -------------------------------- | ----------------- | ------------------------------")
    print(" Inter-Metro Flow Matrix (Bps)   | YES (c_src/dst)   | NO                             ")
    print(" Core LSP Interface Bps & PPS     | YES (Flow/SNMP)   | YES (Interface counters)       ")
    print(" Destination Type Breakdown      | YES (c_dst_type)  | NO                             ")
    print(" Ingress RSVP LSP Name (HSD-1)    | NO                | YES ('show lsp ingress')       ")
    print(" RRO Hop Path & Label Stack       | NO                | YES ('show lsp detail')        ")
    print(" Signal Bandwidth / PHP State     | NO                | YES ('show rsvp session')      ")
    print("================================================================================\n")

if __name__ == "__main__":
    main()
