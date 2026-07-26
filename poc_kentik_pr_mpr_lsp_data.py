#!/usr/bin/env python3
"""
poc_kentik_pr_mpr_lsp_data.py
-----------------------------
POC script to discover what kind of ingress LSP, MPLS, interface, and flow data
are stored at the Kentik server for PR and MPR routers.
"""

import os
import sys
import json
import time
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

def inspect_devices_and_interfaces(client: KentikAPI) -> List[Dict[str, Any]]:
    print("=== 1. Discovering PR and MPR Routers in Kentik Inventory ===")
    all_devices = client.devices.get_all()
    pr_mpr_devices = [d for d in all_devices if d.device_name.startswith(("pr", "mpr"))]
    print(f"Found {len(pr_mpr_devices)} total PR and MPR routers:")
    
    device_summary = []
    for d in sorted(pr_mpr_devices, key=lambda x: x.device_name):
        print(f"  - Device: {d.device_name:20s} | ID: {d.id} | Type: {d.device_type} | Subtype: {d.device_subtype}")
        device_summary.append({
            "id": d.id,
            "name": d.device_name,
            "type": d.device_type,
            "subtype": d.device_subtype
        })
    return device_summary

def inspect_interface_inventory(client: KentikAPI, pr_mpr_devices: List[Dict[str, Any]]):
    print("\n=== 2. Inspecting SNMP Interface Inventory for PR/MPR Devices ===")
    for dev in pr_mpr_devices[:5]:
        dev_name = dev["name"]
        dev_id = dev["id"]
        print(f"\n--- {dev_name} (ID: {dev_id}) ---")
        try:
            detail = client.devices.get(dev_id)
            if hasattr(detail, "interfaces") and detail.interfaces:
                intfs = detail.interfaces
                print(f"Total Interfaces Configured: {len(intfs)}")
                core_intfs = []
                lsp_intfs = []
                for item in intfs:
                    iname = getattr(item, "name", "") or ""
                    idesc = getattr(item, "interface_description", "") or ""
                    ialias = getattr(item, "alias", "") or ""
                    full_str = f"name='{iname}', desc='{idesc}', alias='{ialias}'"
                    if "CORE" in idesc or "CORE" in full_str:
                        core_intfs.append((iname, idesc, getattr(item, "speed", 0)))
                    if any(k in full_str.lower() for k in ["lsp", "mpls", "hsd", "rsvp", "tunnel", "to-"]):
                        lsp_intfs.append((iname, idesc))
                
                print(f"  Core Interfaces ([U=CORE]): {len(core_intfs)}")
                for name, desc, spd in core_intfs[:5]:
                    print(f"    * {name:10s} | Speed: {spd/1e9:.0f}G | Desc: {desc}")
                
                print(f"  LSP/MPLS Named Interfaces: {len(lsp_intfs)}")
                for name, desc in lsp_intfs[:5]:
                    print(f"    * {name:10s} | Desc: {desc}")
                
                if not core_intfs and not lsp_intfs:
                    print("  Sample Interfaces (first 5):")
                    for item in intfs[:5]:
                        print(f"    * {getattr(item, 'name', '')} | Desc: {getattr(item, 'interface_description', '')}")
            else:
                print("No interface inventory details found.")
        except Exception as e:
            print(f"Error getting detail for {dev_name}: {e}")

def test_flow_dimensions(client: KentikAPI, device_names: List[str]):
    print("\n=== 3. Testing Flow Query Dimensions on PR/MPR Routers ===")
    end_str = (datetime.now() - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
    start_str = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")

    dimensions_to_test = [
        ("InterfaceID_src (Inbound Traffic)", DimensionType.InterfaceID_src),
        ("InterfaceID_dst (Outbound Traffic)", DimensionType.InterfaceID_dst),
        ("src_nexthop_ip (Next-hop Source IP)", DimensionType.src_nexthop_ip),
        ("dst_nexthop_ip (Next-hop Destination IP)", DimensionType.dst_nexthop_ip),
        ("c_src_metro (Custom Dimension Metro Edge)", "c_src_metro"),
        ("c_dst_metro (Custom Dimension Metro Cx)", "c_dst_metro"),
        ("c_dst_type (Custom Dimension Destination Type)", "c_dst_type")
    ]

    for label, dim in dimensions_to_test:
        print(f"\n--- Testing Dimension: {label} ---")
        try:
            q = Query(
                starting_time=start_str,
                ending_time=end_str,
                device_name=device_names,
                metric=[MetricType.bytes],
                dimension=[dim],
                topx=20,
                fastData=FastDataType.auto
            )
            res = client.query.data(QueryObject(queries=[QueryArrayItem(query=q, bucket="Left +Y Axis")]))
            if res and res.results and "data" in res.results[0]:
                rows = res.results[0]["data"]
                print(f"SUCCESS: Returned {len(rows)} data rows.")
                for row in rows[:5]:
                    key_val = row.get(str(dim)) or row.get("input_port") or row.get("output_port") or row.get("i_device_name") or list(row.values())[0]
                    bps = row.get("avg_bits_per_sec", 0.0)
                    print(f"   Row: {key_val} | Avg Bps: {bps:,.2f}")
            else:
                print("NO DATA returned for this dimension.")
        except Exception as e:
            print(f"FAILED / NOT SUPPORTED: {e}")

def main():
    client = get_client()
    devices = inspect_devices_and_interfaces(client)
    if not devices:
        return
    inspect_interface_inventory(client, devices)
    dev_names = [d["name"] for d in devices]
    test_flow_dimensions(client, dev_names)

if __name__ == "__main__":
    main()
