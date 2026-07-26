#!/usr/bin/env python3
"""
POC script to discover what kind of ingress LSP / MPLS data and traffic metrics
are stored on the Kentik server for PR and MPR routers.
"""

import os
import sys
import json
from datetime import datetime, timedelta

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

def main():
    if not KENTIK_EMAIL or not KENTIK_API_TOKEN:
        print("ERROR: KENTIK_EMAIL and KENTIK_API_TOKEN environment variables must be set.", file=sys.stderr)
        sys.exit(1)

    client = KentikAPI(KENTIK_EMAIL, KENTIK_API_TOKEN)
    print("Initialized KentikAPI client.")

    # 1. Get PR and MPR devices
    all_devices = client.devices.get_all()
    pr_mpr_devices = [d for d in all_devices if d.device_name.startswith(("pr", "mpr"))]
    print(f"\nFound {len(pr_mpr_devices)} PR and MPR routers registered in Kentik:")
    for d in sorted(pr_mpr_devices, key=lambda x: x.device_name):
        print(f"  - {d.device_name} (ID: {d.id}, Type: {d.device_type}, Subtype: {d.device_subtype})")

    if not pr_mpr_devices:
        print("No PR or MPR devices found.")
        return

    pr_mpr_names = [d.device_name for d in pr_mpr_devices]

    # Time window: last 1 hour
    end_str = (datetime.now() - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
    start_str = (datetime.now() - timedelta(hours=1, minutes=5)).strftime("%Y-%m-%d %H:%M:%S")

    print(f"\nQuerying flow data window: {start_str} to {end_str}")

    # 2. Query 1: Top Src/Dst IP and interfaces on PR/MPR devices
    print("\n--- Query 1: Top Flow Dimensions (InterfaceID_src, IP_src, IP_dst) ---")
    q1 = Query(
        starting_time=start_str,
        ending_time=end_str,
        device_name=pr_mpr_names[:5],
        metric=[MetricType.bytes, MetricType.packets],
        dimension=[
            DimensionType.InterfaceID_src,
            DimensionType.IP_src,
            DimensionType.IP_dst
        ],
        topx=15,
        fastData=FastDataType.auto
    )
    try:
        res1 = client.query.data(QueryObject(queries=[QueryArrayItem(query=q1, bucket="Left +Y Axis")]))
        if res1 and res1.results and "data" in res1.results[0]:
            print(f"Query 1 returned {len(res1.results[0]['data'])} rows.")
            for row in res1.results[0]['data'][:5]:
                print("  ", json.dumps(row))
        else:
            print("Query 1 returned no data.")
    except Exception as e:
        print(f"Query 1 failed: {e}")

    # 3. Custom Dimensions
    print("\n--- Query 2: Custom Dimensions ---")
    try:
        cds = client.custom_dimensions.get_all()
        print(f"Registered Custom Dimensions in Kentik: {[cd.name for cd in cds]}")
    except Exception as e:
        print(f"Error fetching custom dimensions: {e}")

    # 4. Check interface inventory for any MPLS / LSP interface naming conventions
    print("\n--- Query 3: Inspecting Interface Inventory on PR/MPR Routers ---")
    for d in pr_mpr_devices[:3]:
        try:
            dev_detail = client.devices.get(d.id)
            if hasattr(dev_detail, 'interfaces') and dev_detail.interfaces:
                print(f"\nDevice {d.device_name} has {len(dev_detail.interfaces)} interfaces.")
                lsp_like = []
                for intf in dev_detail.interfaces:
                    iname = getattr(intf, 'name', '') or ''
                    idesc = getattr(intf, 'interface_description', '') or ''
                    ialias = getattr(intf, 'alias', '') or ''
                    combined = f"name='{iname}', desc='{idesc}', alias='{ialias}'"
                    if any(k in combined.lower() for k in ['lsp', 'mpls', 'hsd', 'rsvp', 'tunnel', 'to-']):
                        lsp_like.append(combined)
                print(f"  Interfaces matching LSP/MPLS keywords ({len(lsp_like)}):")
                for item in lsp_like[:10]:
                    print("   *", item)
                if not lsp_like:
                    print("  Sample interface descriptions (first 5):")
                    for intf in dev_detail.interfaces[:5]:
                        print(f"   * name='{getattr(intf, 'name', '')}', desc='{getattr(intf, 'interface_description', '')}'")
        except Exception as e:
            print(f"Error inspecting device {d.device_name}: {e}")

if __name__ == "__main__":
    main()
