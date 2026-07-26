#!/usr/bin/env python3
"""
Kentik API Python SDK Client Script
-----------------------------------
This script uses the official `kentik-api` Python SDK (`from kentik_api import KentikAPI`)
to authenticate and retrieve device, site, and plan inventories from Kentik.

Usage:
    export KENTIK_EMAIL="mikezh@google.com"
    export KENTIK_API_TOKEN="052d51fa6df10577aa924cf8b696d788"
    python3 kentik_api_example.py
"""

import os
import sys

try:
    from dotenv import load_dotenv
    load_dotenv(override=True)
except ImportError:
    pass

try:
    from kentik_api import KentikAPI
except ImportError:
    print("ERROR: kentik-api package is not installed. Run: pip install kentik-api", file=sys.stderr)
    sys.exit(1)

# Kentik API Configuration
KENTIK_EMAIL = os.environ.get("KENTIK_EMAIL", "")
KENTIK_API_TOKEN = os.environ.get("KENTIK_API_TOKEN", "")

def get_client() -> KentikAPI:
    """Instantiate the KentikAPI client SDK."""
    if not KENTIK_EMAIL or not KENTIK_API_TOKEN:
        print("ERROR: Please set KENTIK_EMAIL and KENTIK_API_TOKEN environment variables.", file=sys.stderr)
        sys.exit(1)
    return KentikAPI(KENTIK_EMAIL, KENTIK_API_TOKEN)

def main():
    print("=== Kentik API Python SDK Script ===\n")
    client = get_client()

    # 1. Fetch Devices via KentikAPI SDK
    try:
        print("Fetching device inventory via KentikAPI SDK...")
        devices = client.devices.get_all()
        print(f"Successfully retrieved {len(devices)} devices.\n")
        print("Sample Devices:")
        for d in devices[:5]:
            print(f" - Name: {d.device_name}, Type: {d.device_type}, Subtype: {d.device_subtype}, ID: {d.id}")
    except Exception as e:
        print(f"Failed to list devices: {e}")

    print()

    # 2. Fetch Sites via KentikAPI SDK
    try:
        print("Fetching site inventory via KentikAPI SDK...")
        sites = client.sites.get_all()
        print(f"Successfully retrieved {len(sites)} sites.\n")
        print("Sample Sites:")
        for s in sites[:5]:
            print(f" - Site: {s.site_name}, ID: {s.id}")
    except Exception as e:
        print(f"Failed to list sites: {e}")

    print()

    # 3. Fetch Plans via KentikAPI SDK
    try:
        print("Fetching plans via KentikAPI SDK...")
        plans = client.plans.get_all()
        print(f"Successfully retrieved {len(plans)} plans.\n")
        print("Sample Plans:")
        for p in plans[:5]:
            print(f" - Plan Name: {p.name}, Active: {p.active}, ID: {p.id}")
    except Exception as e:
        print(f"Failed to list plans: {e}")

if __name__ == "__main__":
    main()
