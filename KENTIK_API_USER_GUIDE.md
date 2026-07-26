# Kentik API & Python SDK User Guide

Welcome to the **Kentik API User Guide**. This document details authentication, environment configuration, the official `kentik-api` Python SDK, REST API endpoints, and code examples.

---

## 1. Overview & Architecture

Kentik provides two main API interfaces:
- **v5 API (REST)**: Handles network device inventory, sites, plans, custom dimensions, saved filters, and legacy queries.
- **v6 API (gRPC / gRPC-Gateway)**: Modern high-performance APIs for Synthetic Monitoring, Cloud Export, Data Engine queries, and administrative controls.

The official Python client library **`kentik-api`** wraps Kentik's APIs into high-level Python objects.

---

## 2. Authentication & Environment Configuration

### Credentials
Kentik authentication requires two credentials:
- **Account Email**: The registered email address associated with your Kentik account (e.g. `mikezh@google.com`).
- **API Token**: Generated from your Kentik Portal profile (`Profile` -> `Authentication` tab).

### Environment Setup
Store your credentials in `.env` or set environment variables in your shell.

#### `.env` File (Git-ignored)
```env
KENTIK_EMAIL="mikezh@google.com"
KENTIK_API_TOKEN="052d51fa6df10577aa924cf8b696d788"
KENTIK_BASE_URL="https://api.kentik.com/api/v5"
```

#### Shell Script (`env_kentik.sh`)
```bash
#!/usr/bin/env bash
export KENTIK_EMAIL="mikezh@google.com"
export KENTIK_API_TOKEN="052d51fa6df10577aa924cf8b696d788"
export KENTIK_BASE_URL="https://api.kentik.com/api/v5"
```

---

## 3. Official Python SDK (`kentik-api`)

### Installation
```bash
pip install kentik-api
```

### Initializing the SDK Client
```python
import os
from dotenv import load_dotenv
from kentik_api import KentikAPI

# Load .env file automatically
load_dotenv(override=True)

email = os.environ.get("KENTIK_EMAIL")
token = os.environ.get("KENTIK_API_TOKEN")

# Initialize SDK client
client = KentikAPI(email, token)
```

---

## 4. Key SDK Modules & Usage Examples

### A. Device Management (`client.devices`)
Retrieve and manage network device inventory (routers, switches, BNGs, SARs):

```python
# List all registered devices
devices = client.devices.get_all()
print(f"Total Devices: {len(devices)}")

for device in devices[:5]:
    print(f"Device Name: {device.device_name}")
    print(f"  ID:          {device.id}")
    print(f"  Type:        {device.device_type}")
    print(f"  Subtype:     {device.device_subtype}")
    print(f"  Sample Rate: {device.device_sample_rate}")

# Retrieve single device by ID
device_id = devices[0].id
single_device = client.devices.get(device_id)
print(f"Fetched Device: {single_device.device_name}")
```

### B. Site Management (`client.sites`)
Retrieve physical sites and POP locations:

```python
# List all sites
sites = client.sites.get_all()
print(f"Total Sites: {len(sites)}")

for site in sites[:5]:
    print(f"Site Name: {site.site_name} (ID: {site.id})")
```

### C. Plan Management (`client.plans`)
Check active bandwidth and device capacity plans:

```python
# List active & inactive plans
plans = client.plans.get_all()

for plan in plans:
    print(f"Plan: {plan.name} | Active: {plan.active} | ID: {plan.id}")
```

### D. Device Cache Utility (`DeviceCache`)
For performance-critical code or batch processing, cache devices locally to index by name or ID:

```python
from kentik_api.utils.device_cache import DeviceCache

# Initialize device cache
cache = DeviceCache(client)

# High-speed lookup by device name
target_device = cache.get_device_by_name("bng01.mci121")
if target_device:
    print(f"Found Device: {target_device.device_name} (ID: {target_device.id})")
```

---

## 5. REST API Endpoint Reference

For raw HTTP integration, send `X-CH-Auth-Email` and `X-CH-Auth-API-Token` HTTP headers:

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `https://api.kentik.com/api/v5/devices` | `GET` | Fetch all network devices |
| `https://api.kentik.com/api/v5/sites` | `GET` | Fetch registered physical sites |
| `https://api.kentik.com/api/v5/plans` | `GET` | Fetch organization plans |
| `https://api.kentik.com/api/v5/customdimensions` | `GET` | List custom dimensions |
| `https://api.kentik.com/api/v5/query/topXdata` | `POST` | Execute Top Talker data queries |

### cURL Example
```bash
curl -s -X GET https://api.kentik.com/api/v5/devices \
  -H "X-CH-Auth-Email: mikezh@google.com" \
  -H "X-CH-Auth-API-Token: 052d51fa6df10577aa924cf8b696d788" \
  -H "Content-Type: application/json"
```

---

## 6. Best Practices & Security

1. **Email Domain Match**: Always confirm your exact registered Kentik user email (`@google.com` vs `@gfiber.com`).
2. **Secrets Protection**: Never commit API keys into source control. Always add `.env` and `env_*.sh` to `.gitignore`.
3. **Environment Overrides**: Use `load_dotenv(override=True)` in Python scripts to ensure local `.env` values take precedence over stale shell variables.
