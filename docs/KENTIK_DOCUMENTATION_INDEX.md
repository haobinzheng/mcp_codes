# Kentik API & SDK Local Documentation Repository

This directory contains the official Kentik API schemas, OpenAPI specifications, and runnable Python SDK examples downloaded for your project.

---

## 📁 Repository Structure

### 1. Python SDK Examples (`docs/kentik_sdk_python/examples/`)
Runnable Python scripts for the official `kentik-api` library:

- **Devices**: [`docs/kentik_sdk_python/examples/devices_example.py`](file:///usr/local/google/home/mikezh/Coding/mcp_codes/docs/kentik_sdk_python/examples/devices_example.py)
- **Sites**: [`docs/kentik_sdk_python/examples/sites_example.py`](file:///usr/local/google/home/mikezh/Coding/mcp_codes/docs/kentik_sdk_python/examples/sites_example.py)
- **Plans**: [`docs/kentik_sdk_python/examples/plans_example.py`](file:///usr/local/google/home/mikezh/Coding/mcp_codes/docs/kentik_sdk_python/examples/plans_example.py)
- **Dimensions**: [`docs/kentik_sdk_python/examples/dimensions_example.py`](file:///usr/local/google/home/mikezh/Coding/mcp_codes/docs/kentik_sdk_python/examples/dimensions_example.py)
- **Tags & Labels**: [`docs/kentik_sdk_python/examples/tags_example.py`](file:///usr/local/google/home/mikezh/Coding/mcp_codes/docs/kentik_sdk_python/examples/tags_example.py) / [`labels_example.py`](file:///usr/local/google/home/mikezh/Coding/mcp_codes/docs/kentik_sdk_python/examples/labels_example.py)
- **Synthetics**: [`docs/kentik_sdk_python/examples/synthetics_example.py`](file:///usr/local/google/home/mikezh/Coding/mcp_codes/docs/kentik_sdk_python/examples/synthetics_example.py)
- **Saved Filters**: [`docs/kentik_sdk_python/examples/saved_filters_example.py`](file:///usr/local/google/home/mikezh/Coding/mcp_codes/docs/kentik_sdk_python/examples/saved_filters_example.py)
- **Alerting**: [`docs/kentik_sdk_python/examples/alerting_example.py`](file:///usr/local/google/home/mikezh/Coding/mcp_codes/docs/kentik_sdk_python/examples/alerting_example.py)
- **Cloud Export**: [`docs/kentik_sdk_python/examples/cloud_export_example.py`](file:///usr/local/google/home/mikezh/Coding/mcp_codes/docs/kentik_sdk_python/examples/cloud_export_example.py)
- **Users**: [`docs/kentik_sdk_python/examples/users_example.py`](file:///usr/local/google/home/mikezh/Coding/mcp_codes/docs/kentik_sdk_python/examples/users_example.py)
- **Analytics & SQL**: [`docs/kentik_sdk_python/examples/analytics_example_topx.py`](file:///usr/local/google/home/mikezh/Coding/mcp_codes/docs/kentik_sdk_python/examples/analytics_example_topx.py)

---

### 2. OpenAPI & Protobuf Schemas (`docs/kentik_api_schema/`)
Official v6 OpenAPI Swagger JSON specifications and Protobuf schemas:

- **Device Management**: `docs/kentik_api_schema/gen/openapiv2/kentik/device/v202504beta2/device.swagger.json`
- **Device Configuration**: `docs/kentik_api_schema/gen/openapiv2/kentik/deviceconf/v202511/device_configuration_service.swagger.json`
- **Alerting & Policies**: `docs/kentik_api_schema/gen/openapiv2/kentik/alerting/public/v202505/policy.swagger.json`
- **Synthetic Monitoring**: `docs/kentik_api_schema/gen/openapiv2/kentik/synthetics/v202309/synthetics.swagger.json`
- **Capacity Planning**: `docs/kentik_api_schema/gen/openapiv2/kentik/capacity_plan/v202212/capacity_plan.swagger.json`
- **Custom Dimensions**: `docs/kentik_api_schema/gen/openapiv2/kentik/custom_dimension/v202411alpha1/custom_dimension.swagger.json`
- **Cloud Export**: `docs/kentik_api_schema/gen/openapiv2/kentik/cloud_export/v202506/cloud_export.swagger.json`

---

## 🚀 Quick Execution Guide

To run any SDK example with your credentials:

```bash
source env_kentik.sh
python3 docs/kentik_sdk_python/examples/devices_example.py
python3 docs/kentik_sdk_python/examples/sites_example.py
python3 docs/kentik_sdk_python/examples/plans_example.py
```
