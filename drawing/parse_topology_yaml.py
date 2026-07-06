"""Parse drawing/topology.yaml (link list with per-end port labels)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from topology_model import Topology, TopologyLink


def _endpoint_name_and_port(endpoint: Any, label: str) -> tuple[str, str]:
    if not isinstance(endpoint, dict):
        raise ValueError(f"{label}: expected a mapping with device name keys, got {type(endpoint).__name__}")
    if len(endpoint) != 1:
        raise ValueError(f"{label}: expected exactly one device key, got {list(endpoint)}")
    device, meta = next(iter(endpoint.items()))
    if not isinstance(device, str) or not device.strip():
        raise ValueError(f"{label}: device name must be a non-empty string")
    port = ""
    if meta is not None:
        if not isinstance(meta, dict):
            raise ValueError(f"{label}[{device}]: expected mapping with optional 'port'")
        port = str(meta.get("port", "") or "")
    return device.strip(), port


def parse_topology_dict(data: dict[str, Any]) -> Topology:
    raw_links = data.get("links")
    if raw_links is None:
        raise ValueError("topology YAML must contain a top-level 'links' list")
    if not isinstance(raw_links, list):
        raise ValueError("'links' must be a list")

    links: list[TopologyLink] = []
    devices: set[str] = set()

    for i, entry in enumerate(raw_links):
        if not isinstance(entry, dict):
            raise ValueError(f"links[{i}]: expected a mapping with two device endpoints")
        if len(entry) != 2:
            raise ValueError(f"links[{i}]: expected exactly two device endpoints, got {list(entry)}")
        keys = list(entry.keys())
        device_a, port_a = _endpoint_name_and_port({keys[0]: entry[keys[0]]}, f"links[{i}].{keys[0]}")
        device_b, port_b = _endpoint_name_and_port({keys[1]: entry[keys[1]]}, f"links[{i}].{keys[1]}")
        devices.add(device_a)
        devices.add(device_b)
        links.append(TopologyLink(device_a, port_a, device_b, port_b))

    if not devices:
        raise ValueError("topology has no devices")

    return Topology(devices=sorted(devices), links=links)


def load_topology_yaml(path: str | Path) -> Topology:
    path = Path(path)
    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a YAML mapping at the top level")
    return parse_topology_dict(data)
