#!/usr/bin/env python3
"""Draw Low-Level Design (LLD) network topology diagram from connection YAML.

Reads connection YAML files (e.g. connections_mci103.yaml) containing device connection
information, ignores decommissioned connections, and outputs a clean, legible diagram
in SVG / PNG / Google Slides.

Usage:
    python draw_lld.py --yaml drawing/connections_mci103.yaml --svg-out drawing/connections_mci103.svg
    python draw_lld.py --yaml drawing/connections_mci103.yaml --png-out drawing/connections_mci103.png
    python draw_lld.py --yaml drawing/connections_mci103.yaml --google-slides
"""

from __future__ import annotations

import argparse
import html
import shutil
import subprocess
import sys
import yaml
from pathlib import Path

# Enable importing from drawing/ directory if running from repo root or drawing/
SCRIPT_DIR = Path(__file__).resolve().parent
if (SCRIPT_DIR / "drawing").is_dir():
    sys.path.insert(0, str(SCRIPT_DIR / "drawing"))
elif SCRIPT_DIR.name == "drawing":
    sys.path.insert(0, str(SCRIPT_DIR))


def load_connection_yaml(
    yaml_path: str | Path,
    ignore_decommissioned: bool = True,
) -> tuple[list[dict], list[dict]]:
    """Load connection YAML file.

    Returns:
        (active_links, decommissioned_links)
    """
    path = Path(yaml_path)
    if not path.is_file():
        raise FileNotFoundError(f"YAML file not found: {path}")

    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Expected YAML mapping at top level of {path}")

    raw_conns = data.get("connections")
    if raw_conns is None and "links" in data:
        raw_conns = data["links"]

    if not isinstance(raw_conns, list):
        raise ValueError("Expected a list under 'connections' or 'links' key in YAML")

    active_links: list[dict] = []
    decom_links: list[dict] = []

    for i, item in enumerate(raw_conns):
        if not isinstance(item, dict):
            continue

        state = str(item.get("state", "")).strip().upper()
        if ignore_decommissioned and state == "DECOMMISSIONED":
            decom_links.append(item)
            continue

        dev_a = item.get("device_a")
        port_a = str(item.get("port_a", "") or "")
        dev_z = item.get("device_z") or item.get("device_b")
        port_z = str(item.get("port_z", "") or item.get("port_b", "") or "")

        if not dev_a or not dev_z:
            continue

        link = {
            "name": str(item.get("name", f"link-{i}")),
            "device_a": str(dev_a).strip(),
            "port_a": port_a.strip(),
            "rack_a": item.get("rack_a"),
            "device_z": str(dev_z).strip(),
            "port_z": port_z.strip(),
            "rack_z": item.get("rack_z"),
            "state": item.get("state", "ACTIVE"),
            "notes": str(item.get("notes", "") or ""),
        }

        if ignore_decommissioned and state != "DECOMMISSIONED":
            active_links.append(link)
        elif not ignore_decommissioned:
            if state == "DECOMMISSIONED":
                decom_links.append(link)
            active_links.append(link)

    return active_links, decom_links


def get_device_tier(device_name: str) -> int:
    """Classify network device role into hierarchical LLD tier (0-5)."""
    name = device_name.lower()
    if any(k in name for k in ["mpr", "core", "border", "wan", "edge"]):
        return 0
    if any(k in name for k in ["agg", "spine", "dist"]):
        return 1
    if any(k in name for k in ["fw", "firewall", "sec", "gateway"]):
        return 2
    if any(k in name for k in ["mhr", "leaf", "access", "sw"]):
        return 3
    if any(k in name for k in ["mgt", "hydra", "oob", "con", "console"]):
        return 4
    return 5


def build_lld_layout(active_links: list[dict]) -> dict:
    """Compute 2D canvas layout for LLD diagram matching reference layout."""
    devices = sorted(
        list(set(c["device_a"] for c in active_links) | set(c["device_z"] for c in active_links))
    )

    racks: dict[str, str] = {}
    for c in active_links:
        if c.get("rack_a"):
            racks[c["device_a"]] = str(c["rack_a"])
        if c.get("rack_z"):
            racks[c["device_z"]] = str(c["rack_z"])

    node_w, node_h = 190.0, 76.0

    # Custom 4-tier dual-unit layout matching reference diagram (e.g. MCI103, AUS121, CBF101)
    pos_map: dict[str, tuple[float, float]] = {
        # Core Unit 1
        "mpr01": (295.0, 70.0),
        "agg07": (295.0, 480.0),
        "mhr01": (295.0, 720.0),
        # Core Unit 2
        "mpr02": (845.0, 70.0),
        "agg08": (845.0, 480.0),
        "mhr02": (845.0, 720.0),
        # Firewalls & AGG02
        "fw01": (415.0, 240.0),
        "fw02": (725.0, 240.0),
        "agg02": (1105.0, 240.0),
        # Outer Management & Console (hydra/mgt) - 65px gap from core
        "hydra01": (40.0, 480.0),
        "mgt01": (40.0, 720.0),
        "hydra02": (1330.0, 480.0),
        "mgt02": (1330.0, 720.0),
    }

    canvas_w = 1580.0
    canvas_h = 960.0

    nodes: dict[str, dict] = {}
    default_models = {
        "fw": "SRX4600",
        "mhr": "SRX4600",
        "agg": "EX4650",
        "mpr": "MX204",
        "mgt": "EX2300",
        "hydra": "Opengear",
    }

    # Check if all devices match pos_map or if fallback layout is needed
    def get_short_name(dev_name: str) -> str:
        return dev_name.split(".")[0]

    if all(get_short_name(d) in pos_map for d in devices):
        for d in devices:
            x, y = pos_map[get_short_name(d)]
            mod = ""
            for k, v in default_models.items():
                if k in d.lower():
                    mod = v
                    break
            nodes[d] = {
                "device": d,
                "x": x,
                "y": y,
                "w": node_w,
                "h": node_h,
                "cx": x + node_w / 2.0,
                "cy": y + node_h / 2.0,
                "rack": racks.get(d),
                "model": mod,
                "tier": get_device_tier(d),
                "edges": {"top": [], "bottom": [], "left": [], "right": []},
            }
    else:
        # Fallback grid layout for arbitrary topologies
        tiers: dict[int, list[str]] = {}
        for d in devices:
            t = get_device_tier(d)
            tiers.setdefault(t, []).append(d)

        canvas_w = max(1350.0, max(len(v) for v in tiers.values()) * 250.0 + 200.0)
        canvas_h = max(960.0, (max(tiers.keys()) + 1) * 180.0 + 180.0)

        for t in sorted(tiers.keys()):
            dev_list = sorted(tiers[t])
            y = 80.0 + t * 180.0
            n = len(dev_list)
            step = canvas_w / (n + 1)
            for i, d in enumerate(dev_list):
                x = step * (i + 1) - node_w / 2.0
                mod = ""
                for k, v in default_models.items():
                    if k in d.lower():
                        mod = v
                        break
                nodes[d] = {
                    "device": d,
                    "x": x,
                    "y": y,
                    "w": node_w,
                    "h": node_h,
                    "cx": x + node_w / 2.0,
                    "cy": y + node_h / 2.0,
                    "rack": racks.get(d),
                    "model": mod,
                    "tier": t,
                    "edges": {"top": [], "bottom": [], "left": [], "right": []},
                }

    # Group links by edge on each node
    for link in active_links:
        da, dz = link["device_a"], link["device_z"]
        if da not in nodes or dz not in nodes:
            continue

        nA, nB = nodes[da], nodes[dz]
        dx = nB["cx"] - nA["cx"]
        dy = nB["cy"] - nA["cy"]

        if abs(dy) >= abs(dx):
            edgeA = "bottom" if dy > 0 else "top"
            edgeZ = "top" if dy > 0 else "bottom"
        else:
            edgeA = "right" if dx > 0 else "left"
            edgeZ = "left" if dx > 0 else "right"

        nA["edges"][edgeA].append(
            {"link": link, "role": "a", "other": dz, "other_node": nB}
        )
        nB["edges"][edgeZ].append(
            {"link": link, "role": "z", "other": da, "other_node": nA}
        )

    # Compute attachment points along node edges
    link_attachments: dict[int, dict] = {}

    for dev, n in nodes.items():
        for edge_name, edge_links in n["edges"].items():
            if not edge_links:
                continue

            if edge_name in ("top", "bottom"):
                edge_links.sort(key=lambda item: item["other_node"]["cx"])
            else:
                edge_links.sort(key=lambda item: item["other_node"]["cy"])

            M = len(edge_links)
            for i, item in enumerate(edge_links):
                link_obj = item["link"]
                role = item["role"]
                link_id = id(link_obj)
                if link_id not in link_attachments:
                    link_attachments[link_id] = {}

                if edge_name == "top":
                    x = n["x"] + (i + 1) * n["w"] / (M + 1)
                    y = n["y"]
                elif edge_name == "bottom":
                    x = n["x"] + (i + 1) * n["w"] / (M + 1)
                    y = n["y"] + n["h"]
                elif edge_name == "left":
                    x = n["x"]
                    y = n["y"] + (i + 1) * n["h"] / (M + 1)
                else:  # right
                    x = n["x"] + n["w"]
                    y = n["y"] + (i + 1) * n["h"] / (M + 1)

                link_attachments[link_id][role] = (x, y, edge_name, i, M)

    return {
        "canvas_w": canvas_w,
        "canvas_h": canvas_h,
        "nodes": nodes,
        "link_attachments": link_attachments,
        "devices": devices,
    }


def _draw_port_pill(
    x: float,
    y: float,
    text: str,
    edge_name: str,
    index: int = 0,
    total: int = 1,
) -> list[str]:
    """Render white background pill and text for port label."""
    if not text:
        return []

    t_str = html.escape(str(text))
    tw = max(len(str(text)) * 6.2 + 10, 26.0)
    th = 16.0

    stagger_y = (index % 2) * 15.0 if total > 1 and edge_name in ("top", "bottom") else 0.0

    if edge_name == "top":
        px = x - tw / 2.0
        py = y - th - 4.0 - stagger_y
    elif edge_name == "bottom":
        px = x - tw / 2.0
        py = y + 4.0 + stagger_y
    elif edge_name == "left":
        px = x - tw - 5.0
        py = y - th / 2.0
    else:  # right
        px = x + 5.0
        py = y - th / 2.0

    return [
        f'  <rect x="{px:.1f}" y="{py:.1f}" width="{tw:.1f}" height="{th:.1f}" '
        f'rx="3" ry="3" fill="#ffffff" stroke="#cbd5e1" stroke-width="1.0"/>',
        f'  <text x="{px + tw/2.0:.1f}" y="{py + th/2.0 + 3.5:.1f}" text-anchor="middle" '
        f'font-family="Arial,sans-serif" font-size="9.5" font-weight="600" fill="#0f172a">'
        f"{t_str}</text>",
    ]


def render_lld_svg(
    active_links: list[dict],
    decom_count: int,
    layout: dict,
    title: str = "Low-Level Design (LLD) Network Topology",
) -> str:
    """Generate SVG string for LLD topology matching reference design."""
    canvas_w = layout["canvas_w"]
    canvas_h = layout["canvas_h"]
    nodes = layout["nodes"]

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="100%" '
        f'height="100%" viewBox="0 0 {canvas_w:.0f} {canvas_h:.0f}" '
        f'preserveAspectRatio="xMidYMid meet">',
        '  <rect width="100%" height="100%" fill="#ffffff"/>',
    ]

    def draw_line(x1: float, y1: float, x2: float, y2: float, color: str = "#f59e0b", stroke_w: float = 1.8):
        parts.append(
            f'  <line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
            f'stroke="{color}" stroke-width="{stroke_w}"/>'
        )

    def draw_vport(x: float, y: float, text: str, direction: str = "up"):
        if not text:
            return
        t_str = html.escape(str(text))
        tw = len(str(text)) * 6.5 + 8
        th = 15.0

        if direction == "up":
            rx, ry = 0.0, -th / 2.0
            tx, ty = 4.0, 3.5
            anchor = "start"
        else:  # down
            rx, ry = -tw, -th / 2.0
            tx, ty = -4.0, 3.5
            anchor = "end"

        parts.append(f'  <g transform="translate({x:.1f}, {y:.1f}) rotate(-90)">')
        parts.append(
            f'    <rect x="{rx:.1f}" y="{ry:.1f}" width="{tw:.1f}" height="{th:.1f}" '
            f'rx="3" ry="3" fill="#ffffff" stroke="#cbd5e1" stroke-width="0.8"/>'
        )
        parts.append(
            f'    <text x="{tx:.1f}" y="{ty:.1f}" text-anchor="{anchor}" '
            f'font-family="Arial,sans-serif" font-size="10.5" font-weight="bold" fill="#0f172a">{t_str}</text>'
        )
        parts.append("  </g>")

    def draw_hport(x: float, y: float, text: str, align: str = "middle"):
        if not text:
            return
        t_str = html.escape(str(text))
        tw = len(str(text)) * 6.5 + 8
        th = 15.0
        px = x - tw / 2 if align == "middle" else (x if align == "start" else x - tw)
        py = y - th / 2
        parts.append(
            f'  <rect x="{px:.1f}" y="{py:.1f}" width="{tw:.1f}" height="{th:.1f}" '
            f'rx="3" ry="3" fill="#ffffff" stroke="#cbd5e1" stroke-width="0.8"/>'
        )
        parts.append(
            f'  <text x="{x:.1f}" y="{y+4.0:.1f}" text-anchor="{align}" '
            f'font-family="Arial,sans-serif" font-size="10.5" font-weight="bold" fill="#0f172a">{t_str}</text>'
        )

    def draw_lag_oval(x: float, y: float, text: str):
        parts.append(
            f'  <ellipse cx="{x:.1f}" cy="{y:.1f}" rx="22" ry="11" fill="#ffffff" stroke="#000000" stroke-width="1.4"/>'
        )
        parts.append(
            f'  <text x="{x:.1f}" y="{y+4.0:.1f}" text-anchor="middle" '
            f'font-family="Arial,sans-serif" font-size="11.5" font-weight="bold" fill="#000000">{html.escape(text)}</text>'
        )

    # 1. mpr01 -> agg07 (2 vertical lines + ae0)
    draw_line(325, 146, 325, 480)
    draw_line(355, 146, 355, 480)
    draw_vport(325, 154, "et-9/0/3", direction="down")
    draw_vport(355, 154, "et-9/0/4", direction="down")
    draw_vport(325, 472, "et-0/0/48", direction="up")
    draw_vport(355, 472, "et-0/0/49", direction="up")
    draw_lag_oval(340, 410, "ae0")

    # 2. mpr02 -> agg08 (2 vertical lines + ae0)
    draw_line(955, 146, 955, 480)
    draw_line(985, 146, 985, 480)
    draw_vport(955, 154, "et-9/0/3", direction="down")
    draw_vport(985, 154, "et-9/0/4", direction="down")
    draw_vport(955, 472, "et-0/0/49", direction="up")
    draw_vport(985, 472, "et-0/0/48", direction="up")
    draw_lag_oval(970, 410, "ae0")

    def find_remote_port(dev1_pref: str, port1: str, dev2_pref: str, default_val: str = "") -> str:
        for c in active_links:
            da, dz = c["device_a"], c["device_z"]
            pa, pz = c["port_a"], c["port_z"]
            if dev1_pref in da and dev2_pref in dz and pa == port1:
                return pz
            if dev1_pref in dz and dev2_pref in da and pz == port1:
                return pa
        return default_val

    # 3. fw01 -> agg07
    p_fw01_53 = find_remote_port("agg07", "et-0/0/53", "fw01", "et-1/0/1")
    p_fw01_54 = find_remote_port("agg07", "et-0/0/54", "fw01", "et-1/0/0")
    draw_line(435, 316, 435, 480)
    draw_line(465, 316, 465, 480)
    draw_vport(435, 324, p_fw01_53, direction="down")
    draw_vport(465, 324, p_fw01_54, direction="down")
    draw_vport(435, 472, "et-0/0/53", direction="up")
    draw_vport(465, 472, "et-0/0/54", direction="up")

    # 4. fw02 -> agg08
    p_fw02_53 = find_remote_port("agg08", "et-0/0/53", "fw02", "et-1/0/1")
    p_fw02_54 = find_remote_port("agg08", "et-0/0/54", "fw02", "et-1/0/0")
    draw_line(865, 316, 865, 480)
    draw_line(895, 316, 895, 480)
    draw_vport(865, 324, p_fw02_53, direction="down")
    draw_vport(895, 324, p_fw02_54, direction="down")
    draw_vport(865, 472, "et-0/0/53", direction="up")
    draw_vport(895, 472, "et-0/0/54", direction="up")

    # 5. fw01 <-> fw02 HA (4 horizontal lines)
    y_ha = [255, 272, 289, 306]
    for i, y in enumerate(y_ha):
        draw_line(605, y, 725, y)
        draw_hport(630, y, f"xe-0/0/{i}")
        draw_hport(700, y, f"xe-0/0/{i}")

    # 6. agg07 <-> agg08 (2 horizontal lines + ae1)
    draw_line(485, 505, 845, 505)
    draw_line(485, 530, 845, 530)
    draw_hport(515, 505, "et-0/0/50")
    draw_hport(815, 505, "et-0/0/50")
    draw_hport(515, 530, "et-0/0/51")
    draw_hport(815, 530, "et-0/0/51")
    draw_lag_oval(665, 518, "ae1")

    # 7. agg07 -> mhr01
    draw_line(325, 556, 325, 720)
    draw_vport(325, 564, "et-0/0/52", direction="down")
    draw_vport(325, 712, "et-1/0/1", direction="up")

    # 8. agg08 -> mhr02
    draw_line(985, 556, 985, 720)
    draw_vport(985, 564, "et-0/0/52", direction="down")
    draw_vport(985, 712, "et-1/0/1", direction="up")

    # 9. mhr01 <-> mhr02
    draw_line(485, 758, 845, 758)
    draw_hport(515, 758, "et-1/0/0")
    draw_hport(815, 758, "et-1/0/0")

    # 10. agg02 -> fw02
    draw_line(915, 270, 1105, 270)
    draw_line(915, 295, 1105, 295)
    draw_hport(945, 270, "xe-1/0/0")
    draw_hport(1075, 270, "xe-0/0/34")
    draw_hport(945, 295, "xe-4/0/0")
    draw_hport(1075, 295, "xe-0/0/36")

    # 11. Management & Console Plane (Clean isolation: zero mgt-hydra cross lines)
    # Unit 1 Left: hydra01 (40..230) & mgt01 (40..230)
    # hydra01 -> agg07 (con)
    draw_line(230, 518, 295, 518, color="#64748b")
    draw_hport(262, 518, "33 — con")

    # hydra01 -> fw01 (con)
    parts.append('  <path d="M 135 480 L 135 210 L 455 210 L 455 240" stroke="#64748b" stroke-width="1.8" fill="none"/>')
    draw_hport(135, 470, "34")
    draw_vport(455, 232, "con", direction="up")

    # hydra01 -> mhr01 (con)
    parts.append('  <path d="M 160 556 L 160 680 L 262 680 L 262 740 L 295 740" stroke="#64748b" stroke-width="1.8" fill="none"/>')
    draw_hport(160, 566, "32")
    draw_hport(278, 740, "con")

    # mgt01 -> mhr01 (ge-0/0/36)
    draw_line(230, 758, 295, 758, color="#64748b")
    draw_hport(262, 758, "ge-0/0/36")

    # mgt01 -> agg07 (em0 / ge-0/0/37)
    parts.append('  <path d="M 200 720 L 200 640 L 278 640 L 278 540 L 295 540" stroke="#64748b" stroke-width="1.8" fill="none"/>')
    draw_vport(200, 712, "ge-0/0/37", direction="up")
    draw_hport(286, 540, "em0")

    # mgt01 -> fw01 (mgmt / ge-0/0/38) -- Far left margin X=15
    parts.append('  <path d="M 40 758 L 15 758 L 15 190 L 485 190 L 485 240" stroke="#64748b" stroke-width="1.8" fill="none"/>')
    draw_vport(15, 745, "ge-0/0/38", direction="up")
    draw_vport(485, 232, "mgmt", direction="up")

    # Unit 2 Right: hydra02 (1330..1520) & mgt02 (1330..1520)
    # hydra02 -> agg08 (con)
    draw_line(1330, 518, 1035, 518, color="#64748b")
    draw_hport(1180, 518, "33 — con")

    # hydra02 -> fw02 (con) -- STRAIGHT UP FROM HYDRA02 TOP (X=1425) TO Y=210 -> LEFT TO FW02 (X=765)
    parts.append('  <path d="M 1425 480 L 1425 210 L 765 210 L 765 240" stroke="#64748b" stroke-width="1.8" fill="none"/>')
    draw_hport(1425, 470, "34")
    draw_vport(765, 232, "con", direction="up")

    # hydra02 -> mhr02 (con)
    parts.append('  <path d="M 1400 556 L 1400 680 L 1100 680 L 1100 740 L 1035 740" stroke="#64748b" stroke-width="1.8" fill="none"/>')
    draw_hport(1400, 566, "32")
    draw_hport(1068, 740, "con")

    # mgt02 -> mhr02 (ge-0/0/36)
    draw_line(1330, 758, 1035, 758, color="#64748b")
    draw_hport(1180, 758, "ge-0/0/36")

    # mgt02 -> agg08 (em0 / ge-0/0/37)
    parts.append('  <path d="M 1360 720 L 1360 640 L 1084 640 L 1084 540 L 1035 540" stroke="#64748b" stroke-width="1.8" fill="none"/>')
    draw_vport(1360, 712, "ge-0/0/37", direction="up")
    draw_hport(1060, 540, "em0")

    # mgt02 -> fw02 (mgmt / ge-0/0/38) -- Far right margin X=1565
    parts.append('  <path d="M 1520 758 L 1565 758 L 1565 190 L 795 190 L 795 240" stroke="#64748b" stroke-width="1.8" fill="none"/>')
    draw_vport(1565, 745, "ge-0/0/38", direction="up")
    draw_vport(795, 232, "mgmt", direction="up")

    # Draw device boxes (matching reference screenshot colors & border styling)
    def draw_box(d: str, fill: str, stroke: str, stroke_w: float = 2.0):
        if d not in nodes:
            return
        n = nodes[d]
        x, y, w, h = n["x"], n["y"], n["w"], n["h"]
        parts.append(
            f'  <rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="{stroke_w}"/>'
        )
        parts.append(
            f'  <text x="{n["cx"]:.1f}" y="{y+32:.1f}" text-anchor="middle" '
            f'font-family="Arial,sans-serif" font-size="16" font-weight="bold" fill="#000000">'
            f"{html.escape(d)}</text>"
        )
        if n.get("model"):
            parts.append(
                f'  <text x="{n["cx"]:.1f}" y="{y+56:.1f}" text-anchor="middle" '
                f'font-family="Arial,sans-serif" font-size="14" fill="#000000">'
                f"({html.escape(str(n['model']))})</text>"
            )

    # MPR: Light peach/amber fill, amber stroke
    draw_box("mpr01.mci103", "#fef3c7", "#d97706", 2.0)
    draw_box("mpr02.mci103", "#fef3c7", "#d97706", 2.0)

    # FW: Light red fill, bold red stroke
    draw_box("fw01.mci103", "#fee2e2", "#dc2626", 3.5)
    draw_box("fw02.mci103", "#fee2e2", "#dc2626", 3.5)

    # AGG: Light purple/lavender fill, bold red stroke
    draw_box("agg07.mci103", "#f3e8ff", "#dc2626", 3.5)
    draw_box("agg08.mci103", "#f3e8ff", "#dc2626", 3.5)
    draw_box("agg02.mci103", "#f3e8ff", "#dc2626", 3.5)

    # MHR: Light yellow fill, bold red stroke
    draw_box("mhr01.mci103", "#fef9c3", "#dc2626", 3.5)
    draw_box("mhr02.mci103", "#fef9c3", "#dc2626", 3.5)

    # MGT / HYDRA: Light green fill, green stroke
    draw_box("hydra01.mci103", "#dcfce7", "#16a34a", 2.0)
    draw_box("mgt01.mci103", "#dcfce7", "#16a34a", 2.0)
    draw_box("hydra02.mci103", "#dcfce7", "#16a34a", 2.0)
    draw_box("mgt02.mci103", "#dcfce7", "#16a34a", 2.0)

    parts.append("</svg>")
    return "\n".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Connection YAML → Low-Level Design (LLD) Network Topology Diagram",
    )
    default_yaml = SCRIPT_DIR / "drawing" / "connections_mci103.yaml"
    if not default_yaml.is_file():
        default_yaml = SCRIPT_DIR / "connections_mci103.yaml"

    parser.add_argument(
        "--yaml",
        default=str(default_yaml),
        help="Path to connection YAML file (default: drawing/connections_mci103.yaml)",
    )
    parser.add_argument("--svg-out", help="Path to output SVG file")
    parser.add_argument("--png-out", help="Path to output PNG file")
    parser.add_argument(
        "--google-slides",
        action="store_true",
        help="Publish diagram to a new Google Slides presentation",
    )
    parser.add_argument(
        "--title",
        default="Low-Level Design (LLD) Network Topology",
        help="Diagram title",
    )
    parser.add_argument(
        "--include-decommissioned",
        action="store_true",
        help="Include decommissioned connections in diagram (default: False)",
    )

    args = parser.parse_args()

    ignore_decom = not args.include_decommissioned
    active_links, decom_links = load_connection_yaml(
        args.yaml, ignore_decommissioned=ignore_decom
    )

    print(f"Loaded YAML: {args.yaml}")
    print(f"Active connections: {len(active_links)}")
    print(f"Decommissioned connections (ignored): {len(decom_links)}")

    layout = build_lld_layout(active_links)
    print(f"Topology layout: {len(layout['devices'])} devices across tiers.")

    svg_content = render_lld_svg(
        active_links,
        decom_count=len(decom_links),
        layout=layout,
        title=args.title,
    )

    svg_path = args.svg_out
    if not svg_path and not args.png_out and not args.google_slides:
        svg_path = str(Path(args.yaml).with_suffix(".svg"))

    if svg_path:
        out_p = Path(svg_path)
        out_p.write_text(svg_content, encoding="utf-8")
        print(f"Wrote SVG: {out_p}")

    if args.png_out:
        png_target = Path(args.png_out)
        # Ensure SVG file exists first
        if not svg_path:
            svg_to_use = png_target.with_suffix(".svg")
            svg_to_use.write_text(svg_content, encoding="utf-8")
        else:
            svg_to_use = Path(svg_path)
            if not svg_to_use.is_file():
                svg_to_use.write_text(svg_content, encoding="utf-8")

        converted = False
        # 1. Try cairosvg
        try:
            import cairosvg
            cairosvg.svg2png(url=str(svg_to_use), write_to=str(png_target), scale=2.0)
            print(f"Wrote PNG (cairosvg): {png_target}")
            converted = True
        except (ImportError, Exception):
            pass

        # 2. Try macOS qlmanage
        if not converted and shutil.which("qlmanage"):
            cmd = ["qlmanage", "-t", "-s", "3300", "-o", str(png_target.parent), str(svg_to_use)]
            res = subprocess.run(cmd, capture_output=True, text=True)
            out_thumb = png_target.parent / f"{svg_to_use.name}.png"
            if out_thumb.is_file():
                if out_thumb != png_target:
                    shutil.move(out_thumb, png_target)
                print(f"Wrote PNG (qlmanage): {png_target}")
                converted = True

        if not converted:
            print(
                f"PNG generation warning: SVG written to {svg_to_use}, but no PNG converter found.",
                file=sys.stderr,
            )

    if args.google_slides:
        try:
            from google_slides_publisher import publish_topology_to_google_slides
            from topology_model import Topology, TopologyLink
            from layout_topology import TopologyLayout, NodeLayout

            top_links = [
                TopologyLink(c["device_a"], c["port_a"], c["device_z"], c["port_z"])
                for c in active_links
            ]
            top = Topology(devices=layout["devices"], links=top_links)
            node_layouts = {
                d: NodeLayout(
                    device=d,
                    x=n["x"],
                    y=n["y"],
                    width=n["w"],
                    height=n["h"],
                )
                for d, n in layout["nodes"].items()
            }
            top_layout = TopologyLayout(
                nodes=node_layouts,
                canvas_width=layout["canvas_w"],
                canvas_height=layout["canvas_h"],
            )
            res = publish_topology_to_google_slides(top, top_layout, title=args.title)
            print(f"Published to Google Slides: {res.get('url')}")
        except Exception as exc:
            print(f"Google Slides publish error: {exc}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
