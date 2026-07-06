"""Render topology to SVG (importable into Google Drawings: File → Import)."""

from __future__ import annotations

import html
from pathlib import Path

from layout_topology import TopologyLayout
from topology_model import Topology


def _svg_header(width: float, height: float) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" '
        f'height="{height:.0f}" viewBox="0 0 {width:.0f} {height:.0f}">'
    )


def render_topology_svg(topology: Topology, layout: TopologyLayout) -> str:
    parts = [
        _svg_header(layout.canvas_width, layout.canvas_height),
        '<defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">'
        '<polygon points="0 0, 8 3, 0 6" fill="#444"/></marker></defs>',
        '<rect width="100%" height="100%" fill="#fafafa"/>',
    ]

    for link in topology.links:
        a = layout.nodes[link.device_a]
        b = layout.nodes[link.device_b]
        x1, y1 = a.center_x, a.center_y
        x2, y2 = b.center_x, b.center_y
        parts.append(
            f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
            f'stroke="#555" stroke-width="2"/>'
        )
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2 - 10
        label = html.escape(f"{link.port_a} — {link.port_b}".strip(" —"))
        if label:
            parts.append(
                f'<text x="{mx:.1f}" y="{my:.1f}" text-anchor="middle" '
                f'font-family="Arial,sans-serif" font-size="11" fill="#333">{label}</text>'
            )

    for node in layout.nodes.values():
        parts.append(
            f'<rect x="{node.x:.1f}" y="{node.y:.1f}" width="{node.width:.1f}" '
            f'height="{node.height:.1f}" rx="8" ry="8" fill="#e8f0fe" stroke="#1a73e8" stroke-width="2"/>'
        )
        parts.append(
            f'<text x="{node.center_x:.1f}" y="{node.center_y + 5:.1f}" text-anchor="middle" '
            f'font-family="Arial,sans-serif" font-size="14" font-weight="bold" fill="#174ea6">'
            f'{html.escape(node.device)}</text>'
        )

    parts.append("</svg>")
    return "\n".join(parts)


def write_topology_svg(topology: Topology, layout: TopologyLayout, path: str | Path) -> Path:
    path = Path(path)
    path.write_text(render_topology_svg(topology, layout), encoding="utf-8")
    return path
