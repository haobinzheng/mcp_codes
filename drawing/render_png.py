"""PNG export for Google Drawings (Insert → Image → Upload from computer)."""

from __future__ import annotations

from pathlib import Path

from layout_topology import TopologyLayout
from render_svg import render_topology_svg
from topology_model import Topology


def _write_topology_png_pillow(
    topology: Topology,
    layout: TopologyLayout,
    path: Path,
    *,
    scale: float = 2.0,
) -> None:
    from PIL import Image, ImageDraw, ImageFont

    w = int(layout.canvas_width * scale)
    h = int(layout.canvas_height * scale)
    img = Image.new("RGB", (w, h), "#fafafa")
    draw = ImageDraw.Draw(img)

    try:
        font = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial.ttf", int(14 * scale))
        small = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial.ttf", int(11 * scale))
    except OSError:
        font = ImageFont.load_default()
        small = font

    def pt(x: float, y: float) -> tuple[float, float]:
        return x * scale, y * scale

    for link in topology.links:
        a = layout.nodes[link.device_a]
        b = layout.nodes[link.device_b]
        draw.line(
            [pt(a.center_x, a.center_y), pt(b.center_x, b.center_y)],
            fill="#555555",
            width=max(1, int(2 * scale)),
        )
        label = f"{link.port_a} — {link.port_b}".strip(" —")
        if label:
            mx, my = (a.center_x + b.center_x) / 2, (a.center_y + b.center_y) / 2 - 10
            bbox = draw.textbbox((0, 0), label, font=small)
            tw = bbox[2] - bbox[0]
            draw.text(pt(mx - tw / 2, my), label, fill="#333333", font=small)

    radius = int(8 * scale)
    for node in layout.nodes.values():
        x0, y0 = pt(node.x, node.y)
        x1, y1 = pt(node.x + node.width, node.y + node.height)
        draw.rounded_rectangle(
            [x0, y0, x1, y1],
            radius=radius,
            fill="#e8f0fe",
            outline="#1a73e8",
            width=max(1, int(2 * scale)),
        )
        bbox = draw.textbbox((0, 0), node.device, font=font)
        tw = bbox[2] - bbox[0]
        th = bbox[3] - bbox[1]
        tx = node.center_x * scale - tw / 2
        ty = node.center_y * scale - th / 2
        draw.text((tx, ty), node.device, fill="#174ea6", font=font)

    img.save(path, format="PNG")


def write_topology_png(
    topology: Topology,
    layout: TopologyLayout,
    path: str | Path,
    *,
    scale: float = 2.0,
) -> Path:
    """Write PNG. Uses cairosvg when available; otherwise Pillow (no system cairo)."""
    path = Path(path)

    try:
        import cairosvg  # type: ignore[import-untyped]

        svg_bytes = render_topology_svg(topology, layout).encode("utf-8")
        cairosvg.svg2png(
            bytestring=svg_bytes,
            write_to=str(path),
            scale=scale,
        )
        return path
    except ImportError:
        pass
    except OSError:
        # libcairo missing on macOS without `brew install cairo`
        pass

    try:
        from PIL import Image  # noqa: F401
    except ImportError as exc:
        raise ImportError(
            "PNG export needs Pillow or cairosvg. Install with:\n"
            "  pip install pillow\n"
            "  # or: pip install cairosvg  (also needs system cairo on macOS)"
        ) from exc

    _write_topology_png_pillow(topology, layout, path, scale=scale)
    return path
