#!/usr/bin/env python3
"""Build a network topology diagram from YAML and publish to Google Workspace or image files.

Google Drawings has no public API and no File → Import menu. Practical paths:
  - --google-slides  : automated deck (editable shapes); copy/paste into Drawings if needed
  - --png-out        : raster image → Drawings: Insert → Image → Upload from computer
  - --svg-out        : for other tools; Drawings does not accept SVG directly

Examples:
  python publish_topology.py --yaml topology.yaml --png-out topology.png
  python publish_topology.py --yaml topology.yaml --google-slides --title "Lab topology"
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow running as `python drawing/publish_topology.py` from repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from layout_topology import layout_topology
from parse_topology_yaml import load_topology_yaml
from render_svg import write_topology_svg


DRAWINGS_HELP = """
Google Drawings (no Import under File):
  A) Editable shapes — use --google-slides, open the deck URL, select all (Ctrl/Cmd+A),
     copy, paste into a new drawing at https://docs.google.com/drawings/create
  B) Picture only — use --png-out, then in Drawings: Insert → Image → Upload from computer
  C) SVG is not supported natively in Drawings; use Slides path (A) or PNG (B).
"""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Topology YAML → diagram (PNG / SVG / Google Slides)",
        epilog=DRAWINGS_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--yaml",
        default=str(Path(__file__).resolve().parent / "topology.yaml"),
        help="Path to topology YAML (default: drawing/topology.yaml)",
    )
    parser.add_argument("--svg-out", help="Write SVG (not usable directly in Google Drawings)")
    parser.add_argument("--png-out", help="Write PNG for Drawings: Insert → Image → Upload")
    parser.add_argument(
        "--google-slides",
        action="store_true",
        help="Create a Google Slides presentation (closest automated Google option)",
    )
    parser.add_argument("--title", default="Network topology", help="Slides deck title")
    parser.add_argument(
        "--oauth-help",
        action="store_true",
        help="Print Google OAuth setup steps for --google-slides and exit",
    )
    args = parser.parse_args()

    if args.oauth_help:
        from google_slides_publisher import OAUTH_SETUP_HELP

        print(OAUTH_SETUP_HELP.strip())
        return 0

    topology = load_topology_yaml(args.yaml)
    layout = layout_topology(topology)

    print(f"Devices ({len(topology.devices)}): {', '.join(topology.devices)}")
    for link in topology.links:
        print(f"  {link.device_a} ({link.port_a}) — {link.device_b} ({link.port_b})")

    svg_path = args.svg_out
    if not svg_path and not args.google_slides and not args.png_out:
        svg_path = str(Path(args.yaml).with_suffix(".svg"))

    if args.png_out:
        from render_png import write_topology_png

        png_out = write_topology_png(topology, layout, args.png_out)
        print(f"\nWrote PNG: {png_out}")
        print("Google Drawings: Insert → Image → Upload from computer → choose this PNG")

    if svg_path:
        out = write_topology_svg(topology, layout, svg_path)
        print(f"Wrote SVG: {out} (for Inkscape/other tools; not for Drawings Import)")

    if args.google_slides:
        try:
            from google_slides_publisher import publish_topology_to_google_slides
        except ImportError as exc:
            print(
                "Missing Google Slides dependencies. Install with:\n"
                "  pip install google-api-python-client google-auth-oauthlib\n"
                "Or from repo root with venv:\n"
                "  .venv/bin/pip install -r requirements.txt",
                file=sys.stderr,
            )
            raise SystemExit(1) from exc

        result = publish_topology_to_google_slides(topology, layout, title=args.title)
        print("\nGoogle Slides (automated):")
        print(json.dumps(result, indent=2))
        print(
            "\nTo use in Google Drawings with editable shapes: open the URL above, "
            "select all, copy, paste into https://docs.google.com/drawings/create"
        )

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
