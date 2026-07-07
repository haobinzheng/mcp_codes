#!/usr/bin/env python3
"""Wrapper for draw_lld.py in drawing/ directory."""

import sys
from pathlib import Path

# Insert project root into sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from draw_lld import main

if __name__ == "__main__":
    raise SystemExit(main())
