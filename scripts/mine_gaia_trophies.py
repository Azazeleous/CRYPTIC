"""Shebang-free entry point for the GAIA/NEXUS local trophy solver."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.mining.trophy_solver import main


if __name__ == "__main__":
    raise SystemExit(main())
