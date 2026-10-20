"""Compatibility entry point for the local witness service."""

from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))
runpy.run_path(str(ROOT / "src" / "remote_witness.py"), run_name="__main__")
