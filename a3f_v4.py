"""Compatibility entry point for the v4 command-line interface."""

from pathlib import Path
import importlib.util
import runpy
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

if __name__ == "__main__":
    runpy.run_path(str(ROOT / "src" / "a3f_v4.py"), run_name="__main__")
else:
    spec = importlib.util.spec_from_file_location("_a3f_v4_impl", ROOT / "src" / "a3f_v4.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.__name__ = __name__
    sys.modules[__name__] = module
    globals().update({name: value for name, value in vars(module).items() if not name.startswith("__")})
