
import sys
from pathlib import Path

_PM_DIR = str(Path(__file__).resolve().parent)
if _PM_DIR not in sys.path:
    sys.path.insert(0, _PM_DIR)

from .manager import PluginManager

__all__ = [
    "PluginManager"
]