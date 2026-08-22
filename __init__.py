"""Repository-root shim for native Hermes Git installs."""

from pathlib import Path
import sys


PLUGIN_ROOT = Path(__file__).resolve().parent
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))

from hermes_plugin import register  # noqa: E402

__all__ = ["register"]
