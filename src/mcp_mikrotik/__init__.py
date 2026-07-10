"""mcp-mikrotik: Model Context Protocol server for MikroTik RouterOS devices."""

from importlib.metadata import PackageNotFoundError, version

try:
    # Single source of truth: pyproject.toml's [project] version, read back
    # from the installed package's metadata. Keeps this file from ever
    # drifting out of sync with pyproject.toml again - a plain
    # `pip install -e .` (or a normal build) after a version bump is enough
    # for this to pick it up, with nothing to remember to edit twice.
    __version__ = version("mcp-mikrotik")
except PackageNotFoundError:
    # Fallback for the rare case this module is imported without the
    # package being installed at all (e.g. a stray `sys.path` hack) - never
    # raise just to report a version.
    __version__ = "1.0.0"
