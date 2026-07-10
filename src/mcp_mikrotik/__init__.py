"""mcp-mikrotik: Model Context Protocol server for MikroTik RouterOS devices."""

from importlib.metadata import PackageNotFoundError, version

try:
    # Single source of truth: pyproject.toml's [project] version, read back
    # from the installed package's metadata. Keeps this file from ever
    # drifting out of sync with pyproject.toml again - a plain
    # `pip install -e .` (or a normal build) after a version bump is enough
    # for this to pick it up, with nothing to remember to edit twice.
    __version__ = version("mcp-mikrotik")
except PackageNotFoundError:  # pragma: no cover - only reachable when the
    # package is imported without being installed at all (e.g. a stray
    # sys.path hack); the test suite always runs against an installed
    # (editable) package, so this fallback is never exercised in CI.
    __version__ = "1.0.0"
