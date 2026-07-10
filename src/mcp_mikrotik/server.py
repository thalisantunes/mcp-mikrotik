"""MCP server entrypoint.

Registers the v0 read tools plus the single exemplary write tool
(set_identity). Transport is stdio only for v0 - this process is meant to
run on the operator's own machine, launched by an MCP client (e.g. Claude
Code) over stdio, with no network exposure at all.

TODO(http-transport): if a streamable-http transport is added later, it
MUST default to binding 127.0.0.1 (never 0.0.0.0) and MUST require a bearer
token supplied via an environment variable, checked on every request. Do not
add HTTP transport without both of those in place.
"""

from __future__ import annotations

import contextlib
import functools
import logging
import os
from dataclasses import asdict
from typing import Any, AsyncIterator

from mcp.server.fastmcp import FastMCP

from . import guard
from .client import ClientFactory, ClientPool, MikrotikClient, get_client
from .config import Settings, load_settings
from .exceptions import MikrotikMCPError
from .formatting import filter_disabled, rows_to_list
from .validation import validate_ping_address, validate_positive_limit

logger = logging.getLogger("mcp_mikrotik")

DEFAULT_LOG_LIMIT = 50
MAX_LOG_LIMIT = 500
DEFAULT_PING_COUNT = 4
MAX_PING_COUNT = 20
MAX_ROUTE_LIMIT = 500

_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_DEFAULT_LOG_LEVEL = "INFO"


def build_server(settings: Settings | None = None, client_factory: ClientFactory = get_client) -> FastMCP:
    """Build the FastMCP server and register every tool.

    `settings` and `client_factory` are injectable so tests can run the
    exact tool functions registered here against a fake device layer,
    without touching environment variables or a real router.
    """
    settings = settings or load_settings()
    # N2+N3: one MikrotikClient (and its underlying connection) per device
    # name, reused across tool calls instead of reconnecting every time, and
    # closed deterministically by the lifespan hook below rather than
    # leaking sockets until GC - see client.ClientPool's docstring.
    pool = ClientPool(settings, client_factory)

    @contextlib.asynccontextmanager
    async def _lifespan(_server: FastMCP) -> AsyncIterator[dict[str, Any]]:
        try:
            yield {}
        finally:
            pool.close_all()

    mcp = FastMCP("mikrotik", lifespan=_lifespan)

    def _client(device_name: str) -> MikrotikClient:
        return pool.get(device_name)

    def _safe(fn):
        """Make sure nothing unexpected leaks a raw traceback or a secret.

        Deliberately re-raises rather than returning an error dict: each
        tool's return type is annotated (e.g. `list[dict[str, Any]]`) and
        FastMCP validates successful results against that schema, so an
        error path can't return a different shape without tripping output
        validation. Letting a clean exception propagate instead lets
        FastMCP/MCP's own error path turn it into a proper isError tool
        result carrying just the exception's message - see
        MikrotikMCPError subclasses in exceptions.py, whose messages are
        already safe to show a caller.

        Uses functools.wraps (not just __name__/__doc__) so FastMCP's schema
        introspection - which follows __wrapped__ - still sees the original
        function's parameter names/types instead of a generic (*args, **kwargs).
        """

        @functools.wraps(fn)
        def inner(*args: Any, **kwargs: Any) -> Any:
            try:
                return fn(*args, **kwargs)
            except MikrotikMCPError:
                raise
            except Exception:
                logger.exception("Unhandled error in tool %s", fn.__name__)
                raise RuntimeError("Internal error handling this tool call; see server logs.") from None

        return inner

    # --- Read tools ---------------------------------------------------

    @mcp.tool()
    @_safe
    def list_devices() -> list[dict[str, Any]]:
        """List configured MikroTik devices. Read-only; passwords are never included."""
        return [device.to_public_dict() for device in settings.devices.values()]

    @mcp.tool()
    @_safe
    def system_info(device_name: str) -> dict[str, Any]:
        """Get RouterOS identity + resource info (board, version, uptime, CPU/memory)."""
        client = _client(device_name)
        identity = client.path("system", "identity")
        resource = client.path("system", "resource")
        return {
            "identity": identity[0] if identity else {},
            "resource": resource[0] if resource else {},
        }

    @mcp.tool()
    @_safe
    def interfaces(device_name: str, include_disabled: bool = False) -> list[dict[str, Any]]:
        """List network interfaces on a device."""
        client = _client(device_name)
        return filter_disabled(client.path("interface"), include_disabled)

    @mcp.tool()
    @_safe
    def ip_addresses(device_name: str) -> list[dict[str, Any]]:
        """List IPv4 addresses configured on a device."""
        client = _client(device_name)
        return rows_to_list(client.path("ip", "address"))

    @mcp.tool()
    @_safe
    def ip_routes(device_name: str, limit: int | None = None) -> list[dict[str, Any]]:
        """List the IPv4 routing table of a device.

        `limit`, if given, caps the number of rows returned (capped at 500);
        omit it to get the full table, mirroring `logs`' `limit` parameter.
        """
        client = _client(device_name)
        rows = rows_to_list(client.path("ip", "route"))
        if limit is not None:
            capped_limit = validate_positive_limit(limit, MAX_ROUTE_LIMIT, "limit")
            rows = rows[:capped_limit]
        return rows

    @mcp.tool()
    @_safe
    def neighbors(device_name: str) -> list[dict[str, Any]]:
        """List neighbors discovered via RouterOS neighbor discovery (CDP/MNDP/LLDP)."""
        client = _client(device_name)
        return rows_to_list(client.path("ip", "neighbor"))

    @mcp.tool()
    @_safe
    def logs(device_name: str, limit: int = DEFAULT_LOG_LIMIT, topics: str | None = None) -> list[dict[str, Any]]:
        """Read recent RouterOS log entries (most recent last).

        `limit` must be positive and is capped at 500. `topics`, if given, is
        matched as a plain substring against each entry's topics field - no
        regex, no unbounded scans - and is applied BEFORE the `limit` cut:
        the full log is filtered by `topics` first, then the last `limit`
        matching entries are returned (not the last `limit` raw entries,
        then filtered - that would silently drop matches).

        R1: this reads the whole `/log` table via librouteros' path().select()
        and slices in Python rather than asking RouterOS for only the last
        `limit` rows. librouteros' structured API doesn't expose a clean
        "give me only the tail" query for /log (RouterOS's own count-only
        print flags aren't reachable through path().select() the way a
        `.limit()`/offset would be), so a "request fewer rows" optimization
        here would mean building a fragile ad-hoc workaround for a table
        that is small in practice (a few hundred to low thousands of rows on
        RouterOS's own ring buffer). Left as-is; revisit if a real device
        turns out to have a much larger log buffer than expected.
        """
        client = _client(device_name)
        capped_limit = validate_positive_limit(limit, MAX_LOG_LIMIT, "limit")
        rows = rows_to_list(client.path("log"))
        if topics:
            rows = [row for row in rows if topics in row.get("topics", "")]
        return rows[-capped_limit:]

    @mcp.tool()
    @_safe
    def ping(device_name: str, address: str, count: int = DEFAULT_PING_COUNT) -> list[dict[str, Any]]:
        """Ping an address from a device. `address` must be a valid IPv4/IPv6 address or hostname."""
        validated_address = validate_ping_address(address)
        capped_count = validate_positive_limit(count, MAX_PING_COUNT, "count")
        client = _client(device_name)
        return client.ping(validated_address, count=capped_count)

    @mcp.tool()
    @_safe
    def list_write_operations() -> list[dict[str, Any]]:
        """List every guarded write operation and the RouterOS path/action it maps to.

        Read-only: this only surfaces guard.ALLOWLIST's metadata (D3) - it
        does not perform or preview a write, and is not gated by
        MIKROTIK_ALLOW_WRITE.
        """
        return [
            {
                "name": op.name,
                "path": "/".join(op.path),
                "action": op.action,
                "description": op.description,
            }
            for op in guard.ALLOWLIST.values()
        ]

    # --- Write tools ---------------------------------------------------
    # Every write tool must call a dedicated function in guard.py - never
    # MikrotikClient.update/add/remove directly. See guard.py's module
    # docstring for how to add the next one.

    @mcp.tool()
    @_safe
    def set_identity(device_name: str, new_name: str, confirm: bool = False) -> dict[str, Any]:
        """Set a device's RouterOS identity (hostname).

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it.
        """
        client = _client(device_name)
        preview = guard.set_identity(client, settings, new_name=new_name, confirm=confirm)
        return asdict(preview)

    return mcp


def _resolve_log_level(raw: str | None) -> str:
    """Validate MIKROTIK_LOG_LEVEL against Python logging's level names (E4).

    An invalid value used to be passed straight to logging.basicConfig(),
    which raises ValueError and crashes the server before it even starts.
    Falls back to INFO (with a warning) instead.
    """
    level = (raw or _DEFAULT_LOG_LEVEL).strip().upper()
    if level not in _VALID_LOG_LEVELS:
        logger.warning(
            "Invalid MIKROTIK_LOG_LEVEL %r; falling back to %s. Valid values: %s",
            raw,
            _DEFAULT_LOG_LEVEL,
            ", ".join(sorted(_VALID_LOG_LEVELS)),
        )
        return _DEFAULT_LOG_LEVEL
    return level


def main() -> None:
    logging.basicConfig(level=_resolve_log_level(os.environ.get("MIKROTIK_LOG_LEVEL")))
    server = build_server()
    server.run()


if __name__ == "__main__":
    main()
