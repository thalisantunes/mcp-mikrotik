"""Server-level smoke tests: tool registration, and each tool's happy/error
paths driven through FastMCP's own call_tool (not by calling the plain
Python functions directly), against fake devices only.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from mcp_mikrotik.client import MikrotikClient
from mcp_mikrotik.config import Device, Settings
from mcp_mikrotik.server import _resolve_log_level, build_server

from .fakes import FakeConnection, RaisingConnection

EXPECTED_TOOLS = {
    "list_devices",
    "system_info",
    "interfaces",
    "ip_addresses",
    "ip_routes",
    "neighbors",
    "logs",
    "ping",
    "list_write_operations",
    "set_identity",
}


def _factory(fake_connection: FakeConnection):
    def factory(settings: Settings, device_name: str) -> MikrotikClient:
        device = settings.get_device(device_name)
        return MikrotikClient(device, connection=fake_connection)

    return factory


@pytest.mark.asyncio
async def test_all_expected_tools_are_registered(settings: Settings):
    mcp = build_server(settings=settings, client_factory=lambda s, n: None)
    tools = await mcp.list_tools()
    assert {t.name for t in tools} == EXPECTED_TOOLS


@pytest.mark.asyncio
async def test_list_devices_never_exposes_password(settings: Settings):
    mcp = build_server(settings=settings, client_factory=lambda s, n: None)
    _content, result = await mcp.call_tool("list_devices", {})
    assert "password" not in result["result"][0]
    assert "s3cret" not in str(result)


@pytest.mark.asyncio
async def test_system_info_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("system_info", {"device_name": "core-switch"})
    assert result["identity"] == {"name": "MikroTik"}
    assert result["resource"]["board-name"] == "hAP ac2"


@pytest.mark.asyncio
async def test_interfaces_filters_disabled_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("interfaces", {"device_name": "core-switch"})
    names = {row["name"] for row in result["result"]}
    assert names == {"ether1"}

    _content, result_all = await mcp.call_tool(
        "interfaces", {"device_name": "core-switch", "include_disabled": True}
    )
    names_all = {row["name"] for row in result_all["result"]}
    assert names_all == {"ether1", "ether2"}


@pytest.mark.asyncio
async def test_unknown_device_returns_clean_error_not_a_crash(settings: Settings):
    mcp = build_server(settings=settings, client_factory=lambda s, n: s.get_device(n))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("system_info", {"device_name": "ghost"})
    assert "ghost" in str(exc_info.value)


@pytest.mark.asyncio
async def test_ping_rejects_invalid_address_before_touching_device(settings: Settings):
    mcp = build_server(
        settings=settings,
        client_factory=lambda s, n: MikrotikClient(s.get_device(n), connection=RaisingConnection()),
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("ping", {"device_name": "core-switch", "address": "8.8.8.8; reboot"})
    assert "not a valid" in str(exc_info.value)


@pytest.mark.asyncio
async def test_ping_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("ping", {"device_name": "core-switch", "address": "8.8.8.8"})
    assert result["result"][0]["host"] == "8.8.8.8"


@pytest.mark.asyncio
async def test_set_identity_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_identity", {"device_name": "core-switch", "new_name": "renamed", "confirm": True}
        )
    assert "read-only" in str(exc_info.value)
    # Device was never touched.
    assert fake_connection.path("system", "identity")._rows == [{"name": "MikroTik"}]


@pytest.mark.asyncio
async def test_set_identity_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "set_identity", {"device_name": "core-switch", "new_name": "renamed", "confirm": False}
    )
    assert preview["applied"] is False
    assert fake_connection.path("system", "identity")._rows == [{"name": "MikroTik"}]

    _content, applied = await mcp.call_tool(
        "set_identity", {"device_name": "core-switch", "new_name": "renamed", "confirm": True}
    )
    assert applied["applied"] is True
    assert fake_connection.path("system", "identity")._rows == [{"name": "renamed"}]


# --- D3: list_write_operations surfaces guard.ALLOWLIST metadata ---------


@pytest.mark.asyncio
async def test_list_write_operations_exposes_allowlist_metadata(settings: Settings):
    mcp = build_server(settings=settings, client_factory=lambda s, n: None)
    _content, result = await mcp.call_tool("list_write_operations", {})
    rows = result["result"]
    entry = next(row for row in rows if row["name"] == "set_identity")
    assert entry["path"] == "system/identity"
    assert entry["action"] == "update"
    assert "identity" in entry["description"].lower()


@pytest.mark.asyncio
async def test_list_write_operations_does_not_require_write_enabled(settings: Settings):
    """Read-only metadata tool: must work even with MIKROTIK_ALLOW_WRITE=false."""
    assert settings.allow_write is False
    mcp = build_server(settings=settings, client_factory=lambda s, n: None)
    _content, result = await mcp.call_tool("list_write_operations", {})
    assert result["result"]


# --- R3: limit/count <= 0 must raise a validation error, not clamp -------


@pytest.mark.asyncio
async def test_logs_rejects_non_positive_limit(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("logs", {"device_name": "core-switch", "limit": 0})
    assert "positive" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_ping_rejects_non_positive_count(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("ping", {"device_name": "core-switch", "address": "8.8.8.8", "count": -1})
    assert "positive" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_ip_routes_rejects_non_positive_limit(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("ip_routes", {"device_name": "core-switch", "limit": 0})
    assert "positive" in str(exc_info.value).lower()


# --- R2: ip_routes accepts an optional limit, mirroring logs -------------


@pytest.mark.asyncio
async def test_ip_routes_without_limit_returns_all_rows(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("ip_routes", {"device_name": "core-switch"})
    assert len(result["result"]) == 1


@pytest.mark.asyncio
async def test_ip_routes_limit_caps_returned_rows(settings: Settings):
    fake = FakeConnection(
        data={
            ("ip", "route"): [
                {".id": "*1", "dst-address": "0.0.0.0/0"},
                {".id": "*2", "dst-address": "10.0.0.0/24"},
                {".id": "*3", "dst-address": "192.168.0.0/24"},
            ]
        }
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("ip_routes", {"device_name": "core-switch", "limit": 2})
    assert len(result["result"]) == 2


# --- A2: meta-test - server.py must never call a write primitive directly.
# The guard (guard.py) is the only place allowed to call
# MikrotikClient.update()/add()/remove(); server.py must always go through a
# named guard.py function instead. This makes that invariant self-enforcing
# instead of a convention a future PR could silently break. -----------------


def test_server_never_calls_write_primitives_directly():
    server_src = (Path(__file__).resolve().parent.parent / "src" / "mcp_mikrotik" / "server.py").read_text(
        encoding="utf-8"
    )
    forbidden = re.compile(r"\.(update|add|remove)\(")
    match = forbidden.search(server_src)
    assert match is None, (
        f"server.py contains a direct write-primitive call ({match.group() if match else ''!r}) - "
        "every write must go through a dedicated function in guard.py instead "
        "(see guard.py's module docstring)."
    )


# --- E4: MIKROTIK_LOG_LEVEL validation, fallback to INFO with a warning --


@pytest.mark.parametrize("raw,expected", [("DEBUG", "DEBUG"), ("debug", "DEBUG"), ("warning", "WARNING")])
def test_resolve_log_level_accepts_valid_values(raw: str, expected: str):
    assert _resolve_log_level(raw) == expected


def test_resolve_log_level_defaults_to_info_when_unset():
    assert _resolve_log_level(None) == "INFO"


def test_resolve_log_level_falls_back_to_info_on_invalid_value(caplog: pytest.LogCaptureFixture):
    with caplog.at_level("WARNING", logger="mcp_mikrotik"):
        result = _resolve_log_level("NOT_A_LEVEL")
    assert result == "INFO"
    assert any("Invalid MIKROTIK_LOG_LEVEL" in record.message for record in caplog.records)
