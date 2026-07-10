"""Server-level smoke tests: tool registration, and each tool's happy/error
paths driven through FastMCP's own call_tool (not by calling the plain
Python functions directly), against fake devices only.
"""

from __future__ import annotations

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from mcp_mikrotik.client import MikrotikClient
from mcp_mikrotik.config import Device, Settings
from mcp_mikrotik.server import build_server

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
