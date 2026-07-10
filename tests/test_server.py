"""Server-level smoke tests: tool registration, and each tool's happy/error
paths driven through FastMCP's own call_tool (not by calling the plain
Python functions directly), against fake devices only.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from librouteros.exceptions import LibRouterosError
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
    "dhcp_leases",
    "wireless_registrations",
    "dns_cache",
    "firewall_filter",
    "system_health",
    "logs",
    "ping",
    "list_write_operations",
    "set_identity",
    "enable_interface",
    "disable_interface",
    "set_wifi_ssid",
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
async def test_dhcp_leases_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("dhcp_leases", {"device_name": "core-switch"})
    assert result["result"][0]["host-name"] == "laptop-1"


@pytest.mark.asyncio
async def test_dns_cache_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("dns_cache", {"device_name": "core-switch"})
    assert result["result"][0]["name"] == "example.com"


@pytest.mark.asyncio
async def test_firewall_filter_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("firewall_filter", {"device_name": "core-switch"})
    assert result["result"][0]["chain"] == "input"


@pytest.mark.asyncio
async def test_system_health_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("system_health", {"device_name": "core-switch"})
    names = {row["name"] for row in result["result"]}
    assert names == {"voltage", "temperature"}


@pytest.mark.asyncio
async def test_system_health_returns_empty_when_unsupported(settings: Settings):
    fake = FakeConnection(raise_for={("system", "health"): LibRouterosError("no such command")})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("system_health", {"device_name": "core-switch"})
    assert result["result"] == []


@pytest.mark.asyncio
async def test_wireless_registrations_ros7_happy_path(settings: Settings):
    fake = FakeConnection(
        data={
            ("interface", "wifi", "registration-table"): [
                {"mac-address": "AA:BB:CC:DD:EE:01", "signal-strength": "-55dBm", "interface": "wifi1", "uptime": "1h"}
            ]
        }
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("wireless_registrations", {"device_name": "core-switch"})
    assert result["result"][0]["interface"] == "wifi1"


@pytest.mark.asyncio
async def test_wireless_registrations_falls_back_to_ros6(settings: Settings):
    fake = FakeConnection(
        raise_for={("interface", "wifi", "registration-table"): LibRouterosError("no such command")},
        data={
            ("interface", "wireless", "registration-table"): [
                {"mac-address": "AA:BB:CC:DD:EE:02", "signal-strength": "-60", "interface": "wlan1", "uptime": "2h"}
            ]
        },
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("wireless_registrations", {"device_name": "core-switch"})
    assert result["result"][0]["interface"] == "wlan1"


@pytest.mark.asyncio
async def test_wireless_registrations_returns_empty_when_no_radio(settings: Settings):
    fake = FakeConnection(
        raise_for={
            ("interface", "wifi", "registration-table"): LibRouterosError("no such command"),
            ("interface", "wireless", "registration-table"): LibRouterosError("no such command"),
        }
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("wireless_registrations", {"device_name": "core-switch"})
    assert result["result"] == []


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


# --- enable_interface / disable_interface --------------------------------


@pytest.mark.asyncio
async def test_enable_interface_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "enable_interface", {"device_name": "core-switch", "interface_name": "ether2", "confirm": True}
        )
    assert "read-only" in str(exc_info.value)
    # Device was never touched.
    rows = {row["name"]: row["disabled"] for row in fake_connection.path("interface")._rows}
    assert rows == {"ether1": "false", "ether2": "true"}


@pytest.mark.asyncio
async def test_disable_interface_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "disable_interface", {"device_name": "core-switch", "interface_name": "ether1", "confirm": True}
        )
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_enable_interface_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "enable_interface", {"device_name": "core-switch", "interface_name": "ether2", "confirm": False}
    )
    assert preview["applied"] is False
    assert preview["before"]["disabled"] == "true"
    assert preview["after"]["disabled"] == "no"
    # Preview must not have touched the device.
    rows = {row["name"]: row["disabled"] for row in fake_connection.path("interface")._rows}
    assert rows["ether2"] == "true"

    _content, applied = await mcp.call_tool(
        "enable_interface", {"device_name": "core-switch", "interface_name": "ether2", "confirm": True}
    )
    assert applied["applied"] is True
    rows = {row["name"]: row["disabled"] for row in fake_connection.path("interface")._rows}
    assert rows == {"ether1": "false", "ether2": "no"}


@pytest.mark.asyncio
async def test_disable_interface_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, applied = await mcp.call_tool(
        "disable_interface", {"device_name": "core-switch", "interface_name": "ether1", "confirm": True}
    )
    assert applied["applied"] is True
    rows = {row["name"]: row["disabled"] for row in fake_connection.path("interface")._rows}
    assert rows == {"ether1": "yes", "ether2": "true"}


@pytest.mark.asyncio
async def test_enable_interface_unknown_interface_raises_clear_error(
    device: Device, fake_connection: FakeConnection
):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "enable_interface", {"device_name": "core-switch", "interface_name": "ghost0", "confirm": False}
        )
    assert "ghost0" in str(exc_info.value)
    # Nothing was created.
    names = {row["name"] for row in fake_connection.path("interface")._rows}
    assert names == {"ether1", "ether2"}


# --- set_wifi_ssid ---------------------------------------------------------


@pytest.mark.asyncio
async def test_set_wifi_ssid_blocked_read_only_by_default(settings: Settings):
    fake = FakeConnection(data={("interface", "wifi"): [{".id": "*1", "name": "wifi1", "ssid": "old-ssid"}]})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_wifi_ssid",
            {"device_name": "core-switch", "interface_name": "wifi1", "new_ssid": "new-ssid", "confirm": True},
        )
    assert "read-only" in str(exc_info.value)


@pytest.mark.asyncio
async def test_set_wifi_ssid_ros7_preview_then_confirm(device: Device):
    fake = FakeConnection(data={("interface", "wifi"): [{".id": "*1", "name": "wifi1", "ssid": "old-ssid"}]})
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, preview = await mcp.call_tool(
        "set_wifi_ssid",
        {"device_name": "core-switch", "interface_name": "wifi1", "new_ssid": "new-ssid", "confirm": False},
    )
    assert preview["applied"] is False
    assert preview["operation"] == "set_wifi_ssid_ros7"
    assert fake.path("interface", "wifi")._rows[0]["ssid"] == "old-ssid"

    _content, applied = await mcp.call_tool(
        "set_wifi_ssid",
        {"device_name": "core-switch", "interface_name": "wifi1", "new_ssid": "new-ssid", "confirm": True},
    )
    assert applied["applied"] is True
    assert fake.path("interface", "wifi")._rows[0]["ssid"] == "new-ssid"


@pytest.mark.asyncio
async def test_set_wifi_ssid_falls_back_to_ros6_when_ros7_path_unsupported(device: Device):
    fake = FakeConnection(
        raise_for={("interface", "wifi"): LibRouterosError("no such command")},
        data={("interface", "wireless"): [{".id": "*1", "name": "wlan1", "ssid": "old-ssid"}]},
    )
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, applied = await mcp.call_tool(
        "set_wifi_ssid",
        {"device_name": "core-switch", "interface_name": "wlan1", "new_ssid": "new-ssid", "confirm": True},
    )
    assert applied["applied"] is True
    assert applied["operation"] == "set_wifi_ssid_ros6"
    assert fake.path("interface", "wireless")._rows[0]["ssid"] == "new-ssid"


@pytest.mark.asyncio
async def test_set_wifi_ssid_unknown_interface_raises_clear_error(device: Device):
    fake = FakeConnection(data={("interface", "wifi"): [{".id": "*1", "name": "wifi1", "ssid": "old-ssid"}]})
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_wifi_ssid",
            {"device_name": "core-switch", "interface_name": "ghost-radio", "new_ssid": "x", "confirm": False},
        )
    assert "ghost-radio" in str(exc_info.value)


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
