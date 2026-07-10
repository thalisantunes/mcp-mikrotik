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

from .fakes import FakeConnection, FakePath, RaisingConnection

EXPECTED_TOOLS = {
    "list_devices",
    "system_info",
    "interfaces",
    "ip_addresses",
    "ip_routes",
    "neighbors",
    "dhcp_leases",
    "simple_queues",
    "address_lists",
    "firewall_nat",
    "scheduler",
    "ip_pools",
    "wireless_registrations",
    "dns_cache",
    "firewall_filter",
    "system_health",
    "logs",
    "ping",
    "traceroute",
    "arp_table",
    "bridge_hosts",
    "interface_traffic",
    "poe_status",
    "list_write_operations",
    "set_identity",
    "enable_interface",
    "disable_interface",
    "set_wifi_ssid",
    "set_client_bandwidth",
    "add_static_dhcp_lease",
    "remove_simple_queue",
    "add_to_address_list",
    "remove_from_address_list",
    "set_poe_out",
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
async def test_simple_queues_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("simple_queues", {"device_name": "core-switch"})
    assert result["result"][0]["target"] == "10.0.0.50/32"
    assert result["result"][0]["max-limit"] == "10M/5M"


@pytest.mark.asyncio
async def test_address_lists_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("address_lists", {"device_name": "core-switch"})
    assert result["result"][0]["list"] == "blocked-clients"
    assert result["result"][0]["address"] == "10.0.0.60"


@pytest.mark.asyncio
async def test_firewall_nat_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("firewall_nat", {"device_name": "core-switch"})
    assert result["result"][0]["chain"] == "srcnat"
    assert result["result"][0]["action"] == "masquerade"


@pytest.mark.asyncio
async def test_scheduler_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("scheduler", {"device_name": "core-switch"})
    assert result["result"][0]["name"] == "backup-daily"


@pytest.mark.asyncio
async def test_ip_pools_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("ip_pools", {"device_name": "core-switch"})
    assert result["result"][0]["name"] == "dhcp-pool"
    assert result["result"][0]["ranges"] == "10.0.0.100-10.0.0.200"


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


# --- traceroute (v0.4, diagnostic - not gated by MIKROTIK_ALLOW_WRITE) -----


@pytest.mark.asyncio
async def test_traceroute_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("traceroute", {"device_name": "core-switch", "address": "8.8.8.8"})
    assert result["result"][0]["address"] == "10.0.0.254"
    assert result["result"][1]["address"] == "8.8.8.8"


@pytest.mark.asyncio
async def test_traceroute_rejects_invalid_address_before_touching_device(settings: Settings):
    mcp = build_server(
        settings=settings,
        client_factory=lambda s, n: MikrotikClient(s.get_device(n), connection=RaisingConnection()),
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("traceroute", {"device_name": "core-switch", "address": "8.8.8.8; reboot"})
    assert "not a valid" in str(exc_info.value)


@pytest.mark.asyncio
async def test_traceroute_does_not_require_write_enabled(settings: Settings, fake_connection: FakeConnection):
    """Diagnostic, read-only tool: must work even with MIKROTIK_ALLOW_WRITE=false."""
    assert settings.allow_write is False
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("traceroute", {"device_name": "core-switch", "address": "8.8.8.8"})
    assert result["result"]


@pytest.mark.asyncio
async def test_traceroute_caps_count_and_max_hops_sent_to_device(settings: Settings):
    fake = FakeConnection()
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    await mcp.call_tool(
        "traceroute",
        {"device_name": "core-switch", "address": "8.8.8.8", "count": 999, "max_hops": 999},
    )
    cmd, kwargs = fake.calls[-1]
    assert cmd == "/tool/traceroute"
    assert kwargs["count"] == "2"  # MAX_TRACEROUTE_COUNT
    assert kwargs["max-hops"] == "10"  # MAX_TRACEROUTE_MAX_HOPS
    assert kwargs["timeout"] == "00:00:01"  # fixed short per-hop timeout


@pytest.mark.asyncio
async def test_traceroute_rejects_non_positive_count(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool("traceroute", {"device_name": "core-switch", "address": "8.8.8.8", "count": 0})
    assert "positive" in str(exc_info.value).lower()


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


# --- arp_table / bridge_hosts (v0.6, read-only) -----------------------------


@pytest.mark.asyncio
async def test_arp_table_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("arp_table", {"device_name": "core-switch"})
    assert result["result"] == [
        {
            ".id": "*1",
            "address": "10.0.0.70",
            "mac-address": "AA:BB:CC:DD:EE:70",
            "interface": "ether1",
            "dynamic": "false",
            "complete": "true",
        }
    ]


@pytest.mark.asyncio
async def test_bridge_hosts_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("bridge_hosts", {"device_name": "core-switch"})
    assert result["result"] == [
        {
            ".id": "*1",
            "mac-address": "AA:BB:CC:DD:EE:70",
            "on-interface": "ether1",
            "bridge": "bridge1",
            "dynamic": "false",
            "local": "false",
        }
    ]


# --- interface_traffic / poe_status (v0.6, read-only - not gated by --------
# --- MIKROTIK_ALLOW_WRITE) --------------------------------------------------


@pytest.mark.asyncio
async def test_interface_traffic_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool(
        "interface_traffic", {"device_name": "core-switch", "interface": "ether1"}
    )
    # A dict-returning tool's structured content is the dict itself - not
    # wrapped under a "result" key (that wrapping only applies to
    # list-returning tools; see e.g. set_identity's `preview["applied"]`).
    assert result["rx-bits-per-second"] == "1000000"
    assert result["tx-bits-per-second"] == "500000"


@pytest.mark.asyncio
async def test_interface_traffic_does_not_require_write_enabled(
    settings: Settings, fake_connection: FakeConnection
):
    assert settings.allow_write is False
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool(
        "interface_traffic", {"device_name": "core-switch", "interface": "ether1"}
    )
    assert result


@pytest.mark.asyncio
async def test_interface_traffic_rejects_invalid_interface_name_before_touching_device(settings: Settings):
    mcp = build_server(
        settings=settings,
        client_factory=lambda s, n: MikrotikClient(s.get_device(n), connection=RaisingConnection()),
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "interface_traffic", {"device_name": "core-switch", "interface": "ether1; reboot"}
        )
    assert "not valid" in str(exc_info.value)


@pytest.mark.asyncio
async def test_interface_traffic_sends_once_flag_as_structured_param(settings: Settings):
    fake = FakeConnection()
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    await mcp.call_tool("interface_traffic", {"device_name": "core-switch", "interface": "ether1"})
    cmd, kwargs = fake.calls[-1]
    assert cmd == "/interface/monitor-traffic"
    assert kwargs == {"interface": "ether1", "once": ""}


@pytest.mark.asyncio
async def test_poe_status_happy_path(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("poe_status", {"device_name": "core-switch"})
    rows = {row["interface"]: row for row in result["result"]}
    # sfp1 (no `poe-out` field on the fixture device) must never appear.
    assert set(rows) == {"ether1", "ether2"}
    assert rows["ether1"]["poe-out"] == "auto-on"
    assert rows["ether1"]["poe-out-status"] == "powered-on"
    assert rows["ether1"]["voltage"] == "48.0"
    assert rows["ether1"]["current"] == "150"
    assert rows["ether1"]["power"] == "7.2"
    assert rows["ether2"]["poe-out"] == "off"
    assert rows["ether2"]["poe-out-status"] == "poe-out-off"


@pytest.mark.asyncio
async def test_poe_status_does_not_require_write_enabled(settings: Settings, fake_connection: FakeConnection):
    assert settings.allow_write is False
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    _content, result = await mcp.call_tool("poe_status", {"device_name": "core-switch"})
    assert result["result"]


@pytest.mark.asyncio
async def test_poe_status_returns_empty_list_for_device_with_no_poe(settings: Settings):
    """A device with no PoE hardware at all has no `poe-out` field on any
    /interface/ethernet row - poe_status must return an empty list, not an
    error, exactly like wireless_registrations does for a wired-only device."""
    fake = FakeConnection(
        data={("interface", "ethernet"): [{".id": "*1", "name": "ether1"}, {".id": "*2", "name": "ether2"}]}
    )
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    _content, result = await mcp.call_tool("poe_status", {"device_name": "core-switch"})
    assert result["result"] == []


@pytest.mark.asyncio
async def test_poe_status_survives_a_failed_monitor_call_for_one_port(settings: Settings):
    """A PoE-capable port whose live monitor call fails must still be listed
    (with its configured `poe-out`, just without live monitor fields) -
    one bad port must not fail the whole tool. `fake_connection`'s __call__
    is a bound method looked up on the type for the implicit `connection(...)`
    call form (client.py's poe_monitor), so it can't be monkeypatched per
    instance - a small standalone fake connection is used instead."""

    class _FlakyMonitorConnection:
        def path(self, *segments: str) -> FakePath:
            if segments == ("interface", "ethernet"):
                return FakePath([{".id": "*1", "name": "ether1", "poe-out": "auto-on"}])
            return FakePath([])

        def __call__(self, cmd: str, **kwargs):
            if cmd == "/interface/ethernet/poe/monitor":
                raise LibRouterosError("no such port")
            return []

        def close(self) -> None:
            pass

    def factory(s: Settings, n: str) -> MikrotikClient:
        return MikrotikClient(s.get_device(n), connection=_FlakyMonitorConnection())

    mcp = build_server(settings=settings, client_factory=factory)
    _content, result = await mcp.call_tool("poe_status", {"device_name": "core-switch"})
    assert result["result"] == [{"interface": "ether1", "poe-out": "auto-on"}]


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


# --- set_client_bandwidth ---------------------------------------------------


@pytest.mark.asyncio
async def test_set_client_bandwidth_blocked_read_only_by_default(settings: Settings):
    fake = FakeConnection(data={("queue", "simple"): []})
    mcp = build_server(settings=settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_client_bandwidth",
            {"device_name": "core-switch", "target": "10.0.0.50", "max_limit": "10M/5M", "confirm": True},
        )
    assert "read-only" in str(exc_info.value)
    assert fake.path("queue", "simple")._rows == []


@pytest.mark.asyncio
async def test_set_client_bandwidth_creates_then_updates(device: Device):
    fake = FakeConnection(data={("queue", "simple"): []})
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))

    _content, preview = await mcp.call_tool(
        "set_client_bandwidth",
        {"device_name": "core-switch", "target": "10.0.0.50", "max_limit": "10M/5M", "confirm": False},
    )
    assert preview["operation"] == "set_client_bandwidth_add"
    assert preview["applied"] is False
    assert fake.path("queue", "simple")._rows == []

    _content, applied = await mcp.call_tool(
        "set_client_bandwidth",
        {"device_name": "core-switch", "target": "10.0.0.50", "max_limit": "10M/5M", "confirm": True},
    )
    assert applied["operation"] == "set_client_bandwidth_add"
    assert applied["applied"] is True
    assert len(fake.path("queue", "simple")._rows) == 1

    # Calling it again for the same target updates the existing queue instead of adding a second one.
    _content, updated = await mcp.call_tool(
        "set_client_bandwidth",
        {"device_name": "core-switch", "target": "10.0.0.50", "max_limit": "20M/10M", "confirm": True},
    )
    assert updated["operation"] == "set_client_bandwidth_update"
    assert updated["applied"] is True
    rows = fake.path("queue", "simple")._rows
    assert len(rows) == 1
    assert rows[0]["max-limit"] == "20M/10M"


@pytest.mark.asyncio
async def test_set_client_bandwidth_rejects_invalid_max_limit_before_touching_device(settings: Settings):
    fake = FakeConnection(data={("queue", "simple"): []})
    write_settings = Settings(allow_write=True, devices=settings.devices)
    mcp = build_server(settings=write_settings, client_factory=_factory(fake))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_client_bandwidth",
            {"device_name": "core-switch", "target": "10.0.0.50", "max_limit": "not-a-rate", "confirm": True},
        )
    assert "rate pair" in str(exc_info.value).lower()
    assert fake.path("queue", "simple")._rows == []


# --- add_static_dhcp_lease ---------------------------------------------------


@pytest.mark.asyncio
async def test_add_static_dhcp_lease_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_static_dhcp_lease",
            {"device_name": "core-switch", "address": "10.0.0.60", "mac_address": "AA:BB:CC:DD:EE:02", "confirm": True},
        )
    assert "read-only" in str(exc_info.value)
    assert len(fake_connection.path("ip", "dhcp-server", "lease")._rows) == 1


@pytest.mark.asyncio
async def test_add_static_dhcp_lease_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "add_static_dhcp_lease",
        {"device_name": "core-switch", "address": "10.0.0.60", "mac_address": "AA:BB:CC:DD:EE:02", "confirm": False},
    )
    assert preview["applied"] is False
    assert len(fake_connection.path("ip", "dhcp-server", "lease")._rows) == 1

    _content, applied = await mcp.call_tool(
        "add_static_dhcp_lease",
        {"device_name": "core-switch", "address": "10.0.0.60", "mac_address": "AA:BB:CC:DD:EE:02", "confirm": True},
    )
    assert applied["applied"] is True
    rows = fake_connection.path("ip", "dhcp-server", "lease")._rows
    assert any(row["mac-address"] == "AA:BB:CC:DD:EE:02" for row in rows)


@pytest.mark.asyncio
async def test_add_static_dhcp_lease_rejects_duplicate_mac(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_static_dhcp_lease",
            {"device_name": "core-switch", "address": "10.0.0.99", "mac_address": "AA:BB:CC:DD:EE:01", "confirm": True},
        )
    assert "already exists" in str(exc_info.value)
    assert len(fake_connection.path("ip", "dhcp-server", "lease")._rows) == 1


# --- remove_simple_queue ------------------------------------------------------


@pytest.mark.asyncio
async def test_remove_simple_queue_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "remove_simple_queue", {"device_name": "core-switch", "target": "10.0.0.50/32", "confirm": True}
        )
    assert "read-only" in str(exc_info.value)
    assert len(fake_connection.path("queue", "simple")._rows) == 1


@pytest.mark.asyncio
async def test_remove_simple_queue_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "remove_simple_queue", {"device_name": "core-switch", "target": "10.0.0.50/32", "confirm": False}
    )
    assert preview["applied"] is False
    assert len(fake_connection.path("queue", "simple")._rows) == 1

    _content, applied = await mcp.call_tool(
        "remove_simple_queue", {"device_name": "core-switch", "target": "10.0.0.50/32", "confirm": True}
    )
    assert applied["applied"] is True
    assert fake_connection.path("queue", "simple")._rows == []


@pytest.mark.asyncio
async def test_remove_simple_queue_unknown_raises_clear_error(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "remove_simple_queue", {"device_name": "core-switch", "target": "10.0.0.99", "confirm": True}
        )
    assert "10.0.0.99" in str(exc_info.value)


# --- add_to_address_list / remove_from_address_list (v0.4) ------------------


@pytest.mark.asyncio
async def test_add_to_address_list_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_to_address_list",
            {"device_name": "core-switch", "list_name": "blocked-clients", "address": "10.0.0.61", "confirm": True},
        )
    assert "read-only" in str(exc_info.value)
    assert len(fake_connection.path("ip", "firewall", "address-list")._rows) == 1


@pytest.mark.asyncio
async def test_add_to_address_list_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "add_to_address_list",
        {"device_name": "core-switch", "list_name": "blocked-clients", "address": "10.0.0.61", "confirm": False},
    )
    assert preview["applied"] is False
    assert len(fake_connection.path("ip", "firewall", "address-list")._rows) == 1

    _content, applied = await mcp.call_tool(
        "add_to_address_list",
        {"device_name": "core-switch", "list_name": "blocked-clients", "address": "10.0.0.61", "confirm": True},
    )
    assert applied["applied"] is True
    rows = fake_connection.path("ip", "firewall", "address-list")._rows
    assert any(row["list"] == "blocked-clients" and row["address"] == "10.0.0.61" for row in rows)


@pytest.mark.asyncio
async def test_add_to_address_list_rejects_duplicate(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "add_to_address_list",
            {"device_name": "core-switch", "list_name": "blocked-clients", "address": "10.0.0.60", "confirm": True},
        )
    assert "already exists" in str(exc_info.value)
    assert len(fake_connection.path("ip", "firewall", "address-list")._rows) == 1


@pytest.mark.asyncio
async def test_remove_from_address_list_blocked_read_only_by_default(
    settings: Settings, fake_connection: FakeConnection
):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "remove_from_address_list",
            {"device_name": "core-switch", "list_name": "blocked-clients", "address": "10.0.0.60", "confirm": True},
        )
    assert "read-only" in str(exc_info.value)
    assert len(fake_connection.path("ip", "firewall", "address-list")._rows) == 1


@pytest.mark.asyncio
async def test_remove_from_address_list_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "remove_from_address_list",
        {"device_name": "core-switch", "list_name": "blocked-clients", "address": "10.0.0.60", "confirm": False},
    )
    assert preview["applied"] is False
    assert len(fake_connection.path("ip", "firewall", "address-list")._rows) == 1

    _content, applied = await mcp.call_tool(
        "remove_from_address_list",
        {"device_name": "core-switch", "list_name": "blocked-clients", "address": "10.0.0.60", "confirm": True},
    )
    assert applied["applied"] is True
    assert fake_connection.path("ip", "firewall", "address-list")._rows == []


@pytest.mark.asyncio
async def test_remove_from_address_list_unknown_raises_clear_error(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "remove_from_address_list",
            {"device_name": "core-switch", "list_name": "blocked-clients", "address": "10.0.0.99", "confirm": True},
        )
    assert "10.0.0.99" in str(exc_info.value)


# --- set_poe_out (v0.6) ------------------------------------------------------


@pytest.mark.asyncio
async def test_set_poe_out_blocked_read_only_by_default(settings: Settings, fake_connection: FakeConnection):
    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_poe_out",
            {"device_name": "core-switch", "interface_name": "ether1", "poe_out": "off", "confirm": True},
        )
    assert "read-only" in str(exc_info.value)
    # Device was never touched.
    assert fake_connection.path("interface", "ethernet")._rows[0]["poe-out"] == "auto-on"


@pytest.mark.asyncio
async def test_set_poe_out_preview_then_confirm(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    _content, preview = await mcp.call_tool(
        "set_poe_out",
        {"device_name": "core-switch", "interface_name": "ether1", "poe_out": "off", "confirm": False},
    )
    assert preview["applied"] is False
    assert preview["before"]["poe-out"] == "auto-on"
    assert preview["after"]["poe-out"] == "off"
    assert fake_connection.path("interface", "ethernet")._rows[0]["poe-out"] == "auto-on"

    _content, applied = await mcp.call_tool(
        "set_poe_out",
        {"device_name": "core-switch", "interface_name": "ether1", "poe_out": "off", "confirm": True},
    )
    assert applied["applied"] is True
    assert fake_connection.path("interface", "ethernet")._rows[0]["poe-out"] == "off"


@pytest.mark.asyncio
async def test_set_poe_out_unknown_interface_raises_clear_error(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_poe_out",
            {"device_name": "core-switch", "interface_name": "ghost0", "poe_out": "off", "confirm": True},
        )
    assert "ghost0" in str(exc_info.value)


@pytest.mark.asyncio
async def test_set_poe_out_non_poe_interface_raises_clear_error(device: Device, fake_connection: FakeConnection):
    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_poe_out",
            {"device_name": "core-switch", "interface_name": "sfp1", "poe_out": "off", "confirm": True},
        )
    assert "sfp1" in str(exc_info.value)


@pytest.mark.asyncio
async def test_set_poe_out_rejects_invalid_poe_out_value_before_touching_device(settings: Settings):
    write_settings = Settings(allow_write=True, devices=settings.devices)
    mcp = build_server(
        settings=write_settings,
        client_factory=lambda s, n: MikrotikClient(s.get_device(n), connection=RaisingConnection()),
    )
    with pytest.raises(ToolError) as exc_info:
        await mcp.call_tool(
            "set_poe_out",
            {"device_name": "core-switch", "interface_name": "ether1", "poe_out": "on", "confirm": True},
        )
    assert "not valid" in str(exc_info.value)


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


# --- v0.5: audit journal + correlation id, exercised end to end through ---
# --- FastMCP's call_tool boundary (not by calling guard.py directly) ------


@pytest.mark.asyncio
async def test_write_tool_call_produces_one_audit_journal_entry(
    device: Device, fake_connection: FakeConnection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    import json

    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("MIKROTIK_AUDIT_LOG", str(log_path))

    write_settings = Settings(allow_write=True, devices={device.name: device})
    mcp = build_server(settings=write_settings, client_factory=_factory(fake_connection))

    await mcp.call_tool("set_identity", {"device_name": "core-switch", "new_name": "renamed", "confirm": True})

    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["outcome"] == "applied"
    assert event["tool"] == "set_identity"
    assert "s3cret" not in log_path.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_read_tool_call_never_writes_to_the_audit_journal(
    settings: Settings, fake_connection: FakeConnection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Only guarded writes are audit-journaled - a plain read tool call must
    not produce a journal entry."""
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("MIKROTIK_AUDIT_LOG", str(log_path))

    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    await mcp.call_tool("system_info", {"device_name": "core-switch"})

    assert not log_path.exists() or log_path.read_text(encoding="utf-8") == ""


@pytest.mark.asyncio
async def test_blocked_write_tool_call_still_journals_an_error(
    settings: Settings, fake_connection: FakeConnection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    import json

    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("MIKROTIK_AUDIT_LOG", str(log_path))

    mcp = build_server(settings=settings, client_factory=_factory(fake_connection))
    with pytest.raises(ToolError):
        await mcp.call_tool(
            "set_identity", {"device_name": "core-switch", "new_name": "renamed", "confirm": True}
        )

    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["outcome"] == "error"


@pytest.mark.asyncio
async def test_unhandled_error_log_line_is_prefixed_with_a_correlation_id(
    settings: Settings, caplog: pytest.LogCaptureFixture
):
    """server.py's `_safe` wrapper binds a correlation id for every tool
    call and prefixes it onto the server-side log line for that call - see
    server.py's `_safe`/`correlation.bind`."""

    def _broken_factory(_settings: Settings, _device_name: str):
        raise RuntimeError("boom - not a MikrotikMCPError, so _safe's generic path handles it")

    mcp = build_server(settings=settings, client_factory=_broken_factory)

    with caplog.at_level("ERROR", logger="mcp_mikrotik"):
        with pytest.raises(ToolError):
            await mcp.call_tool("system_info", {"device_name": "core-switch"})

    matches = [r for r in caplog.records if "Unhandled error in tool system_info" in r.message]
    assert len(matches) == 1
    # "[<12 hex chars>] Unhandled error in tool system_info"
    prefix = matches[0].message.split("]")[0].lstrip("[")
    assert len(prefix) == 12
