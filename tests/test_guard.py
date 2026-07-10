from __future__ import annotations

import dataclasses

import pytest
from librouteros.exceptions import LibRouterosError

from mcp_mikrotik import guard
from mcp_mikrotik.client import MikrotikClient
from mcp_mikrotik.config import Device, Settings
from mcp_mikrotik.exceptions import (
    GuardViolationError,
    ResourceAlreadyExistsError,
    ResourceNotFoundError,
    ValidationError,
    WriteDisabledError,
)

from .fakes import FakeConnection, RaisingConnection


def test_set_identity_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    assert settings.allow_write is False
    with pytest.raises(WriteDisabledError):
        guard.set_identity(client, settings, new_name="new-name", confirm=True)


def test_set_identity_read_only_gate_applies_even_with_confirm_true(
    device: Device, settings: Settings
):
    """Read-only gate must block *before* touching the device at all, regardless of confirm."""
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.set_identity(guarded_client, settings, new_name="new-name", confirm=True)


def test_set_identity_preview_does_not_apply(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.set_identity(client, settings_write_enabled, new_name="new-name", confirm=False)

    assert preview.applied is False
    assert preview.before == {"name": "MikroTik"}
    assert preview.after == {"name": "new-name"}
    # Nothing was written to the fake device.
    assert fake_connection.path("system", "identity")._rows == [{"name": "MikroTik"}]


def test_set_identity_confirm_true_applies(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.set_identity(client, settings_write_enabled, new_name="new-name", confirm=True)

    assert preview.applied is True
    assert preview.before == {"name": "MikroTik"}
    assert preview.after == {"name": "new-name"}
    assert fake_connection.path("system", "identity")._rows == [{"name": "new-name"}]


def test_allowlist_only_contains_named_operations():
    for name, op in guard.ALLOWLIST.items():
        assert op.name == name
        assert isinstance(op.path, tuple) and op.path
        assert op.action in {"update", "add", "remove", "start", "stop"}


def test_require_allowed_rejects_unknown_operation(settings_write_enabled: Settings):
    with pytest.raises(GuardViolationError):
        guard._require_allowed(settings_write_enabled, "delete_everything")


def test_set_identity_dispatch_follows_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, client: MikrotikClient, settings_write_enabled: Settings
):
    """A1: guard.set_identity must dispatch via ALLOWLIST["set_identity"].action,
    not a hardcoded call to client.update(). Point the allowlist entry's
    action at an arbitrary stub method and confirm THAT method gets called
    instead of .update() - proving `action` actually governs dispatch."""
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["set_identity"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "set_identity", patched_op)

    guard.set_identity(client, settings_write_enabled, new_name="renamed", confirm=True)

    assert called == {"path": patched_op.path, "fields": {"name": "renamed"}}


# --- enable_interface / disable_interface ---------------------------------


def test_enable_interface_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    assert settings.allow_write is False
    with pytest.raises(WriteDisabledError):
        guard.enable_interface(client, settings, interface_name="ether2", confirm=True)


def test_enable_interface_read_only_gate_applies_even_with_confirm_true(device: Device, settings: Settings):
    """Read-only gate must block *before* touching the device at all, regardless of confirm."""
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.enable_interface(guarded_client, settings, interface_name="ether2", confirm=True)


def test_enable_interface_preview_does_not_apply(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.enable_interface(client, settings_write_enabled, interface_name="ether2", confirm=False)

    assert preview.applied is False
    assert preview.before["disabled"] == "true"
    assert preview.after["disabled"] == "no"
    # Nothing was written to the fake device.
    rows = {row["name"]: row["disabled"] for row in fake_connection.path("interface")._rows}
    assert rows == {"ether1": "false", "ether2": "true"}


def test_disable_interface_confirm_true_applies(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.disable_interface(client, settings_write_enabled, interface_name="ether1", confirm=True)

    assert preview.applied is True
    assert preview.before["disabled"] == "false"
    assert preview.after["disabled"] == "yes"
    rows = {row["name"]: row["disabled"] for row in fake_connection.path("interface")._rows}
    assert rows == {"ether1": "yes", "ether2": "true"}


def test_enable_interface_unknown_name_raises_resource_not_found(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.enable_interface(client, settings_write_enabled, interface_name="ghost0", confirm=True)
    assert "ghost0" in str(exc_info.value)
    # Nothing was created.
    names = {row["name"] for row in fake_connection.path("interface")._rows}
    assert names == {"ether1", "ether2"}


def test_enable_interface_dispatches_via_allowlist_id(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    """The write must target the specific interface row by `.id`, not blindly update row 0."""
    guard.enable_interface(client, settings_write_enabled, interface_name="ether2", confirm=True)
    rows = {row["name"]: row["disabled"] for row in fake_connection.path("interface")._rows}
    # ether1 (row 0) must be untouched; only ether2 (the requested name) changes.
    assert rows == {"ether1": "false", "ether2": "no"}


# --- set_wifi_ssid ----------------------------------------------------------


def test_set_wifi_ssid_blocked_when_write_disabled(settings: Settings, device: Device):
    fake = FakeConnection(data={("interface", "wifi"): [{".id": "*1", "name": "wifi1", "ssid": "old-ssid"}]})
    client = MikrotikClient(device, connection=fake)
    with pytest.raises(WriteDisabledError):
        guard.set_wifi_ssid(client, settings, interface_name="wifi1", new_ssid="new-ssid", confirm=True)


def test_set_wifi_ssid_read_only_gate_applies_before_touching_device(settings: Settings, device: Device):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.set_wifi_ssid(guarded_client, settings, interface_name="wifi1", new_ssid="new-ssid", confirm=True)


def test_set_wifi_ssid_prefers_ros7_when_present(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(data={("interface", "wifi"): [{".id": "*1", "name": "wifi1", "ssid": "old-ssid"}]})
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wifi_ssid(
        client, settings_write_enabled, interface_name="wifi1", new_ssid="new-ssid", confirm=False
    )
    assert preview.operation == "set_wifi_ssid_ros7"
    assert preview.applied is False
    assert preview.before["ssid"] == "old-ssid"
    assert preview.after["ssid"] == "new-ssid"

    applied = guard.set_wifi_ssid(
        client, settings_write_enabled, interface_name="wifi1", new_ssid="new-ssid", confirm=True
    )
    assert applied.applied is True
    assert fake.path("interface", "wifi")._rows[0]["ssid"] == "new-ssid"


def test_set_wifi_ssid_falls_back_to_ros6_when_ros7_unsupported(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(
        raise_for={("interface", "wifi"): LibRouterosError("no such command")},
        data={("interface", "wireless"): [{".id": "*1", "name": "wlan1", "ssid": "old-ssid"}]},
    )
    client = MikrotikClient(device, connection=fake)

    applied = guard.set_wifi_ssid(
        client, settings_write_enabled, interface_name="wlan1", new_ssid="new-ssid", confirm=True
    )
    assert applied.operation == "set_wifi_ssid_ros6"
    assert applied.applied is True
    assert fake.path("interface", "wireless")._rows[0]["ssid"] == "new-ssid"


def test_set_wifi_ssid_unknown_interface_raises_resource_not_found(
    settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(data={("interface", "wifi"): [{".id": "*1", "name": "wifi1", "ssid": "old-ssid"}]})
    client = MikrotikClient(device, connection=fake)
    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.set_wifi_ssid(client, settings_write_enabled, interface_name="ghost-radio", new_ssid="x", confirm=True)
    assert "ghost-radio" in str(exc_info.value)


# --- set_client_bandwidth ---------------------------------------------------


def test_set_client_bandwidth_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    assert settings.allow_write is False
    with pytest.raises(WriteDisabledError):
        guard.set_client_bandwidth(client, settings, target="10.0.0.50", max_limit="10M/5M", confirm=True)


def test_set_client_bandwidth_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.set_client_bandwidth(guarded_client, settings, target="10.0.0.50", max_limit="10M/5M", confirm=True)


def test_set_client_bandwidth_creates_queue_when_none_exists(
    settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(data={("queue", "simple"): []})
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_client_bandwidth(
        client, settings_write_enabled, target="10.0.0.50", max_limit="10M/5M", confirm=False
    )
    assert preview.operation == "set_client_bandwidth_add"
    assert preview.applied is False
    assert preview.before == {}
    assert preview.after["target"] == "10.0.0.50"
    assert preview.after["max-limit"] == "10M/5M"
    assert preview.after["name"]
    # Nothing was written yet.
    assert fake.path("queue", "simple")._rows == []

    applied = guard.set_client_bandwidth(
        client, settings_write_enabled, target="10.0.0.50", max_limit="10M/5M", confirm=True
    )
    assert applied.operation == "set_client_bandwidth_add"
    assert applied.applied is True
    rows = fake.path("queue", "simple")._rows
    assert len(rows) == 1
    assert rows[0]["target"] == "10.0.0.50"
    assert rows[0]["max-limit"] == "10M/5M"


def test_set_client_bandwidth_updates_existing_queue_for_same_target(
    settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(
        data={
            ("queue", "simple"): [
                {".id": "*1", "name": "limit-10-0-0-50", "target": "10.0.0.50", "max-limit": "1M/1M"}
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_client_bandwidth(
        client, settings_write_enabled, target="10.0.0.50", max_limit="10M/5M", confirm=False
    )
    assert preview.operation == "set_client_bandwidth_update"
    assert preview.applied is False
    assert preview.before["max-limit"] == "1M/1M"
    assert preview.after["max-limit"] == "10M/5M"
    # Preview must not have touched the device.
    assert fake.path("queue", "simple")._rows[0]["max-limit"] == "1M/1M"

    applied = guard.set_client_bandwidth(
        client, settings_write_enabled, target="10.0.0.50", max_limit="10M/5M", confirm=True
    )
    assert applied.applied is True
    assert fake.path("queue", "simple")._rows[0]["max-limit"] == "10M/5M"
    # Only the one existing queue row remains - no duplicate was created.
    assert len(fake.path("queue", "simple")._rows) == 1


def test_set_client_bandwidth_sets_limit_at_when_given(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(data={("queue", "simple"): []})
    client = MikrotikClient(device, connection=fake)

    applied = guard.set_client_bandwidth(
        client, settings_write_enabled, target="10.0.0.50", max_limit="10M/5M", limit_at="2M/1M", confirm=True
    )
    assert applied.applied is True
    assert fake.path("queue", "simple")._rows[0]["limit-at"] == "2M/1M"


def test_set_client_bandwidth_rejects_invalid_target(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(data={("queue", "simple"): []})
    client = MikrotikClient(device, connection=fake)
    with pytest.raises(ValidationError):
        guard.set_client_bandwidth(
            client, settings_write_enabled, target="not-an-ip", max_limit="10M/5M", confirm=True
        )
    assert fake.path("queue", "simple")._rows == []


def test_set_client_bandwidth_rejects_invalid_max_limit(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(data={("queue", "simple"): []})
    client = MikrotikClient(device, connection=fake)
    with pytest.raises(ValidationError):
        guard.set_client_bandwidth(
            client, settings_write_enabled, target="10.0.0.50", max_limit="not-a-rate", confirm=True
        )
    assert fake.path("queue", "simple")._rows == []


# --- add_static_dhcp_lease ---------------------------------------------------


def test_add_static_dhcp_lease_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    assert settings.allow_write is False
    with pytest.raises(WriteDisabledError):
        guard.add_static_dhcp_lease(
            client, settings, address="10.0.0.60", mac_address="AA:BB:CC:DD:EE:02", confirm=True
        )


def test_add_static_dhcp_lease_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.add_static_dhcp_lease(
            guarded_client, settings, address="10.0.0.60", mac_address="AA:BB:CC:DD:EE:02", confirm=True
        )


def test_add_static_dhcp_lease_preview_does_not_create(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.add_static_dhcp_lease(
        client, settings_write_enabled, address="10.0.0.60", mac_address="AA:BB:CC:DD:EE:02", confirm=False
    )
    assert preview.applied is False
    assert preview.before == {}
    assert preview.after["address"] == "10.0.0.60"
    assert preview.after["mac-address"] == "AA:BB:CC:DD:EE:02"
    assert len(fake_connection.path("ip", "dhcp-server", "lease")._rows) == 1  # only the fixture's existing lease


def test_add_static_dhcp_lease_confirm_true_creates(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    applied = guard.add_static_dhcp_lease(
        client, settings_write_enabled, address="10.0.0.60", mac_address="AA:BB:CC:DD:EE:02", confirm=True
    )
    assert applied.applied is True
    rows = fake_connection.path("ip", "dhcp-server", "lease")._rows
    assert any(row["mac-address"] == "AA:BB:CC:DD:EE:02" and row["address"] == "10.0.0.60" for row in rows)


def test_add_static_dhcp_lease_rejects_duplicate_mac(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    """The fixture already has a lease for AA:BB:CC:DD:EE:01 - adding another must be refused, not duplicated."""
    with pytest.raises(ResourceAlreadyExistsError) as exc_info:
        guard.add_static_dhcp_lease(
            client, settings_write_enabled, address="10.0.0.99", mac_address="AA:BB:CC:DD:EE:01", confirm=True
        )
    assert "AA:BB:CC:DD:EE:01" in str(exc_info.value)
    rows = fake_connection.path("ip", "dhcp-server", "lease")._rows
    assert len(rows) == 1  # no duplicate created


def test_add_static_dhcp_lease_rejects_invalid_mac(client: MikrotikClient, settings_write_enabled: Settings):
    with pytest.raises(ValidationError):
        guard.add_static_dhcp_lease(
            client, settings_write_enabled, address="10.0.0.60", mac_address="not-a-mac", confirm=True
        )


def test_add_static_dhcp_lease_rejects_invalid_address(client: MikrotikClient, settings_write_enabled: Settings):
    with pytest.raises(ValidationError):
        guard.add_static_dhcp_lease(
            client, settings_write_enabled, address="not-an-ip", mac_address="AA:BB:CC:DD:EE:02", confirm=True
        )


def test_add_static_dhcp_lease_optional_comment_and_server(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    applied = guard.add_static_dhcp_lease(
        client,
        settings_write_enabled,
        address="10.0.0.61",
        mac_address="AA:BB:CC:DD:EE:03",
        comment="reserved for AP",
        server="dhcp1",
        confirm=True,
    )
    assert applied.applied is True
    rows = fake_connection.path("ip", "dhcp-server", "lease")._rows
    created = next(row for row in rows if row["mac-address"] == "AA:BB:CC:DD:EE:03")
    assert created["comment"] == "reserved for AP"
    assert created["server"] == "dhcp1"


# --- remove_simple_queue -----------------------------------------------------


def test_remove_simple_queue_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    assert settings.allow_write is False
    with pytest.raises(WriteDisabledError):
        guard.remove_simple_queue(client, settings, target="10.0.0.50/32", confirm=True)


def test_remove_simple_queue_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.remove_simple_queue(guarded_client, settings, target="10.0.0.50/32", confirm=True)


def test_remove_simple_queue_requires_target_or_name(client: MikrotikClient, settings_write_enabled: Settings):
    with pytest.raises(ValidationError):
        guard.remove_simple_queue(client, settings_write_enabled, confirm=True)


def test_remove_simple_queue_by_target_preview_then_confirm(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.remove_simple_queue(
        client, settings_write_enabled, target="10.0.0.50/32", confirm=False
    )
    assert preview.applied is False
    assert preview.before["name"] == "limit-10-0-0-50"
    # Preview must not have removed anything.
    assert len(fake_connection.path("queue", "simple")._rows) == 1

    applied = guard.remove_simple_queue(client, settings_write_enabled, target="10.0.0.50/32", confirm=True)
    assert applied.applied is True
    assert fake_connection.path("queue", "simple")._rows == []


def test_remove_simple_queue_by_name(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    applied = guard.remove_simple_queue(client, settings_write_enabled, name="limit-10-0-0-50", confirm=True)
    assert applied.applied is True
    assert fake_connection.path("queue", "simple")._rows == []


def test_remove_simple_queue_unknown_target_raises_resource_not_found(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.remove_simple_queue(client, settings_write_enabled, target="10.0.0.99", confirm=True)
    assert "10.0.0.99" in str(exc_info.value)
    # Nothing was removed.
    assert len(fake_connection.path("queue", "simple")._rows) == 1


def test_remove_simple_queue_rejects_invalid_target_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    """An invalid `target` must be rejected before client.path() is ever
    called - RaisingConnection asserts if path()/call() is invoked at all."""
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.remove_simple_queue(guarded_client, settings_write_enabled, target="not-an-ip", confirm=True)


# --- add_to_address_list / remove_from_address_list (v0.4) ------------------


def test_add_to_address_list_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    assert settings.allow_write is False
    with pytest.raises(WriteDisabledError):
        guard.add_to_address_list(
            client, settings, list_name="blocked-clients", address="10.0.0.61", confirm=True
        )


def test_add_to_address_list_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.add_to_address_list(
            guarded_client, settings, list_name="blocked-clients", address="10.0.0.61", confirm=True
        )


def test_add_to_address_list_preview_does_not_create(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.add_to_address_list(
        client, settings_write_enabled, list_name="blocked-clients", address="10.0.0.61", confirm=False
    )
    assert preview.applied is False
    assert preview.before == {}
    assert preview.after["list"] == "blocked-clients"
    assert preview.after["address"] == "10.0.0.61"
    assert len(fake_connection.path("ip", "firewall", "address-list")._rows) == 1  # only the fixture's entry


def test_add_to_address_list_confirm_true_creates(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    applied = guard.add_to_address_list(
        client, settings_write_enabled, list_name="blocked-clients", address="10.0.0.61", confirm=True
    )
    assert applied.applied is True
    rows = fake_connection.path("ip", "firewall", "address-list")._rows
    assert any(row["list"] == "blocked-clients" and row["address"] == "10.0.0.61" for row in rows)


def test_add_to_address_list_optional_comment_and_timeout(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    applied = guard.add_to_address_list(
        client,
        settings_write_enabled,
        list_name="blocked-clients",
        address="10.0.0.62",
        comment="repeat offender",
        timeout="1d",
        confirm=True,
    )
    assert applied.applied is True
    rows = fake_connection.path("ip", "firewall", "address-list")._rows
    created = next(row for row in rows if row["address"] == "10.0.0.62")
    assert created["comment"] == "repeat offender"
    assert created["timeout"] == "1d"


def test_add_to_address_list_rejects_duplicate_list_and_address(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    """The fixture already has list=blocked-clients address=10.0.0.60 - adding it again must be refused."""
    with pytest.raises(ResourceAlreadyExistsError) as exc_info:
        guard.add_to_address_list(
            client, settings_write_enabled, list_name="blocked-clients", address="10.0.0.60", confirm=True
        )
    assert "blocked-clients" in str(exc_info.value)
    assert "10.0.0.60" in str(exc_info.value)
    rows = fake_connection.path("ip", "firewall", "address-list")._rows
    assert len(rows) == 1  # no duplicate created


def test_add_to_address_list_allows_same_address_in_a_different_list(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    """Same `address` already exists in "blocked-clients" - adding it to a
    different list is a distinct entry, not a duplicate."""
    applied = guard.add_to_address_list(
        client, settings_write_enabled, list_name="allowed-clients", address="10.0.0.60", confirm=True
    )
    assert applied.applied is True
    rows = fake_connection.path("ip", "firewall", "address-list")._rows
    assert len(rows) == 2


def test_add_to_address_list_rejects_invalid_list_name(client: MikrotikClient, settings_write_enabled: Settings):
    with pytest.raises(ValidationError):
        guard.add_to_address_list(
            client, settings_write_enabled, list_name="bad list", address="10.0.0.61", confirm=True
        )


def test_add_to_address_list_rejects_invalid_address(client: MikrotikClient, settings_write_enabled: Settings):
    with pytest.raises(ValidationError):
        guard.add_to_address_list(
            client, settings_write_enabled, list_name="blocked-clients", address="not-an-ip", confirm=True
        )


def test_add_to_address_list_rejects_invalid_comment(client: MikrotikClient, settings_write_enabled: Settings):
    with pytest.raises(ValidationError):
        guard.add_to_address_list(
            client,
            settings_write_enabled,
            list_name="blocked-clients",
            address="10.0.0.61",
            comment="bad\ncomment",
            confirm=True,
        )


def test_add_to_address_list_rejects_invalid_timeout(client: MikrotikClient, settings_write_enabled: Settings):
    with pytest.raises(ValidationError):
        guard.add_to_address_list(
            client,
            settings_write_enabled,
            list_name="blocked-clients",
            address="10.0.0.61",
            timeout="not-a-timeout",
            confirm=True,
        )


def test_add_to_address_list_rejects_invalid_input_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_to_address_list(
            guarded_client, settings_write_enabled, list_name="blocked-clients", address="not-an-ip", confirm=True
        )


def test_remove_from_address_list_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    assert settings.allow_write is False
    with pytest.raises(WriteDisabledError):
        guard.remove_from_address_list(
            client, settings, list_name="blocked-clients", address="10.0.0.60", confirm=True
        )


def test_remove_from_address_list_read_only_gate_applies_before_touching_device(
    device: Device, settings: Settings
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.remove_from_address_list(
            guarded_client, settings, list_name="blocked-clients", address="10.0.0.60", confirm=True
        )


def test_remove_from_address_list_preview_then_confirm(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.remove_from_address_list(
        client, settings_write_enabled, list_name="blocked-clients", address="10.0.0.60", confirm=False
    )
    assert preview.applied is False
    assert preview.before["address"] == "10.0.0.60"
    # Preview must not have removed anything.
    assert len(fake_connection.path("ip", "firewall", "address-list")._rows) == 1

    applied = guard.remove_from_address_list(
        client, settings_write_enabled, list_name="blocked-clients", address="10.0.0.60", confirm=True
    )
    assert applied.applied is True
    assert fake_connection.path("ip", "firewall", "address-list")._rows == []


def test_remove_from_address_list_unknown_entry_raises_resource_not_found(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.remove_from_address_list(
            client, settings_write_enabled, list_name="blocked-clients", address="10.0.0.99", confirm=True
        )
    assert "10.0.0.99" in str(exc_info.value)
    assert len(fake_connection.path("ip", "firewall", "address-list")._rows) == 1


def test_remove_from_address_list_wrong_list_raises_resource_not_found(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    """The fixture's 10.0.0.60 entry is in "blocked-clients", not "other-list"."""
    with pytest.raises(ResourceNotFoundError):
        guard.remove_from_address_list(
            client, settings_write_enabled, list_name="other-list", address="10.0.0.60", confirm=True
        )
    assert len(fake_connection.path("ip", "firewall", "address-list")._rows) == 1


def test_remove_from_address_list_rejects_invalid_input_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.remove_from_address_list(
            guarded_client, settings_write_enabled, list_name="blocked-clients", address="not-an-ip", confirm=True
        )


# --- set_poe_out (v0.6) ------------------------------------------------------


def test_set_poe_out_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    assert settings.allow_write is False
    with pytest.raises(WriteDisabledError):
        guard.set_poe_out(client, settings, interface_name="ether1", poe_out="off", confirm=True)


def test_set_poe_out_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    """Read-only gate must block *before* touching the device at all, regardless of confirm."""
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.set_poe_out(guarded_client, settings, interface_name="ether1", poe_out="off", confirm=True)


def test_set_poe_out_preview_does_not_apply(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.set_poe_out(
        client, settings_write_enabled, interface_name="ether1", poe_out="off", confirm=False
    )

    assert preview.applied is False
    assert preview.before["poe-out"] == "auto-on"
    assert preview.after["poe-out"] == "off"
    # Nothing was written to the fake device.
    rows = {row["name"]: row.get("poe-out") for row in fake_connection.path("interface", "ethernet")._rows}
    assert rows == {"ether1": "auto-on", "ether2": "off", "sfp1": None}


def test_set_poe_out_confirm_true_applies(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.set_poe_out(
        client, settings_write_enabled, interface_name="ether1", poe_out="off", confirm=True
    )

    assert preview.applied is True
    assert preview.before["poe-out"] == "auto-on"
    assert preview.after["poe-out"] == "off"
    rows = {row["name"]: row.get("poe-out") for row in fake_connection.path("interface", "ethernet")._rows}
    assert rows == {"ether1": "off", "ether2": "off", "sfp1": None}


def test_set_poe_out_dispatches_via_allowlist_id(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    """The write must target the specific interface row by `.id`, not blindly update row 0."""
    guard.set_poe_out(client, settings_write_enabled, interface_name="ether2", poe_out="forced-on", confirm=True)
    rows = {row["name"]: row.get("poe-out") for row in fake_connection.path("interface", "ethernet")._rows}
    # ether1 (row 0) must be untouched; only ether2 (the requested name) changes.
    assert rows == {"ether1": "auto-on", "ether2": "forced-on", "sfp1": None}


def test_set_poe_out_unknown_interface_raises_resource_not_found(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.set_poe_out(client, settings_write_enabled, interface_name="ghost0", poe_out="off", confirm=True)
    assert "ghost0" in str(exc_info.value)
    # Nothing was created.
    names = {row["name"] for row in fake_connection.path("interface", "ethernet")._rows}
    assert names == {"ether1", "ether2", "sfp1"}


def test_set_poe_out_non_poe_interface_raises_resource_not_found(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    """sfp1 exists on the fixture device but has no `poe-out` field at all -
    it must never be silently coerced into a PoE-capable row."""
    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.set_poe_out(client, settings_write_enabled, interface_name="sfp1", poe_out="off", confirm=True)
    assert "sfp1" in str(exc_info.value)


def test_set_poe_out_rejects_invalid_poe_out_value_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.set_poe_out(guarded_client, settings_write_enabled, interface_name="ether1", poe_out="on", confirm=True)


def test_set_poe_out_rejects_invalid_interface_name_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.set_poe_out(
            guarded_client, settings_write_enabled, interface_name="ether1; reboot", poe_out="off", confirm=True
        )


# --- start_container / stop_container (v0.7) --------------------------------


def _containers_fixture() -> FakeConnection:
    return FakeConnection(
        data={
            ("container",): [
                {".id": "*1", "name": "grafana", "tag": "grafana/grafana:latest", "status": "stopped"},
                {".id": "*2", "tag": "alpine:latest", "status": "running"},
            ]
        }
    )


def test_start_container_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    assert settings.allow_write is False
    with pytest.raises(WriteDisabledError):
        guard.start_container(client, settings, container="grafana", confirm=True)


def test_stop_container_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    assert settings.allow_write is False
    with pytest.raises(WriteDisabledError):
        guard.stop_container(client, settings, container="grafana", confirm=True)


def test_start_container_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    """Read-only gate must block *before* touching the device at all, regardless of confirm."""
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.start_container(guarded_client, settings, container="grafana", confirm=True)


def test_stop_container_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.stop_container(guarded_client, settings, container="grafana", confirm=True)


def test_start_container_preview_does_not_apply(settings_write_enabled: Settings, device: Device):
    fake = _containers_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.start_container(client, settings_write_enabled, container="grafana", confirm=False)

    assert preview.applied is False
    assert preview.before["status"] == "stopped"
    assert preview.after["status"] == "starting"
    # Nothing was written to the fake device.
    rows = {row.get("name") or row["tag"]: row["status"] for row in fake.path("container")._rows}
    assert rows == {"grafana": "stopped", "alpine:latest": "running"}


def test_start_container_confirm_true_applies_by_name(settings_write_enabled: Settings, device: Device):
    fake = _containers_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.start_container(client, settings_write_enabled, container="grafana", confirm=True)

    assert preview.applied is True
    assert preview.before["status"] == "stopped"
    assert preview.after["status"] == "starting"
    rows = {row.get("name") or row["tag"]: row["status"] for row in fake.path("container")._rows}
    # FakePath's action handler mutates the row's status to "running" once
    # the "start" command is actually dispatched (confirm=True) - see
    # tests/fakes.py's FakePath.__call__.
    assert rows == {"grafana": "running", "alpine:latest": "running"}


def test_stop_container_confirm_true_applies_by_tag(settings_write_enabled: Settings, device: Device):
    """"alpine:latest" has no `name` field on the fixture row - resolution
    must fall back to matching on `tag`."""
    fake = _containers_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.stop_container(client, settings_write_enabled, container="alpine:latest", confirm=True)

    assert preview.applied is True
    assert preview.operation == "stop_container"
    rows = {row.get("name") or row["tag"]: row["status"] for row in fake.path("container")._rows}
    assert rows == {"grafana": "stopped", "alpine:latest": "stopped"}


def test_start_container_dispatches_via_allowlist_id_only_targeted_row_changes(
    settings_write_enabled: Settings, device: Device
):
    fake = _containers_fixture()
    client = MikrotikClient(device, connection=fake)

    guard.start_container(client, settings_write_enabled, container="grafana", confirm=True)

    rows = {row.get("name") or row["tag"]: row["status"] for row in fake.path("container")._rows}
    # alpine:latest (row 1, already running) must be untouched.
    assert rows == {"grafana": "running", "alpine:latest": "running"}


def test_start_container_unknown_container_raises_resource_not_found(
    settings_write_enabled: Settings, device: Device
):
    fake = _containers_fixture()
    client = MikrotikClient(device, connection=fake)
    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.start_container(client, settings_write_enabled, container="ghost", confirm=True)
    assert "ghost" in str(exc_info.value)
    # Nothing was created or changed.
    rows = {row.get("name") or row["tag"]: row["status"] for row in fake.path("container")._rows}
    assert rows == {"grafana": "stopped", "alpine:latest": "running"}


def test_stop_container_unknown_container_raises_resource_not_found(
    settings_write_enabled: Settings, device: Device
):
    fake = _containers_fixture()
    client = MikrotikClient(device, connection=fake)
    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.stop_container(client, settings_write_enabled, container="ghost", confirm=True)
    assert "ghost" in str(exc_info.value)


def test_start_container_rejects_invalid_identifier_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.start_container(guarded_client, settings_write_enabled, container="grafana\nrm -rf /", confirm=True)


def test_start_container_dispatch_follows_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, settings_write_enabled: Settings, device: Device
):
    """Same proof as test_set_identity_dispatch_follows_allowlist_action
    (A1), for the new start/stop action-command dispatch: point
    ALLOWLIST["start_container"].action at a stub method and confirm THAT
    method gets called with the resolved `.id`, proving `action` (not a
    hardcoded client.start(...) call) actually governs dispatch."""
    fake = _containers_fixture()
    client = MikrotikClient(device, connection=fake)
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["start_container"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "start_container", patched_op)

    guard.start_container(client, settings_write_enabled, container="grafana", confirm=True)

    assert called == {"path": patched_op.path, "fields": {"id": "*1"}}
