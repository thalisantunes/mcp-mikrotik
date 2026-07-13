from __future__ import annotations

import dataclasses

import pytest
from librouteros.exceptions import LibRouterosError

from mcp_mikrotik import guard
from mcp_mikrotik.client import MikrotikClient
from mcp_mikrotik.config import Device, Settings
from mcp_mikrotik.exceptions import (
    AmbiguousResourceError,
    DeviceCommandError,
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


def test_set_identity_read_only_gate_applies_even_with_confirm_true(device: Device, settings: Settings):
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
        assert op.action in {"update", "add", "remove", "start", "stop", "flush", "wol", "save", "move"}


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
    # `before` is the raw fixture row (a real device's bool - see conftest.py
    # and coerce_ros_bool's docstring); `after` is the literal "yes"/"no"
    # RouterOS itself expects as a `set` command value, unaffected.
    assert preview.before["disabled"] is True
    assert preview.after["disabled"] == "no"
    # Nothing was written to the fake device.
    rows = {row["name"]: row["disabled"] for row in fake_connection.path("interface")._rows}
    assert rows == {"ether1": False, "ether2": True}


def test_disable_interface_confirm_true_applies(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.disable_interface(client, settings_write_enabled, interface_name="ether1", confirm=True)

    assert preview.applied is True
    assert preview.before["disabled"] is False
    assert preview.after["disabled"] == "yes"
    rows = {row["name"]: row["disabled"] for row in fake_connection.path("interface")._rows}
    assert rows == {"ether1": "yes", "ether2": True}


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
    assert rows == {"ether1": False, "ether2": "no"}


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


def test_set_wifi_ssid_unknown_interface_raises_resource_not_found(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(data={("interface", "wifi"): [{".id": "*1", "name": "wifi1", "ssid": "old-ssid"}]})
    client = MikrotikClient(device, connection=fake)
    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.set_wifi_ssid(client, settings_write_enabled, interface_name="ghost-radio", new_ssid="x", confirm=True)
    assert "ghost-radio" in str(exc_info.value)


# --- set_wifi_ssid: ROS7 named `configuration` (real-hardware regression) --
#
# Confirmed against a real mANTBox (ROS7, production layout): the
# /interface/wifi row has NO writable `ssid` field at all when it references
# a named `configuration` - only `configuration=<name>`. The real target is
# the matching /interface/wifi/configuration row's own `ssid` field.


def test_set_wifi_ssid_ros7_with_named_configuration_writes_to_configuration_row(
    settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(
        data={
            ("interface", "wifi"): [{".id": "*1", "name": "wifi1", "configuration": "cfg1"}],
            ("interface", "wifi", "configuration"): [{".id": "*5", "name": "cfg1", "ssid": "old-ssid", "mode": "ap"}],
        }
    )
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wifi_ssid(
        client, settings_write_enabled, interface_name="wifi1", new_ssid="new-ssid", confirm=False
    )
    assert preview.operation == "set_wifi_ssid_ros7_configuration"
    assert preview.applied is False
    # Honest before/after: reflects the configuration row's real ssid, not a
    # synthesized field on the interface row (which has none).
    assert preview.before == {".id": "*5", "name": "cfg1", "ssid": "old-ssid", "mode": "ap"}
    assert preview.after["ssid"] == "new-ssid"
    # Preview must not touch the device.
    assert fake.path("interface", "wifi", "configuration")._rows[0]["ssid"] == "old-ssid"
    assert "ssid" not in fake.path("interface", "wifi")._rows[0]

    applied = guard.set_wifi_ssid(
        client, settings_write_enabled, interface_name="wifi1", new_ssid="new-ssid", confirm=True
    )
    assert applied.applied is True
    assert applied.operation == "set_wifi_ssid_ros7_configuration"
    # The configuration row changed...
    assert fake.path("interface", "wifi", "configuration")._rows[0]["ssid"] == "new-ssid"
    # ...and the interface row itself was never touched (still no ssid field).
    assert "ssid" not in fake.path("interface", "wifi")._rows[0]


def test_set_wifi_ssid_ros7_inline_ssid_when_no_configuration_reference(
    settings_write_enabled: Settings, device: Device
):
    """The rare/legacy case (no named `configuration` at all) keeps writing
    inline on /interface/wifi, unchanged from before this fix."""
    fake = FakeConnection(data={("interface", "wifi"): [{".id": "*1", "name": "wifi1", "ssid": "old-ssid"}]})
    client = MikrotikClient(device, connection=fake)

    applied = guard.set_wifi_ssid(
        client, settings_write_enabled, interface_name="wifi1", new_ssid="new-ssid", confirm=True
    )
    assert applied.operation == "set_wifi_ssid_ros7"
    assert fake.path("interface", "wifi")._rows[0]["ssid"] == "new-ssid"


def test_set_wifi_ssid_ros7_unknown_configuration_name_raises_resource_not_found(
    settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(
        data={
            ("interface", "wifi"): [{".id": "*1", "name": "wifi1", "configuration": "ghost-cfg"}],
            ("interface", "wifi", "configuration"): [{".id": "*5", "name": "cfg1", "ssid": "old-ssid"}],
        }
    )
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.set_wifi_ssid(client, settings_write_enabled, interface_name="wifi1", new_ssid="new-ssid", confirm=True)
    assert "ghost-cfg" in str(exc_info.value)
    # Nothing was written anywhere.
    assert fake.path("interface", "wifi", "configuration")._rows[0]["ssid"] == "old-ssid"


def test_set_wifi_ssid_ros7_configuration_read_failure_wrapped_with_clear_context(
    settings_write_enabled: Settings, device: Device
):
    """If the interface references a `configuration` name but
    /interface/wifi/configuration itself can't be read (e.g. a transient
    device-side failure), the resulting DeviceCommandError must be
    re-raised with a message naming BOTH the referenced configuration and
    the underlying failure - never a bare, context-free error."""
    fake = FakeConnection(
        data={("interface", "wifi"): [{".id": "*1", "name": "wifi1", "configuration": "cfg1"}]},
        raise_for={("interface", "wifi", "configuration"): LibRouterosError("no such command")},
    )
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(DeviceCommandError) as exc_info:
        guard.set_wifi_ssid(client, settings_write_enabled, interface_name="wifi1", new_ssid="new-ssid", confirm=True)
    assert "cfg1" in str(exc_info.value)
    assert "could not be read" in str(exc_info.value)


def test_set_wifi_ssid_ros7_ambiguous_interface_raises_clear_device_command_error(
    settings_write_enabled: Settings, device: Device
):
    """No `configuration` reference AND no inline `ssid` field: refuse with a
    clear, explicit error rather than sending a write RouterOS would reject."""
    fake = FakeConnection(data={("interface", "wifi"): [{".id": "*1", "name": "wifi1"}]})
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(DeviceCommandError) as exc_info:
        guard.set_wifi_ssid(client, settings_write_enabled, interface_name="wifi1", new_ssid="new-ssid", confirm=True)
    assert "configuration" in str(exc_info.value)


def test_set_wifi_ssid_ros7_configuration_read_only_gate_applies_before_touching_device(
    device: Device, settings: Settings
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.set_wifi_ssid(guarded_client, settings, interface_name="wifi1", new_ssid="new-ssid", confirm=True)


# --- set_client_bandwidth ---------------------------------------------------


def test_set_client_bandwidth_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    assert settings.allow_write is False
    with pytest.raises(WriteDisabledError):
        guard.set_client_bandwidth(client, settings, target="10.0.0.50", max_limit="10M/5M", confirm=True)


def test_set_client_bandwidth_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.set_client_bandwidth(guarded_client, settings, target="10.0.0.50", max_limit="10M/5M", confirm=True)


def test_set_client_bandwidth_creates_queue_when_none_exists(settings_write_enabled: Settings, device: Device):
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


def test_set_client_bandwidth_updates_existing_queue_for_same_target(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(
        data={
            ("queue", "simple"): [{".id": "*1", "name": "limit-10-0-0-50", "target": "10.0.0.50", "max-limit": "1M/1M"}]
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


def test_set_client_bandwidth_updates_limit_at_on_existing_queue(settings_write_enabled: Settings, device: Device):
    # Same "update" path as test_set_client_bandwidth_updates_existing_queue_for_same_target
    # above, but also passing limit_at - covers the update branch's own
    # (separate) "if limit_at given" handling, not just the create path's.
    fake = FakeConnection(
        data={
            ("queue", "simple"): [{".id": "*1", "name": "limit-10-0-0-50", "target": "10.0.0.50", "max-limit": "1M/1M"}]
        }
    )
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_client_bandwidth(
        client,
        settings_write_enabled,
        target="10.0.0.50",
        max_limit="10M/5M",
        limit_at="2M/1M",
        confirm=False,
    )
    assert preview.after["limit-at"] == "2M/1M"

    applied = guard.set_client_bandwidth(
        client,
        settings_write_enabled,
        target="10.0.0.50",
        max_limit="10M/5M",
        limit_at="2M/1M",
        confirm=True,
    )
    assert applied.applied is True
    assert fake.path("queue", "simple")._rows[0]["limit-at"] == "2M/1M"


def test_set_client_bandwidth_rejects_invalid_target(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(data={("queue", "simple"): []})
    client = MikrotikClient(device, connection=fake)
    with pytest.raises(ValidationError):
        guard.set_client_bandwidth(client, settings_write_enabled, target="not-an-ip", max_limit="10M/5M", confirm=True)
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
    preview = guard.remove_simple_queue(client, settings_write_enabled, target="10.0.0.50/32", confirm=False)
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
        guard.add_to_address_list(client, settings, list_name="blocked-clients", address="10.0.0.61", confirm=True)


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
        guard.remove_from_address_list(client, settings, list_name="blocked-clients", address="10.0.0.60", confirm=True)


def test_remove_from_address_list_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
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
    preview = guard.set_poe_out(client, settings_write_enabled, interface_name="ether1", poe_out="off", confirm=False)

    assert preview.applied is False
    assert preview.before["poe-out"] == "auto-on"
    assert preview.after["poe-out"] == "off"
    # Nothing was written to the fake device.
    rows = {row["name"]: row.get("poe-out") for row in fake_connection.path("interface", "ethernet")._rows}
    assert rows == {"ether1": "auto-on", "ether2": "off", "sfp1": None}


def test_set_poe_out_confirm_true_applies(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.set_poe_out(client, settings_write_enabled, interface_name="ether1", poe_out="off", confirm=True)

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
    """ "alpine:latest" has no `name` field on the fixture row - resolution
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


def test_start_container_unknown_container_raises_resource_not_found(settings_write_enabled: Settings, device: Device):
    fake = _containers_fixture()
    client = MikrotikClient(device, connection=fake)
    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.start_container(client, settings_write_enabled, container="ghost", confirm=True)
    assert "ghost" in str(exc_info.value)
    # Nothing was created or changed.
    rows = {row.get("name") or row["tag"]: row["status"] for row in fake.path("container")._rows}
    assert rows == {"grafana": "stopped", "alpine:latest": "running"}


def test_stop_container_unknown_container_raises_resource_not_found(settings_write_enabled: Settings, device: Device):
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


# --- start/stop_container: no /container menu at all (secondary finding) ---
#
# A device with no container package/hardware support (e.g. a ROS6-only box)
# raises a raw DeviceCommandError from client.path("container") - the read
# tool `containers()` already degrades that gracefully to `[]` (server.py);
# start/stop_container must not leak that raw device-side error either.


def test_start_container_no_container_menu_raises_resource_not_found_not_raw_error(
    settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(raise_for={("container",): LibRouterosError("no such command prefix")})
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.start_container(client, settings_write_enabled, container="grafana", confirm=True)
    assert "grafana" in str(exc_info.value)
    # Never the raw device-side message.
    assert "no such command prefix" not in str(exc_info.value)


def test_stop_container_no_container_menu_raises_resource_not_found_not_raw_error(
    settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(raise_for={("container",): LibRouterosError("no such command prefix")})
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.stop_container(client, settings_write_enabled, container="grafana", confirm=True)
    assert "grafana" in str(exc_info.value)
    assert "no such command prefix" not in str(exc_info.value)


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


# --- set_route_distance / enable_route / disable_route (v0.9) ---------------
#
# The fixture device's ("ip", "route") table (see conftest.fake_connection)
# has row *1: dst-address "0.0.0.0/0" via gateway "10.0.0.254", no
# `distance` field set yet (plus, since v1.5, a couple of unrelated
# static/dynamic rows used by add_route/remove_route tests - see
# conftest.py). Ambiguity tests below build their own two-route
# FakeConnection instead, mirroring set_wifi_ssid's pattern for scenarios
# the shared fixture doesn't cover.


def test_set_route_distance_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    assert settings.allow_write is False
    with pytest.raises(WriteDisabledError):
        guard.set_route_distance(
            client, settings, dst_address="0.0.0.0/0", gateway="10.0.0.254", distance=10, confirm=True
        )


def test_set_route_distance_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.set_route_distance(
            guarded_client, settings, dst_address="0.0.0.0/0", gateway="10.0.0.254", distance=10, confirm=True
        )


def test_set_route_distance_preview_does_not_apply(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.set_route_distance(
        client, settings_write_enabled, dst_address="0.0.0.0/0", gateway="10.0.0.254", distance=5, confirm=False
    )
    assert preview.applied is False
    assert preview.before == {".id": "*1", "dst-address": "0.0.0.0/0", "gateway": "10.0.0.254"}
    assert preview.after["distance"] == "5"
    # Nothing was written to the fake device.
    assert "distance" not in fake_connection.path("ip", "route")._rows[0]


def test_set_route_distance_confirm_true_applies(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.set_route_distance(
        client, settings_write_enabled, dst_address="0.0.0.0/0", gateway="10.0.0.254", distance=5, confirm=True
    )
    assert preview.applied is True
    assert fake_connection.path("ip", "route")._rows[0]["distance"] == "5"


def test_set_route_distance_resolves_by_dst_and_gateway_never_by_index(
    settings_write_enabled: Settings, device: Device
):
    """Two routes share the same dst-address; only the one whose gateway
    also matches must be touched - never row 0 / a positional index."""
    fake = FakeConnection(
        data={
            ("ip", "route"): [
                {".id": "*1", "dst-address": "0.0.0.0/0", "gateway": "10.0.0.254"},
                {".id": "*2", "dst-address": "0.0.0.0/0", "gateway": "10.0.0.253"},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    guard.set_route_distance(
        client, settings_write_enabled, dst_address="0.0.0.0/0", gateway="10.0.0.253", distance=20, confirm=True
    )
    rows = {row["gateway"]: row.get("distance") for row in fake.path("ip", "route")._rows}
    assert rows == {"10.0.0.254": None, "10.0.0.253": "20"}


def test_set_route_distance_unknown_dst_and_gateway_raises_resource_not_found(
    client: MikrotikClient, settings_write_enabled: Settings
):
    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.set_route_distance(
            client, settings_write_enabled, dst_address="10.10.10.0/24", gateway="10.0.0.254", distance=5, confirm=True
        )
    assert "10.10.10.0/24" in str(exc_info.value)


def test_set_route_distance_ambiguous_dst_and_gateway_raises_ambiguous_resource_error(
    settings_write_enabled: Settings, device: Device
):
    """Even (dst-address, gateway) together can, in principle, match more
    than one row (a genuine duplicate) - this is never silently resolved to
    the first match."""
    fake = FakeConnection(
        data={
            ("ip", "route"): [
                {".id": "*1", "dst-address": "0.0.0.0/0", "gateway": "10.0.0.254"},
                {".id": "*2", "dst-address": "0.0.0.0/0", "gateway": "10.0.0.254", "comment": "dup"},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)
    with pytest.raises(AmbiguousResourceError) as exc_info:
        guard.set_route_distance(
            client, settings_write_enabled, dst_address="0.0.0.0/0", gateway="10.0.0.254", distance=5, confirm=True
        )
    assert "0.0.0.0/0" in str(exc_info.value)


def test_set_route_distance_rejects_invalid_distance_before_touching_device(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    with pytest.raises(ValidationError):
        guard.set_route_distance(
            client, settings_write_enabled, dst_address="0.0.0.0/0", gateway="10.0.0.254", distance=999, confirm=True
        )
    assert "distance" not in fake_connection.path("ip", "route")._rows[0]


def test_set_route_distance_rejects_invalid_dst_address_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.set_route_distance(
            guarded_client,
            settings_write_enabled,
            dst_address="not-an-ip",
            gateway="10.0.0.254",
            distance=5,
            confirm=True,
        )


def test_set_route_distance_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, client: MikrotikClient, settings_write_enabled: Settings
):
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["set_route_distance"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "set_route_distance", patched_op)

    guard.set_route_distance(
        client, settings_write_enabled, dst_address="0.0.0.0/0", gateway="10.0.0.254", distance=7, confirm=True
    )

    assert called == {"path": patched_op.path, "fields": {".id": "*1", "distance": "7"}}


def test_enable_route_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.enable_route(client, settings, dst_address="0.0.0.0/0", gateway="10.0.0.254", confirm=True)


def test_disable_route_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.disable_route(client, settings, dst_address="0.0.0.0/0", gateway="10.0.0.254", confirm=True)


def test_enable_route_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.enable_route(guarded_client, settings, dst_address="0.0.0.0/0", gateway="10.0.0.254", confirm=True)


def test_disable_route_preview_then_confirm(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.disable_route(
        client, settings_write_enabled, dst_address="0.0.0.0/0", gateway="10.0.0.254", confirm=False
    )
    assert preview.applied is False
    assert preview.after["disabled"] == "yes"
    assert "disabled" not in fake_connection.path("ip", "route")._rows[0] or (
        fake_connection.path("ip", "route")._rows[0].get("disabled") != "yes"
    )

    applied = guard.disable_route(
        client, settings_write_enabled, dst_address="0.0.0.0/0", gateway="10.0.0.254", confirm=True
    )
    assert applied.applied is True
    assert fake_connection.path("ip", "route")._rows[0]["disabled"] == "yes"


def test_enable_route_after_disable_flips_back(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    guard.disable_route(client, settings_write_enabled, dst_address="0.0.0.0/0", gateway="10.0.0.254", confirm=True)
    applied = guard.enable_route(
        client, settings_write_enabled, dst_address="0.0.0.0/0", gateway="10.0.0.254", confirm=True
    )
    assert applied.applied is True
    assert applied.after["disabled"] == "no"
    assert fake_connection.path("ip", "route")._rows[0]["disabled"] == "no"


def test_disable_route_unknown_route_raises_resource_not_found(
    client: MikrotikClient, settings_write_enabled: Settings
):
    with pytest.raises(ResourceNotFoundError):
        guard.disable_route(
            client, settings_write_enabled, dst_address="10.10.10.0/24", gateway="10.0.0.254", confirm=True
        )


def test_disable_route_ambiguous_without_gateway_or_comment_raises_ambiguous_resource_error(
    settings_write_enabled: Settings, device: Device
):
    """Two routes share dst-address "0.0.0.0/0" - the classic failover
    shape (primary + backup default route). Calling without `gateway` or
    `comment` to disambiguate must error rather than silently pick one."""
    fake = FakeConnection(
        data={
            ("ip", "route"): [
                {".id": "*1", "dst-address": "0.0.0.0/0", "gateway": "10.0.0.254", "comment": "primary"},
                {".id": "*2", "dst-address": "0.0.0.0/0", "gateway": "10.0.0.253", "comment": "backup"},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)
    with pytest.raises(AmbiguousResourceError) as exc_info:
        guard.disable_route(client, settings_write_enabled, dst_address="0.0.0.0/0", confirm=True)
    assert "0.0.0.0/0" in str(exc_info.value)
    # Neither row was touched.
    assert all(row.get("disabled") != "yes" for row in fake.path("ip", "route")._rows)


def test_disable_route_disambiguated_by_comment(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(
        data={
            ("ip", "route"): [
                {".id": "*1", "dst-address": "0.0.0.0/0", "gateway": "10.0.0.254", "comment": "primary"},
                {".id": "*2", "dst-address": "0.0.0.0/0", "gateway": "10.0.0.253", "comment": "backup"},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    applied = guard.disable_route(
        client, settings_write_enabled, dst_address="0.0.0.0/0", comment="backup", confirm=True
    )
    assert applied.applied is True
    rows = {row["comment"]: row.get("disabled") for row in fake.path("ip", "route")._rows}
    assert rows == {"primary": None, "backup": "yes"}


def test_disable_route_default_route_preview_carries_warning(client: MikrotikClient, settings_write_enabled: Settings):
    """dst-address "0.0.0.0/0" (route *1 in the fixture) IS the default
    route - the preview must carry a non-null, explicit warning about
    cutting outbound traffic, both on preview and on the applied result
    (not just one or the other)."""
    preview = guard.disable_route(
        client, settings_write_enabled, dst_address="0.0.0.0/0", gateway="10.0.0.254", confirm=False
    )
    assert preview.warning is not None
    assert "0.0.0.0/0" in preview.warning
    assert "default" in preview.warning.lower()

    applied = guard.disable_route(
        client, settings_write_enabled, dst_address="0.0.0.0/0", gateway="10.0.0.254", confirm=True
    )
    assert applied.warning is not None


def test_disable_route_non_default_route_preview_has_no_warning(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(
        data={("ip", "route"): [{".id": "*1", "dst-address": "10.10.0.0/24", "gateway": "10.0.0.254"}]}
    )
    client = MikrotikClient(device, connection=fake)

    preview = guard.disable_route(
        client, settings_write_enabled, dst_address="10.10.0.0/24", gateway="10.0.0.254", confirm=False
    )
    assert preview.warning is None


def test_enable_route_of_default_route_carries_no_warning(client: MikrotikClient, settings_write_enabled: Settings):
    """Re-enabling (restoring traffic) is never the risky direction - only
    disable_route's warning fires."""
    guard.disable_route(client, settings_write_enabled, dst_address="0.0.0.0/0", gateway="10.0.0.254", confirm=True)
    preview = guard.enable_route(
        client, settings_write_enabled, dst_address="0.0.0.0/0", gateway="10.0.0.254", confirm=False
    )
    assert preview.warning is None


def test_enable_route_rejects_invalid_dst_address_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.enable_route(guarded_client, settings_write_enabled, dst_address="not-an-ip", confirm=True)


# --- add_route / remove_route (v1.5) -----------------------------------------
#
# Closes ROADMAP.md's Tier 1. Reuses _resolve_route/_DEFAULT_ROUTE_DST_ADDRESSES
# (see set_route_distance/enable_route/disable_route block above). Dedicated
# small FakeConnection route tables are built per-test below (mirroring
# test_set_route_distance_resolves_by_dst_and_gateway_never_by_index's
# pattern) rather than relying only on the shared fixture, so each test's
# route table is exactly what it needs.


def test_add_route_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    assert settings.allow_write is False
    with pytest.raises(WriteDisabledError):
        guard.add_route(client, settings, dst_address="10.40.0.0/24", gateway="10.0.0.254", confirm=True)


def test_add_route_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.add_route(guarded_client, settings, dst_address="10.40.0.0/24", gateway="10.0.0.254", confirm=True)


def test_add_route_preview_does_not_apply(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(data={("ip", "route"): [{".id": "*1", "dst-address": "0.0.0.0/0", "gateway": "10.0.0.254"}]})
    client = MikrotikClient(device, connection=fake)

    preview = guard.add_route(
        client, settings_write_enabled, dst_address="10.40.0.0/24", gateway="10.0.0.254", confirm=False
    )
    assert preview.applied is False
    assert preview.before == {}
    assert preview.after == {"dst-address": "10.40.0.0/24", "gateway": "10.0.0.254"}
    # Nothing was written to the fake device.
    assert len(fake.path("ip", "route")._rows) == 1


def test_add_route_confirm_true_applies(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(data={("ip", "route"): [{".id": "*1", "dst-address": "0.0.0.0/0", "gateway": "10.0.0.254"}]})
    client = MikrotikClient(device, connection=fake)

    preview = guard.add_route(
        client, settings_write_enabled, dst_address="10.40.0.0/24", gateway="10.0.0.254", confirm=True
    )
    assert preview.applied is True
    rows = fake.path("ip", "route")._rows
    assert len(rows) == 2
    created = next(row for row in rows if row["dst-address"] == "10.40.0.0/24")
    assert created["gateway"] == "10.0.0.254"
    assert "distance" not in created
    assert "comment" not in created


def test_add_route_includes_optional_distance_and_comment_when_given(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(data={("ip", "route"): []})
    client = MikrotikClient(device, connection=fake)

    guard.add_route(
        client,
        settings_write_enabled,
        dst_address="10.40.0.0/24",
        gateway="10.0.0.254",
        distance=3,
        comment="failover",
        confirm=True,
    )
    created = fake.path("ip", "route")._rows[0]
    assert created["distance"] == "3"
    assert created["comment"] == "failover"


def test_add_route_never_refuses_duplicate_dst_address(settings_write_enabled: Settings, device: Device):
    """Multiple routes sharing a dst-address is the normal failover shape -
    add_route must never raise ResourceAlreadyExistsError, unlike
    add_vlan/add_static_dns."""
    fake = FakeConnection(data={("ip", "route"): [{".id": "*1", "dst-address": "0.0.0.0/0", "gateway": "10.0.0.254"}]})
    client = MikrotikClient(device, connection=fake)

    preview = guard.add_route(
        client, settings_write_enabled, dst_address="0.0.0.0/0", gateway="10.0.0.253", confirm=True
    )
    assert preview.applied is True
    matches = [row for row in fake.path("ip", "route")._rows if row["dst-address"] == "0.0.0.0/0"]
    assert len(matches) == 2


def test_add_route_default_dst_address_carries_warning_on_preview_and_applied(
    settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(data={("ip", "route"): []})
    client = MikrotikClient(device, connection=fake)

    preview = guard.add_route(
        client, settings_write_enabled, dst_address="0.0.0.0/0", gateway="10.0.0.254", confirm=False
    )
    assert preview.warning is not None
    assert "0.0.0.0/0" in preview.warning
    assert "default" in preview.warning.lower()

    applied = guard.add_route(
        client, settings_write_enabled, dst_address="0.0.0.0/0", gateway="10.0.0.254", confirm=True
    )
    assert applied.warning is not None


def test_add_route_non_default_dst_address_carries_no_warning(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(data={("ip", "route"): []})
    client = MikrotikClient(device, connection=fake)

    preview = guard.add_route(
        client, settings_write_enabled, dst_address="10.40.0.0/24", gateway="10.0.0.254", confirm=False
    )
    assert preview.warning is None


def test_add_route_rejects_invalid_dst_address_before_touching_device(settings_write_enabled: Settings, device: Device):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_route(
            guarded_client, settings_write_enabled, dst_address="not-an-ip", gateway="10.0.0.254", confirm=True
        )


def test_add_route_rejects_invalid_gateway_before_touching_device(settings_write_enabled: Settings, device: Device):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_route(
            guarded_client, settings_write_enabled, dst_address="10.40.0.0/24", gateway="not-a-gateway!", confirm=True
        )


def test_add_route_rejects_invalid_distance_before_touching_device(settings_write_enabled: Settings, device: Device):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_route(
            guarded_client,
            settings_write_enabled,
            dst_address="10.40.0.0/24",
            gateway="10.0.0.254",
            distance=999,
            confirm=True,
        )


def test_add_route_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(data={("ip", "route"): []})
    client = MikrotikClient(device, connection=fake)
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["add_route"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "add_route", patched_op)

    guard.add_route(client, settings_write_enabled, dst_address="10.40.0.0/24", gateway="10.0.0.254", confirm=True)

    assert called == {"path": patched_op.path, "fields": {"dst-address": "10.40.0.0/24", "gateway": "10.0.0.254"}}


def test_remove_route_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    assert settings.allow_write is False
    with pytest.raises(WriteDisabledError):
        guard.remove_route(client, settings, dst_address="10.20.0.0/24", confirm=True)


def test_remove_route_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.remove_route(guarded_client, settings, dst_address="10.20.0.0/24", confirm=True)


def _route_fake_with_static_and_dynamic() -> FakeConnection:
    # `dynamic` is a Python `bool` here, not the string "true" - this is
    # what librouteros actually hands back from a real device (confirmed
    # against ROS6/ROS7 hardware; see coerce_ros_bool's docstring in
    # formatting.py). The old string-typed fake masked the 1.5.0 security
    # bug where remove_route's refusal compared this field against the
    # literal string "true" and so never matched a real `True`.
    return FakeConnection(
        data={
            ("ip", "route"): [
                {".id": "*1", "dst-address": "10.20.0.0/24", "gateway": "10.0.0.254"},
                {".id": "*2", "dst-address": "10.30.0.0/24", "gateway": "ether1", "dynamic": True},
            ]
        }
    )


def test_remove_route_preview_does_not_apply(settings_write_enabled: Settings, device: Device):
    fake = _route_fake_with_static_and_dynamic()
    client = MikrotikClient(device, connection=fake)

    preview = guard.remove_route(client, settings_write_enabled, dst_address="10.20.0.0/24", confirm=False)
    assert preview.applied is False
    assert preview.before == {".id": "*1", "dst-address": "10.20.0.0/24", "gateway": "10.0.0.254"}
    assert preview.after == {}
    # Nothing was removed from the fake device.
    assert len(fake.path("ip", "route")._rows) == 2


def test_remove_route_confirm_true_applies(settings_write_enabled: Settings, device: Device):
    fake = _route_fake_with_static_and_dynamic()
    client = MikrotikClient(device, connection=fake)

    preview = guard.remove_route(client, settings_write_enabled, dst_address="10.20.0.0/24", confirm=True)
    assert preview.applied is True
    remaining = {row["dst-address"] for row in fake.path("ip", "route")._rows}
    assert remaining == {"10.30.0.0/24"}


def test_remove_route_resolves_by_dst_address_and_gateway(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(
        data={
            ("ip", "route"): [
                {".id": "*1", "dst-address": "0.0.0.0/0", "gateway": "10.0.0.254", "comment": "primary"},
                {".id": "*2", "dst-address": "0.0.0.0/0", "gateway": "10.0.0.253", "comment": "backup"},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    guard.remove_route(client, settings_write_enabled, dst_address="0.0.0.0/0", gateway="10.0.0.253", confirm=True)
    remaining = {row["gateway"] for row in fake.path("ip", "route")._rows}
    assert remaining == {"10.0.0.254"}


def test_remove_route_ambiguous_without_gateway_raises_ambiguous_resource_error_and_removes_nothing(
    settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(
        data={
            ("ip", "route"): [
                {".id": "*1", "dst-address": "0.0.0.0/0", "gateway": "10.0.0.254", "comment": "primary"},
                {".id": "*2", "dst-address": "0.0.0.0/0", "gateway": "10.0.0.253", "comment": "backup"},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(AmbiguousResourceError) as exc_info:
        guard.remove_route(client, settings_write_enabled, dst_address="0.0.0.0/0", confirm=True)
    assert "0.0.0.0/0" in str(exc_info.value)
    assert len(fake.path("ip", "route")._rows) == 2


def test_remove_route_unknown_dst_address_raises_resource_not_found(settings_write_enabled: Settings, device: Device):
    fake = _route_fake_with_static_and_dynamic()
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.remove_route(client, settings_write_enabled, dst_address="10.99.0.0/24", confirm=True)
    assert "10.99.0.0/24" in str(exc_info.value)


def test_remove_route_refuses_dynamic_route_and_does_not_remove_it(settings_write_enabled: Settings, device: Device):
    """CRITICAL for this round: a route whose resolved row has
    dynamic=True - a Python bool, the real shape librouteros hands back
    from hardware, NOT the string "true" (see coerce_ros_bool) - must raise
    ValidationError and must NOT be removed from the device - removing a
    device's connected/dynamic route can sever the network."""
    fake = _route_fake_with_static_and_dynamic()
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ValidationError) as exc_info:
        guard.remove_route(client, settings_write_enabled, dst_address="10.30.0.0/24", confirm=True)
    assert "dynamic" in str(exc_info.value).lower()

    # The row must still be present in the fake's own row storage - proof
    # the write primitive was never called.
    remaining = {row["dst-address"] for row in fake.path("ip", "route")._rows}
    assert "10.30.0.0/24" in remaining
    assert len(fake.path("ip", "route")._rows) == 2


def test_remove_route_refuses_dynamic_route_even_on_preview(settings_write_enabled: Settings, device: Device):
    """The dynamic-route refusal must fire identically for confirm=False -
    a caller must never be able to even preview past this refusal in a way
    that suggests removing a dynamic/connected route is fine."""
    fake = _route_fake_with_static_and_dynamic()
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ValidationError) as exc_info:
        guard.remove_route(client, settings_write_enabled, dst_address="10.30.0.0/24", confirm=False)
    assert "dynamic" in str(exc_info.value).lower()

    # The row must still be present in the fake's own row storage - proof
    # the refusal happens before any preview/write path is reached.
    remaining = {row["dst-address"] for row in fake.path("ip", "route")._rows}
    assert "10.30.0.0/24" in remaining
    assert len(fake.path("ip", "route")._rows) == 2


def test_remove_route_regression_dynamic_bool_true_is_refused_not_silently_removed(
    settings_write_enabled: Settings, device: Device
):
    """SECURITY REGRESSION (1.5.0): before the fix, remove_route's refusal
    was `row.get("dynamic") == "true"`. librouteros never actually sends
    the string "true" for a RouterOS boolean field - a real device sends
    the Python bool `True` (ROS7) or, for a false/absent one, `False` or
    omits the field entirely (ROS6) - so `True == "true"` was always
    `False` and this refusal never fired on real hardware: a dynamic/
    connected/default route could be removed outright, potentially
    severing the network. This test proves the CURRENT behaviour is
    correct for the real (bool) shape; before the `coerce_ros_bool` fix,
    it would have failed - the write would have gone through instead of
    raising."""
    fake = FakeConnection(
        data={
            ("ip", "route"): [
                {".id": "*1", "dst-address": "10.30.0.0/24", "gateway": "ether1", "dynamic": True},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ValidationError):
        guard.remove_route(client, settings_write_enabled, dst_address="10.30.0.0/24", confirm=True)

    # Nothing was removed - the write primitive was never reached.
    assert len(fake.path("ip", "route")._rows) == 1


def test_remove_route_allows_removal_when_dynamic_is_bool_false(settings_write_enabled: Settings, device: Device):
    """ROS7 shape for a static route: `dynamic` present and explicitly
    `False` (bool). Must be removable - only dynamic=True is refused."""
    fake = FakeConnection(
        data={
            ("ip", "route"): [
                {".id": "*1", "dst-address": "10.20.0.0/24", "gateway": "10.0.0.254", "dynamic": False},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    preview = guard.remove_route(client, settings_write_enabled, dst_address="10.20.0.0/24", confirm=True)
    assert preview.applied is True
    assert fake.path("ip", "route")._rows == []


def test_remove_route_allows_removal_when_dynamic_field_is_absent(settings_write_enabled: Settings, device: Device):
    """ROS6 shape for a static route: `dynamic` OMITTED entirely (not sent
    as False) - `row.get("dynamic")` is `None`. Must still be removable;
    only a resolved dynamic=True refuses."""
    fake = FakeConnection(
        data={
            ("ip", "route"): [
                {".id": "*1", "dst-address": "10.20.0.0/24", "gateway": "10.0.0.254"},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    preview = guard.remove_route(client, settings_write_enabled, dst_address="10.20.0.0/24", confirm=True)
    assert preview.applied is True
    assert fake.path("ip", "route")._rows == []


def test_remove_route_still_refuses_dynamic_string_true_for_defensive_compatibility(
    settings_write_enabled: Settings, device: Device
):
    """coerce_ros_bool also accepts the string "true" (case-insensitively) -
    belt-and-suspenders in case any code path/RouterOS version ever does
    send a string instead of the real bool."""
    fake = FakeConnection(
        data={
            ("ip", "route"): [
                {".id": "*1", "dst-address": "10.30.0.0/24", "gateway": "ether1", "dynamic": "true"},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ValidationError):
        guard.remove_route(client, settings_write_enabled, dst_address="10.30.0.0/24", confirm=True)


def test_remove_route_default_dst_address_carries_warning_not_refusal(settings_write_enabled: Settings, device: Device):
    """Removing a STATIC default route is a legitimate operation - it gets
    a warning, not the hard refusal reserved for dynamic routes."""
    fake = FakeConnection(data={("ip", "route"): [{".id": "*1", "dst-address": "0.0.0.0/0", "gateway": "10.0.0.254"}]})
    client = MikrotikClient(device, connection=fake)

    preview = guard.remove_route(client, settings_write_enabled, dst_address="0.0.0.0/0", confirm=False)
    assert preview.warning is not None
    assert "0.0.0.0/0" in preview.warning
    assert "default" in preview.warning.lower()

    applied = guard.remove_route(client, settings_write_enabled, dst_address="0.0.0.0/0", confirm=True)
    assert applied.warning is not None
    assert applied.applied is True


def test_remove_route_non_default_dst_address_carries_no_warning(settings_write_enabled: Settings, device: Device):
    fake = _route_fake_with_static_and_dynamic()
    client = MikrotikClient(device, connection=fake)

    preview = guard.remove_route(client, settings_write_enabled, dst_address="10.20.0.0/24", confirm=False)
    assert preview.warning is None


def test_remove_route_rejects_invalid_dst_address_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.remove_route(guarded_client, settings_write_enabled, dst_address="not-an-ip", confirm=True)


def test_remove_route_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(
        data={("ip", "route"): [{".id": "*1", "dst-address": "10.20.0.0/24", "gateway": "10.0.0.254"}]}
    )
    client = MikrotikClient(device, connection=fake)
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["remove_route"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "remove_route", patched_op)

    guard.remove_route(client, settings_write_enabled, dst_address="10.20.0.0/24", confirm=True)

    assert called == {"path": patched_op.path, "fields": {"ids": ("*1",)}}


# --- add_netwatch / remove_netwatch (v0.9) -----------------------------------
#
# The fixture device's ("tool", "netwatch") table (see conftest) has one row
# already: host "8.8.8.8", comment "primary gateway".


def test_add_netwatch_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.add_netwatch(client, settings, host="1.1.1.1", confirm=True)


def test_add_netwatch_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.add_netwatch(guarded_client, settings, host="1.1.1.1", confirm=True)


def test_add_netwatch_preview_does_not_create(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.add_netwatch(client, settings_write_enabled, host="1.1.1.1", confirm=False)
    assert preview.applied is False
    assert preview.before == {}
    assert preview.after == {"host": "1.1.1.1"}
    hosts = {row["host"] for row in fake_connection.path("tool", "netwatch")._rows}
    assert hosts == {"8.8.8.8"}


def test_add_netwatch_confirm_true_creates(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.add_netwatch(
        client, settings_write_enabled, host="1.1.1.1", interval="30s", comment="secondary gateway", confirm=True
    )
    assert preview.applied is True
    hosts = {row["host"]: row for row in fake_connection.path("tool", "netwatch")._rows}
    assert "1.1.1.1" in hosts
    assert hosts["1.1.1.1"]["interval"] == "30s"
    assert hosts["1.1.1.1"]["comment"] == "secondary gateway"


def test_add_netwatch_rejects_duplicate_host(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    with pytest.raises(ResourceAlreadyExistsError) as exc_info:
        guard.add_netwatch(client, settings_write_enabled, host="8.8.8.8", confirm=True)
    assert "8.8.8.8" in str(exc_info.value)
    # Still exactly one row for that host.
    hosts = [row["host"] for row in fake_connection.path("tool", "netwatch")._rows]
    assert hosts.count("8.8.8.8") == 1


def test_add_netwatch_rejects_invalid_host_before_touching_device(settings_write_enabled: Settings, device: Device):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_netwatch(guarded_client, settings_write_enabled, host="not-an-ip", confirm=True)


def test_add_netwatch_rejects_invalid_interval_before_touching_device(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    with pytest.raises(ValidationError):
        guard.add_netwatch(client, settings_write_enabled, host="1.1.1.1", interval="not-a-duration", confirm=True)
    hosts = {row["host"] for row in fake_connection.path("tool", "netwatch")._rows}
    assert "1.1.1.1" not in hosts


def test_add_netwatch_never_accepts_up_script_or_down_script(client: MikrotikClient, settings_write_enabled: Settings):
    """SECURITY: add_netwatch has no up_script/down_script parameter at
    all - passing one raises TypeError (an unexpected keyword argument),
    proving there is no code path through which a caller can smuggle an
    executable RouterOS script onto this monitor."""
    with pytest.raises(TypeError):
        guard.add_netwatch(
            client,
            settings_write_enabled,
            host="1.1.1.1",
            confirm=True,
            up_script=':log warning "gw down"',  # type: ignore[call-arg]
        )
    with pytest.raises(TypeError):
        guard.add_netwatch(
            client,
            settings_write_enabled,
            host="1.1.1.2",
            confirm=True,
            down_script=':log warning "gw down"',  # type: ignore[call-arg]
        )


def test_remove_netwatch_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.remove_netwatch(client, settings, host="8.8.8.8", confirm=True)


def test_remove_netwatch_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.remove_netwatch(guarded_client, settings, host="8.8.8.8", confirm=True)


def test_remove_netwatch_requires_host_or_comment(client: MikrotikClient, settings_write_enabled: Settings):
    with pytest.raises(ValidationError):
        guard.remove_netwatch(client, settings_write_enabled, confirm=True)


def test_remove_netwatch_by_host_preview_then_confirm(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.remove_netwatch(client, settings_write_enabled, host="8.8.8.8", confirm=False)
    assert preview.applied is False
    assert preview.before["host"] == "8.8.8.8"
    assert preview.after == {}
    # Not removed yet.
    hosts = {row["host"] for row in fake_connection.path("tool", "netwatch")._rows}
    assert "8.8.8.8" in hosts

    applied = guard.remove_netwatch(client, settings_write_enabled, host="8.8.8.8", confirm=True)
    assert applied.applied is True
    hosts = {row["host"] for row in fake_connection.path("tool", "netwatch")._rows}
    assert "8.8.8.8" not in hosts


def test_remove_netwatch_by_comment(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    applied = guard.remove_netwatch(client, settings_write_enabled, comment="primary gateway", confirm=True)
    assert applied.applied is True
    hosts = {row["host"] for row in fake_connection.path("tool", "netwatch")._rows}
    assert "8.8.8.8" not in hosts


def test_remove_netwatch_unknown_host_raises_resource_not_found(
    client: MikrotikClient, settings_write_enabled: Settings
):
    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.remove_netwatch(client, settings_write_enabled, host="9.9.9.9", confirm=True)
    assert "9.9.9.9" in str(exc_info.value)


def test_remove_netwatch_rejects_invalid_host_before_touching_device(settings_write_enabled: Settings, device: Device):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.remove_netwatch(guarded_client, settings_write_enabled, host="not-an-ip", confirm=True)


def test_remove_netwatch_ambiguous_host_raises_ambiguous_resource_error(
    settings_write_enabled: Settings, device: Device
):
    """Two netwatch monitors sharing the same `host` (only reachable via
    manual/WinBox configuration outside this tool - add_netwatch itself
    refuses to create a duplicate host). remove_netwatch must never guess
    which one to remove; it must raise instead of silently first-matching."""
    fake = FakeConnection(
        data={
            ("tool", "netwatch"): [
                {".id": "*1", "host": "8.8.8.8", "comment": "primary gateway"},
                {".id": "*2", "host": "8.8.8.8", "comment": "duplicate probe"},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)
    with pytest.raises(AmbiguousResourceError) as exc_info:
        guard.remove_netwatch(client, settings_write_enabled, host="8.8.8.8", confirm=True)
    assert "8.8.8.8" in str(exc_info.value)
    # Neither row was removed.
    hosts = [row["host"] for row in fake.path("tool", "netwatch")._rows]
    assert hosts.count("8.8.8.8") == 2


def test_remove_netwatch_ambiguous_comment_raises_ambiguous_resource_error(
    settings_write_enabled: Settings, device: Device
):
    """Same ambiguity guard, but resolved by `comment` (no `host` match) -
    two rows sharing the same `comment`."""
    fake = FakeConnection(
        data={
            ("tool", "netwatch"): [
                {".id": "*1", "host": "8.8.8.8", "comment": "shared label"},
                {".id": "*2", "host": "1.1.1.1", "comment": "shared label"},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)
    with pytest.raises(AmbiguousResourceError) as exc_info:
        guard.remove_netwatch(client, settings_write_enabled, comment="shared label", confirm=True)
    assert "shared label" in str(exc_info.value)
    assert len(fake.path("tool", "netwatch")._rows) == 2


def test_remove_netwatch_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, client: MikrotikClient, settings_write_enabled: Settings
):
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["remove_netwatch"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "remove_netwatch", patched_op)

    guard.remove_netwatch(client, settings_write_enabled, host="8.8.8.8", confirm=True)

    assert called == {"path": patched_op.path, "fields": {"ids": ("*1",)}}


# --- add_static_dns / remove_static_dns (v0.10) -----------------------------


def _static_dns_fixture() -> FakeConnection:
    return FakeConnection(
        data={
            ("ip", "dns", "static"): [
                {".id": "*1", "name": "blocked.example.com", "type": "A", "address": "0.0.0.0"},
                {".id": "*2", "name": "alias.example.com", "type": "CNAME", "cname": "target.example.com"},
                # Round-robin: two "A" records sharing a `name` - the
                # ambiguity case remove_static_dns must refuse to guess on.
                {".id": "*3", "name": "roundrobin.example.com", "type": "A", "address": "10.0.0.1"},
                {".id": "*4", "name": "roundrobin.example.com", "type": "A", "address": "10.0.0.2"},
            ]
        }
    )


def test_add_static_dns_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.add_static_dns(client, settings, name="new.example.com", address="10.0.0.9", confirm=True)


def test_add_static_dns_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.add_static_dns(guarded_client, settings, name="new.example.com", address="10.0.0.9", confirm=True)


def test_add_static_dns_preview_does_not_apply(settings_write_enabled: Settings, device: Device):
    fake = _static_dns_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.add_static_dns(
        client, settings_write_enabled, name="new.example.com", address="10.0.0.9", confirm=False
    )

    assert preview.applied is False
    assert preview.before == {}
    assert preview.after == {"name": "new.example.com", "type": "A", "address": "10.0.0.9"}
    names = {row["name"] for row in fake.path("ip", "dns", "static")._rows}
    assert "new.example.com" not in names


def test_add_static_dns_confirm_true_applies_a_record(settings_write_enabled: Settings, device: Device):
    fake = _static_dns_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.add_static_dns(
        client,
        settings_write_enabled,
        name="new.example.com",
        address="10.0.0.9",
        ttl="1d",
        comment="internal override",
        confirm=True,
    )

    assert preview.applied is True
    rows = fake.path("ip", "dns", "static")._rows
    created = next(row for row in rows if row["name"] == "new.example.com")
    assert created["type"] == "A"
    assert created["address"] == "10.0.0.9"
    assert created["ttl"] == "1d"
    assert created["comment"] == "internal override"


def test_add_static_dns_cname_writes_cname_field_not_address(settings_write_enabled: Settings, device: Device):
    fake = _static_dns_fixture()
    client = MikrotikClient(device, connection=fake)

    guard.add_static_dns(
        client,
        settings_write_enabled,
        name="www.example.com",
        address="target.example.com",
        record_type="CNAME",
        confirm=True,
    )

    rows = fake.path("ip", "dns", "static")._rows
    created = next(row for row in rows if row["name"] == "www.example.com")
    assert created["type"] == "CNAME"
    assert created["cname"] == "target.example.com"
    assert "address" not in created


def test_add_static_dns_rejects_duplicate_name_and_type(settings_write_enabled: Settings, device: Device):
    fake = _static_dns_fixture()
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ResourceAlreadyExistsError):
        guard.add_static_dns(
            client, settings_write_enabled, name="blocked.example.com", address="1.2.3.4", confirm=True
        )
    # Nothing was added.
    rows = [row for row in fake.path("ip", "dns", "static")._rows if row["name"] == "blocked.example.com"]
    assert len(rows) == 1


def test_add_static_dns_allows_same_name_different_type(settings_write_enabled: Settings, device: Device):
    """A CNAME and an A record can legitimately share a `name` with a
    different `type` - only the exact name+type pair is a duplicate."""
    fake = _static_dns_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.add_static_dns(
        client, settings_write_enabled, name="alias.example.com", address="10.0.0.5", record_type="A", confirm=True
    )
    assert preview.applied is True


def test_add_static_dns_rejects_invalid_name_before_touching_device(settings_write_enabled: Settings, device: Device):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_static_dns(
            guarded_client, settings_write_enabled, name="not a host", address="10.0.0.9", confirm=True
        )


def test_add_static_dns_rejects_invalid_address_for_a_record_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_static_dns(
            guarded_client, settings_write_enabled, name="new.example.com", address="not-an-ip", confirm=True
        )


def test_add_static_dns_rejects_ip_as_cname_target_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    """A CNAME target must be a hostname, not a literal IP - validate_dns_name
    (not validate_ip_address) governs the `address` param when record_type
    is CNAME."""
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_static_dns(
            guarded_client,
            settings_write_enabled,
            name="www.example.com",
            address="10.0.0.9",
            record_type="CNAME",
            confirm=True,
        )


def test_add_static_dns_rejects_invalid_record_type_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_static_dns(
            guarded_client,
            settings_write_enabled,
            name="new.example.com",
            address="10.0.0.9",
            record_type="MX",
            confirm=True,
        )


def test_add_static_dns_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, settings_write_enabled: Settings, device: Device
):
    fake = _static_dns_fixture()
    client = MikrotikClient(device, connection=fake)
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["add_static_dns"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "add_static_dns", patched_op)

    guard.add_static_dns(client, settings_write_enabled, name="new.example.com", address="10.0.0.9", confirm=True)

    assert called == {
        "path": patched_op.path,
        "fields": {"name": "new.example.com", "type": "A", "address": "10.0.0.9"},
    }


def test_remove_static_dns_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.remove_static_dns(client, settings, name="blocked.example.com", confirm=True)


def test_remove_static_dns_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.remove_static_dns(guarded_client, settings, name="blocked.example.com", confirm=True)


def test_remove_static_dns_preview_then_confirm(settings_write_enabled: Settings, device: Device):
    fake = _static_dns_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.remove_static_dns(client, settings_write_enabled, name="blocked.example.com", confirm=False)
    assert preview.applied is False
    assert preview.before["address"] == "0.0.0.0"
    names = {row["name"] for row in fake.path("ip", "dns", "static")._rows}
    assert "blocked.example.com" in names

    applied = guard.remove_static_dns(client, settings_write_enabled, name="blocked.example.com", confirm=True)
    assert applied.applied is True
    names = {row["name"] for row in fake.path("ip", "dns", "static")._rows}
    assert "blocked.example.com" not in names


def test_remove_static_dns_unknown_name_raises_resource_not_found(settings_write_enabled: Settings, device: Device):
    fake = _static_dns_fixture()
    client = MikrotikClient(device, connection=fake)
    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.remove_static_dns(client, settings_write_enabled, name="ghost.example.com", confirm=True)
    assert "ghost.example.com" in str(exc_info.value)


def test_remove_static_dns_ambiguous_without_record_type_raises(settings_write_enabled: Settings, device: Device):
    fake = _static_dns_fixture()
    client = MikrotikClient(device, connection=fake)
    with pytest.raises(AmbiguousResourceError):
        guard.remove_static_dns(client, settings_write_enabled, name="roundrobin.example.com", confirm=True)
    # Neither row was removed.
    rows = [row for row in fake.path("ip", "dns", "static")._rows if row["name"] == "roundrobin.example.com"]
    assert len(rows) == 2


def test_remove_static_dns_resolves_uniquely_when_type_given(settings_write_enabled: Settings, device: Device):
    """Same `name` shared by two rows is only ambiguous when `record_type`
    is also shared - a CNAME and an A record with the same `name` resolve
    unambiguously by `record_type` alone."""
    fake = _static_dns_fixture()
    client = MikrotikClient(device, connection=fake)

    applied = guard.remove_static_dns(
        client, settings_write_enabled, name="alias.example.com", record_type="CNAME", confirm=True
    )
    assert applied.applied is True
    names = {row["name"] for row in fake.path("ip", "dns", "static")._rows}
    assert "alias.example.com" not in names


def test_remove_static_dns_rejects_invalid_name_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.remove_static_dns(guarded_client, settings_write_enabled, name="not a host", confirm=True)


def test_remove_static_dns_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, settings_write_enabled: Settings, device: Device
):
    fake = _static_dns_fixture()
    client = MikrotikClient(device, connection=fake)
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["remove_static_dns"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "remove_static_dns", patched_op)

    guard.remove_static_dns(client, settings_write_enabled, name="blocked.example.com", confirm=True)

    assert called == {"path": patched_op.path, "fields": {"ids": ("*1",)}}


# --- clear_dns_cache (v0.10) -------------------------------------------------


def test_clear_dns_cache_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.clear_dns_cache(client, settings, confirm=True)


def test_clear_dns_cache_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.clear_dns_cache(guarded_client, settings, confirm=True)


def test_clear_dns_cache_preview_reports_current_count_and_does_not_apply(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    """The shared fixture's ("ip", "dns", "cache") has exactly one cached
    entry."""
    preview = guard.clear_dns_cache(client, settings_write_enabled, confirm=False)
    assert preview.applied is False
    assert preview.before == {"cached_entries": 1}
    assert preview.after == {"cached_entries": 0}
    assert fake_connection.calls == []  # nothing sent to the device yet


def test_clear_dns_cache_confirm_true_sends_the_flush_command(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.clear_dns_cache(client, settings_write_enabled, confirm=True)
    assert preview.applied is True
    assert ("/ip/dns/cache/flush", {}) in fake_connection.calls


def test_clear_dns_cache_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, client: MikrotikClient, settings_write_enabled: Settings
):
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["clear_dns_cache"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "clear_dns_cache", patched_op)

    guard.clear_dns_cache(client, settings_write_enabled, confirm=True)

    assert called == {"path": patched_op.path, "fields": {}}


# --- remove_dhcp_lease (v0.10) -----------------------------------------------


def _dhcp_leases_fixture() -> FakeConnection:
    # `dynamic` is a Python bool here (librouteros' real shape - see
    # coerce_ros_bool in formatting.py), not the string "true"/"false" a
    # prior version of this fixture used.
    return FakeConnection(
        data={
            ("ip", "dhcp-server", "lease"): [
                {
                    ".id": "*1",
                    "address": "10.0.0.50",
                    "mac-address": "AA:BB:CC:DD:EE:01",
                    "dynamic": True,
                    "status": "bound",
                },
                {
                    ".id": "*2",
                    "address": "10.0.0.60",
                    "mac-address": "AA:BB:CC:DD:EE:02",
                    "dynamic": False,
                    "status": "bound",
                },
            ]
        }
    )


def test_remove_dhcp_lease_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.remove_dhcp_lease(client, settings, mac_address="AA:BB:CC:DD:EE:01", confirm=True)


def test_remove_dhcp_lease_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.remove_dhcp_lease(guarded_client, settings, mac_address="AA:BB:CC:DD:EE:01", confirm=True)


def test_remove_dhcp_lease_requires_address_or_mac(settings_write_enabled: Settings, device: Device):
    fake = _dhcp_leases_fixture()
    client = MikrotikClient(device, connection=fake)
    with pytest.raises(ValidationError):
        guard.remove_dhcp_lease(client, settings_write_enabled, confirm=True)


def test_remove_dhcp_lease_by_mac_dynamic_no_warning(settings_write_enabled: Settings, device: Device):
    fake = _dhcp_leases_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.remove_dhcp_lease(client, settings_write_enabled, mac_address="AA:BB:CC:DD:EE:01", confirm=False)
    assert preview.applied is False
    assert preview.warning is None
    assert preview.before["address"] == "10.0.0.50"

    applied = guard.remove_dhcp_lease(client, settings_write_enabled, mac_address="AA:BB:CC:DD:EE:01", confirm=True)
    assert applied.applied is True
    assert applied.warning is None
    macs = {row["mac-address"] for row in fake.path("ip", "dhcp-server", "lease")._rows}
    assert "AA:BB:CC:DD:EE:01" not in macs


def test_remove_dhcp_lease_by_address_dynamic_no_warning(settings_write_enabled: Settings, device: Device):
    fake = _dhcp_leases_fixture()
    client = MikrotikClient(device, connection=fake)

    applied = guard.remove_dhcp_lease(client, settings_write_enabled, address="10.0.0.50", confirm=True)
    assert applied.applied is True
    assert applied.warning is None
    addresses = {row["address"] for row in fake.path("ip", "dhcp-server", "lease")._rows}
    assert "10.0.0.50" not in addresses


def test_remove_dhcp_lease_static_lease_carries_warning_on_preview_and_apply(
    settings_write_enabled: Settings, device: Device
):
    fake = _dhcp_leases_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.remove_dhcp_lease(client, settings_write_enabled, mac_address="AA:BB:CC:DD:EE:02", confirm=False)
    assert preview.applied is False
    assert preview.warning is not None
    assert "STATIC" in preview.warning

    applied = guard.remove_dhcp_lease(client, settings_write_enabled, mac_address="AA:BB:CC:DD:EE:02", confirm=True)
    assert applied.applied is True
    assert applied.warning is not None
    assert "STATIC" in applied.warning
    macs = {row["mac-address"] for row in fake.path("ip", "dhcp-server", "lease")._rows}
    assert "AA:BB:CC:DD:EE:02" not in macs


def test_remove_dhcp_lease_static_warning_fires_when_dynamic_field_is_absent(
    settings_write_enabled: Settings, device: Device
):
    """ROS6 shape: `dynamic` OMITTED entirely on a static lease (not sent
    as False) - `row.get("dynamic")` is `None`. Same class of fix as
    remove_route: coerce_ros_bool(None) is not True, so this must still be
    treated as "not confirmably dynamic" and carry the static-lease
    warning, same as an explicit dynamic=False."""
    fake = FakeConnection(
        data={
            ("ip", "dhcp-server", "lease"): [
                {".id": "*1", "address": "10.0.0.70", "mac-address": "AA:BB:CC:DD:EE:03", "status": "bound"},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    preview = guard.remove_dhcp_lease(client, settings_write_enabled, mac_address="AA:BB:CC:DD:EE:03", confirm=False)
    assert preview.warning is not None
    assert "STATIC" in preview.warning


def test_remove_dhcp_lease_mac_tried_before_address_when_both_given(settings_write_enabled: Settings, device: Device):
    """mac_address is the more stable identifier - tried first if both are
    given, mirroring remove_netwatch's "host tried first" convention."""
    fake = _dhcp_leases_fixture()
    client = MikrotikClient(device, connection=fake)

    # Mismatched pair: mac_address resolves to the dynamic lease, address
    # would resolve to the static one - the mac_address match must win.
    preview = guard.remove_dhcp_lease(
        client,
        settings_write_enabled,
        mac_address="AA:BB:CC:DD:EE:01",
        address="10.0.0.60",
        confirm=False,
    )
    assert preview.before["mac-address"] == "AA:BB:CC:DD:EE:01"
    assert preview.warning is None  # resolved the dynamic one, not the static one


def test_remove_dhcp_lease_unknown_raises_resource_not_found(settings_write_enabled: Settings, device: Device):
    fake = _dhcp_leases_fixture()
    client = MikrotikClient(device, connection=fake)
    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.remove_dhcp_lease(client, settings_write_enabled, mac_address="AA:BB:CC:DD:EE:99", confirm=True)
    assert "AA:BB:CC:DD:EE:99" in str(exc_info.value)


def test_remove_dhcp_lease_rejects_invalid_mac_before_touching_device(settings_write_enabled: Settings, device: Device):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.remove_dhcp_lease(guarded_client, settings_write_enabled, mac_address="not-a-mac", confirm=True)


def test_remove_dhcp_lease_rejects_invalid_address_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.remove_dhcp_lease(guarded_client, settings_write_enabled, address="not-an-ip", confirm=True)


def test_remove_dhcp_lease_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, settings_write_enabled: Settings, device: Device
):
    fake = _dhcp_leases_fixture()
    client = MikrotikClient(device, connection=fake)
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["remove_dhcp_lease"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "remove_dhcp_lease", patched_op)

    guard.remove_dhcp_lease(client, settings_write_enabled, mac_address="AA:BB:CC:DD:EE:01", confirm=True)

    assert called == {"path": patched_op.path, "fields": {"ids": ("*1",)}}


# --- wake_on_lan (v0.10) ------------------------------------------------------


def test_wake_on_lan_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.wake_on_lan(client, settings, mac_address="AA:BB:CC:DD:EE:FF", interface="ether1", confirm=True)


def test_wake_on_lan_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.wake_on_lan(guarded_client, settings, mac_address="AA:BB:CC:DD:EE:FF", interface="ether1", confirm=True)


def test_wake_on_lan_preview_never_touches_the_device(settings_write_enabled: Settings, device: Device):
    """wake_on_lan resolves nothing on the device first (unlike every other
    write tool, there is no existing row to read) - a preview must not call
    the connection at all."""
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    preview = guard.wake_on_lan(
        guarded_client, settings_write_enabled, mac_address="AA:BB:CC:DD:EE:FF", interface="ether1", confirm=False
    )
    assert preview.applied is False
    assert preview.after == {"mac_address": "AA:BB:CC:DD:EE:FF", "interface": "ether1"}


def test_wake_on_lan_confirm_true_sends_the_wol_command(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.wake_on_lan(
        client, settings_write_enabled, mac_address="aa:bb:cc:dd:ee:ff", interface="ether1", confirm=True
    )
    assert preview.applied is True
    assert ("/tool/wol", {"mac-address": "AA:BB:CC:DD:EE:FF", "interface": "ether1"}) in fake_connection.calls


def test_wake_on_lan_rejects_invalid_mac_before_touching_device(settings_write_enabled: Settings, device: Device):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.wake_on_lan(
            guarded_client, settings_write_enabled, mac_address="not-a-mac", interface="ether1", confirm=True
        )


def test_wake_on_lan_rejects_invalid_interface_before_touching_device(settings_write_enabled: Settings, device: Device):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.wake_on_lan(
            guarded_client,
            settings_write_enabled,
            mac_address="AA:BB:CC:DD:EE:FF",
            interface="ether 1",
            confirm=True,
        )


def test_wake_on_lan_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, client: MikrotikClient, settings_write_enabled: Settings
):
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["wake_on_lan"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "wake_on_lan", patched_op)

    guard.wake_on_lan(client, settings_write_enabled, mac_address="AA:BB:CC:DD:EE:FF", interface="ether1", confirm=True)

    assert called == {
        "path": patched_op.path,
        "fields": {"mac_address": "AA:BB:CC:DD:EE:FF", "interface": "ether1"},
    }


# --- enable_firewall_rule / disable_firewall_rule (v0.11) -----------------
#
# The shared fixture's ("ip", "firewall", "filter") table (see conftest) has
# two rows: "*1" (comment "allow established", chain "input", enabled) and
# "*2" (comment "Bloqueio_Ataque_X", chain "forward", action "drop",
# pre-created DISABLED - the admin-creates/LLM-enables workflow this pair of
# tools exists for).


def test_enable_firewall_rule_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.enable_firewall_rule(client, settings, comment="Bloqueio_Ataque_X", confirm=True)


def test_disable_firewall_rule_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.disable_firewall_rule(client, settings, comment="allow established", confirm=True)


def test_enable_firewall_rule_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.enable_firewall_rule(guarded_client, settings, comment="Bloqueio_Ataque_X", confirm=True)


def test_enable_firewall_rule_preview_does_not_apply(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.enable_firewall_rule(client, settings_write_enabled, comment="Bloqueio_Ataque_X", confirm=False)
    assert preview.applied is False
    assert preview.before["disabled"] is True
    assert preview.after["disabled"] == "no"
    # The full matched row - chain/action included - not just `disabled`,
    # so the caller can confirm WHICH rule this is before applying.
    assert preview.before["chain"] == "forward"
    assert preview.before["action"] == "drop"
    row = next(r for r in fake_connection.path("ip", "firewall", "filter")._rows if r["comment"] == "Bloqueio_Ataque_X")
    assert row["disabled"] is True


def test_enable_firewall_rule_confirm_true_applies(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    applied = guard.enable_firewall_rule(client, settings_write_enabled, comment="Bloqueio_Ataque_X", confirm=True)
    assert applied.applied is True
    row = next(r for r in fake_connection.path("ip", "firewall", "filter")._rows if r["comment"] == "Bloqueio_Ataque_X")
    assert row["disabled"] == "no"


def test_disable_firewall_rule_confirm_true_applies(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    applied = guard.disable_firewall_rule(client, settings_write_enabled, comment="allow established", confirm=True)
    assert applied.applied is True
    row = next(r for r in fake_connection.path("ip", "firewall", "filter")._rows if r["comment"] == "allow established")
    assert row["disabled"] == "yes"


def test_enable_firewall_rule_never_creates_a_rule(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    """A comment that matches nothing must raise, never silently create a
    new rule - the one invariant this whole tool pair exists to guarantee."""
    before_count = len(fake_connection.path("ip", "firewall", "filter")._rows)
    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.enable_firewall_rule(client, settings_write_enabled, comment="no-such-comment", confirm=True)
    assert "no-such-comment" in str(exc_info.value)
    assert len(fake_connection.path("ip", "firewall", "filter")._rows) == before_count


def test_disable_firewall_rule_unknown_comment_raises_resource_not_found(
    client: MikrotikClient, settings_write_enabled: Settings
):
    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.disable_firewall_rule(client, settings_write_enabled, comment="ghost", confirm=True)
    assert "ghost" in str(exc_info.value)


def test_enable_firewall_rule_ambiguous_comment_raises_ambiguous_resource_error(
    settings_write_enabled: Settings, device: Device
):
    """Two rules can legitimately share a comment on different chains - the
    tool must never guess which one to toggle."""
    fake = FakeConnection(
        data={
            ("ip", "firewall", "filter"): [
                {".id": "*1", "chain": "input", "action": "drop", "comment": "dup", "disabled": "true"},
                {".id": "*2", "chain": "forward", "action": "drop", "comment": "dup", "disabled": "true"},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)
    with pytest.raises(AmbiguousResourceError) as exc_info:
        guard.enable_firewall_rule(client, settings_write_enabled, comment="dup", confirm=True)
    assert "dup" in str(exc_info.value)
    # Neither row was touched.
    assert all(row.get("disabled") == "true" for row in fake.path("ip", "firewall", "filter")._rows)


def test_enable_firewall_rule_disambiguated_by_chain(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(
        data={
            ("ip", "firewall", "filter"): [
                {".id": "*1", "chain": "input", "action": "drop", "comment": "dup", "disabled": "true"},
                {".id": "*2", "chain": "forward", "action": "drop", "comment": "dup", "disabled": "true"},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    applied = guard.enable_firewall_rule(client, settings_write_enabled, comment="dup", chain="forward", confirm=True)
    assert applied.applied is True
    rows = {row["chain"]: row["disabled"] for row in fake.path("ip", "firewall", "filter")._rows}
    assert rows == {"input": "true", "forward": "no"}


def test_enable_firewall_rule_rejects_empty_comment_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.enable_firewall_rule(guarded_client, settings_write_enabled, comment="", confirm=True)


def test_disable_firewall_rule_rejects_invalid_chain_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.disable_firewall_rule(
            guarded_client, settings_write_enabled, comment="allow established", chain="bad chain!", confirm=True
        )


def test_enable_firewall_rule_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, client: MikrotikClient, settings_write_enabled: Settings
):
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["enable_firewall_rule"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "enable_firewall_rule", patched_op)

    guard.enable_firewall_rule(client, settings_write_enabled, comment="Bloqueio_Ataque_X", confirm=True)

    assert called == {"path": patched_op.path, "fields": {".id": "*2", "disabled": "no"}}


def test_enable_firewall_rule_unknown_comment_error_names_filter_resource(
    client: MikrotikClient, settings_write_enabled: Settings
):
    """Regression guard for the v1.4 generalization of the shared
    _set_firewall_rule_disabled helper (now also used by enable_nat_rule/
    disable_nat_rule and enable_mangle_rule/disable_mangle_rule): the filter
    pair's own resource_label default must be UNCHANGED - still "Firewall
    filter rule", never accidentally "Firewall NAT rule"/"Firewall mangle
    rule" from a shared default that drifted."""
    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.enable_firewall_rule(client, settings_write_enabled, comment="no-such-comment", confirm=True)
    assert "Firewall filter rule" in str(exc_info.value)


# --- enable_nat_rule / disable_nat_rule (v1.4) -----------------------------
#
# The shared fixture's ("ip", "firewall", "nat") table (see conftest) has
# two rows: "*1" (comment "wan-masquerade", chain "srcnat", enabled) and
# "*2" (comment "rdp-forward-maintenance", chain "dstnat", pre-created
# DISABLED - same admin-creates/LLM-enables workflow enable_firewall_rule's
# fixture rows establish for filter).


def test_enable_nat_rule_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.enable_nat_rule(client, settings, comment="rdp-forward-maintenance", confirm=True)


def test_disable_nat_rule_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.disable_nat_rule(client, settings, comment="wan-masquerade", confirm=True)


def test_enable_nat_rule_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.enable_nat_rule(guarded_client, settings, comment="rdp-forward-maintenance", confirm=True)


def test_enable_nat_rule_preview_does_not_apply(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.enable_nat_rule(client, settings_write_enabled, comment="rdp-forward-maintenance", confirm=False)
    assert preview.applied is False
    assert preview.before["disabled"] is True
    assert preview.after["disabled"] == "no"
    assert preview.before["chain"] == "dstnat"
    row = next(
        r for r in fake_connection.path("ip", "firewall", "nat")._rows if r["comment"] == "rdp-forward-maintenance"
    )
    assert row["disabled"] is True


def test_enable_nat_rule_confirm_true_applies(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    applied = guard.enable_nat_rule(client, settings_write_enabled, comment="rdp-forward-maintenance", confirm=True)
    assert applied.applied is True
    row = next(
        r for r in fake_connection.path("ip", "firewall", "nat")._rows if r["comment"] == "rdp-forward-maintenance"
    )
    assert row["disabled"] == "no"


def test_disable_nat_rule_confirm_true_applies(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    applied = guard.disable_nat_rule(client, settings_write_enabled, comment="wan-masquerade", confirm=True)
    assert applied.applied is True
    row = next(r for r in fake_connection.path("ip", "firewall", "nat")._rows if r["comment"] == "wan-masquerade")
    assert row["disabled"] == "yes"


def test_enable_nat_rule_never_creates_a_rule(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    before_count = len(fake_connection.path("ip", "firewall", "nat")._rows)
    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.enable_nat_rule(client, settings_write_enabled, comment="no-such-comment", confirm=True)
    assert "no-such-comment" in str(exc_info.value)
    assert "Firewall NAT rule" in str(exc_info.value)
    assert len(fake_connection.path("ip", "firewall", "nat")._rows) == before_count


def test_disable_nat_rule_unknown_comment_raises_resource_not_found(
    client: MikrotikClient, settings_write_enabled: Settings
):
    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.disable_nat_rule(client, settings_write_enabled, comment="ghost", confirm=True)
    assert "ghost" in str(exc_info.value)


def test_enable_nat_rule_ambiguous_comment_raises_ambiguous_resource_error(
    settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(
        data={
            ("ip", "firewall", "nat"): [
                {".id": "*1", "chain": "srcnat", "action": "masquerade", "comment": "dup", "disabled": "true"},
                {".id": "*2", "chain": "dstnat", "action": "dst-nat", "comment": "dup", "disabled": "true"},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)
    with pytest.raises(AmbiguousResourceError) as exc_info:
        guard.enable_nat_rule(client, settings_write_enabled, comment="dup", confirm=True)
    assert "dup" in str(exc_info.value)
    assert all(row.get("disabled") == "true" for row in fake.path("ip", "firewall", "nat")._rows)


def test_enable_nat_rule_disambiguated_by_chain(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(
        data={
            ("ip", "firewall", "nat"): [
                {".id": "*1", "chain": "srcnat", "action": "masquerade", "comment": "dup", "disabled": "true"},
                {".id": "*2", "chain": "dstnat", "action": "dst-nat", "comment": "dup", "disabled": "true"},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    applied = guard.enable_nat_rule(client, settings_write_enabled, comment="dup", chain="dstnat", confirm=True)
    assert applied.applied is True
    rows = {row["chain"]: row["disabled"] for row in fake.path("ip", "firewall", "nat")._rows}
    assert rows == {"srcnat": "true", "dstnat": "no"}


def test_enable_nat_rule_rejects_empty_comment_before_touching_device(settings_write_enabled: Settings, device: Device):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.enable_nat_rule(guarded_client, settings_write_enabled, comment="", confirm=True)


def test_disable_nat_rule_rejects_invalid_chain_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.disable_nat_rule(
            guarded_client, settings_write_enabled, comment="wan-masquerade", chain="bad chain!", confirm=True
        )


def test_enable_nat_rule_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, client: MikrotikClient, settings_write_enabled: Settings
):
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["enable_nat_rule"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "enable_nat_rule", patched_op)

    guard.enable_nat_rule(client, settings_write_enabled, comment="rdp-forward-maintenance", confirm=True)

    assert called == {"path": patched_op.path, "fields": {".id": "*2", "disabled": "no"}}


# --- enable_mangle_rule / disable_mangle_rule (v1.4) -----------------------
#
# The shared fixture's ("ip", "firewall", "mangle") table (see conftest) has
# two rows: "*1" (comment "mark-voip", chain "forward", enabled) and "*2"
# (comment "Mark_Backup_Traffic", chain "prerouting", pre-created DISABLED).


def test_enable_mangle_rule_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.enable_mangle_rule(client, settings, comment="Mark_Backup_Traffic", confirm=True)


def test_disable_mangle_rule_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.disable_mangle_rule(client, settings, comment="mark-voip", confirm=True)


def test_enable_mangle_rule_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.enable_mangle_rule(guarded_client, settings, comment="Mark_Backup_Traffic", confirm=True)


def test_enable_mangle_rule_preview_does_not_apply(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.enable_mangle_rule(client, settings_write_enabled, comment="Mark_Backup_Traffic", confirm=False)
    assert preview.applied is False
    assert preview.before["disabled"] is True
    assert preview.after["disabled"] == "no"
    assert preview.before["chain"] == "prerouting"
    row = next(
        r for r in fake_connection.path("ip", "firewall", "mangle")._rows if r["comment"] == "Mark_Backup_Traffic"
    )
    assert row["disabled"] is True


def test_enable_mangle_rule_confirm_true_applies(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    applied = guard.enable_mangle_rule(client, settings_write_enabled, comment="Mark_Backup_Traffic", confirm=True)
    assert applied.applied is True
    row = next(
        r for r in fake_connection.path("ip", "firewall", "mangle")._rows if r["comment"] == "Mark_Backup_Traffic"
    )
    assert row["disabled"] == "no"


def test_disable_mangle_rule_confirm_true_applies(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    applied = guard.disable_mangle_rule(client, settings_write_enabled, comment="mark-voip", confirm=True)
    assert applied.applied is True
    row = next(r for r in fake_connection.path("ip", "firewall", "mangle")._rows if r["comment"] == "mark-voip")
    assert row["disabled"] == "yes"


def test_enable_mangle_rule_never_creates_a_rule(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    before_count = len(fake_connection.path("ip", "firewall", "mangle")._rows)
    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.enable_mangle_rule(client, settings_write_enabled, comment="no-such-comment", confirm=True)
    assert "no-such-comment" in str(exc_info.value)
    assert "Firewall mangle rule" in str(exc_info.value)
    assert len(fake_connection.path("ip", "firewall", "mangle")._rows) == before_count


def test_disable_mangle_rule_unknown_comment_raises_resource_not_found(
    client: MikrotikClient, settings_write_enabled: Settings
):
    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.disable_mangle_rule(client, settings_write_enabled, comment="ghost", confirm=True)
    assert "ghost" in str(exc_info.value)


def test_enable_mangle_rule_ambiguous_comment_raises_ambiguous_resource_error(
    settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(
        data={
            ("ip", "firewall", "mangle"): [
                {".id": "*1", "chain": "prerouting", "action": "mark-packet", "comment": "dup", "disabled": "true"},
                {".id": "*2", "chain": "forward", "action": "mark-packet", "comment": "dup", "disabled": "true"},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)
    with pytest.raises(AmbiguousResourceError) as exc_info:
        guard.enable_mangle_rule(client, settings_write_enabled, comment="dup", confirm=True)
    assert "dup" in str(exc_info.value)
    assert all(row.get("disabled") == "true" for row in fake.path("ip", "firewall", "mangle")._rows)


def test_enable_mangle_rule_disambiguated_by_chain(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(
        data={
            ("ip", "firewall", "mangle"): [
                {".id": "*1", "chain": "prerouting", "action": "mark-packet", "comment": "dup", "disabled": "true"},
                {".id": "*2", "chain": "forward", "action": "mark-packet", "comment": "dup", "disabled": "true"},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    applied = guard.enable_mangle_rule(client, settings_write_enabled, comment="dup", chain="forward", confirm=True)
    assert applied.applied is True
    rows = {row["chain"]: row["disabled"] for row in fake.path("ip", "firewall", "mangle")._rows}
    assert rows == {"prerouting": "true", "forward": "no"}


def test_enable_mangle_rule_rejects_empty_comment_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.enable_mangle_rule(guarded_client, settings_write_enabled, comment="", confirm=True)


def test_disable_mangle_rule_rejects_invalid_chain_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.disable_mangle_rule(
            guarded_client, settings_write_enabled, comment="mark-voip", chain="bad chain!", confirm=True
        )


def test_enable_mangle_rule_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, client: MikrotikClient, settings_write_enabled: Settings
):
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["enable_mangle_rule"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "enable_mangle_rule", patched_op)

    guard.enable_mangle_rule(client, settings_write_enabled, comment="Mark_Backup_Traffic", confirm=True)

    assert called == {"path": patched_op.path, "fields": {".id": "*2", "disabled": "no"}}


# --- add_wireguard_interface / add_wireguard_peer / remove_wireguard_peer --
# --- (v0.13) ------------------------------------------------------------
#
# The most sensitive round: WireGuard uses private keys. The shared
# fixture's ("interface", "wireguard") table (see conftest) has one
# interface, "wg1"; ("interface", "wireguard", "peers") has one peer,
# "peer1", on interface "wg1". 44-char base64-shaped public keys are used
# below - validate_wireguard_key is strict about that shape, unlike the
# shared fixture's own loosely-shaped "PUBKEYAAAA==" placeholder.

_REMOTE_PEER_PUBKEY_1 = "OaQx4l1wQNnz9J+odnvI4yyND+HG699QWpM8fL1XAO0="
_REMOTE_PEER_PUBKEY_2 = "idtcei5gRabTeh7XqgAXUdSWE5+QsiES7xHooeHonO8="


def test_add_wireguard_interface_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.add_wireguard_interface(client, settings, name="wg2", confirm=True)


def test_add_wireguard_interface_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.add_wireguard_interface(guarded_client, settings, name="wg2", confirm=True)


def test_add_wireguard_interface_preview_does_not_create(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.add_wireguard_interface(client, settings_write_enabled, name="wg2", confirm=False)
    assert preview.applied is False
    assert preview.before == {}
    assert preview.after == {"name": "wg2"}
    names = {row["name"] for row in fake_connection.path("interface", "wireguard")._rows}
    assert "wg2" not in names


def test_add_wireguard_interface_confirm_true_creates_and_reports_public_key_never_private_key(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.add_wireguard_interface(client, settings_write_enabled, name="wg2", listen_port=51821, confirm=True)
    assert preview.applied is True
    assert preview.after["name"] == "wg2"
    assert preview.after["listen-port"] == "51821"
    assert "public-key" in preview.after
    assert "private-key" not in preview.after
    row = next(r for r in fake_connection.path("interface", "wireguard")._rows if r["name"] == "wg2")
    # The fake device DID generate a private-key (proving redaction had
    # something real to strip) - it just never made it into the preview.
    assert "private-key" in row


def test_add_wireguard_interface_rejects_duplicate_name(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    with pytest.raises(ResourceAlreadyExistsError) as exc_info:
        guard.add_wireguard_interface(client, settings_write_enabled, name="wg1", confirm=True)
    assert "wg1" in str(exc_info.value)
    assert len(fake_connection.path("interface", "wireguard")._rows) == 1


def test_add_wireguard_interface_rejects_invalid_listen_port_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_wireguard_interface(
            guarded_client, settings_write_enabled, name="wg2", listen_port=70000, confirm=True
        )


def test_add_wireguard_interface_never_accepts_a_private_key_parameter(
    client: MikrotikClient, settings_write_enabled: Settings
):
    """SECURITY: there is no `private_key` parameter at all on this
    function - passing one raises TypeError, proving there is no code path
    through which a caller could ever supply RouterOS's own generated key
    (or smuggle in one of their own)."""
    with pytest.raises(TypeError):
        guard.add_wireguard_interface(
            client,
            settings_write_enabled,
            name="wg2",
            confirm=True,
            private_key="SOME-KEY==",  # type: ignore[call-arg]
        )


def test_add_wireguard_interface_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, client: MikrotikClient, settings_write_enabled: Settings
):
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields
        return "*99"

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["add_wireguard_interface"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "add_wireguard_interface", patched_op)

    guard.add_wireguard_interface(client, settings_write_enabled, name="wg2", confirm=True)

    assert called == {"path": patched_op.path, "fields": {"name": "wg2"}}


def test_add_wireguard_peer_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.add_wireguard_peer(
            client,
            settings,
            interface="wg1",
            public_key=_REMOTE_PEER_PUBKEY_1,
            allowed_address="10.10.0.5/32",
            confirm=True,
        )


def test_add_wireguard_peer_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.add_wireguard_peer(
            guarded_client,
            settings,
            interface="wg1",
            public_key=_REMOTE_PEER_PUBKEY_1,
            allowed_address="10.10.0.5/32",
            confirm=True,
        )


def test_add_wireguard_peer_preview_does_not_create(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.add_wireguard_peer(
        client,
        settings_write_enabled,
        interface="wg1",
        public_key=_REMOTE_PEER_PUBKEY_1,
        allowed_address="10.10.0.5/32",
        confirm=False,
    )
    assert preview.applied is False
    assert preview.before == {}
    assert preview.after["public-key"] == _REMOTE_PEER_PUBKEY_1
    assert preview.after["allowed-address"] == "10.10.0.5/32"
    keys = {row["public-key"] for row in fake_connection.path("interface", "wireguard", "peers")._rows}
    assert _REMOTE_PEER_PUBKEY_1 not in keys


def test_add_wireguard_peer_confirm_true_creates_with_optional_fields(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.add_wireguard_peer(
        client,
        settings_write_enabled,
        interface="wg1",
        public_key=_REMOTE_PEER_PUBKEY_1,
        allowed_address="10.10.0.5/32,10.10.0.6/32",
        endpoint_address="203.0.113.9",
        endpoint_port=51820,
        persistent_keepalive="25s",
        comment="laptop",
        confirm=True,
    )
    assert preview.applied is True
    row = next(
        r
        for r in fake_connection.path("interface", "wireguard", "peers")._rows
        if r["public-key"] == _REMOTE_PEER_PUBKEY_1
    )
    assert row["interface"] == "wg1"
    assert row["allowed-address"] == "10.10.0.5/32,10.10.0.6/32"
    assert row["endpoint-address"] == "203.0.113.9"
    assert row["endpoint-port"] == "51820"
    assert row["persistent-keepalive"] == "25s"
    assert row["comment"] == "laptop"


def test_add_wireguard_peer_unknown_interface_raises_resource_not_found(
    client: MikrotikClient, settings_write_enabled: Settings
):
    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.add_wireguard_peer(
            client,
            settings_write_enabled,
            interface="ghost-tunnel",
            public_key=_REMOTE_PEER_PUBKEY_1,
            allowed_address="10.10.0.5/32",
            confirm=True,
        )
    assert "ghost-tunnel" in str(exc_info.value)


def test_add_wireguard_peer_rejects_duplicate_public_key_on_same_interface(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    guard.add_wireguard_peer(
        client,
        settings_write_enabled,
        interface="wg1",
        public_key=_REMOTE_PEER_PUBKEY_1,
        allowed_address="10.10.0.5/32",
        confirm=True,
    )
    with pytest.raises(ResourceAlreadyExistsError) as exc_info:
        guard.add_wireguard_peer(
            client,
            settings_write_enabled,
            interface="wg1",
            public_key=_REMOTE_PEER_PUBKEY_1,
            allowed_address="10.10.0.6/32",
            confirm=True,
        )
    assert _REMOTE_PEER_PUBKEY_1 in str(exc_info.value)
    matches = [
        row
        for row in fake_connection.path("interface", "wireguard", "peers")._rows
        if row["public-key"] == _REMOTE_PEER_PUBKEY_1
    ]
    assert len(matches) == 1


def test_add_wireguard_peer_rejects_invalid_public_key_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_wireguard_peer(
            guarded_client,
            settings_write_enabled,
            interface="wg1",
            public_key="not-a-valid-key",
            allowed_address="10.10.0.5/32",
            confirm=True,
        )


def test_add_wireguard_peer_rejects_invalid_allowed_address_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_wireguard_peer(
            guarded_client,
            settings_write_enabled,
            interface="wg1",
            public_key=_REMOTE_PEER_PUBKEY_1,
            allowed_address="not-a-cidr",
            confirm=True,
        )


def test_add_wireguard_peer_never_accepts_a_private_key_or_preshared_key_parameter(
    client: MikrotikClient, settings_write_enabled: Settings
):
    """SECURITY: no `private_key`/`preshared_key` parameter exists on this
    function at all - passing either raises TypeError."""
    with pytest.raises(TypeError):
        guard.add_wireguard_peer(
            client,
            settings_write_enabled,
            interface="wg1",
            public_key=_REMOTE_PEER_PUBKEY_1,
            allowed_address="10.10.0.5/32",
            confirm=True,
            private_key="SOME-KEY==",  # type: ignore[call-arg]
        )
    with pytest.raises(TypeError):
        guard.add_wireguard_peer(
            client,
            settings_write_enabled,
            interface="wg1",
            public_key=_REMOTE_PEER_PUBKEY_2,
            allowed_address="10.10.0.5/32",
            confirm=True,
            preshared_key="SOME-KEY==",  # type: ignore[call-arg]
        )


def test_remove_wireguard_peer_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.remove_wireguard_peer(client, settings, interface="wg1", public_key="PUBKEYAAAA==", confirm=True)


def test_remove_wireguard_peer_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.remove_wireguard_peer(guarded_client, settings, interface="wg1", public_key="PUBKEYAAAA==", confirm=True)


def test_remove_wireguard_peer_requires_public_key_or_comment(client: MikrotikClient, settings_write_enabled: Settings):
    with pytest.raises(ValidationError):
        guard.remove_wireguard_peer(client, settings_write_enabled, interface="wg1", confirm=True)


def _wireguard_peer_fixture(interface: str = "wg1") -> FakeConnection:
    return FakeConnection(
        data={
            ("interface", "wireguard", "peers"): [
                {".id": "*1", "interface": interface, "public-key": _REMOTE_PEER_PUBKEY_1, "comment": "laptop"}
            ]
        }
    )


def test_remove_wireguard_peer_by_public_key_preview_then_confirm(settings_write_enabled: Settings, device: Device):
    fake = _wireguard_peer_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.remove_wireguard_peer(
        client, settings_write_enabled, interface="wg1", public_key=_REMOTE_PEER_PUBKEY_1, confirm=False
    )
    assert preview.applied is False
    assert preview.before["public-key"] == _REMOTE_PEER_PUBKEY_1
    assert preview.after == {}
    assert len(fake.path("interface", "wireguard", "peers")._rows) == 1

    applied = guard.remove_wireguard_peer(
        client, settings_write_enabled, interface="wg1", public_key=_REMOTE_PEER_PUBKEY_1, confirm=True
    )
    assert applied.applied is True
    assert fake.path("interface", "wireguard", "peers")._rows == []


def test_remove_wireguard_peer_by_comment(settings_write_enabled: Settings, device: Device):
    fake = _wireguard_peer_fixture()
    client = MikrotikClient(device, connection=fake)

    applied = guard.remove_wireguard_peer(
        client, settings_write_enabled, interface="wg1", comment="laptop", confirm=True
    )
    assert applied.applied is True
    assert fake.path("interface", "wireguard", "peers")._rows == []


def test_remove_wireguard_peer_unknown_public_key_raises_resource_not_found(
    client: MikrotikClient, settings_write_enabled: Settings
):
    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.remove_wireguard_peer(
            client, settings_write_enabled, interface="wg1", public_key=_REMOTE_PEER_PUBKEY_1, confirm=True
        )
    assert _REMOTE_PEER_PUBKEY_1 in str(exc_info.value)


def test_remove_wireguard_peer_scoped_to_interface(settings_write_enabled: Settings, device: Device):
    """A peer with a matching public-key on a DIFFERENT interface must not
    match - `interface` scopes the resolution."""
    fake = _wireguard_peer_fixture(interface="wg-other")
    client = MikrotikClient(device, connection=fake)
    with pytest.raises(ResourceNotFoundError):
        guard.remove_wireguard_peer(
            client, settings_write_enabled, interface="wg1", public_key=_REMOTE_PEER_PUBKEY_1, confirm=True
        )


def test_remove_wireguard_peer_ambiguous_comment_raises_ambiguous_resource_error(
    settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(
        data={
            ("interface", "wireguard", "peers"): [
                {".id": "*1", "interface": "wg1", "public-key": _REMOTE_PEER_PUBKEY_1, "comment": "dup"},
                {".id": "*2", "interface": "wg1", "public-key": _REMOTE_PEER_PUBKEY_2, "comment": "dup"},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)
    with pytest.raises(AmbiguousResourceError) as exc_info:
        guard.remove_wireguard_peer(client, settings_write_enabled, interface="wg1", comment="dup", confirm=True)
    assert "dup" in str(exc_info.value)
    assert len(fake.path("interface", "wireguard", "peers")._rows) == 2


def test_remove_wireguard_peer_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, settings_write_enabled: Settings, device: Device
):
    fake = _wireguard_peer_fixture()
    client = MikrotikClient(device, connection=fake)
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["remove_wireguard_peer"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "remove_wireguard_peer", patched_op)

    guard.remove_wireguard_peer(
        client, settings_write_enabled, interface="wg1", public_key=_REMOTE_PEER_PUBKEY_1, confirm=True
    )

    assert called == {"path": patched_op.path, "fields": {"ids": ("*1",)}}


# --- add_hotspot_user / create_backup (v0.14) -------------------------------
#
# The last feature round before 1.0. add_hotspot_user's password asymmetry
# (present in the tool RESULT, absent from the audit journal) is proven in
# tests/test_guard_audit.py, not here - these tests cover the ordinary
# guard mechanics (gate, preview/confirm, duplicate rejection, validation).


def test_add_hotspot_user_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.add_hotspot_user(client, settings, name="visitor2", password="Passw0rd!", confirm=True)


def test_add_hotspot_user_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.add_hotspot_user(guarded_client, settings, name="visitor2", password="Passw0rd!", confirm=True)


def test_add_hotspot_user_preview_does_not_create(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.add_hotspot_user(
        client, settings_write_enabled, name="visitor2", password="Passw0rd!", confirm=False
    )
    assert preview.applied is False
    assert preview.before == {}
    assert preview.after == {"name": "visitor2", "password": "Passw0rd!"}
    assert fake_connection.path("ip", "hotspot", "user")._rows == []


def test_add_hotspot_user_confirm_true_creates(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.add_hotspot_user(
        client, settings_write_enabled, name="visitor2", password="Passw0rd!", confirm=True
    )
    assert preview.applied is True
    assert preview.after == {"name": "visitor2", "password": "Passw0rd!"}
    rows = fake_connection.path("ip", "hotspot", "user")._rows
    assert rows == [{"name": "visitor2", "password": "Passw0rd!"}]


def test_add_hotspot_user_confirm_true_with_optional_fields(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.add_hotspot_user(
        client,
        settings_write_enabled,
        name="visitor3",
        password="Passw0rd!",
        profile="guest-profile",
        limit_uptime="01:00:00",
        limit_bytes_total=104857600,
        confirm=True,
    )
    assert preview.applied is True
    assert preview.after == {
        "name": "visitor3",
        "password": "Passw0rd!",
        "profile": "guest-profile",
        "limit-uptime": "01:00:00",
        "limit-bytes-total": "104857600",
    }


def test_add_hotspot_user_rejects_duplicate_name(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    guard.add_hotspot_user(client, settings_write_enabled, name="visitor2", password="Passw0rd!", confirm=True)
    with pytest.raises(ResourceAlreadyExistsError) as exc_info:
        guard.add_hotspot_user(client, settings_write_enabled, name="visitor2", password="AnotherPass1", confirm=True)
    assert "visitor2" in str(exc_info.value)
    assert len(fake_connection.path("ip", "hotspot", "user")._rows) == 1


def test_add_hotspot_user_rejects_invalid_username_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_hotspot_user(
            guarded_client, settings_write_enabled, name="visitor 2!", password="Passw0rd!", confirm=True
        )


def test_add_hotspot_user_rejects_empty_password_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_hotspot_user(guarded_client, settings_write_enabled, name="visitor2", password="", confirm=True)


def test_add_hotspot_user_rejects_invalid_limit_bytes_total_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_hotspot_user(
            guarded_client,
            settings_write_enabled,
            name="visitor2",
            password="Passw0rd!",
            limit_bytes_total=-5,
            confirm=True,
        )


def test_add_hotspot_user_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, client: MikrotikClient, settings_write_enabled: Settings
):
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["add_hotspot_user"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "add_hotspot_user", patched_op)

    guard.add_hotspot_user(client, settings_write_enabled, name="visitor2", password="Passw0rd!", confirm=True)

    assert called == {"path": patched_op.path, "fields": {"name": "visitor2", "password": "Passw0rd!"}}


# --- create_backup (v0.14) --------------------------------------------------
#
# The shared fixture's ("file",) table (see conftest) already has one
# ".backup" file - "core-switch-2026-01-01.backup" - used below to exercise
# the duplicate-name rejection.


def test_create_backup_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.create_backup(client, settings, name="nightly-backup", confirm=True)


def test_create_backup_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.create_backup(guarded_client, settings, name="nightly-backup", confirm=True)


def test_create_backup_preview_does_not_apply(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.create_backup(client, settings_write_enabled, name="nightly-backup", confirm=False)
    assert preview.applied is False
    assert preview.before == {}
    assert preview.after == {"name": "nightly-backup"}
    assert ("/system/backup/save", {"name": "nightly-backup"}) not in fake_connection.calls


def test_create_backup_confirm_true_sends_the_save_command(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    preview = guard.create_backup(client, settings_write_enabled, name="nightly-backup", confirm=True)
    assert preview.applied is True
    assert preview.after == {"name": "nightly-backup"}
    assert ("/system/backup/save", {"name": "nightly-backup"}) in fake_connection.calls


def test_create_backup_confirm_true_forwards_password_to_the_device(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    guard.create_backup(client, settings_write_enabled, name="nightly-backup", password="encrypt-me", confirm=True)
    assert (
        "/system/backup/save",
        {"name": "nightly-backup", "password": "encrypt-me"},
    ) in fake_connection.calls


def test_create_backup_preview_and_applied_never_carry_the_password(
    client: MikrotikClient, settings_write_enabled: Settings
):
    """See guard.create_backup's docstring: the backup-file encryption
    password is redacted BEFORE a WritePreview is ever constructed - it must
    never show up in `before`/`after`, on either preview or applied."""
    preview = guard.create_backup(
        client, settings_write_enabled, name="nightly-backup", password="encrypt-me", confirm=False
    )
    assert "password" not in preview.after
    applied = guard.create_backup(
        client, settings_write_enabled, name="another-backup", password="encrypt-me", confirm=True
    )
    assert "password" not in applied.after


def test_create_backup_rejects_duplicate_name(
    client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    with pytest.raises(ResourceAlreadyExistsError) as exc_info:
        guard.create_backup(client, settings_write_enabled, name="core-switch-2026-01-01", confirm=True)
    assert "core-switch-2026-01-01" in str(exc_info.value)


def test_create_backup_rejects_duplicate_name_when_caller_already_included_the_extension(
    client: MikrotikClient, settings_write_enabled: Settings
):
    with pytest.raises(ResourceAlreadyExistsError):
        guard.create_backup(client, settings_write_enabled, name="core-switch-2026-01-01.backup", confirm=True)


def test_create_backup_rejects_invalid_name_before_touching_device(settings_write_enabled: Settings, device: Device):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.create_backup(guarded_client, settings_write_enabled, name="bad name!", confirm=True)


def test_create_backup_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, client: MikrotikClient, settings_write_enabled: Settings
):
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["create_backup"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "create_backup", patched_op)

    guard.create_backup(client, settings_write_enabled, name="nightly-backup", confirm=True)

    assert called == {"path": patched_op.path, "fields": {"name": "nightly-backup"}}


# --- v1.2: add_vlan ----------------------------------------------------------


def _vlan_fixture() -> FakeConnection:
    return FakeConnection(
        data={
            ("interface", "vlan"): [
                {".id": "*1", "name": "vlan100", "vlan-id": "100", "interface": "bridge1", "disabled": "false"},
            ]
        }
    )


def test_add_vlan_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.add_vlan(client, settings, name="vlan200", vlan_id=200, interface="bridge1", confirm=True)


def test_add_vlan_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.add_vlan(guarded_client, settings, name="vlan200", vlan_id=200, interface="bridge1", confirm=True)


def test_add_vlan_preview_does_not_apply(settings_write_enabled: Settings, device: Device):
    fake = _vlan_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.add_vlan(
        client, settings_write_enabled, name="vlan200", vlan_id=200, interface="bridge1", confirm=False
    )

    assert preview.applied is False
    assert preview.before == {}
    assert preview.after == {"name": "vlan200", "vlan-id": "200", "interface": "bridge1"}
    names = {row["name"] for row in fake.path("interface", "vlan")._rows}
    assert "vlan200" not in names


def test_add_vlan_confirm_true_applies(settings_write_enabled: Settings, device: Device):
    fake = _vlan_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.add_vlan(
        client,
        settings_write_enabled,
        name="vlan200",
        vlan_id=200,
        interface="bridge1",
        mtu=1500,
        comment="guest network",
        confirm=True,
    )

    assert preview.applied is True
    rows = fake.path("interface", "vlan")._rows
    created = next(row for row in rows if row["name"] == "vlan200")
    assert created["vlan-id"] == "200"
    assert created["interface"] == "bridge1"
    assert created["mtu"] == "1500"
    assert created["comment"] == "guest network"


def test_add_vlan_rejects_duplicate_name(settings_write_enabled: Settings, device: Device):
    fake = _vlan_fixture()
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ResourceAlreadyExistsError) as exc_info:
        guard.add_vlan(client, settings_write_enabled, name="vlan100", vlan_id=101, interface="bridge1", confirm=True)
    assert "vlan100" in str(exc_info.value)
    rows = [row for row in fake.path("interface", "vlan")._rows if row["name"] == "vlan100"]
    assert len(rows) == 1


def test_add_vlan_rejects_invalid_vlan_id_before_touching_device(settings_write_enabled: Settings, device: Device):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_vlan(
            guarded_client, settings_write_enabled, name="vlan200", vlan_id=5000, interface="bridge1", confirm=True
        )


def test_add_vlan_rejects_invalid_name_before_touching_device(settings_write_enabled: Settings, device: Device):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_vlan(
            guarded_client, settings_write_enabled, name="bad name!", vlan_id=200, interface="bridge1", confirm=True
        )


def test_add_vlan_rejects_invalid_mtu_before_touching_device(settings_write_enabled: Settings, device: Device):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_vlan(
            guarded_client,
            settings_write_enabled,
            name="vlan200",
            vlan_id=200,
            interface="bridge1",
            mtu=40,
            confirm=True,
        )


def test_add_vlan_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, client: MikrotikClient, settings_write_enabled: Settings
):
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["add_vlan"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "add_vlan", patched_op)

    guard.add_vlan(client, settings_write_enabled, name="vlan200", vlan_id=200, interface="bridge1", confirm=True)

    assert called == {
        "path": patched_op.path,
        "fields": {"name": "vlan200", "vlan-id": "200", "interface": "bridge1"},
    }


# --- v1.2: remove_vlan --------------------------------------------------------


def test_remove_vlan_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.remove_vlan(client, settings, name="vlan100", confirm=True)


def test_remove_vlan_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.remove_vlan(guarded_client, settings, name="vlan100", confirm=True)


def test_remove_vlan_preview_does_not_apply(settings_write_enabled: Settings, device: Device):
    fake = _vlan_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.remove_vlan(client, settings_write_enabled, name="vlan100", confirm=False)

    assert preview.applied is False
    assert preview.before["name"] == "vlan100"
    assert preview.after == {}
    names = {row["name"] for row in fake.path("interface", "vlan")._rows}
    assert "vlan100" in names


def test_remove_vlan_confirm_true_removes(settings_write_enabled: Settings, device: Device):
    fake = _vlan_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.remove_vlan(client, settings_write_enabled, name="vlan100", confirm=True)

    assert preview.applied is True
    names = {row["name"] for row in fake.path("interface", "vlan")._rows}
    assert "vlan100" not in names


def test_remove_vlan_unknown_name_raises_resource_not_found(settings_write_enabled: Settings, device: Device):
    fake = _vlan_fixture()
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.remove_vlan(client, settings_write_enabled, name="ghost-vlan", confirm=True)
    assert "ghost-vlan" in str(exc_info.value)


def test_remove_vlan_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, settings_write_enabled: Settings, device: Device
):
    fake = _vlan_fixture()
    client = MikrotikClient(device, connection=fake)
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["remove_vlan"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "remove_vlan", patched_op)

    guard.remove_vlan(client, settings_write_enabled, name="vlan100", confirm=True)

    assert called == {"path": patched_op.path, "fields": {"ids": ("*1",)}}


# --- v1.2: move_firewall_rule --------------------------------------------------


def _move_fixture() -> FakeConnection:
    return FakeConnection(
        data={
            ("ip", "firewall", "filter"): [
                {".id": "*1", "chain": "forward", "action": "accept", "comment": "rule-a"},
                {".id": "*2", "chain": "forward", "action": "accept", "comment": "rule-b"},
                {".id": "*3", "chain": "forward", "action": "drop", "comment": "rule-c"},
            ]
        }
    )


def test_move_firewall_rule_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.move_firewall_rule(client, settings, comment="rule-c", position=0, confirm=True)


def test_move_firewall_rule_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.move_firewall_rule(guarded_client, settings, comment="rule-c", position=0, confirm=True)


def test_move_firewall_rule_requires_exactly_one_of_before_comment_or_position(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.move_firewall_rule(guarded_client, settings_write_enabled, comment="rule-c", confirm=True)


def test_move_firewall_rule_rejects_both_before_comment_and_position(settings_write_enabled: Settings, device: Device):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.move_firewall_rule(
            guarded_client,
            settings_write_enabled,
            comment="rule-c",
            before_comment="rule-a",
            position=0,
            confirm=True,
        )


def test_move_firewall_rule_by_position_preview_shows_from_to(settings_write_enabled: Settings, device: Device):
    fake = _move_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.move_firewall_rule(client, settings_write_enabled, comment="rule-c", position=0, confirm=False)

    assert preview.applied is False
    assert preview.before == {"comment": "rule-c", "chain": "forward", "position": 2}
    assert preview.after == {"comment": "rule-c", "chain": "forward", "position": 0}
    # Nothing was reordered yet.
    order = [row["comment"] for row in fake.path("ip", "firewall", "filter")._rows]
    assert order == ["rule-a", "rule-b", "rule-c"]


def test_move_firewall_rule_by_position_confirm_true_reorders(settings_write_enabled: Settings, device: Device):
    fake = _move_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.move_firewall_rule(client, settings_write_enabled, comment="rule-c", position=0, confirm=True)

    assert preview.applied is True
    order = [row["comment"] for row in fake.path("ip", "firewall", "filter")._rows]
    assert order == ["rule-c", "rule-a", "rule-b"]


def test_move_firewall_rule_by_position_beyond_end_moves_to_end(settings_write_enabled: Settings, device: Device):
    fake = _move_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.move_firewall_rule(client, settings_write_enabled, comment="rule-a", position=99, confirm=True)

    assert preview.after["position"] == 2
    order = [row["comment"] for row in fake.path("ip", "firewall", "filter")._rows]
    assert order == ["rule-b", "rule-c", "rule-a"]


def test_move_firewall_rule_by_before_comment_confirm_true_reorders(settings_write_enabled: Settings, device: Device):
    fake = _move_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.move_firewall_rule(
        client, settings_write_enabled, comment="rule-c", before_comment="rule-a", confirm=True
    )

    assert preview.applied is True
    order = [row["comment"] for row in fake.path("ip", "firewall", "filter")._rows]
    assert order == ["rule-c", "rule-a", "rule-b"]


def test_move_firewall_rule_never_edits_rule_fields(settings_write_enabled: Settings, device: Device):
    """The tool's ONE job is to reorder - it must never touch a rule's own
    chain/action/etc, only its position, exactly like enable_firewall_rule/
    disable_firewall_rule never touch anything but `disabled`."""
    fake = _move_fixture()
    client = MikrotikClient(device, connection=fake)

    guard.move_firewall_rule(client, settings_write_enabled, comment="rule-c", position=0, confirm=True)

    row = next(r for r in fake.path("ip", "firewall", "filter")._rows if r["comment"] == "rule-c")
    assert row["action"] == "drop"
    assert row["chain"] == "forward"


def test_move_firewall_rule_unknown_comment_raises_resource_not_found(settings_write_enabled: Settings, device: Device):
    fake = _move_fixture()
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.move_firewall_rule(client, settings_write_enabled, comment="ghost", position=0, confirm=True)
    assert "ghost" in str(exc_info.value)


def test_move_firewall_rule_unknown_before_comment_raises_resource_not_found(
    settings_write_enabled: Settings, device: Device
):
    fake = _move_fixture()
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.move_firewall_rule(client, settings_write_enabled, comment="rule-a", before_comment="ghost", confirm=True)
    assert "ghost" in str(exc_info.value)
    # Nothing was reordered.
    order = [row["comment"] for row in fake.path("ip", "firewall", "filter")._rows]
    assert order == ["rule-a", "rule-b", "rule-c"]


def test_move_firewall_rule_ambiguous_comment_raises_ambiguous_resource_error(
    settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(
        data={
            ("ip", "firewall", "filter"): [
                {".id": "*1", "chain": "input", "action": "drop", "comment": "dup"},
                {".id": "*2", "chain": "forward", "action": "drop", "comment": "dup"},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(AmbiguousResourceError) as exc_info:
        guard.move_firewall_rule(client, settings_write_enabled, comment="dup", position=0, confirm=True)
    assert "dup" in str(exc_info.value)
    # Neither row was touched.
    order = [row[".id"] for row in fake.path("ip", "firewall", "filter")._rows]
    assert order == ["*1", "*2"]


def test_move_firewall_rule_disambiguated_by_chain(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(
        data={
            ("ip", "firewall", "filter"): [
                {".id": "*1", "chain": "input", "action": "drop", "comment": "dup"},
                {".id": "*2", "chain": "forward", "action": "accept", "comment": "anchor"},
                {".id": "*3", "chain": "forward", "action": "drop", "comment": "dup"},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    preview = guard.move_firewall_rule(
        client, settings_write_enabled, comment="dup", chain="forward", before_comment="anchor", confirm=True
    )
    assert preview.applied is True
    order = [row[".id"] for row in fake.path("ip", "firewall", "filter")._rows]
    assert order == ["*1", "*3", "*2"]


def test_move_firewall_rule_ambiguous_before_comment_raises_ambiguous_resource_error(
    settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(
        data={
            ("ip", "firewall", "filter"): [
                {".id": "*1", "chain": "input", "action": "drop", "comment": "target"},
                {".id": "*2", "chain": "forward", "action": "drop", "comment": "dup"},
                {".id": "*3", "chain": "output", "action": "drop", "comment": "dup"},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(AmbiguousResourceError) as exc_info:
        guard.move_firewall_rule(client, settings_write_enabled, comment="target", before_comment="dup", confirm=True)
    assert "dup" in str(exc_info.value)


def test_move_firewall_rule_chain_disambiguates_before_comment(settings_write_enabled: Settings, device: Device):
    # 'dup' exists in two chains; chain='forward' must narrow the DESTINATION too,
    # not only the target rule - otherwise this would raise AmbiguousResourceError.
    fake = FakeConnection(
        data={
            ("ip", "firewall", "filter"): [
                {".id": "*2", "chain": "forward", "action": "accept", "comment": "dup"},
                {".id": "*3", "chain": "input", "action": "drop", "comment": "dup"},
                {".id": "*1", "chain": "forward", "action": "drop", "comment": "target"},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    preview = guard.move_firewall_rule(
        client, settings_write_enabled, comment="target", chain="forward", before_comment="dup", confirm=True
    )
    assert preview.applied is True
    order = [row[".id"] for row in fake.path("ip", "firewall", "filter")._rows]
    assert order == ["*1", "*2", "*3"]


def test_move_firewall_rule_rejects_empty_comment_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.move_firewall_rule(guarded_client, settings_write_enabled, comment="", position=0, confirm=True)


def test_move_firewall_rule_rejects_invalid_position_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.move_firewall_rule(guarded_client, settings_write_enabled, comment="rule-c", position=-1, confirm=True)


def test_move_firewall_rule_rejects_invalid_chain_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.move_firewall_rule(
            guarded_client, settings_write_enabled, comment="rule-c", chain="bad chain!", position=0, confirm=True
        )


def test_move_firewall_rule_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, settings_write_enabled: Settings, device: Device
):
    fake = _move_fixture()
    client = MikrotikClient(device, connection=fake)
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["move_firewall_rule"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "move_firewall_rule", patched_op)

    guard.move_firewall_rule(client, settings_write_enabled, comment="rule-c", position=0, confirm=True)


# --- v1.3: add_ppp_secret -----------------------------------------------------
#
# add_ppp_secret's password asymmetry (present in the tool RESULT, absent
# from the audit journal - mirroring add_hotspot_user's own) is proven in
# tests/test_guard_audit.py, not here - these tests cover the ordinary
# guard mechanics (gate, preview/confirm, duplicate rejection, validation).


def _ppp_secret_fixture() -> FakeConnection:
    return FakeConnection(
        data={
            ("ppp", "secret"): [
                {
                    ".id": "*1",
                    "name": "pppoe-client1",
                    "password": "s3cret-fake",
                    "service": "pppoe",
                    "profile": "default-encryption",
                    "remote-address": "10.40.0.10",
                    "disabled": "false",
                }
            ]
        }
    )


def test_add_ppp_secret_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.add_ppp_secret(client, settings, name="customer2", password="Passw0rd!", confirm=True)


def test_add_ppp_secret_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.add_ppp_secret(guarded_client, settings, name="customer2", password="Passw0rd!", confirm=True)


def test_add_ppp_secret_preview_does_not_create(settings_write_enabled: Settings, device: Device):
    fake = _ppp_secret_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.add_ppp_secret(
        client, settings_write_enabled, name="customer2", password="Passw0rd!", confirm=False
    )
    assert preview.applied is False
    assert preview.before == {}
    assert preview.after == {"name": "customer2", "password": "Passw0rd!", "service": "any"}
    names = {row["name"] for row in fake.path("ppp", "secret")._rows}
    assert "customer2" not in names


def test_add_ppp_secret_confirm_true_creates(settings_write_enabled: Settings, device: Device):
    fake = _ppp_secret_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.add_ppp_secret(client, settings_write_enabled, name="customer2", password="Passw0rd!", confirm=True)
    assert preview.applied is True
    assert preview.after == {"name": "customer2", "password": "Passw0rd!", "service": "any"}
    rows = fake.path("ppp", "secret")._rows
    created = next(row for row in rows if row["name"] == "customer2")
    assert created["password"] == "Passw0rd!"
    assert created["service"] == "any"


def test_add_ppp_secret_confirm_true_with_optional_fields(settings_write_enabled: Settings, device: Device):
    fake = _ppp_secret_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.add_ppp_secret(
        client,
        settings_write_enabled,
        name="customer3",
        password="Passw0rd!",
        service="pppoe",
        profile="guest-profile",
        remote_address="10.40.0.99",
        comment="new customer",
        confirm=True,
    )
    assert preview.applied is True
    assert preview.after == {
        "name": "customer3",
        "password": "Passw0rd!",
        "service": "pppoe",
        "profile": "guest-profile",
        "remote-address": "10.40.0.99",
        "comment": "new customer",
    }


def test_add_ppp_secret_rejects_duplicate_name(settings_write_enabled: Settings, device: Device):
    fake = _ppp_secret_fixture()
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ResourceAlreadyExistsError) as exc_info:
        guard.add_ppp_secret(
            client, settings_write_enabled, name="pppoe-client1", password="AnotherPass1", confirm=True
        )
    assert "pppoe-client1" in str(exc_info.value)
    rows = [row for row in fake.path("ppp", "secret")._rows if row["name"] == "pppoe-client1"]
    assert len(rows) == 1


def test_add_ppp_secret_rejects_invalid_name_before_touching_device(settings_write_enabled: Settings, device: Device):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_ppp_secret(
            guarded_client, settings_write_enabled, name="bad name!", password="Passw0rd!", confirm=True
        )


def test_add_ppp_secret_rejects_empty_password_before_touching_device(settings_write_enabled: Settings, device: Device):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_ppp_secret(guarded_client, settings_write_enabled, name="customer2", password="", confirm=True)


def test_add_ppp_secret_rejects_invalid_service_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_ppp_secret(
            guarded_client, settings_write_enabled, name="customer2", password="Passw0rd!", service="ike2", confirm=True
        )


def test_add_ppp_secret_rejects_invalid_profile_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_ppp_secret(
            guarded_client,
            settings_write_enabled,
            name="customer2",
            password="Passw0rd!",
            profile="bad profile!",
            confirm=True,
        )


def test_add_ppp_secret_rejects_invalid_remote_address_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_ppp_secret(
            guarded_client,
            settings_write_enabled,
            name="customer2",
            password="Passw0rd!",
            remote_address="not-an-ip",
            confirm=True,
        )


def test_add_ppp_secret_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, client: MikrotikClient, settings_write_enabled: Settings
):
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["add_ppp_secret"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "add_ppp_secret", patched_op)

    guard.add_ppp_secret(client, settings_write_enabled, name="customer2", password="Passw0rd!", confirm=True)

    assert called == {
        "path": patched_op.path,
        "fields": {"name": "customer2", "password": "Passw0rd!", "service": "any"},
    }


# --- v1.3: remove_ppp_secret --------------------------------------------------


def test_remove_ppp_secret_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.remove_ppp_secret(client, settings, name="pppoe-client1", confirm=True)


def test_remove_ppp_secret_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.remove_ppp_secret(guarded_client, settings, name="pppoe-client1", confirm=True)


def test_remove_ppp_secret_preview_does_not_apply(settings_write_enabled: Settings, device: Device):
    fake = _ppp_secret_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.remove_ppp_secret(client, settings_write_enabled, name="pppoe-client1", confirm=False)

    assert preview.applied is False
    assert preview.before["name"] == "pppoe-client1"
    assert preview.after == {}
    names = {row["name"] for row in fake.path("ppp", "secret")._rows}
    assert "pppoe-client1" in names


def test_remove_ppp_secret_preview_never_includes_password(settings_write_enabled: Settings, device: Device):
    """SECURITY: the matched row's `password` must be stripped from `before`
    in guard.py itself, before the WritePreview is ever constructed - see
    guard.remove_ppp_secret's docstring."""
    fake = _ppp_secret_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.remove_ppp_secret(client, settings_write_enabled, name="pppoe-client1", confirm=False)
    assert "password" not in preview.before


def test_remove_ppp_secret_confirm_true_removes(settings_write_enabled: Settings, device: Device):
    fake = _ppp_secret_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.remove_ppp_secret(client, settings_write_enabled, name="pppoe-client1", confirm=True)

    assert preview.applied is True
    names = {row["name"] for row in fake.path("ppp", "secret")._rows}
    assert "pppoe-client1" not in names


def test_remove_ppp_secret_unknown_name_raises_resource_not_found(settings_write_enabled: Settings, device: Device):
    fake = _ppp_secret_fixture()
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.remove_ppp_secret(client, settings_write_enabled, name="ghost-secret", confirm=True)
    assert "ghost-secret" in str(exc_info.value)


def test_remove_ppp_secret_ambiguous_name_raises_and_removes_nothing(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(
        data={
            ("ppp", "secret"): [
                {".id": "*1", "name": "dup-secret", "password": "one-fake", "service": "pppoe"},
                {".id": "*2", "name": "dup-secret", "password": "two-fake", "service": "l2tp"},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(AmbiguousResourceError) as exc_info:
        guard.remove_ppp_secret(client, settings_write_enabled, name="dup-secret", confirm=True)
    assert "dup-secret" in str(exc_info.value)
    rows = [row for row in fake.path("ppp", "secret")._rows if row["name"] == "dup-secret"]
    assert len(rows) == 2


def test_remove_ppp_secret_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, settings_write_enabled: Settings, device: Device
):
    fake = _ppp_secret_fixture()
    client = MikrotikClient(device, connection=fake)
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["remove_ppp_secret"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "remove_ppp_secret", patched_op)

    guard.remove_ppp_secret(client, settings_write_enabled, name="pppoe-client1", confirm=True)

    assert called == {"path": patched_op.path, "fields": {"ids": ("*1",)}}


# --- set_ntp_servers (v1.8) --------------------------------------------------


def _ros7_ntp_fixture(enabled: bool | None = True) -> FakeConnection:
    row: dict = {"mode": "unicast", "servers": "10.0.0.1,old.pool.ntp.org"}
    if enabled is not None:
        row["enabled"] = enabled
    return FakeConnection(data={("system", "ntp", "client"): [row]})


def _ros6_ntp_fixture(with_dns_names: bool = False, enabled: bool | None = True) -> FakeConnection:
    row: dict = {"mode": "unicast", "primary-ntp": "10.0.0.1", "secondary-ntp": "0.0.0.0"}
    if with_dns_names:
        row["server-dns-names"] = ""
    if enabled is not None:
        row["enabled"] = enabled
    return FakeConnection(data={("system", "ntp", "client"): [row]})


def test_set_ntp_servers_blocked_when_write_disabled(settings: Settings, device: Device):
    fake = _ros7_ntp_fixture()
    client = MikrotikClient(device, connection=fake)
    with pytest.raises(WriteDisabledError):
        guard.set_ntp_servers(client, settings, servers=["10.0.0.2"], confirm=True)


def test_set_ntp_servers_read_only_gate_applies_before_touching_device(settings: Settings, device: Device):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.set_ntp_servers(guarded_client, settings, servers=["10.0.0.2"], confirm=True)


def test_set_ntp_servers_requires_at_least_one_server(settings_write_enabled: Settings, device: Device):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.set_ntp_servers(guarded_client, settings_write_enabled, servers=[], confirm=True)


def test_set_ntp_servers_validates_fail_fast_before_touching_device(settings_write_enabled: Settings, device: Device):
    """An invalid server must be rejected before /system/ntp/client is ever
    read - RaisingConnection proves the device is never touched."""
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.set_ntp_servers(guarded_client, settings_write_enabled, servers=["not a valid host!!"], confirm=True)


def test_set_ntp_servers_ros7_preview_then_confirm(settings_write_enabled: Settings, device: Device):
    fake = _ros7_ntp_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_ntp_servers(client, settings_write_enabled, servers=["1.2.3.4", "pool.ntp.org"], confirm=False)
    assert preview.operation == "set_ntp_servers"
    assert preview.applied is False
    assert preview.before["servers"] == "10.0.0.1,old.pool.ntp.org"
    assert preview.after["servers"] == "1.2.3.4,pool.ntp.org"
    # Preview must not touch the device.
    assert fake.path("system", "ntp", "client")._rows[0]["servers"] == "10.0.0.1,old.pool.ntp.org"

    applied = guard.set_ntp_servers(client, settings_write_enabled, servers=["1.2.3.4", "pool.ntp.org"], confirm=True)
    assert applied.applied is True
    assert fake.path("system", "ntp", "client")._rows[0]["servers"] == "1.2.3.4,pool.ntp.org"


def test_set_ntp_servers_ros6_maps_first_two_servers_to_primary_secondary(
    settings_write_enabled: Settings, device: Device
):
    fake = _ros6_ntp_fixture()
    client = MikrotikClient(device, connection=fake)

    applied = guard.set_ntp_servers(client, settings_write_enabled, servers=["1.2.3.4", "5.6.7.8"], confirm=True)

    assert applied.operation == "set_ntp_servers"
    assert applied.applied is True
    assert applied.after["primary-ntp"] == "1.2.3.4"
    assert applied.after["secondary-ntp"] == "5.6.7.8"
    row = fake.path("system", "ntp", "client")._rows[0]
    assert row["primary-ntp"] == "1.2.3.4"
    assert row["secondary-ntp"] == "5.6.7.8"
    # ROS6 has no `servers` list at all - never invented on the write side.
    assert "servers" not in row


def test_set_ntp_servers_ros6_single_server_only_sets_primary(settings_write_enabled: Settings, device: Device):
    fake = _ros6_ntp_fixture()
    client = MikrotikClient(device, connection=fake)

    applied = guard.set_ntp_servers(client, settings_write_enabled, servers=["1.2.3.4"], confirm=True)

    assert applied.applied is True
    row = fake.path("system", "ntp", "client")._rows[0]
    assert row["primary-ntp"] == "1.2.3.4"
    # secondary-ntp untouched (still its old fixture value).
    assert row["secondary-ntp"] == "0.0.0.0"


def test_set_ntp_servers_ros6_ignores_extra_servers_with_warning(settings_write_enabled: Settings, device: Device):
    fake = _ros6_ntp_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_ntp_servers(
        client, settings_write_enabled, servers=["1.2.3.4", "5.6.7.8", "9.9.9.9"], confirm=False
    )

    assert preview.warning is not None
    assert "9.9.9.9" in preview.warning
    assert preview.after["primary-ntp"] == "1.2.3.4"
    assert preview.after["secondary-ntp"] == "5.6.7.8"


def test_set_ntp_servers_ros6_hostname_routes_to_server_dns_names_when_field_exists(
    settings_write_enabled: Settings, device: Device
):
    fake = _ros6_ntp_fixture(with_dns_names=True)
    client = MikrotikClient(device, connection=fake)

    applied = guard.set_ntp_servers(client, settings_write_enabled, servers=["1.2.3.4", "pool.ntp.org"], confirm=True)

    assert applied.applied is True
    row = fake.path("system", "ntp", "client")._rows[0]
    assert row["primary-ntp"] == "1.2.3.4"
    assert row["server-dns-names"] == "pool.ntp.org"
    # The hostname is NOT forced into secondary-ntp - RouterOS wouldn't accept it there.
    assert row["secondary-ntp"] == "0.0.0.0"
    assert applied.warning is None


def test_set_ntp_servers_ros6_hostname_warns_when_no_server_dns_names_field(
    settings_write_enabled: Settings, device: Device
):
    fake = _ros6_ntp_fixture(with_dns_names=False)
    client = MikrotikClient(device, connection=fake)

    applied = guard.set_ntp_servers(client, settings_write_enabled, servers=["1.2.3.4", "pool.ntp.org"], confirm=True)

    assert applied.applied is True
    row = fake.path("system", "ntp", "client")._rows[0]
    assert row["primary-ntp"] == "1.2.3.4"
    # secondary-ntp left untouched - the hostname could not be honestly applied.
    assert row["secondary-ntp"] == "0.0.0.0"
    assert applied.warning is not None
    assert "pool.ntp.org" in applied.warning
    assert "not applied" in applied.warning


def test_set_ntp_servers_ros6_all_hostnames_with_no_server_dns_names_raises_validation_error(
    settings_write_enabled: Settings, device: Device
):
    """Nothing at all could be honestly applied - must fail loudly rather
    than silently perform a no-op write."""
    fake = _ros6_ntp_fixture(with_dns_names=False)
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ValidationError):
        guard.set_ntp_servers(client, settings_write_enabled, servers=["pool.ntp.org"], confirm=True)
    # Nothing was written.
    row = fake.path("system", "ntp", "client")._rows[0]
    assert row["primary-ntp"] == "10.0.0.1"


def test_set_ntp_servers_warns_when_client_disabled(settings_write_enabled: Settings, device: Device):
    fake = _ros7_ntp_fixture(enabled=False)
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_ntp_servers(client, settings_write_enabled, servers=["1.2.3.4"], confirm=False)

    assert preview.warning is not None
    assert "disabled" in preview.warning


def test_set_ntp_servers_no_warning_when_client_enabled(settings_write_enabled: Settings, device: Device):
    fake = _ros7_ntp_fixture(enabled=True)
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_ntp_servers(client, settings_write_enabled, servers=["1.2.3.4"], confirm=False)

    assert preview.warning is None


def test_set_ntp_servers_defaults_to_ros7_shape_when_menu_row_empty(settings_write_enabled: Settings, device: Device):
    """A device row with neither `servers` nor `primary-ntp` (e.g. a brand
    new/never-configured NTP client) is treated as ROS7 - documented
    behaviour, not an error."""
    fake = FakeConnection(data={("system", "ntp", "client"): [{}]})
    client = MikrotikClient(device, connection=fake)

    applied = guard.set_ntp_servers(client, settings_write_enabled, servers=["1.2.3.4"], confirm=True)

    assert applied.applied is True
    assert fake.path("system", "ntp", "client")._rows[0]["servers"] == "1.2.3.4"


def test_set_ntp_servers_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, settings_write_enabled: Settings, device: Device
):
    fake = _ros7_ntp_fixture()
    client = MikrotikClient(device, connection=fake)
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["set_ntp_servers"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "set_ntp_servers", patched_op)

    guard.set_ntp_servers(client, settings_write_enabled, servers=["1.2.3.4"], confirm=True)

    assert called == {"path": patched_op.path, "fields": {"servers": "1.2.3.4"}}


# --- v1.10: IPv6 write parity ------------------------------------------------
#
# enable_ipv6_firewall_rule/disable_ipv6_firewall_rule, add_ipv6_route/
# remove_ipv6_route, add_to_ipv6_address_list/remove_from_ipv6_address_list
# mirror their IPv4 counterparts field-for-field on the equivalent /ipv6/*
# path. Coverage below deliberately focuses on what's actually NEW/risky in
# this round rather than re-proving every IPv4 behavior a second time:
#   - IPv6-only address validation (an IPv4 address/subnet must be rejected
#     BEFORE the device is touched, same "fail fast" contract as every other
#     validated write).
#   - remove_ipv6_route's dynamic-route refusal (the single most important
#     safety property carried over from remove_route, tested explicitly with
#     a real Python bool - the v1.5 lesson this whole codebase learned the
#     hard way, see remove_route's own regression test above).
#   - ambiguous/not-found resolution, never-creates guarantees, dispatch via
#     ALLOWLIST.
#   - the "ipv6 package disabled" trap: unlike the v1.9 READS (which catch
#     DeviceCommandError and return []), these WRITES must let
#     DeviceCommandError propagate - a write has no safe "nothing happened"
#     empty-list shape to fall back to.


def test_enable_ipv6_firewall_rule_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    assert settings.allow_write is False
    with pytest.raises(WriteDisabledError):
        guard.enable_ipv6_firewall_rule(client, settings, comment="allow-v6-mgmt", confirm=True)


def test_disable_ipv6_firewall_rule_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    assert settings.allow_write is False
    with pytest.raises(WriteDisabledError):
        guard.disable_ipv6_firewall_rule(client, settings, comment="allow-v6-mgmt", confirm=True)


def test_enable_ipv6_firewall_rule_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.enable_ipv6_firewall_rule(guarded_client, settings, comment="allow-v6-mgmt", confirm=True)


def _ipv6_filter_fixture() -> FakeConnection:
    return FakeConnection(
        data={
            ("ipv6", "firewall", "filter"): [
                {".id": "*1", "chain": "input", "action": "accept", "comment": "allow-v6-mgmt", "disabled": True},
                {".id": "*2", "chain": "forward", "action": "drop", "comment": "block-v6-guest", "disabled": False},
            ]
        }
    )


def test_enable_ipv6_firewall_rule_preview_does_not_apply(settings_write_enabled: Settings, device: Device):
    fake = _ipv6_filter_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.enable_ipv6_firewall_rule(client, settings_write_enabled, comment="allow-v6-mgmt", confirm=False)
    assert preview.applied is False
    assert preview.before["disabled"] is True
    assert preview.after["disabled"] == "no"
    assert fake.path("ipv6", "firewall", "filter")._rows[0]["disabled"] is True


def test_enable_ipv6_firewall_rule_confirm_true_applies(settings_write_enabled: Settings, device: Device):
    fake = _ipv6_filter_fixture()
    client = MikrotikClient(device, connection=fake)

    applied = guard.enable_ipv6_firewall_rule(client, settings_write_enabled, comment="allow-v6-mgmt", confirm=True)
    assert applied.applied is True
    assert fake.path("ipv6", "firewall", "filter")._rows[0]["disabled"] == "no"


def test_disable_ipv6_firewall_rule_confirm_true_applies(settings_write_enabled: Settings, device: Device):
    fake = _ipv6_filter_fixture()
    client = MikrotikClient(device, connection=fake)

    applied = guard.disable_ipv6_firewall_rule(client, settings_write_enabled, comment="block-v6-guest", confirm=True)
    assert applied.applied is True
    assert fake.path("ipv6", "firewall", "filter")._rows[1]["disabled"] == "yes"


def test_enable_ipv6_firewall_rule_never_creates_a_rule(settings_write_enabled: Settings, device: Device):
    fake = _ipv6_filter_fixture()
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ResourceNotFoundError):
        guard.enable_ipv6_firewall_rule(client, settings_write_enabled, comment="no-such-rule", confirm=True)
    assert len(fake.path("ipv6", "firewall", "filter")._rows) == 2


def test_enable_ipv6_firewall_rule_ambiguous_comment_raises_ambiguous_resource_error(
    settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(
        data={
            ("ipv6", "firewall", "filter"): [
                {".id": "*1", "chain": "input", "comment": "dup", "disabled": True},
                {".id": "*2", "chain": "forward", "comment": "dup", "disabled": True},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(AmbiguousResourceError):
        guard.enable_ipv6_firewall_rule(client, settings_write_enabled, comment="dup", confirm=True)


def test_enable_ipv6_firewall_rule_disambiguated_by_chain(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(
        data={
            ("ipv6", "firewall", "filter"): [
                {".id": "*1", "chain": "input", "comment": "dup", "disabled": True},
                {".id": "*2", "chain": "forward", "comment": "dup", "disabled": True},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    applied = guard.enable_ipv6_firewall_rule(
        client, settings_write_enabled, comment="dup", chain="forward", confirm=True
    )
    assert applied.applied is True
    assert applied.before[".id"] == "*2"


def test_enable_ipv6_firewall_rule_unknown_comment_error_names_ipv6_filter_resource(
    settings_write_enabled: Settings, device: Device
):
    """resource_label="IPv6 firewall filter rule" - distinct from the IPv4
    pair's "Firewall filter rule" - so an error is never confused between
    the two menus."""
    fake = _ipv6_filter_fixture()
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.enable_ipv6_firewall_rule(client, settings_write_enabled, comment="missing", confirm=True)
    assert "IPv6 firewall filter rule" in str(exc_info.value)


def test_enable_ipv6_firewall_rule_rejects_empty_comment_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.enable_ipv6_firewall_rule(guarded_client, settings_write_enabled, comment="", confirm=True)


def test_enable_ipv6_firewall_rule_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, settings_write_enabled: Settings, device: Device
):
    fake = _ipv6_filter_fixture()
    client = MikrotikClient(device, connection=fake)
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["enable_ipv6_firewall_rule"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "enable_ipv6_firewall_rule", patched_op)

    guard.enable_ipv6_firewall_rule(client, settings_write_enabled, comment="allow-v6-mgmt", confirm=True)

    assert called["path"] == patched_op.path
    assert called["fields"][".id"] == "*1"
    assert called["fields"]["disabled"] == "no"


def test_enable_ipv6_firewall_rule_propagates_error_when_ipv6_package_disabled(
    settings_write_enabled: Settings, device: Device
):
    """WRITE tools must NOT catch DeviceCommandError like the v1.9 reads do
    - a write has no safe empty-list fallback, so the ipv6-disabled error
    must surface clearly instead of looking like "nothing to toggle"."""
    fake = FakeConnection(raise_for={("ipv6", "firewall", "filter"): LibRouterosError("no such command")})
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(DeviceCommandError):
        guard.enable_ipv6_firewall_rule(client, settings_write_enabled, comment="allow-v6-mgmt", confirm=True)


# --- add_ipv6_route / remove_ipv6_route --------------------------------------


def test_add_ipv6_route_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    assert settings.allow_write is False
    with pytest.raises(WriteDisabledError):
        guard.add_ipv6_route(client, settings, dst_address="2001:db8:40::/64", gateway="2001:db8::254", confirm=True)


def test_add_ipv6_route_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.add_ipv6_route(
            guarded_client, settings, dst_address="2001:db8:40::/64", gateway="2001:db8::254", confirm=True
        )


def test_add_ipv6_route_preview_does_not_apply(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(data={("ipv6", "route"): []})
    client = MikrotikClient(device, connection=fake)

    preview = guard.add_ipv6_route(
        client, settings_write_enabled, dst_address="2001:db8:40::/64", gateway="2001:db8::254", confirm=False
    )
    assert preview.applied is False
    assert preview.before == {}
    assert preview.after == {"dst-address": "2001:db8:40::/64", "gateway": "2001:db8::254"}
    assert fake.path("ipv6", "route")._rows == []


def test_add_ipv6_route_confirm_true_applies(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(data={("ipv6", "route"): []})
    client = MikrotikClient(device, connection=fake)

    preview = guard.add_ipv6_route(
        client, settings_write_enabled, dst_address="2001:db8:40::/64", gateway="2001:db8::254", confirm=True
    )
    assert preview.applied is True
    created = fake.path("ipv6", "route")._rows[0]
    assert created == {"dst-address": "2001:db8:40::/64", "gateway": "2001:db8::254"}


def test_add_ipv6_route_includes_optional_distance_and_comment_when_given(
    settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(data={("ipv6", "route"): []})
    client = MikrotikClient(device, connection=fake)

    guard.add_ipv6_route(
        client,
        settings_write_enabled,
        dst_address="2001:db8:40::/64",
        gateway="2001:db8::254",
        distance=3,
        comment="failover-v6",
        confirm=True,
    )
    created = fake.path("ipv6", "route")._rows[0]
    assert created["distance"] == "3"
    assert created["comment"] == "failover-v6"


def test_add_ipv6_route_never_refuses_duplicate_dst_address(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(data={("ipv6", "route"): [{".id": "*1", "dst-address": "::/0", "gateway": "2001:db8::254"}]})
    client = MikrotikClient(device, connection=fake)

    preview = guard.add_ipv6_route(
        client, settings_write_enabled, dst_address="::/0", gateway="2001:db8::253", confirm=True
    )
    assert preview.applied is True
    matches = [row for row in fake.path("ipv6", "route")._rows if row["dst-address"] == "::/0"]
    assert len(matches) == 2


def test_add_ipv6_route_default_dst_address_carries_warning(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(data={("ipv6", "route"): []})
    client = MikrotikClient(device, connection=fake)

    preview = guard.add_ipv6_route(
        client, settings_write_enabled, dst_address="::/0", gateway="2001:db8::254", confirm=False
    )
    assert preview.warning is not None
    assert "::/0" in preview.warning
    assert "default" in preview.warning.lower()

    applied = guard.add_ipv6_route(
        client, settings_write_enabled, dst_address="::/0", gateway="2001:db8::254", confirm=True
    )
    assert applied.warning is not None


def test_add_ipv6_route_non_default_dst_address_carries_no_warning(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(data={("ipv6", "route"): []})
    client = MikrotikClient(device, connection=fake)

    preview = guard.add_ipv6_route(
        client, settings_write_enabled, dst_address="2001:db8:40::/64", gateway="2001:db8::254", confirm=False
    )
    assert preview.warning is None


def test_add_ipv6_route_rejects_ipv4_dst_address_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    """The IPv6 route tool must reject an IPv4 dst_address outright - /ipv6/route
    has no IPv4 concept."""
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_ipv6_route(
            guarded_client, settings_write_enabled, dst_address="10.40.0.0/24", gateway="2001:db8::254", confirm=True
        )


def test_add_ipv6_route_rejects_ipv4_gateway_before_touching_device(settings_write_enabled: Settings, device: Device):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_ipv6_route(
            guarded_client,
            settings_write_enabled,
            dst_address="2001:db8:40::/64",
            gateway="10.0.0.254",
            confirm=True,
        )


def test_add_ipv6_route_rejects_invalid_distance_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_ipv6_route(
            guarded_client,
            settings_write_enabled,
            dst_address="2001:db8:40::/64",
            gateway="2001:db8::254",
            distance=999,
            confirm=True,
        )


def test_add_ipv6_route_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(data={("ipv6", "route"): []})
    client = MikrotikClient(device, connection=fake)
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["add_ipv6_route"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "add_ipv6_route", patched_op)

    guard.add_ipv6_route(
        client, settings_write_enabled, dst_address="2001:db8:40::/64", gateway="2001:db8::254", confirm=True
    )

    assert called == {
        "path": patched_op.path,
        "fields": {"dst-address": "2001:db8:40::/64", "gateway": "2001:db8::254"},
    }


def test_add_ipv6_route_propagates_error_when_ipv6_package_disabled(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(raise_for={("ipv6", "route"): LibRouterosError("no such command")})
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(DeviceCommandError):
        guard.add_ipv6_route(
            client, settings_write_enabled, dst_address="2001:db8:40::/64", gateway="2001:db8::254", confirm=True
        )


def test_remove_ipv6_route_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    assert settings.allow_write is False
    with pytest.raises(WriteDisabledError):
        guard.remove_ipv6_route(client, settings, dst_address="2001:db8:20::/64", confirm=True)


def test_remove_ipv6_route_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.remove_ipv6_route(guarded_client, settings, dst_address="2001:db8:20::/64", confirm=True)


def _ipv6_route_fake_with_static_and_dynamic() -> FakeConnection:
    """Mirrors _route_fake_with_static_and_dynamic (IPv4) above:
    `dynamic` is a real Python `bool`, never the string "true"."""
    return FakeConnection(
        data={
            ("ipv6", "route"): [
                {".id": "*1", "dst-address": "2001:db8:20::/64", "gateway": "2001:db8::254"},
                {".id": "*2", "dst-address": "2001:db8:30::/64", "gateway": "ether1", "dynamic": True},
            ]
        }
    )


def test_remove_ipv6_route_preview_does_not_apply(settings_write_enabled: Settings, device: Device):
    fake = _ipv6_route_fake_with_static_and_dynamic()
    client = MikrotikClient(device, connection=fake)

    preview = guard.remove_ipv6_route(client, settings_write_enabled, dst_address="2001:db8:20::/64", confirm=False)
    assert preview.applied is False
    assert preview.before == {".id": "*1", "dst-address": "2001:db8:20::/64", "gateway": "2001:db8::254"}
    assert len(fake.path("ipv6", "route")._rows) == 2


def test_remove_ipv6_route_confirm_true_applies(settings_write_enabled: Settings, device: Device):
    fake = _ipv6_route_fake_with_static_and_dynamic()
    client = MikrotikClient(device, connection=fake)

    preview = guard.remove_ipv6_route(client, settings_write_enabled, dst_address="2001:db8:20::/64", confirm=True)
    assert preview.applied is True
    remaining = {row["dst-address"] for row in fake.path("ipv6", "route")._rows}
    assert remaining == {"2001:db8:30::/64"}


def test_remove_ipv6_route_ambiguous_without_gateway_raises_ambiguous_resource_error(
    settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(
        data={
            ("ipv6", "route"): [
                {".id": "*1", "dst-address": "::/0", "gateway": "2001:db8::254", "comment": "primary"},
                {".id": "*2", "dst-address": "::/0", "gateway": "2001:db8::253", "comment": "backup"},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(AmbiguousResourceError):
        guard.remove_ipv6_route(client, settings_write_enabled, dst_address="::/0", confirm=True)
    assert len(fake.path("ipv6", "route")._rows) == 2


def test_remove_ipv6_route_unknown_dst_address_raises_resource_not_found(
    settings_write_enabled: Settings, device: Device
):
    fake = _ipv6_route_fake_with_static_and_dynamic()
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ResourceNotFoundError):
        guard.remove_ipv6_route(client, settings_write_enabled, dst_address="2001:db8:99::/64", confirm=True)


def test_remove_ipv6_route_refuses_dynamic_route_and_does_not_remove_it(
    settings_write_enabled: Settings, device: Device
):
    """CRITICAL for this round: same dynamic-route refusal remove_route
    (IPv4) enforces, reused unchanged by _remove_route. dynamic=True is a
    real Python bool here, the actual shape librouteros hands back from
    hardware - NOT the string "true" (see coerce_ros_bool)."""
    fake = _ipv6_route_fake_with_static_and_dynamic()
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ValidationError) as exc_info:
        guard.remove_ipv6_route(client, settings_write_enabled, dst_address="2001:db8:30::/64", confirm=True)
    assert "dynamic" in str(exc_info.value).lower()

    remaining = {row["dst-address"] for row in fake.path("ipv6", "route")._rows}
    assert "2001:db8:30::/64" in remaining
    assert len(fake.path("ipv6", "route")._rows) == 2


def test_remove_ipv6_route_regression_dynamic_bool_true_is_refused_not_silently_removed(
    settings_write_enabled: Settings, device: Device
):
    """Same regression proof as remove_route's IPv4 test above, on the IPv6
    menu: a `dynamic=True` (Python bool) row must be refused, never removed -
    this is the exact 1.5.0 security fix `_remove_route` shares with both
    menus."""
    fake = FakeConnection(
        data={
            ("ipv6", "route"): [
                {".id": "*1", "dst-address": "2001:db8:30::/64", "gateway": "ether1", "dynamic": True},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ValidationError):
        guard.remove_ipv6_route(client, settings_write_enabled, dst_address="2001:db8:30::/64", confirm=True)

    assert len(fake.path("ipv6", "route")._rows) == 1


def test_remove_ipv6_route_allows_removal_when_dynamic_is_bool_false(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(
        data={
            ("ipv6", "route"): [
                {".id": "*1", "dst-address": "2001:db8:20::/64", "gateway": "2001:db8::254", "dynamic": False},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    preview = guard.remove_ipv6_route(client, settings_write_enabled, dst_address="2001:db8:20::/64", confirm=True)
    assert preview.applied is True
    assert fake.path("ipv6", "route")._rows == []


def test_remove_ipv6_route_allows_removal_when_dynamic_field_is_absent(
    settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(
        data={
            ("ipv6", "route"): [
                {".id": "*1", "dst-address": "2001:db8:20::/64", "gateway": "2001:db8::254"},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    preview = guard.remove_ipv6_route(client, settings_write_enabled, dst_address="2001:db8:20::/64", confirm=True)
    assert preview.applied is True
    assert fake.path("ipv6", "route")._rows == []


def test_remove_ipv6_route_default_dst_address_carries_warning_not_refusal(
    settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(data={("ipv6", "route"): [{".id": "*1", "dst-address": "::/0", "gateway": "2001:db8::254"}]})
    client = MikrotikClient(device, connection=fake)

    preview = guard.remove_ipv6_route(client, settings_write_enabled, dst_address="::/0", confirm=False)
    assert preview.warning is not None
    assert "::/0" in preview.warning
    assert "default" in preview.warning.lower()

    applied = guard.remove_ipv6_route(client, settings_write_enabled, dst_address="::/0", confirm=True)
    assert applied.applied is True
    assert applied.warning is not None


def test_remove_ipv6_route_rejects_ipv4_dst_address_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.remove_ipv6_route(guarded_client, settings_write_enabled, dst_address="10.20.0.0/24", confirm=True)


def test_remove_ipv6_route_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, settings_write_enabled: Settings, device: Device
):
    fake = _ipv6_route_fake_with_static_and_dynamic()
    client = MikrotikClient(device, connection=fake)
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["remove_ipv6_route"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "remove_ipv6_route", patched_op)

    guard.remove_ipv6_route(client, settings_write_enabled, dst_address="2001:db8:20::/64", confirm=True)

    assert called == {"path": patched_op.path, "fields": {"ids": ("*1",)}}


def test_remove_ipv6_route_propagates_error_when_ipv6_package_disabled(
    settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(raise_for={("ipv6", "route"): LibRouterosError("no such command")})
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(DeviceCommandError):
        guard.remove_ipv6_route(client, settings_write_enabled, dst_address="2001:db8:20::/64", confirm=True)


# --- add_to_ipv6_address_list / remove_from_ipv6_address_list ---------------


def test_add_to_ipv6_address_list_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    assert settings.allow_write is False
    with pytest.raises(WriteDisabledError):
        guard.add_to_ipv6_address_list(
            client, settings, list_name="blocked-clients-v6", address="2001:db8::61", confirm=True
        )


def test_add_to_ipv6_address_list_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.add_to_ipv6_address_list(
            guarded_client, settings, list_name="blocked-clients-v6", address="2001:db8::61", confirm=True
        )


def test_add_to_ipv6_address_list_preview_does_not_create(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(data={("ipv6", "firewall", "address-list"): []})
    client = MikrotikClient(device, connection=fake)

    preview = guard.add_to_ipv6_address_list(
        client, settings_write_enabled, list_name="blocked-clients-v6", address="2001:db8::61", confirm=False
    )
    assert preview.applied is False
    assert preview.before == {}
    assert preview.after["list"] == "blocked-clients-v6"
    assert preview.after["address"] == "2001:db8::61"
    assert fake.path("ipv6", "firewall", "address-list")._rows == []


def test_add_to_ipv6_address_list_confirm_true_creates(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(data={("ipv6", "firewall", "address-list"): []})
    client = MikrotikClient(device, connection=fake)

    applied = guard.add_to_ipv6_address_list(
        client, settings_write_enabled, list_name="blocked-clients-v6", address="2001:db8::61", confirm=True
    )
    assert applied.applied is True
    rows = fake.path("ipv6", "firewall", "address-list")._rows
    assert any(row["list"] == "blocked-clients-v6" and row["address"] == "2001:db8::61" for row in rows)


def test_add_to_ipv6_address_list_rejects_duplicate_list_and_address(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(
        data={
            ("ipv6", "firewall", "address-list"): [
                {".id": "*1", "list": "blocked-clients-v6", "address": "2001:db8::60"}
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ResourceAlreadyExistsError):
        guard.add_to_ipv6_address_list(
            client, settings_write_enabled, list_name="blocked-clients-v6", address="2001:db8::60", confirm=True
        )
    assert len(fake.path("ipv6", "firewall", "address-list")._rows) == 1


def test_add_to_ipv6_address_list_rejects_ipv4_address_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    """The IPv6 address-list tool must reject an IPv4 address outright -
    /ipv6/firewall/address-list has no IPv4 concept."""
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_to_ipv6_address_list(
            guarded_client, settings_write_enabled, list_name="blocked-clients-v6", address="10.0.0.61", confirm=True
        )


def test_add_to_ipv6_address_list_rejects_invalid_list_name(settings_write_enabled: Settings, device: Device):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.add_to_ipv6_address_list(
            guarded_client, settings_write_enabled, list_name="bad list", address="2001:db8::61", confirm=True
        )


def test_add_to_ipv6_address_list_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(data={("ipv6", "firewall", "address-list"): []})
    client = MikrotikClient(device, connection=fake)
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["add_to_ipv6_address_list"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "add_to_ipv6_address_list", patched_op)

    guard.add_to_ipv6_address_list(
        client, settings_write_enabled, list_name="blocked-clients-v6", address="2001:db8::61", confirm=True
    )

    assert called == {"path": patched_op.path, "fields": {"list": "blocked-clients-v6", "address": "2001:db8::61"}}


def test_add_to_ipv6_address_list_propagates_error_when_ipv6_package_disabled(
    settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(raise_for={("ipv6", "firewall", "address-list"): LibRouterosError("no such command")})
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(DeviceCommandError):
        guard.add_to_ipv6_address_list(
            client, settings_write_enabled, list_name="blocked-clients-v6", address="2001:db8::61", confirm=True
        )


def test_remove_from_ipv6_address_list_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    assert settings.allow_write is False
    with pytest.raises(WriteDisabledError):
        guard.remove_from_ipv6_address_list(
            client, settings, list_name="blocked-clients-v6", address="2001:db8::60", confirm=True
        )


def test_remove_from_ipv6_address_list_preview_then_confirm(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(
        data={
            ("ipv6", "firewall", "address-list"): [
                {".id": "*1", "list": "blocked-clients-v6", "address": "2001:db8::60"}
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    preview = guard.remove_from_ipv6_address_list(
        client, settings_write_enabled, list_name="blocked-clients-v6", address="2001:db8::60", confirm=False
    )
    assert preview.applied is False
    assert preview.before["address"] == "2001:db8::60"
    assert len(fake.path("ipv6", "firewall", "address-list")._rows) == 1

    applied = guard.remove_from_ipv6_address_list(
        client, settings_write_enabled, list_name="blocked-clients-v6", address="2001:db8::60", confirm=True
    )
    assert applied.applied is True
    assert fake.path("ipv6", "firewall", "address-list")._rows == []


def test_remove_from_ipv6_address_list_unknown_entry_raises_resource_not_found(
    settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(data={("ipv6", "firewall", "address-list"): []})
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ResourceNotFoundError):
        guard.remove_from_ipv6_address_list(
            client, settings_write_enabled, list_name="blocked-clients-v6", address="2001:db8::99", confirm=True
        )


def test_remove_from_ipv6_address_list_rejects_ipv4_address_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.remove_from_ipv6_address_list(
            guarded_client, settings_write_enabled, list_name="blocked-clients-v6", address="10.0.0.60", confirm=True
        )


def test_remove_from_ipv6_address_list_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(
        data={
            ("ipv6", "firewall", "address-list"): [
                {".id": "*1", "list": "blocked-clients-v6", "address": "2001:db8::60"}
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["remove_from_ipv6_address_list"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "remove_from_ipv6_address_list", patched_op)

    guard.remove_from_ipv6_address_list(
        client, settings_write_enabled, list_name="blocked-clients-v6", address="2001:db8::60", confirm=True
    )

    assert called == {"path": patched_op.path, "fields": {"ids": ("*1",)}}


def test_remove_from_ipv6_address_list_propagates_error_when_ipv6_package_disabled(
    settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(raise_for={("ipv6", "firewall", "address-list"): LibRouterosError("no such command")})
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(DeviceCommandError):
        guard.remove_from_ipv6_address_list(
            client, settings_write_enabled, list_name="blocked-clients-v6", address="2001:db8::60", confirm=True
        )


# =============================================================================
# v1.11: dead-man primitive (arm_dead_man/cancel_dead_man) + wireless RF
# tuning (set_wireless_channel/set_wireless_tx_power/set_wireless_tuning)
# =============================================================================

# --- arm_dead_man ------------------------------------------------------------


def test_arm_dead_man_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.arm_dead_man(
            client, settings, revert_commands=['/interface/wireless set [find name="wlan1"]'], minutes=3, confirm=True
        )


def test_arm_dead_man_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.arm_dead_man(
            guarded_client,
            settings,
            revert_commands=['/interface/wireless set [find name="wlan1"] frequency=5500'],
            minutes=3,
            confirm=True,
        )


def test_arm_dead_man_preview_does_not_apply(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(data={("system", "scheduler"): []})
    client = MikrotikClient(device, connection=fake)

    preview = guard.arm_dead_man(
        client,
        settings_write_enabled,
        revert_commands=['/interface/wireless set [find name="wlan1"] frequency=5500'],
        minutes=3,
        confirm=False,
    )

    assert preview.applied is False
    assert preview.after["name"].startswith("deadman-")
    assert fake.path("system", "scheduler")._rows == []


def test_arm_dead_man_confirm_true_applies(settings_write_enabled: Settings, device: Device):
    """2026-07-13 hardware finding: the scheduler must be a ONE-SHOT
    (`interval="00:00:00"`) with an EXPLICIT future `start-date`/
    `start-time`, computed `minutes` ahead of the device's own
    `/system/clock` - never an `interval`-only recurring schedule, which
    would keep RE-FIRING indefinitely (every `interval`) if the on-event
    ever aborted partway through, instead of failing once and staying
    inert (see guard._dead_man_deadline's docstring)."""
    fake = FakeConnection(
        data={("system", "scheduler"): [], ("system", "clock"): [{"date": "jan/01/2026", "time": "12:00:00"}]}
    )
    client = MikrotikClient(device, connection=fake)

    preview = guard.arm_dead_man(
        client,
        settings_write_enabled,
        revert_commands=['/interface/wireless set [find name="wlan1"] frequency=5500'],
        minutes=3,
        confirm=True,
    )

    assert preview.applied is True
    name = preview.after["name"]
    assert name.startswith("deadman-")
    rows = fake.path("system", "scheduler")._rows
    assert len(rows) == 1
    armed = rows[0]
    assert armed["name"] == name
    assert armed["start-date"] == "jan/01/2026"
    assert armed["start-time"] == "12:03:00"
    assert armed["interval"] == "00:00:00"  # one-shot: never repeats
    assert armed["policy"] == "read,write,test,policy,reboot"
    assert armed["on-event"].startswith(f':log warning "mcp-mikrotik dead-man reverting {name}"; ')
    assert '/interface/wireless set [find name="wlan1"] frequency=5500' in armed["on-event"]
    assert armed["on-event"].endswith(f'/system scheduler remove [find name="{name}"]')
    assert preview.warning is not None and name in preview.warning
    assert "jan/01/2026 12:03:00" in preview.warning


def test_arm_dead_man_deadline_rolls_over_midnight_and_month_correctly(
    settings_write_enabled: Settings, device: Device
):
    """THE edge case that originally motivated `interval`-only scheduling
    (a start-time-based schedule could wait until the SAME clock time the
    NEXT day) - now handled correctly the other way around: real `datetime`
    + `timedelta` arithmetic rolls the DATE forward too, so a dead-man
    armed one minute before midnight fires shortly after midnight the next
    day/month, never a day early or a day late."""
    fake = FakeConnection(
        data={("system", "scheduler"): [], ("system", "clock"): [{"date": "jan/31/2026", "time": "23:59:00"}]}
    )
    client = MikrotikClient(device, connection=fake)

    preview = guard.arm_dead_man(
        client,
        settings_write_enabled,
        revert_commands=['/ip/route set [find dst-address="0.0.0.0/0"] distance=1'],
        minutes=3,
        confirm=True,
    )

    armed = fake.path("system", "scheduler")._rows[0]
    assert armed["start-date"] == "feb/01/2026"
    assert armed["start-time"] == "00:02:00"
    assert preview.applied is True


def test_arm_dead_man_rejects_when_device_clock_has_no_row(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(data={("system", "scheduler"): [], ("system", "clock"): []})
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(DeviceCommandError):
        guard.arm_dead_man(
            client,
            settings_write_enabled,
            revert_commands=['/interface/wireless set [find name="wlan1"] frequency=5500'],
            minutes=3,
            confirm=True,
        )
    assert fake.path("system", "scheduler")._rows == []


def test_arm_dead_man_rejects_when_device_clock_is_unparseable(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(
        data={("system", "scheduler"): [], ("system", "clock"): [{"date": "not-a-date", "time": "not-a-time"}]}
    )
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(DeviceCommandError):
        guard.arm_dead_man(
            client,
            settings_write_enabled,
            revert_commands=['/interface/wireless set [find name="wlan1"] frequency=5500'],
            minutes=3,
            confirm=True,
        )
    assert fake.path("system", "scheduler")._rows == []


def test_arm_dead_man_generates_a_unique_name_each_call(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(data={("system", "scheduler"): []})
    client = MikrotikClient(device, connection=fake)

    first = guard.arm_dead_man(
        client,
        settings_write_enabled,
        revert_commands=['/interface/wireless set [find name="wlan1"] frequency=5500'],
        minutes=3,
        confirm=True,
    )
    second = guard.arm_dead_man(
        client,
        settings_write_enabled,
        revert_commands=['/interface/wireless set [find name="wlan1"] frequency=5500'],
        minutes=3,
        confirm=True,
    )

    assert first.after["name"] != second.after["name"]
    assert len(fake.path("system", "scheduler")._rows) == 2


@pytest.mark.parametrize("minutes", [0, -1, 61, 120])
def test_arm_dead_man_rejects_invalid_minutes_before_touching_device(
    minutes: int, settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.arm_dead_man(
            guarded_client,
            settings_write_enabled,
            revert_commands=['/interface/wireless set [find name="wlan1"] frequency=5500'],
            minutes=minutes,
            confirm=True,
        )


def test_arm_dead_man_rejects_empty_revert_commands_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.arm_dead_man(guarded_client, settings_write_enabled, revert_commands=[], minutes=3, confirm=True)


def test_arm_dead_man_rejects_too_many_revert_commands_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    too_many = [f'/ip/route set [find dst-address="10.{i}.0.0/24"] distance=1' for i in range(11)]
    with pytest.raises(ValidationError):
        guard.arm_dead_man(guarded_client, settings_write_enabled, revert_commands=too_many, minutes=3, confirm=True)


def test_arm_dead_man_rejects_control_characters_in_revert_command_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.arm_dead_man(
            guarded_client,
            settings_write_enabled,
            revert_commands=['/interface/wireless set [find name="wlan1"]\nfrequency=5500'],
            minutes=3,
            confirm=True,
        )


@pytest.mark.parametrize(
    "revert_command",
    [
        '/interface/wireless set [find name="wlan1"] comment=$var',
        '/interface/wireless set [find name="wlan1"] frequency=5500; /system reboot',
    ],
)
def test_arm_dead_man_rejects_unsafe_characters_in_revert_command_before_touching_device(
    revert_command: str, settings_write_enabled: Settings, device: Device
):
    """finding 2(a) of the 2026-07 hardening review."""
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.arm_dead_man(
            guarded_client, settings_write_enabled, revert_commands=[revert_command], minutes=3, confirm=True
        )


def test_arm_dead_man_rejects_dangerous_verb_in_revert_command_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    """finding 2(d) of the 2026-07 hardening review: revert_commands
    restores state already read from the device before a risky write - it
    is not a channel to run arbitrary/dangerous RouterOS commands. A
    caller-supplied revert command naming a dangerous verb is rejected
    before the device is ever touched, exactly like every other shape
    validation in this module."""
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError, match="reboot"):
        guard.arm_dead_man(
            guarded_client, settings_write_enabled, revert_commands=["/system reboot"], minutes=3, confirm=True
        )


def test_arm_dead_man_fire_when_revert_statement_is_unrecognized_does_not_self_remove(
    settings_write_enabled: Settings, device: Device
):
    """finding 2(b)/(c) of the 2026-07 hardening review: RouterOS aborts the
    ENTIRE on-event script at the first statement it can't parse - if a
    revert command breaks, the scheduler's own trailing self-remove never
    runs either, leaving a stale scheduler entry behind instead of healing
    the device. Proven here with a syntactically-plausible, VALID (passes
    validate_revert_command - no denylisted verb, no unsafe character)
    revert command for a menu the fake's own statement recognizer doesn't
    know how to apply (see FakeConnection.fire_scheduler's docstring: it
    only understands /interface/wireless set and /system scheduler remove
    shapes) - fire_scheduler must stop at that statement and never reach
    the self-remove, exactly mirroring what an actual RouterOS parse error
    would do to any revert command this package can't fully validate
    client-side (see validate_revert_command's docstring: "NOT a RouterOS
    script parser/validator")."""
    fake = FakeConnection(data={("system", "scheduler"): []})
    client = MikrotikClient(device, connection=fake)

    preview = guard.arm_dead_man(
        client,
        settings_write_enabled,
        revert_commands=['/ip/route set [find dst-address="0.0.0.0/0"] gateway=10.0.0.1'],
        minutes=3,
        confirm=True,
    )
    name = preview.after["name"]
    fake.advance_clock(3)

    fake.fire_scheduler(name)

    # The self-remove statement never ran - the scheduler entry is left
    # behind exactly as a real device would leave it after an aborted
    # on-event, instead of silently cleaning up after a broken revert.
    assert any(row.get("name") == name for row in fake.path("system", "scheduler")._rows)


def test_arm_dead_man_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, client: MikrotikClient, settings_write_enabled: Settings
):
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["arm_dead_man"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "arm_dead_man", patched_op)

    guard.arm_dead_man(
        client,
        settings_write_enabled,
        revert_commands=['/interface/wireless set [find name="wlan1"] frequency=5500'],
        minutes=3,
        confirm=True,
    )

    assert called["path"] == patched_op.path
    assert called["fields"]["start-date"] == "jan/01/2026"
    assert called["fields"]["start-time"] == "12:03:00"
    assert called["fields"]["interval"] == "00:00:00"
    assert called["fields"]["policy"] == "read,write,test,policy,reboot"
    assert called["fields"]["name"].startswith("deadman-")


# --- cancel_dead_man ----------------------------------------------------------


def test_cancel_dead_man_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.cancel_dead_man(client, settings, name="deadman-abc123", confirm=True)


def test_cancel_dead_man_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.cancel_dead_man(guarded_client, settings, name="deadman-abc123", confirm=True)


def test_cancel_dead_man_rejects_name_not_matching_dead_man_shape_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    """A caller can never point cancel_dead_man at an arbitrary, unrelated
    scheduler entry (e.g. an admin's own 'backup-daily' task) - the shape
    check runs, and rejects it, before the device is ever read."""
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.cancel_dead_man(guarded_client, settings_write_enabled, name="backup-daily", confirm=True)


def test_cancel_dead_man_preview_does_not_remove(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(
        data={
            ("system", "scheduler"): [
                {".id": "*9", "name": "deadman-abc1230000", "on-event": "", "interval": "00:03:00"}
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    preview = guard.cancel_dead_man(client, settings_write_enabled, name="deadman-abc1230000", confirm=False)

    assert preview.applied is False
    assert preview.before["name"] == "deadman-abc1230000"
    names = {row["name"] for row in fake.path("system", "scheduler")._rows}
    assert "deadman-abc1230000" in names


def test_cancel_dead_man_confirm_true_removes(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(
        data={
            ("system", "scheduler"): [
                {".id": "*9", "name": "deadman-abc1230000", "on-event": "", "interval": "00:03:00"}
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    preview = guard.cancel_dead_man(client, settings_write_enabled, name="deadman-abc1230000", confirm=True)

    assert preview.applied is True
    names = {row["name"] for row in fake.path("system", "scheduler")._rows}
    assert "deadman-abc1230000" not in names


def test_cancel_dead_man_unknown_name_raises_resource_not_found(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(data={("system", "scheduler"): []})
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ResourceNotFoundError) as exc_info:
        guard.cancel_dead_man(client, settings_write_enabled, name="deadman-dead0000ff", confirm=True)
    assert "deadman-dead0000ff" in str(exc_info.value)


def test_cancel_dead_man_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(
        data={
            ("system", "scheduler"): [
                {".id": "*9", "name": "deadman-abc1230000", "on-event": "", "interval": "00:03:00"}
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["cancel_dead_man"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "cancel_dead_man", patched_op)

    guard.cancel_dead_man(client, settings_write_enabled, name="deadman-abc1230000", confirm=True)

    assert called == {"path": patched_op.path, "fields": {"ids": ("*9",)}}


# --- set_wireless_channel ------------------------------------------------------

_WIRELESS_FIXTURE_ROW = {
    ".id": "*1",
    "name": "wlan1",
    "frequency": "5500",
    "channel-width": "20mhz",
    "frequency-mode": "regulatory-domain",
    "tx-power-mode": "default",
    "tx-power": "20",
    "adaptive-noise-immunity": "none",
    "distance": "dynamic",
}


def _wireless_fixture(**overrides) -> FakeConnection:
    row = dict(_WIRELESS_FIXTURE_ROW)
    row.update(overrides)
    return FakeConnection(data={("interface", "wireless"): [row], ("system", "scheduler"): []})


def test_set_wireless_channel_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.set_wireless_channel(client, settings, interface_name="wlan1", frequency=5300, confirm=True)


def test_set_wireless_channel_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.set_wireless_channel(guarded_client, settings, interface_name="wlan1", frequency=5300, confirm=True)


def test_set_wireless_channel_preview_does_not_apply_or_arm(settings_write_enabled: Settings, device: Device):
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wireless_channel(
        client, settings_write_enabled, interface_name="wlan1", frequency=5300, confirm=False
    )

    assert preview.applied is False
    assert preview.dead_man is None
    assert fake.path("interface", "wireless")._rows[0]["frequency"] == "5500"
    assert fake.path("system", "scheduler")._rows == []


@pytest.mark.parametrize(
    "frequency,expect_substring",
    [
        (5300, "DFS range"),
        (5620, "weather-radar"),
        (5180, None),
    ],
)
def test_set_wireless_channel_preview_reports_dfs_warning(
    frequency: int, expect_substring: str | None, settings_write_enabled: Settings, device: Device
):
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wireless_channel(
        client, settings_write_enabled, interface_name="wlan1", frequency=frequency, confirm=False
    )

    if expect_substring is None:
        assert preview.warning is None
    else:
        assert preview.warning is not None
        assert expect_substring in preview.warning


def test_set_wireless_channel_preview_reports_instant_switch_in_superchannel_mode(
    settings_write_enabled: Settings, device: Device
):
    fake = _wireless_fixture(**{"frequency-mode": "superchannel"})
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wireless_channel(
        client, settings_write_enabled, interface_name="wlan1", frequency=5620, confirm=False
    )

    assert preview.warning is not None
    assert "superchannel" in preview.warning
    assert "instant" in preview.warning


def test_set_wireless_channel_confirm_true_applies_and_arms_dead_man_by_default(
    settings_write_enabled: Settings, device: Device
):
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wireless_channel(
        client,
        settings_write_enabled,
        interface_name="wlan1",
        frequency=5300,
        channel_width="40mhz-turbo",
        confirm=True,
    )

    assert preview.applied is True
    updated = fake.path("interface", "wireless")._rows[0]
    assert updated["frequency"] == "5300"
    assert updated["channel-width"] == "40mhz-turbo"

    assert preview.dead_man is not None
    dead_man_name = preview.dead_man["name"]
    assert dead_man_name.startswith("deadman-")
    assert preview.dead_man["minutes"] == 3

    scheduler_rows = fake.path("system", "scheduler")._rows
    assert len(scheduler_rows) == 1
    armed = scheduler_rows[0]
    assert armed["name"] == dead_man_name
    # The revert command must capture the interface's PRIOR (before-change)
    # values, not the new ones.
    assert "frequency=5500" in armed["on-event"]
    assert "channel-width=20mhz" in armed["on-event"]


def test_set_wireless_channel_arms_dead_man_before_applying_the_write(
    monkeypatch: pytest.MonkeyPatch, settings_write_enabled: Settings, device: Device
):
    """THE key ordering property: the dead-man must be armed on the device
    BEFORE the risky write itself is sent - so if the write is the one that
    breaks reachability, the scheduler is already there to heal it."""
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    original_update = client.update
    observed: dict = {}

    def spy_update(*segments: str, **fields):
        observed["scheduler_rows_at_write_time"] = [dict(row) for row in fake.path("system", "scheduler")._rows]
        return original_update(*segments, **fields)

    monkeypatch.setattr(client, "update", spy_update)

    guard.set_wireless_channel(client, settings_write_enabled, interface_name="wlan1", frequency=5300, confirm=True)

    armed_at_write_time = observed["scheduler_rows_at_write_time"]
    assert len(armed_at_write_time) == 1
    assert armed_at_write_time[0]["name"].startswith("deadman-")


def test_set_wireless_channel_dead_man_reverts_on_fire_when_not_cancelled(
    settings_write_enabled: Settings, device: Device
):
    """The other half of the dead-man contract: if the caller never calls
    cancel_dead_man, firing (simulated here via FakeConnection.fire_scheduler)
    restores the interface's prior frequency/channel-width and removes the
    scheduler entry."""
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wireless_channel(
        client,
        settings_write_enabled,
        interface_name="wlan1",
        frequency=5300,
        channel_width="40mhz-turbo",
        confirm=True,
    )
    assert fake.path("interface", "wireless")._rows[0]["frequency"] == "5300"

    fake.advance_clock(preview.dead_man["minutes"])
    fake.fire_scheduler(preview.dead_man["name"])

    reverted = fake.path("interface", "wireless")._rows[0]
    assert reverted["frequency"] == "5500"
    assert reverted["channel-width"] == "20mhz"
    assert fake.path("system", "scheduler")._rows == []


def test_set_wireless_channel_dead_man_does_not_fire_before_its_deadline(
    settings_write_enabled: Settings, device: Device
):
    """Proof that `_dead_man_deadline` computes a genuinely FUTURE
    `start-date`/`start-time` (`arm-time + minutes`), not something that
    could be mistaken for "now" - the property the one-shot,
    explicit-future-deadline design (2026-07-13 hardware finding, see
    guard._dead_man_deadline's docstring) depends on. Proven here by NOT
    advancing the fake's simulated clock: firing must refuse (raise), and
    the channel change must still be in place - the protection window has
    not elapsed yet."""
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wireless_channel(
        client, settings_write_enabled, interface_name="wlan1", frequency=5300, confirm=True
    )
    assert fake.path("interface", "wireless")._rows[0]["frequency"] == "5300"

    with pytest.raises(AssertionError):
        fake.fire_scheduler(preview.dead_man["name"])

    # Still armed, still un-reverted - the window has not elapsed yet.
    assert fake.path("interface", "wireless")._rows[0]["frequency"] == "5300"
    assert len(fake.path("system", "scheduler")._rows) == 1

    fake.advance_clock(preview.dead_man["minutes"])
    fake.fire_scheduler(preview.dead_man["name"])

    reverted = fake.path("interface", "wireless")._rows[0]
    assert reverted["frequency"] == "5500"
    assert fake.path("system", "scheduler")._rows == []


def test_set_wireless_channel_dead_man_cancelled_means_no_revert(settings_write_enabled: Settings, device: Device):
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wireless_channel(
        client, settings_write_enabled, interface_name="wlan1", frequency=5300, confirm=True
    )
    guard.cancel_dead_man(client, settings_write_enabled, name=preview.dead_man["name"], confirm=True)

    assert fake.path("system", "scheduler")._rows == []
    with pytest.raises(AssertionError):
        fake.fire_scheduler(preview.dead_man["name"])
    # The confirmed channel change is untouched by the (now-cancelled) dead-man.
    assert fake.path("interface", "wireless")._rows[0]["frequency"] == "5300"


def test_set_wireless_channel_arm_deadman_false_skips_scheduler(settings_write_enabled: Settings, device: Device):
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wireless_channel(
        client, settings_write_enabled, interface_name="wlan1", frequency=5300, arm_deadman=False, confirm=True
    )

    assert preview.applied is True
    assert preview.dead_man is None
    assert fake.path("system", "scheduler")._rows == []


def test_set_wireless_channel_rejects_missing_frequency_field_to_revert(
    settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(
        data={("interface", "wireless"): [{".id": "*1", "name": "wlan2"}], ("system", "scheduler"): []}
    )
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(DeviceCommandError):
        guard.set_wireless_channel(client, settings_write_enabled, interface_name="wlan2", frequency=5300, confirm=True)
    # Never armed, never wrote the frequency change either.
    assert fake.path("system", "scheduler")._rows == []
    assert "frequency" not in fake.path("interface", "wireless")._rows[0]


def test_set_wireless_channel_rejects_invalid_frequency_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.set_wireless_channel(
            guarded_client, settings_write_enabled, interface_name="wlan1", frequency=100, confirm=True
        )


def test_set_wireless_channel_rejects_invalid_channel_width_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.set_wireless_channel(
            guarded_client,
            settings_write_enabled,
            interface_name="wlan1",
            frequency=5300,
            channel_width="not-a-width",
            confirm=True,
        )


def test_set_wireless_channel_rejects_invalid_deadman_minutes_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.set_wireless_channel(
            guarded_client,
            settings_write_enabled,
            interface_name="wlan1",
            frequency=5300,
            deadman_minutes=999,
            confirm=True,
        )


def test_set_wireless_channel_rejects_deadman_minutes_shorter_than_weather_radar_cac(
    settings_write_enabled: Settings, device: Device
):
    """finding 3 of the 2026-07 hardening review: the default
    deadman_minutes=3 (180s) is SHORTER than the ~600s CAC the
    weather-radar sub-band requires - arming here would let the dead-man
    revert the channel while it is still mid-CAC, before an operator could
    ever confirm the link is back up."""
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ValidationError, match="Channel Availability Check"):
        guard.set_wireless_channel(client, settings_write_enabled, interface_name="wlan1", frequency=5620, confirm=True)
    # Never armed, never wrote the frequency change either.
    assert fake.path("system", "scheduler")._rows == []
    assert fake.path("interface", "wireless")._rows[0]["frequency"] == "5500"


def test_set_wireless_channel_accepts_deadman_minutes_that_covers_weather_radar_cac(
    settings_write_enabled: Settings, device: Device
):
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wireless_channel(
        client,
        settings_write_enabled,
        interface_name="wlan1",
        frequency=5620,
        deadman_minutes=10,
        confirm=True,
    )

    assert preview.applied is True
    assert preview.dead_man is not None
    assert fake.path("interface", "wireless")._rows[0]["frequency"] == "5620"
    assert len(fake.path("system", "scheduler")._rows) == 1


def test_set_wireless_channel_non_dfs_frequency_arms_dead_man_without_cac_floor_check(
    settings_write_enabled: Settings, device: Device
):
    """A target frequency that needs no CAC at all (outside every DFS band)
    imposes no deadman_minutes floor - the default 3 minutes is fine."""
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wireless_channel(
        client, settings_write_enabled, interface_name="wlan1", frequency=5180, confirm=True
    )

    assert preview.applied is True
    assert preview.warning is None
    assert preview.dead_man is not None
    assert fake.path("interface", "wireless")._rows[0]["frequency"] == "5180"


def test_set_wireless_channel_warning_notes_revert_target_also_needs_cac(
    settings_write_enabled: Settings, device: Device
):
    """finding 3: when a dead-man is armed, the preview's warning also
    notes that the REVERT target (the interface's prior, pre-change
    frequency) can itself be DFS-governed - if the dead-man fires, RouterOS
    runs a CAC on the way back too. The fixture's prior frequency (5500) is
    itself in the general DFS range."""
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wireless_channel(
        client, settings_write_enabled, interface_name="wlan1", frequency=5300, confirm=False
    )

    assert preview.warning is not None
    assert "revert target" in preview.warning
    assert "5500MHz" in preview.warning


def test_set_wireless_channel_arm_deadman_false_skips_cac_floor_check(settings_write_enabled: Settings, device: Device):
    """arm_deadman=False means no scheduler at all, so the CAC-floor
    enforcement (which only matters for a dead-man that could fire
    mid-CAC) does not apply - a short deadman_minutes against a
    weather-radar frequency is accepted when no dead-man will be armed."""
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wireless_channel(
        client,
        settings_write_enabled,
        interface_name="wlan1",
        frequency=5620,
        arm_deadman=False,
        confirm=True,
    )

    assert preview.applied is True
    assert preview.dead_man is None
    assert fake.path("system", "scheduler")._rows == []


def test_set_wireless_channel_rejects_missing_channel_width_field_to_revert(
    settings_write_enabled: Settings, device: Device
):
    """finding 5 of the 2026-07 hardening review: channel_width was
    requested but the interface's current state has no 'channel-width' to
    revert TO - arming here would produce a PARTIAL revert (frequency
    restored, channel-width silently left on the new value forever if the
    dead-man fires). Must refuse the whole arm, not just skip that field."""
    fake = FakeConnection(
        data={
            ("interface", "wireless"): [{".id": "*1", "name": "wlan2", "frequency": "5500"}],
            ("system", "scheduler"): [],
        }
    )
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(DeviceCommandError):
        guard.set_wireless_channel(
            client,
            settings_write_enabled,
            interface_name="wlan2",
            frequency=5300,
            channel_width="40mhz-turbo",
            confirm=True,
        )
    # Never armed, never wrote the frequency change either - a partial
    # revert would be worse than no write at all.
    assert fake.path("system", "scheduler")._rows == []
    assert fake.path("interface", "wireless")._rows[0]["frequency"] == "5500"


def test_set_wireless_channel_unknown_interface_raises_resource_not_found(
    settings_write_enabled: Settings, device: Device
):
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ResourceNotFoundError):
        guard.set_wireless_channel(
            client, settings_write_enabled, interface_name="ghost-wlan", frequency=5300, confirm=True
        )


def test_set_wireless_channel_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, settings_write_enabled: Settings, device: Device
):
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["set_wireless_channel"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "set_wireless_channel", patched_op)

    guard.set_wireless_channel(
        client, settings_write_enabled, interface_name="wlan1", frequency=5300, arm_deadman=False, confirm=True
    )

    assert called == {"path": patched_op.path, "fields": {".id": "*1", "frequency": "5300"}}


# --- set_wireless_tx_power -----------------------------------------------------


def test_set_wireless_tx_power_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.set_wireless_tx_power(client, settings, interface_name="wlan1", tx_power=8, confirm=True)


def test_set_wireless_tx_power_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.set_wireless_tx_power(guarded_client, settings, interface_name="wlan1", tx_power=8, confirm=True)


def test_set_wireless_tx_power_preview_does_not_apply_or_arm(settings_write_enabled: Settings, device: Device):
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wireless_tx_power(
        client, settings_write_enabled, interface_name="wlan1", tx_power=8, confirm=False
    )

    assert preview.applied is False
    assert preview.dead_man is None
    assert preview.warning is not None and "re-adapt" in preview.warning
    assert fake.path("interface", "wireless")._rows[0]["tx-power"] == "20"
    assert fake.path("system", "scheduler")._rows == []


def test_set_wireless_tx_power_confirm_true_applies_forces_all_rates_fixed_and_arms_dead_man(
    settings_write_enabled: Settings, device: Device
):
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wireless_tx_power(
        client, settings_write_enabled, interface_name="wlan1", tx_power=8, confirm=True
    )

    assert preview.applied is True
    updated = fake.path("interface", "wireless")._rows[0]
    assert updated["tx-power"] == "8"
    assert updated["tx-power-mode"] == "all-rates-fixed"

    assert preview.dead_man is not None
    scheduler_rows = fake.path("system", "scheduler")._rows
    assert len(scheduler_rows) == 1
    on_event = scheduler_rows[0]["on-event"]
    assert "tx-power=20" in on_event
    assert "tx-power-mode=default" in on_event


def test_set_wireless_tx_power_dead_man_reverts_both_fields_on_fire(settings_write_enabled: Settings, device: Device):
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wireless_tx_power(
        client, settings_write_enabled, interface_name="wlan1", tx_power=8, confirm=True
    )
    fake.advance_clock(preview.dead_man["minutes"])
    fake.fire_scheduler(preview.dead_man["name"])

    reverted = fake.path("interface", "wireless")._rows[0]
    assert reverted["tx-power"] == "20"
    assert reverted["tx-power-mode"] == "default"


def test_set_wireless_tx_power_arm_deadman_false_skips_scheduler(settings_write_enabled: Settings, device: Device):
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wireless_tx_power(
        client, settings_write_enabled, interface_name="wlan1", tx_power=8, arm_deadman=False, confirm=True
    )

    assert preview.dead_man is None
    assert fake.path("system", "scheduler")._rows == []


@pytest.mark.parametrize("tx_power", [-31, 41, 100])
def test_set_wireless_tx_power_rejects_invalid_power_before_touching_device(
    tx_power: int, settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.set_wireless_tx_power(
            guarded_client, settings_write_enabled, interface_name="wlan1", tx_power=tx_power, confirm=True
        )


def test_set_wireless_tx_power_rejects_missing_fields_to_revert(settings_write_enabled: Settings, device: Device):
    """finding 4 of the 2026-07 hardening review: previously defaulted to
    `before.get("tx-power-mode", "default")`/`before.get("tx-power", "0")` -
    a fabricated fallback that could revert to a power/mode the interface
    never actually had. Must raise instead, matching
    set_wireless_channel's fail-safe (never invent a revert target)."""
    fake = FakeConnection(
        data={("interface", "wireless"): [{".id": "*1", "name": "wlan2"}], ("system", "scheduler"): []}
    )
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(DeviceCommandError):
        guard.set_wireless_tx_power(client, settings_write_enabled, interface_name="wlan2", tx_power=8, confirm=True)
    # Never armed, never wrote the tx-power change either.
    assert fake.path("system", "scheduler")._rows == []
    assert "tx-power" not in fake.path("interface", "wireless")._rows[0]


def test_set_wireless_tx_power_unknown_interface_raises_resource_not_found(
    settings_write_enabled: Settings, device: Device
):
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ResourceNotFoundError):
        guard.set_wireless_tx_power(
            client, settings_write_enabled, interface_name="ghost-wlan", tx_power=8, confirm=True
        )


def test_set_wireless_tx_power_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, settings_write_enabled: Settings, device: Device
):
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["set_wireless_tx_power"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "set_wireless_tx_power", patched_op)

    guard.set_wireless_tx_power(
        client, settings_write_enabled, interface_name="wlan1", tx_power=8, arm_deadman=False, confirm=True
    )

    assert called == {
        "path": patched_op.path,
        "fields": {".id": "*1", "tx-power-mode": "all-rates-fixed", "tx-power": "8"},
    }


# --- set_wireless_tuning --------------------------------------------------------


def test_set_wireless_tuning_blocked_when_write_disabled(client: MikrotikClient, settings: Settings):
    with pytest.raises(WriteDisabledError):
        guard.set_wireless_tuning(
            client, settings, interface_name="wlan1", adaptive_noise_immunity="ap-and-client-mode", confirm=True
        )


def test_set_wireless_tuning_read_only_gate_applies_before_touching_device(device: Device, settings: Settings):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(WriteDisabledError):
        guard.set_wireless_tuning(guarded_client, settings, interface_name="wlan1", distance=9, confirm=True)


def test_set_wireless_tuning_requires_at_least_one_field(settings_write_enabled: Settings, device: Device):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.set_wireless_tuning(guarded_client, settings_write_enabled, interface_name="wlan1", confirm=True)


def test_set_wireless_tuning_preview_does_not_apply(settings_write_enabled: Settings, device: Device):
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wireless_tuning(
        client, settings_write_enabled, interface_name="wlan1", distance=9, confirm=False
    )

    assert preview.applied is False
    assert fake.path("interface", "wireless")._rows[0]["distance"] == "dynamic"


def test_set_wireless_tuning_confirm_true_applies_distance_only(settings_write_enabled: Settings, device: Device):
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wireless_tuning(
        client, settings_write_enabled, interface_name="wlan1", distance=9, confirm=True
    )

    assert preview.applied is True
    updated = fake.path("interface", "wireless")._rows[0]
    assert updated["distance"] == "9"
    assert updated["adaptive-noise-immunity"] == "none"  # unchanged


def test_set_wireless_tuning_confirm_true_applies_adaptive_noise_immunity_only(
    settings_write_enabled: Settings, device: Device
):
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wireless_tuning(
        client,
        settings_write_enabled,
        interface_name="wlan1",
        adaptive_noise_immunity="ap-and-client-mode",
        confirm=True,
    )

    assert preview.applied is True
    updated = fake.path("interface", "wireless")._rows[0]
    assert updated["adaptive-noise-immunity"] == "ap-and-client-mode"
    assert updated["distance"] == "dynamic"  # unchanged


def test_set_wireless_tuning_confirm_true_applies_both_fields(settings_write_enabled: Settings, device: Device):
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wireless_tuning(
        client,
        settings_write_enabled,
        interface_name="wlan1",
        adaptive_noise_immunity="client-mode",
        distance="indoors",
        confirm=True,
    )

    assert preview.applied is True
    updated = fake.path("interface", "wireless")._rows[0]
    assert updated["adaptive-noise-immunity"] == "client-mode"
    assert updated["distance"] == "indoors"


def test_set_wireless_tuning_adaptive_noise_immunity_alone_never_arms_a_dead_man(
    settings_write_enabled: Settings, device: Device
):
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wireless_tuning(
        client,
        settings_write_enabled,
        interface_name="wlan1",
        adaptive_noise_immunity="ap-and-client-mode",
        confirm=True,
    )

    assert preview.dead_man is None
    assert preview.warning is None
    assert fake.path("system", "scheduler")._rows == []


@pytest.mark.parametrize("distance", ["dynamic", "indoors"])
def test_set_wireless_tuning_named_distance_modes_never_arm_a_dead_man(
    distance: str, settings_write_enabled: Settings, device: Device
):
    """ "dynamic"/"indoors" are RouterOS's own named, self-managed
    ACK-timeout modes - unlike a caller-chosen numeric distance (finding 1
    of the 2026-07 hardening review), they were not the LOCKOUT-RISK case
    verified live and never arm a dead-man here."""
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wireless_tuning(
        client, settings_write_enabled, interface_name="wlan1", distance=distance, confirm=True
    )

    assert preview.dead_man is None
    assert preview.warning is None
    assert fake.path("system", "scheduler")._rows == []


def test_set_wireless_tuning_numeric_distance_is_lockout_risk_and_arms_dead_man_by_default(
    settings_write_enabled: Settings, device: Device
):
    """finding 1 of the 2026-07 hardening review: a NUMERIC distance
    directly changes the ACK-timeout/TDMA timing (unlike "dynamic"/
    "indoors") and can silently drop an already-associated link with no
    protocol-level recovery - CONFIRMED LIVE. Treated as LOCKOUT-RISK
    exactly like set_wireless_channel/set_wireless_tx_power: arms a
    dead-man by default whose revert restores the PRIOR distance."""
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wireless_tuning(
        client, settings_write_enabled, interface_name="wlan1", distance=1, confirm=True
    )

    assert preview.applied is True
    assert fake.path("interface", "wireless")._rows[0]["distance"] == "1"
    assert preview.warning is not None and "LOCKOUT-RISK" in preview.warning

    assert preview.dead_man is not None
    dead_man_name = preview.dead_man["name"]
    scheduler_rows = fake.path("system", "scheduler")._rows
    assert len(scheduler_rows) == 1
    armed = scheduler_rows[0]
    assert armed["name"] == dead_man_name
    # The revert command must capture the PRIOR (before-change) distance,
    # not the new one.
    assert "distance=dynamic" in armed["on-event"]


def test_set_wireless_tuning_numeric_distance_preview_reports_lockout_risk_without_arming(
    settings_write_enabled: Settings, device: Device
):
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wireless_tuning(
        client, settings_write_enabled, interface_name="wlan1", distance=1, confirm=False
    )

    assert preview.applied is False
    assert preview.dead_man is None
    assert preview.warning is not None and "LOCKOUT-RISK" in preview.warning
    assert fake.path("system", "scheduler")._rows == []


def test_set_wireless_tuning_numeric_distance_dead_man_reverts_on_fire_when_not_cancelled(
    settings_write_enabled: Settings, device: Device
):
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wireless_tuning(
        client, settings_write_enabled, interface_name="wlan1", distance=1, confirm=True
    )
    assert fake.path("interface", "wireless")._rows[0]["distance"] == "1"

    fake.advance_clock(preview.dead_man["minutes"])
    fake.fire_scheduler(preview.dead_man["name"])

    reverted = fake.path("interface", "wireless")._rows[0]
    assert reverted["distance"] == "dynamic"
    assert fake.path("system", "scheduler")._rows == []


def test_set_wireless_tuning_numeric_distance_arm_deadman_false_skips_scheduler(
    settings_write_enabled: Settings, device: Device
):
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    preview = guard.set_wireless_tuning(
        client, settings_write_enabled, interface_name="wlan1", distance=1, arm_deadman=False, confirm=True
    )

    assert preview.applied is True
    assert preview.dead_man is None
    assert fake.path("system", "scheduler")._rows == []


def test_set_wireless_tuning_numeric_distance_rejects_invalid_deadman_minutes_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.set_wireless_tuning(
            guarded_client,
            settings_write_enabled,
            interface_name="wlan1",
            distance=1,
            deadman_minutes=999,
            confirm=True,
        )


def test_set_wireless_tuning_rejects_missing_distance_field_to_revert(settings_write_enabled: Settings, device: Device):
    fake = FakeConnection(
        data={("interface", "wireless"): [{".id": "*1", "name": "wlan2"}], ("system", "scheduler"): []}
    )
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(DeviceCommandError):
        guard.set_wireless_tuning(client, settings_write_enabled, interface_name="wlan2", distance=1, confirm=True)
    assert fake.path("system", "scheduler")._rows == []
    assert "distance" not in fake.path("interface", "wireless")._rows[0]


def test_set_wireless_tuning_rejects_invalid_adaptive_noise_immunity_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.set_wireless_tuning(
            guarded_client,
            settings_write_enabled,
            interface_name="wlan1",
            adaptive_noise_immunity="turbo-mode",
            confirm=True,
        )


def test_set_wireless_tuning_rejects_invalid_distance_before_touching_device(
    settings_write_enabled: Settings, device: Device
):
    guarded_client = MikrotikClient(device, connection=RaisingConnection())
    with pytest.raises(ValidationError):
        guard.set_wireless_tuning(
            guarded_client, settings_write_enabled, interface_name="wlan1", distance=99999, confirm=True
        )


def test_set_wireless_tuning_unknown_interface_raises_resource_not_found(
    settings_write_enabled: Settings, device: Device
):
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ResourceNotFoundError):
        guard.set_wireless_tuning(client, settings_write_enabled, interface_name="ghost-wlan", distance=9, confirm=True)


def test_set_wireless_tuning_dispatches_via_allowlist_action(
    monkeypatch: pytest.MonkeyPatch, settings_write_enabled: Settings, device: Device
):
    fake = _wireless_fixture()
    client = MikrotikClient(device, connection=fake)
    called: dict = {}

    def stub_action(*path: str, **fields):
        called["path"] = path
        called["fields"] = fields

    monkeypatch.setattr(client, "stub_action", stub_action, raising=False)
    patched_op = dataclasses.replace(guard.ALLOWLIST["set_wireless_tuning"], action="stub_action")
    monkeypatch.setitem(guard.ALLOWLIST, "set_wireless_tuning", patched_op)

    guard.set_wireless_tuning(client, settings_write_enabled, interface_name="wlan1", distance=9, confirm=True)

    assert called == {"path": patched_op.path, "fields": {".id": "*1", "distance": "9"}}
