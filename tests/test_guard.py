from __future__ import annotations

import dataclasses

import pytest
from librouteros.exceptions import LibRouterosError

from mcp_mikrotik import guard
from mcp_mikrotik.client import MikrotikClient
from mcp_mikrotik.config import Device, Settings
from mcp_mikrotik.exceptions import GuardViolationError, ResourceNotFoundError, WriteDisabledError

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
        assert op.action in {"update", "add", "remove"}


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
