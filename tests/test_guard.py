from __future__ import annotations

import pytest

from mcp_mikrotik import guard
from mcp_mikrotik.client import MikrotikClient
from mcp_mikrotik.config import Device, Settings
from mcp_mikrotik.exceptions import GuardViolationError, WriteDisabledError

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
