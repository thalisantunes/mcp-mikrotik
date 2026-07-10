"""Tests for guard.py's `_audited` decorator: every guarded write call must
produce exactly one audit journal entry (audit.py), carrying a correlation
id, and never a device password - regardless of whether it previewed,
applied, or errored."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_mikrotik import guard
from mcp_mikrotik.client import MikrotikClient
from mcp_mikrotik.config import Device, Settings
from mcp_mikrotik.exceptions import ResourceNotFoundError, WriteDisabledError

from .fakes import FakeConnection, TransportErrorConnection


def _events(log_path: Path) -> list[dict]:
    if not log_path.exists():
        return []
    return [json.loads(line) for line in log_path.read_text(encoding="utf-8").strip().splitlines() if line]


@pytest.fixture
def audit_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("MIKROTIK_AUDIT_LOG", str(log_path))
    return log_path


# --- three outcomes ----------------------------------------------------


def test_preview_call_journals_outcome_preview(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    guard.set_identity(client, settings_write_enabled, new_name="new-name", confirm=False)

    events = _events(audit_log)
    assert len(events) == 1
    event = events[0]
    assert event["outcome"] == "preview"
    assert event["confirm"] is False
    assert event["tool"] == "set_identity"
    assert event["operation"] == "set_identity"
    assert event["action"] == "update"
    assert event["device_name"] == "core-switch"
    assert event["summary"]["before"] == {"name": "MikroTik"}
    assert event["summary"]["after"] == {"name": "new-name"}


def test_confirmed_call_journals_outcome_applied(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    guard.set_identity(client, settings_write_enabled, new_name="new-name", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "applied"
    assert events[0]["confirm"] is True


def test_write_disabled_error_still_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings: Settings
):
    """The read-only gate blocks the write before the device is ever
    touched, but that attempted write is still audit-worthy."""
    with pytest.raises(WriteDisabledError):
        guard.set_identity(client, settings, new_name="new-name", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "set_identity"
    assert "read-only" in events[0]["summary"]["error"] or "blocked" in events[0]["summary"]["error"]


def test_resource_not_found_error_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    with pytest.raises(ResourceNotFoundError):
        guard.enable_interface(client, settings_write_enabled, interface_name="ghost0", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["tool"] == "enable_interface"
    assert events[0]["operation"] == "enable_interface"


def test_device_command_error_journals_outcome_error(
    audit_log: Path, settings_write_enabled: Settings, device: Device
):
    """A genuine device-side transport failure (not the read-only gate)
    still produces exactly one "error" journal entry."""
    from mcp_mikrotik.exceptions import DeviceCommandError

    guarded_client = MikrotikClient(device, connection=TransportErrorConnection(OSError("link down")))
    with pytest.raises(DeviceCommandError):
        guard.enable_interface(guarded_client, settings_write_enabled, interface_name="ether2", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert "link down" in events[0]["summary"]["error"]


# --- correlation id ------------------------------------------------------


def test_journal_entry_carries_a_correlation_id(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    guard.set_identity(client, settings_write_enabled, new_name="new-name", confirm=False)

    events = _events(audit_log)
    assert len(events) == 1
    correlation_id = events[0]["correlation_id"]
    assert isinstance(correlation_id, str)
    assert len(correlation_id) == 12


def test_separate_calls_get_different_correlation_ids(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    guard.set_identity(client, settings_write_enabled, new_name="first", confirm=False)
    guard.set_identity(client, settings_write_enabled, new_name="second", confirm=False)

    events = _events(audit_log)
    assert len(events) == 2
    assert events[0]["correlation_id"] != events[1]["correlation_id"]


# --- CRITICAL: device password must never appear in the journal ------------


def test_journal_never_leaks_device_password_on_preview(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings, device: Device
):
    assert device.password == "s3cret"  # sanity: the fixture device does have a password
    guard.set_identity(client, settings_write_enabled, new_name="new-name", confirm=False)

    raw = audit_log.read_text(encoding="utf-8")
    assert "s3cret" not in raw


def test_journal_never_leaks_device_password_on_applied(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings, device: Device
):
    guard.set_identity(client, settings_write_enabled, new_name="new-name", confirm=True)

    raw = audit_log.read_text(encoding="utf-8")
    assert "s3cret" not in raw


def test_journal_never_leaks_device_password_on_error(
    audit_log: Path, client: MikrotikClient, settings: Settings, device: Device
):
    with pytest.raises(WriteDisabledError):
        guard.set_identity(client, settings, new_name="new-name", confirm=True)

    raw = audit_log.read_text(encoding="utf-8")
    assert "s3cret" not in raw


def test_journal_never_leaks_device_password_across_every_write_tool(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings, device: Device
):
    """Broad sweep: exercise every guarded write tool (preview + apply) and
    assert the device password never shows up anywhere in the journal."""
    guard.set_identity(client, settings_write_enabled, new_name="renamed", confirm=False)
    guard.set_identity(client, settings_write_enabled, new_name="renamed", confirm=True)
    guard.enable_interface(client, settings_write_enabled, interface_name="ether2", confirm=False)
    guard.enable_interface(client, settings_write_enabled, interface_name="ether2", confirm=True)
    guard.disable_interface(client, settings_write_enabled, interface_name="ether1", confirm=True)
    guard.set_client_bandwidth(
        client, settings_write_enabled, target="10.0.0.77", max_limit="5M/5M", confirm=True
    )
    guard.add_static_dhcp_lease(
        client, settings_write_enabled, address="10.0.0.88", mac_address="AA:BB:CC:DD:EE:99", confirm=True
    )
    guard.add_to_address_list(
        client, settings_write_enabled, list_name="watch", address="10.0.0.61", confirm=True
    )
    guard.remove_from_address_list(
        client, settings_write_enabled, list_name="blocked-clients", address="10.0.0.60", confirm=True
    )

    raw = audit_log.read_text(encoding="utf-8")
    assert "s3cret" not in raw
    events = _events(audit_log)
    assert len(events) == 9
    for event in events:
        assert "s3cret" not in json.dumps(event)


# --- dynamic dispatch (set_wifi_ssid / set_client_bandwidth) ---------------


def test_dynamic_dispatch_journal_uses_resolved_operation_on_success(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    fake_connection._data[("interface", "wireless")] = [{".id": "*1", "name": "wifi1", "ssid": "old-ssid"}]

    guard.set_wifi_ssid(
        client, settings_write_enabled, interface_name="wifi1", new_ssid="new-ssid", confirm=True
    )

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["operation"] == "set_wifi_ssid_ros6"
    assert events[0]["tool"] == "set_wifi_ssid"


def test_dynamic_dispatch_journal_uses_anchor_operation_on_error(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    """No interface named "ghost-radio" exists under either ROS7/ROS6 path -
    the error happens before dispatch resolves which of the two candidate
    operations applies, so the anchor ("set_wifi_ssid_ros7") is reported."""
    with pytest.raises(ResourceNotFoundError):
        guard.set_wifi_ssid(
            client, settings_write_enabled, interface_name="ghost-radio", new_ssid="x", confirm=True
        )

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "set_wifi_ssid_ros7"
