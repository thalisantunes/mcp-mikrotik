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
from mcp_mikrotik.exceptions import (
    AmbiguousResourceError,
    ResourceAlreadyExistsError,
    ResourceNotFoundError,
    WriteDisabledError,
)

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


def test_write_disabled_error_still_journals_outcome_error(audit_log: Path, client: MikrotikClient, settings: Settings):
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


def test_device_command_error_journals_outcome_error(audit_log: Path, settings_write_enabled: Settings, device: Device):
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
    audit_log: Path,
    client: MikrotikClient,
    settings_write_enabled: Settings,
    device: Device,
    fake_connection: FakeConnection,
):
    """Broad sweep: exercise every guarded write tool (preview + apply) and
    assert the device password never shows up anywhere in the journal."""
    guard.set_identity(client, settings_write_enabled, new_name="renamed", confirm=False)
    guard.set_identity(client, settings_write_enabled, new_name="renamed", confirm=True)
    guard.enable_interface(client, settings_write_enabled, interface_name="ether2", confirm=False)
    guard.enable_interface(client, settings_write_enabled, interface_name="ether2", confirm=True)
    guard.disable_interface(client, settings_write_enabled, interface_name="ether1", confirm=True)
    guard.set_client_bandwidth(client, settings_write_enabled, target="10.0.0.77", max_limit="5M/5M", confirm=True)
    guard.add_static_dhcp_lease(
        client, settings_write_enabled, address="10.0.0.88", mac_address="AA:BB:CC:DD:EE:99", confirm=True
    )
    guard.add_to_address_list(client, settings_write_enabled, list_name="watch", address="10.0.0.61", confirm=True)
    guard.remove_from_address_list(
        client, settings_write_enabled, list_name="blocked-clients", address="10.0.0.60", confirm=True
    )
    guard.set_poe_out(client, settings_write_enabled, interface_name="ether1", poe_out="off", confirm=True)
    fake_connection._data[("container",)] = [{".id": "*1", "name": "grafana", "status": "stopped"}]
    guard.start_container(client, settings_write_enabled, container="grafana", confirm=True)
    guard.stop_container(client, settings_write_enabled, container="grafana", confirm=True)
    guard.set_route_distance(
        client, settings_write_enabled, dst_address="0.0.0.0/0", gateway="10.0.0.254", distance=5, confirm=True
    )
    guard.disable_route(client, settings_write_enabled, dst_address="0.0.0.0/0", gateway="10.0.0.254", confirm=True)
    guard.enable_route(client, settings_write_enabled, dst_address="0.0.0.0/0", gateway="10.0.0.254", confirm=True)
    guard.add_netwatch(client, settings_write_enabled, host="1.1.1.1", confirm=True)
    guard.remove_netwatch(client, settings_write_enabled, host="1.1.1.1", confirm=True)
    guard.add_static_dns(client, settings_write_enabled, name="blocked.example.com", address="0.0.0.0", confirm=True)
    guard.remove_static_dns(client, settings_write_enabled, name="blocked.example.com", confirm=True)
    guard.clear_dns_cache(client, settings_write_enabled, confirm=True)
    guard.remove_dhcp_lease(client, settings_write_enabled, mac_address="AA:BB:CC:DD:EE:01", confirm=True)
    guard.wake_on_lan(client, settings_write_enabled, mac_address="AA:BB:CC:DD:EE:FF", interface="ether1", confirm=True)
    guard.disable_firewall_rule(client, settings_write_enabled, comment="allow established", confirm=True)
    guard.enable_firewall_rule(client, settings_write_enabled, comment="Bloqueio_Ataque_X", confirm=True)
    guard.add_wireguard_interface(client, settings_write_enabled, name="wg-sweep", confirm=True)
    guard.add_wireguard_peer(
        client,
        settings_write_enabled,
        interface="wg1",
        public_key="OaQx4l1wQNnz9J+odnvI4yyND+HG699QWpM8fL1XAO0=",
        allowed_address="10.10.0.9/32",
        confirm=True,
    )
    guard.remove_wireguard_peer(
        client,
        settings_write_enabled,
        interface="wg1",
        public_key="OaQx4l1wQNnz9J+odnvI4yyND+HG699QWpM8fL1XAO0=",
        confirm=True,
    )
    guard.add_hotspot_user(client, settings_write_enabled, name="sweep-visitor", password="Passw0rd!", confirm=True)
    guard.create_backup(client, settings_write_enabled, name="sweep-backup", password="file-key", confirm=True)

    raw = audit_log.read_text(encoding="utf-8")
    assert "s3cret" not in raw
    events = _events(audit_log)
    assert len(events) == 29
    for event in events:
        assert "s3cret" not in json.dumps(event)


# --- dynamic dispatch (set_wifi_ssid / set_client_bandwidth) ---------------


def test_dynamic_dispatch_journal_uses_resolved_operation_on_success(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    fake_connection._data[("interface", "wireless")] = [{".id": "*1", "name": "wifi1", "ssid": "old-ssid"}]

    guard.set_wifi_ssid(client, settings_write_enabled, interface_name="wifi1", new_ssid="new-ssid", confirm=True)

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
        guard.set_wifi_ssid(client, settings_write_enabled, interface_name="ghost-radio", new_ssid="x", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "set_wifi_ssid_ros7"


def test_ros7_configuration_dispatch_journal_uses_resolved_operation_and_never_leaks_passphrase(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings, fake_connection: FakeConnection
):
    """set_wifi_ssid's ROS7-named-`configuration` path (Bug 2 fix) reads the
    /interface/wifi/configuration row as before/after - if that row (as on
    real hardware) also carries a `passphrase`/WPA2 key field, it must never
    reach the journal, exactly like the device password never does (Bug 3
    fix - see audit._SENSITIVE_KEY)."""
    fake_connection._data[("interface", "wifi")] = [{".id": "*1", "name": "wifi1", "configuration": "cfg1"}]
    fake_connection._data[("interface", "wifi", "configuration")] = [
        {".id": "*5", "name": "cfg1", "ssid": "old-ssid", "security": {"passphrase": "MyWpa2Secret"}}
    ]

    guard.set_wifi_ssid(client, settings_write_enabled, interface_name="wifi1", new_ssid="new-ssid", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["operation"] == "set_wifi_ssid_ros7_configuration"
    assert events[0]["tool"] == "set_wifi_ssid"

    raw = audit_log.read_text(encoding="utf-8")
    assert "MyWpa2Secret" not in raw
    assert "passphrase" not in events[0]["summary"]["before"].get("security", {})
    assert "passphrase" not in events[0]["summary"]["after"].get("security", {})


# --- set_poe_out (v0.6) ------------------------------------------------------


def test_set_poe_out_confirmed_call_journals_outcome_applied_without_leaking_password(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings, device: Device
):
    guard.set_poe_out(client, settings_write_enabled, interface_name="ether1", poe_out="off", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    event = events[0]
    assert event["outcome"] == "applied"
    assert event["tool"] == "set_poe_out"
    assert event["operation"] == "set_poe_out"
    assert event["action"] == "update"
    assert event["summary"]["before"]["poe-out"] == "auto-on"
    assert event["summary"]["after"]["poe-out"] == "off"

    raw = audit_log.read_text(encoding="utf-8")
    assert device.password not in raw


def test_set_poe_out_unknown_interface_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    with pytest.raises(ResourceNotFoundError):
        guard.set_poe_out(client, settings_write_enabled, interface_name="ghost0", poe_out="off", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "set_poe_out"


# --- start_container / stop_container (v0.7) --------------------------------


def test_start_container_confirmed_call_journals_outcome_applied_without_leaking_password(
    audit_log: Path, settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(data={("container",): [{".id": "*1", "name": "grafana", "status": "stopped"}]})
    client = MikrotikClient(device, connection=fake)

    guard.start_container(client, settings_write_enabled, container="grafana", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    event = events[0]
    assert event["outcome"] == "applied"
    assert event["tool"] == "start_container"
    assert event["operation"] == "start_container"
    assert event["action"] == "start"
    assert event["summary"]["before"]["status"] == "stopped"
    assert event["summary"]["after"]["status"] == "starting"

    raw = audit_log.read_text(encoding="utf-8")
    assert device.password not in raw


def test_stop_container_preview_journals_outcome_preview(
    audit_log: Path, settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(data={("container",): [{".id": "*1", "name": "grafana", "status": "running"}]})
    client = MikrotikClient(device, connection=fake)

    guard.stop_container(client, settings_write_enabled, container="grafana", confirm=False)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "preview"
    assert events[0]["confirm"] is False
    assert events[0]["tool"] == "stop_container"
    assert events[0]["operation"] == "stop_container"
    assert events[0]["action"] == "stop"


def test_start_container_unknown_container_journals_outcome_error(
    audit_log: Path, settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(data={("container",): []})
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(ResourceNotFoundError):
        guard.start_container(client, settings_write_enabled, container="ghost", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "start_container"


def test_stop_container_blocked_when_write_disabled_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings: Settings
):
    with pytest.raises(WriteDisabledError):
        guard.stop_container(client, settings, container="grafana", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"


# --- set_route_distance / enable_route / disable_route / netwatch (v0.9) ---


def test_set_route_distance_confirmed_call_journals_outcome_applied_without_leaking_password(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings, device: Device
):
    guard.set_route_distance(
        client, settings_write_enabled, dst_address="0.0.0.0/0", gateway="10.0.0.254", distance=5, confirm=True
    )

    events = _events(audit_log)
    assert len(events) == 1
    event = events[0]
    assert event["outcome"] == "applied"
    assert event["tool"] == "set_route_distance"
    assert event["operation"] == "set_route_distance"
    assert event["action"] == "update"
    assert event["summary"]["after"]["distance"] == "5"

    raw = audit_log.read_text(encoding="utf-8")
    assert device.password not in raw


def test_set_route_distance_preview_journals_outcome_preview(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    guard.set_route_distance(
        client, settings_write_enabled, dst_address="0.0.0.0/0", gateway="10.0.0.254", distance=5, confirm=False
    )

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "preview"
    assert events[0]["confirm"] is False


def test_set_route_distance_blocked_when_write_disabled_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings: Settings
):
    with pytest.raises(WriteDisabledError):
        guard.set_route_distance(
            client, settings, dst_address="0.0.0.0/0", gateway="10.0.0.254", distance=5, confirm=True
        )

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "set_route_distance"


def test_set_route_distance_ambiguous_route_journals_outcome_error(
    audit_log: Path, settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(
        data={
            ("ip", "route"): [
                {".id": "*1", "dst-address": "0.0.0.0/0", "gateway": "10.0.0.254"},
                {".id": "*2", "dst-address": "0.0.0.0/0", "gateway": "10.0.0.254", "comment": "dup"},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    with pytest.raises(AmbiguousResourceError):
        guard.set_route_distance(
            client, settings_write_enabled, dst_address="0.0.0.0/0", gateway="10.0.0.254", distance=5, confirm=True
        )

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "set_route_distance"


def test_disable_route_confirmed_call_journals_outcome_applied_and_carries_warning_in_summary(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings, device: Device
):
    """The default-route warning (see guard.WritePreview.warning) is part
    of the journal's `summary`, not just before/after - a caller
    reconstructing what happened from the audit journal alone must still be
    able to see the same risk callout the tool's own caller saw. It must
    still be journaled password-free like any other write."""
    preview = guard.disable_route(
        client, settings_write_enabled, dst_address="0.0.0.0/0", gateway="10.0.0.254", confirm=True
    )
    assert preview.warning is not None

    events = _events(audit_log)
    assert len(events) == 1
    event = events[0]
    assert event["outcome"] == "applied"
    assert event["tool"] == "disable_route"
    assert event["operation"] == "disable_route"
    assert event["summary"]["after"]["disabled"] == "yes"
    assert event["summary"]["warning"] == preview.warning
    assert "default" in event["summary"]["warning"].lower()

    raw = audit_log.read_text(encoding="utf-8")
    assert device.password not in raw


def test_enable_route_confirmed_call_journals_null_warning_in_summary(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    """The `warning` key is present in every guarded write's audit summary,
    not only ones that happen to carry a risk callout - it is simply `null`
    (never omitted) when WritePreview.warning is None, e.g. re-enabling a
    route."""
    guard.disable_route(client, settings_write_enabled, dst_address="0.0.0.0/0", gateway="10.0.0.254", confirm=True)
    guard.enable_route(client, settings_write_enabled, dst_address="0.0.0.0/0", gateway="10.0.0.254", confirm=True)

    events = _events(audit_log)
    assert len(events) == 2
    assert events[1]["operation"] == "enable_route"
    assert events[1]["summary"]["warning"] is None


def test_disable_route_unknown_route_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    with pytest.raises(ResourceNotFoundError):
        guard.disable_route(
            client, settings_write_enabled, dst_address="10.10.10.0/24", gateway="10.0.0.254", confirm=True
        )

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "disable_route"


def test_enable_route_blocked_when_write_disabled_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings: Settings
):
    with pytest.raises(WriteDisabledError):
        guard.enable_route(client, settings, dst_address="0.0.0.0/0", gateway="10.0.0.254", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "enable_route"


def test_add_netwatch_confirmed_call_journals_outcome_applied_without_leaking_password(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings, device: Device
):
    guard.add_netwatch(client, settings_write_enabled, host="1.1.1.1", comment="secondary", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    event = events[0]
    assert event["outcome"] == "applied"
    assert event["tool"] == "add_netwatch"
    assert event["operation"] == "add_netwatch"
    assert event["action"] == "add"
    assert event["summary"]["after"]["host"] == "1.1.1.1"

    raw = audit_log.read_text(encoding="utf-8")
    assert device.password not in raw


def test_add_netwatch_duplicate_host_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    with pytest.raises(ResourceAlreadyExistsError):
        guard.add_netwatch(client, settings_write_enabled, host="8.8.8.8", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "add_netwatch"


def test_add_netwatch_blocked_when_write_disabled_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings: Settings
):
    with pytest.raises(WriteDisabledError):
        guard.add_netwatch(client, settings, host="1.1.1.1", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "add_netwatch"


def test_remove_netwatch_confirmed_call_journals_outcome_applied(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings, device: Device
):
    guard.remove_netwatch(client, settings_write_enabled, host="8.8.8.8", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    event = events[0]
    assert event["outcome"] == "applied"
    assert event["tool"] == "remove_netwatch"
    assert event["operation"] == "remove_netwatch"
    assert event["action"] == "remove"

    raw = audit_log.read_text(encoding="utf-8")
    assert device.password not in raw


def test_remove_netwatch_not_found_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    with pytest.raises(ResourceNotFoundError):
        guard.remove_netwatch(client, settings_write_enabled, host="9.9.9.9", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "remove_netwatch"


# --- add_static_dns / remove_static_dns / clear_dns_cache / -----------------
# --- remove_dhcp_lease / wake_on_lan (v0.10) --------------------------------


def test_add_static_dns_confirmed_call_journals_outcome_applied_without_leaking_password(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings, device: Device
):
    guard.add_static_dns(client, settings_write_enabled, name="blocked.example.com", address="0.0.0.0", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    event = events[0]
    assert event["outcome"] == "applied"
    assert event["tool"] == "add_static_dns"
    assert event["operation"] == "add_static_dns"
    assert event["action"] == "add"
    assert event["summary"]["after"]["address"] == "0.0.0.0"

    raw = audit_log.read_text(encoding="utf-8")
    assert device.password not in raw


def test_add_static_dns_duplicate_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    guard.add_static_dns(client, settings_write_enabled, name="blocked.example.com", address="0.0.0.0", confirm=True)

    with pytest.raises(ResourceAlreadyExistsError):
        guard.add_static_dns(
            client, settings_write_enabled, name="blocked.example.com", address="1.2.3.4", confirm=True
        )

    events = _events(audit_log)
    assert len(events) == 2
    assert events[1]["outcome"] == "error"
    assert events[1]["operation"] == "add_static_dns"


def test_remove_static_dns_confirmed_call_journals_outcome_applied(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings, device: Device
):
    guard.add_static_dns(client, settings_write_enabled, name="blocked.example.com", address="0.0.0.0", confirm=True)
    guard.remove_static_dns(client, settings_write_enabled, name="blocked.example.com", confirm=True)

    events = _events(audit_log)
    assert len(events) == 2
    event = events[1]
    assert event["outcome"] == "applied"
    assert event["tool"] == "remove_static_dns"
    assert event["operation"] == "remove_static_dns"
    assert event["action"] == "remove"

    raw = audit_log.read_text(encoding="utf-8")
    assert device.password not in raw


def test_remove_static_dns_not_found_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    with pytest.raises(ResourceNotFoundError):
        guard.remove_static_dns(client, settings_write_enabled, name="ghost.example.com", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "remove_static_dns"


def test_clear_dns_cache_confirmed_call_journals_outcome_applied_without_leaking_password(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings, device: Device
):
    guard.clear_dns_cache(client, settings_write_enabled, confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    event = events[0]
    assert event["outcome"] == "applied"
    assert event["tool"] == "clear_dns_cache"
    assert event["operation"] == "clear_dns_cache"
    assert event["action"] == "flush"

    raw = audit_log.read_text(encoding="utf-8")
    assert device.password not in raw


def test_clear_dns_cache_blocked_when_write_disabled_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings: Settings
):
    with pytest.raises(WriteDisabledError):
        guard.clear_dns_cache(client, settings, confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "clear_dns_cache"


def test_remove_dhcp_lease_confirmed_call_journals_outcome_applied_without_leaking_password(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings, device: Device
):
    guard.remove_dhcp_lease(client, settings_write_enabled, mac_address="AA:BB:CC:DD:EE:01", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    event = events[0]
    assert event["outcome"] == "applied"
    assert event["tool"] == "remove_dhcp_lease"
    assert event["operation"] == "remove_dhcp_lease"
    assert event["action"] == "remove"

    raw = audit_log.read_text(encoding="utf-8")
    assert device.password not in raw


def test_remove_dhcp_lease_static_lease_journals_warning_in_summary(
    audit_log: Path, device: Device, settings_write_enabled: Settings
):
    """Same warning-in-summary contract as disable_route's default-route
    callout, exercised on a second warning-carrying write: removing a
    STATIC dhcp lease."""
    fake = FakeConnection(
        data={
            ("ip", "dhcp-server", "lease"): [
                {
                    ".id": "*1",
                    "address": "10.0.0.60",
                    "mac-address": "AA:BB:CC:DD:EE:02",
                    "dynamic": "false",
                    "status": "bound",
                }
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)

    preview = guard.remove_dhcp_lease(client, settings_write_enabled, mac_address="AA:BB:CC:DD:EE:02", confirm=True)
    assert preview.warning is not None

    events = _events(audit_log)
    assert len(events) == 1
    event = events[0]
    assert event["outcome"] == "applied"
    assert event["operation"] == "remove_dhcp_lease"
    assert event["summary"]["warning"] == preview.warning
    assert "STATIC" in event["summary"]["warning"]


def test_remove_dhcp_lease_not_found_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    with pytest.raises(ResourceNotFoundError):
        guard.remove_dhcp_lease(client, settings_write_enabled, mac_address="AA:BB:CC:DD:EE:99", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "remove_dhcp_lease"


def test_wake_on_lan_confirmed_call_journals_outcome_applied_without_leaking_password(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings, device: Device
):
    guard.wake_on_lan(client, settings_write_enabled, mac_address="AA:BB:CC:DD:EE:FF", interface="ether1", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    event = events[0]
    assert event["outcome"] == "applied"
    assert event["tool"] == "wake_on_lan"
    assert event["operation"] == "wake_on_lan"
    assert event["action"] == "wol"
    assert event["summary"]["after"]["mac_address"] == "AA:BB:CC:DD:EE:FF"

    raw = audit_log.read_text(encoding="utf-8")
    assert device.password not in raw


def test_wake_on_lan_blocked_when_write_disabled_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings: Settings
):
    with pytest.raises(WriteDisabledError):
        guard.wake_on_lan(client, settings, mac_address="AA:BB:CC:DD:EE:FF", interface="ether1", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "wake_on_lan"


# --- enable_firewall_rule / disable_firewall_rule (v0.11) -----------------


def test_enable_firewall_rule_confirmed_call_journals_outcome_applied_without_leaking_password(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings, device: Device
):
    guard.enable_firewall_rule(client, settings_write_enabled, comment="Bloqueio_Ataque_X", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    event = events[0]
    assert event["outcome"] == "applied"
    assert event["tool"] == "enable_firewall_rule"
    assert event["operation"] == "enable_firewall_rule"
    assert event["action"] == "update"
    assert event["summary"]["after"]["disabled"] == "no"
    # The full matched rule (chain/action/comment) is journaled, not just
    # the changed field - so an audit reader can tell WHICH rule this was.
    assert event["summary"]["before"]["comment"] == "Bloqueio_Ataque_X"
    assert event["summary"]["before"]["chain"] == "forward"

    raw = audit_log.read_text(encoding="utf-8")
    assert device.password not in raw


def test_enable_firewall_rule_blocked_when_write_disabled_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings: Settings
):
    with pytest.raises(WriteDisabledError):
        guard.enable_firewall_rule(client, settings, comment="Bloqueio_Ataque_X", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "enable_firewall_rule"


def test_enable_firewall_rule_unknown_comment_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    with pytest.raises(ResourceNotFoundError):
        guard.enable_firewall_rule(client, settings_write_enabled, comment="no-such-rule", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "enable_firewall_rule"


def test_enable_firewall_rule_ambiguous_comment_journals_outcome_error(
    audit_log: Path, settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(
        data={
            ("ip", "firewall", "filter"): [
                {".id": "*1", "chain": "input", "action": "drop", "comment": "dup", "disabled": "true"},
                {".id": "*2", "chain": "forward", "action": "drop", "comment": "dup", "disabled": "true"},
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)
    with pytest.raises(AmbiguousResourceError):
        guard.enable_firewall_rule(client, settings_write_enabled, comment="dup", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "enable_firewall_rule"


def test_disable_firewall_rule_confirmed_call_journals_outcome_applied_without_leaking_password(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings, device: Device
):
    guard.disable_firewall_rule(client, settings_write_enabled, comment="allow established", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    event = events[0]
    assert event["outcome"] == "applied"
    assert event["tool"] == "disable_firewall_rule"
    assert event["operation"] == "disable_firewall_rule"
    assert event["action"] == "update"
    assert event["summary"]["after"]["disabled"] == "yes"

    raw = audit_log.read_text(encoding="utf-8")
    assert device.password not in raw


# --- WireGuard management (v0.13): CRITICAL - private-key must never reach --
# --- the audit journal, in any outcome -------------------------------------


def test_add_wireguard_interface_confirmed_call_never_leaks_private_key_into_journal(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    """The fake device (tests/fakes.py) simulates RouterOS generating a real
    key pair - including a distinctively-marked private-key - on
    `/interface/wireguard add`. This proves that marker never reaches the
    audit journal's `before` OR `after`, even though guard.py had to re-read
    the freshly created row (which genuinely carries it) to report the
    public-key."""
    applied = guard.add_wireguard_interface(client, settings_write_enabled, name="wg-audit-test", confirm=True)
    assert "public-key" in applied.after
    assert "private-key" not in applied.after

    events = _events(audit_log)
    assert len(events) == 1
    event = events[0]
    assert event["outcome"] == "applied"
    assert event["tool"] == "add_wireguard_interface"
    assert event["summary"]["after"]["name"] == "wg-audit-test"
    assert "private-key" not in event["summary"]["before"]
    assert "private-key" not in event["summary"]["after"]

    raw = audit_log.read_text(encoding="utf-8")
    assert "FAKE-PRIVATE-KEY-MUST-NEVER-LEAK" not in raw


def test_add_wireguard_interface_preview_never_leaks_a_public_key_that_does_not_exist_yet(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    """A confirm=False preview never invents a public-key (RouterOS hasn't
    generated one yet) - so the journal for a preview can't leak one either,
    by construction."""
    guard.add_wireguard_interface(client, settings_write_enabled, name="wg-preview-test", confirm=False)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "preview"
    assert "public-key" not in events[0]["summary"]["after"]
    assert "private-key" not in events[0]["summary"]["after"]


def test_add_wireguard_interface_duplicate_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    with pytest.raises(ResourceAlreadyExistsError):
        guard.add_wireguard_interface(client, settings_write_enabled, name="wg1", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "add_wireguard_interface"


def test_add_wireguard_interface_blocked_when_write_disabled_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings: Settings
):
    with pytest.raises(WriteDisabledError):
        guard.add_wireguard_interface(client, settings, name="wg2", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "add_wireguard_interface"


def test_add_wireguard_peer_confirmed_call_journals_outcome_applied_without_leaking_password(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings, device: Device
):
    guard.add_wireguard_peer(
        client,
        settings_write_enabled,
        interface="wg1",
        public_key="OaQx4l1wQNnz9J+odnvI4yyND+HG699QWpM8fL1XAO0=",
        allowed_address="10.10.0.9/32",
        confirm=True,
    )

    events = _events(audit_log)
    assert len(events) == 1
    event = events[0]
    assert event["outcome"] == "applied"
    assert event["tool"] == "add_wireguard_peer"
    assert event["operation"] == "add_wireguard_peer"
    assert event["action"] == "add"
    assert event["summary"]["after"]["public-key"] == "OaQx4l1wQNnz9J+odnvI4yyND+HG699QWpM8fL1XAO0="

    raw = audit_log.read_text(encoding="utf-8")
    assert device.password not in raw


def test_add_wireguard_peer_unknown_interface_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    with pytest.raises(ResourceNotFoundError):
        guard.add_wireguard_peer(
            client,
            settings_write_enabled,
            interface="ghost-tunnel",
            public_key="OaQx4l1wQNnz9J+odnvI4yyND+HG699QWpM8fL1XAO0=",
            allowed_address="10.10.0.9/32",
            confirm=True,
        )

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "add_wireguard_peer"


def test_remove_wireguard_peer_confirmed_call_journals_outcome_applied(
    audit_log: Path, settings_write_enabled: Settings, device: Device
):
    fake = FakeConnection(
        data={
            ("interface", "wireguard", "peers"): [
                {
                    ".id": "*1",
                    "interface": "wg1",
                    "public-key": "OaQx4l1wQNnz9J+odnvI4yyND+HG699QWpM8fL1XAO0=",
                }
            ]
        }
    )
    client = MikrotikClient(device, connection=fake)
    guard.remove_wireguard_peer(
        client,
        settings_write_enabled,
        interface="wg1",
        public_key="OaQx4l1wQNnz9J+odnvI4yyND+HG699QWpM8fL1XAO0=",
        confirm=True,
    )

    events = _events(audit_log)
    assert len(events) == 1
    event = events[0]
    assert event["outcome"] == "applied"
    assert event["tool"] == "remove_wireguard_peer"
    assert event["operation"] == "remove_wireguard_peer"
    assert event["action"] == "remove"

    raw = audit_log.read_text(encoding="utf-8")
    assert device.password not in raw


def test_remove_wireguard_peer_not_found_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    with pytest.raises(ResourceNotFoundError):
        guard.remove_wireguard_peer(
            client,
            settings_write_enabled,
            interface="wg1",
            public_key="OaQx4l1wQNnz9J+odnvI4yyND+HG699QWpM8fL1XAO0=",
            confirm=True,
        )

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "remove_wireguard_peer"


# --- add_hotspot_user / create_backup (v0.14) -------------------------------


def test_add_hotspot_user_confirmed_call_journals_outcome_applied(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    guard.add_hotspot_user(client, settings_write_enabled, name="visitor2", password="Passw0rd!", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    event = events[0]
    assert event["outcome"] == "applied"
    assert event["tool"] == "add_hotspot_user"
    assert event["operation"] == "add_hotspot_user"
    assert event["action"] == "add"
    assert event["summary"]["after"]["name"] == "visitor2"


def test_add_hotspot_user_password_never_in_audit_journal(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    """THE deliberate asymmetry this round introduces: unlike every secret
    this package has handled before (a device password, a WireGuard
    private-key - never returned to any caller at all), a hotspot voucher's
    `password` is DELIBERATELY present in what guard.add_hotspot_user
    returns (see its own docstring - the caller needs it to hand to a
    visitor). It must still never reach the audit journal. Proven on both
    outcomes: the returned WritePreview DOES carry the password, but the
    journal - fed the exact same before/after by `_audited` - does not."""
    preview = guard.add_hotspot_user(
        client, settings_write_enabled, name="visitor2", password="Sup3rSecretVoucher!", confirm=True
    )
    # (a) the tool's own return value DOES carry the password - this is the
    # whole point of the tool, not a bug.
    assert preview.after["password"] == "Sup3rSecretVoucher!"

    # (b) the audit journal does not - anywhere, in before or after.
    raw = audit_log.read_text(encoding="utf-8")
    assert "Sup3rSecretVoucher!" not in raw
    events = _events(audit_log)
    assert len(events) == 1
    assert "password" not in events[0]["summary"]["after"]
    assert events[0]["summary"]["after"]["name"] == "visitor2"


def test_add_hotspot_user_password_never_in_audit_journal_on_preview(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    """Same asymmetry as the applied case above, but for a confirm=False
    preview - the password must be absent from the journal there too, even
    though it's present in the preview's own `after`."""
    preview = guard.add_hotspot_user(
        client, settings_write_enabled, name="visitor2", password="Sup3rSecretVoucher!", confirm=False
    )
    assert preview.after["password"] == "Sup3rSecretVoucher!"

    raw = audit_log.read_text(encoding="utf-8")
    assert "Sup3rSecretVoucher!" not in raw
    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "preview"
    assert "password" not in events[0]["summary"]["after"]


def test_add_hotspot_user_duplicate_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    guard.add_hotspot_user(client, settings_write_enabled, name="visitor2", password="Passw0rd!", confirm=True)
    with pytest.raises(ResourceAlreadyExistsError):
        guard.add_hotspot_user(client, settings_write_enabled, name="visitor2", password="AnotherPass1", confirm=True)

    events = _events(audit_log)
    assert len(events) == 2
    assert events[1]["outcome"] == "error"
    assert events[1]["operation"] == "add_hotspot_user"


def test_add_hotspot_user_blocked_when_write_disabled_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings: Settings
):
    with pytest.raises(WriteDisabledError):
        guard.add_hotspot_user(client, settings, name="visitor2", password="Passw0rd!", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "add_hotspot_user"


def test_create_backup_confirmed_call_journals_outcome_applied_without_leaking_device_password(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings, device: Device
):
    guard.create_backup(client, settings_write_enabled, name="nightly-backup", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    event = events[0]
    assert event["outcome"] == "applied"
    assert event["tool"] == "create_backup"
    assert event["operation"] == "create_backup"
    assert event["action"] == "save"
    assert event["summary"]["after"]["name"] == "nightly-backup"

    raw = audit_log.read_text(encoding="utf-8")
    assert device.password not in raw


def test_create_backup_encryption_password_never_in_audit_journal(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    """Unlike add_hotspot_user's voucher password, create_backup's
    `password` (RouterOS's own backup-FILE encryption option) is NOT
    returned to the caller either - redacted before the WritePreview is
    ever constructed, same "redact before constructing the preview" rule
    v0.13's WireGuard round established. Never in the journal, never in the
    returned preview."""
    preview = guard.create_backup(
        client, settings_write_enabled, name="nightly-backup", password="file-encrypt-key", confirm=True
    )
    assert "password" not in preview.after

    raw = audit_log.read_text(encoding="utf-8")
    assert "file-encrypt-key" not in raw
    events = _events(audit_log)
    assert len(events) == 1
    assert "password" not in events[0]["summary"]["after"]


def test_create_backup_duplicate_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    with pytest.raises(ResourceAlreadyExistsError):
        guard.create_backup(client, settings_write_enabled, name="core-switch-2026-01-01", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "create_backup"


def test_create_backup_blocked_when_write_disabled_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings: Settings
):
    with pytest.raises(WriteDisabledError):
        guard.create_backup(client, settings, name="nightly-backup", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "create_backup"


# --- add_ppp_secret / remove_ppp_secret (v1.3) -------------------------------


def test_add_ppp_secret_confirmed_call_journals_outcome_applied(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    guard.add_ppp_secret(client, settings_write_enabled, name="customer2", password="Passw0rd!", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    event = events[0]
    assert event["outcome"] == "applied"
    assert event["tool"] == "add_ppp_secret"
    assert event["operation"] == "add_ppp_secret"
    assert event["action"] == "add"
    assert event["summary"]["after"]["name"] == "customer2"


def test_add_ppp_secret_password_never_in_audit_journal(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    """Same asymmetry as add_hotspot_user's voucher password (v0.14): the
    plaintext `password` DOES appear in what guard.add_ppp_secret returns
    (the caller supplied it and gets it echoed back), but it must never
    reach the audit journal."""
    preview = guard.add_ppp_secret(
        client, settings_write_enabled, name="customer2", password="Sup3rSecretDialup!", confirm=True
    )
    # (a) the tool's own return value DOES carry the password.
    assert preview.after["password"] == "Sup3rSecretDialup!"

    # (b) the audit journal does not - anywhere, in before or after.
    raw = audit_log.read_text(encoding="utf-8")
    assert "Sup3rSecretDialup!" not in raw
    events = _events(audit_log)
    assert len(events) == 1
    assert "password" not in events[0]["summary"]["after"]
    assert events[0]["summary"]["after"]["name"] == "customer2"


def test_add_ppp_secret_password_never_in_audit_journal_on_preview(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    """Same asymmetry as the applied case above, but for a confirm=False
    preview - the password must be absent from the journal there too, even
    though it's present in the preview's own `after`."""
    preview = guard.add_ppp_secret(
        client, settings_write_enabled, name="customer2", password="Sup3rSecretDialup!", confirm=False
    )
    assert preview.after["password"] == "Sup3rSecretDialup!"

    raw = audit_log.read_text(encoding="utf-8")
    assert "Sup3rSecretDialup!" not in raw
    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "preview"
    assert "password" not in events[0]["summary"]["after"]


def test_add_ppp_secret_duplicate_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    """The shared fixture's ("ppp", "secret") table (see conftest) already
    has a "pppoe-client1" secret."""
    with pytest.raises(ResourceAlreadyExistsError):
        guard.add_ppp_secret(client, settings_write_enabled, name="pppoe-client1", password="Passw0rd!", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "add_ppp_secret"


def test_add_ppp_secret_blocked_when_write_disabled_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings: Settings
):
    with pytest.raises(WriteDisabledError):
        guard.add_ppp_secret(client, settings, name="customer2", password="Passw0rd!", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "add_ppp_secret"


def test_remove_ppp_secret_confirmed_call_journals_outcome_applied_without_leaking_password(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    """The shared fixture's "pppoe-client1" secret carries a fake password
    ("s3cret-fake") - proves remove_ppp_secret's `before` never journals it,
    on top of guard.py's own before-the-preview redaction."""
    guard.remove_ppp_secret(client, settings_write_enabled, name="pppoe-client1", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    event = events[0]
    assert event["outcome"] == "applied"
    assert event["tool"] == "remove_ppp_secret"
    assert event["operation"] == "remove_ppp_secret"
    assert event["action"] == "remove"
    assert event["summary"]["before"]["name"] == "pppoe-client1"
    assert "password" not in event["summary"]["before"]

    raw = audit_log.read_text(encoding="utf-8")
    assert "s3cret-fake" not in raw


def test_remove_ppp_secret_not_found_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings_write_enabled: Settings
):
    with pytest.raises(ResourceNotFoundError):
        guard.remove_ppp_secret(client, settings_write_enabled, name="ghost-secret", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "remove_ppp_secret"


def test_remove_ppp_secret_blocked_when_write_disabled_journals_outcome_error(
    audit_log: Path, client: MikrotikClient, settings: Settings
):
    with pytest.raises(WriteDisabledError):
        guard.remove_ppp_secret(client, settings, name="pppoe-client1", confirm=True)

    events = _events(audit_log)
    assert len(events) == 1
    assert events[0]["outcome"] == "error"
    assert events[0]["operation"] == "remove_ppp_secret"
