from __future__ import annotations

import pytest

from mcp_mikrotik.client import MikrotikClient
from mcp_mikrotik.config import Device, Settings

from .fakes import FakeConnection


@pytest.fixture
def device() -> Device:
    return Device(
        name="core-switch",
        host="10.0.0.1",
        port=8728,
        use_ssl=False,
        username="admin",
        password="s3cret",
        disabled=False,
        comment="lab core switch",
    )


@pytest.fixture
def fake_connection() -> FakeConnection:
    return FakeConnection(
        data={
            ("system", "identity"): [{"name": "MikroTik"}],
            ("system", "resource"): [
                {"board-name": "hAP ac2", "version": "7.21", "uptime": "3d5h"}
            ],
            ("interface",): [
                {".id": "*1", "name": "ether1", "disabled": "false"},
                {".id": "*2", "name": "ether2", "disabled": "true"},
            ],
            ("ip", "address"): [{".id": "*1", "address": "10.0.0.1/24", "interface": "ether1"}],
            ("ip", "route"): [{".id": "*1", "dst-address": "0.0.0.0/0", "gateway": "10.0.0.254"}],
            ("ip", "neighbor"): [{".id": "*1", "address": "10.0.0.2", "identity": "ap-1"}],
            ("log",): [
                {".id": "*1", "time": "10:00:00", "topics": "system,info", "message": "boot"},
                {".id": "*2", "time": "10:00:05", "topics": "interface,link", "message": "ether1 up"},
            ],
            ("ip", "dhcp-server", "lease"): [
                {
                    ".id": "*1",
                    "address": "10.0.0.50",
                    "mac-address": "AA:BB:CC:DD:EE:01",
                    "host-name": "laptop-1",
                    "status": "bound",
                    "server": "dhcp1",
                    "comment": "",
                }
            ],
            ("ip", "dns", "cache"): [
                {"name": "example.com", "type": "A", "data": "93.184.216.34", "ttl": "1h"}
            ],
            ("ip", "firewall", "filter"): [
                {".id": "*1", "chain": "input", "action": "accept", "comment": "allow established"}
            ],
            ("system", "health"): [
                {"name": "voltage", "value": "24.1", "type": "V"},
                {"name": "temperature", "value": "38", "type": "C"},
            ],
            ("queue", "simple"): [
                {
                    ".id": "*1",
                    "name": "limit-10-0-0-50",
                    "target": "10.0.0.50/32",
                    "max-limit": "10M/5M",
                    "limit-at": "0/0",
                    "bytes": "1234567/7654321",
                    "disabled": "false",
                }
            ],
            ("ip", "firewall", "address-list"): [
                {
                    ".id": "*1",
                    "list": "blocked-clients",
                    "address": "10.0.0.60",
                    "timeout": "0s",
                    "dynamic": "false",
                    "disabled": "false",
                }
            ],
            ("ip", "firewall", "nat"): [
                {
                    ".id": "*1",
                    "chain": "srcnat",
                    "action": "masquerade",
                    "out-interface": "ether1",
                }
            ],
            ("system", "scheduler"): [
                {
                    ".id": "*1",
                    "name": "backup-daily",
                    "on-event": "backup",
                    "interval": "1d",
                    "next-run": "jan/01/2030 00:00:00",
                    "disabled": "false",
                }
            ],
            ("ip", "pool"): [
                {".id": "*1", "name": "dhcp-pool", "ranges": "10.0.0.100-10.0.0.200"}
            ],
            # v0.6: physical layer / PoE - a CRS318-16P-2S+-like mix of
            # PoE-capable ethernet ports (ether1: high/48V, ether2: low/24V)
            # and a non-PoE-capable one (sfp1: no `poe-out` field at all,
            # like an SFP+ cage or a device with no PoE hardware).
            ("interface", "ethernet"): [
                {".id": "*1", "name": "ether1", "poe-out": "auto-on"},
                {".id": "*2", "name": "ether2", "poe-out": "off"},
                {".id": "*3", "name": "sfp1"},
            ],
            ("ip", "arp"): [
                {
                    ".id": "*1",
                    "address": "10.0.0.70",
                    "mac-address": "AA:BB:CC:DD:EE:70",
                    "interface": "ether1",
                    "dynamic": "false",
                    "complete": "true",
                }
            ],
            ("interface", "bridge", "host"): [
                {
                    ".id": "*1",
                    "mac-address": "AA:BB:CC:DD:EE:70",
                    "on-interface": "ether1",
                    "bridge": "bridge1",
                    "dynamic": "false",
                    "local": "false",
                }
            ],
        },
        ping_replies=[
            {"seq": "0", "host": "8.8.8.8", "time": "3ms"},
            {"seq": "1", "host": "8.8.8.8", "time": "4ms"},
        ],
        traceroute_replies=[
            {"address": "10.0.0.254", "hop": "1", "status": "", "loss": "0%", "time": "1ms"},
            {"address": "8.8.8.8", "hop": "2", "status": "", "loss": "0%", "time": "5ms"},
        ],
        monitor_traffic_replies={
            "ether1": {
                "rx-bits-per-second": "1000000",
                "tx-bits-per-second": "500000",
                "rx-packets-per-second": "120",
                "tx-packets-per-second": "80",
            },
        },
        poe_monitor_replies={
            "ether1": {
                "poe-out-status": "powered-on",
                "poe-out-voltage": "48.0",
                "poe-out-current": "150",
                "poe-out-power": "7.2",
            },
            "ether2": {
                "poe-out-status": "poe-out-off",
                "poe-out-voltage": "0",
                "poe-out-current": "0",
                "poe-out-power": "0",
            },
        },
    )


@pytest.fixture
def client(device: Device, fake_connection: FakeConnection) -> MikrotikClient:
    return MikrotikClient(device, connection=fake_connection)


@pytest.fixture
def settings(device: Device) -> Settings:
    return Settings(allow_write=False, devices={device.name: device})


@pytest.fixture
def settings_write_enabled(device: Device) -> Settings:
    return Settings(allow_write=True, devices={device.name: device})


@pytest.fixture(autouse=True)
def _no_sleep_in_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never actually sleep during the read-retry backoff (client.py's
    MikrotikClient._run_read) - keeps the suite fast and deterministic.
    Tests that specifically exercise retry behaviour assert on call counts
    /exceptions, not on timing, so removing the real delay changes nothing
    they check."""
    monkeypatch.setattr("mcp_mikrotik.client.time.sleep", lambda seconds: None)
