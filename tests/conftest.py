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
        },
        ping_replies=[
            {"seq": "0", "host": "8.8.8.8", "time": "3ms"},
            {"seq": "1", "host": "8.8.8.8", "time": "4ms"},
        ],
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
