from __future__ import annotations

import pytest

from mcp_mikrotik.client import MikrotikClient, get_client
from mcp_mikrotik.config import Device, Settings
from mcp_mikrotik.exceptions import DeviceNotFoundError

from .fakes import FakeConnection


def test_path_returns_plain_dicts(client: MikrotikClient):
    rows = client.path("ip", "address")
    assert rows == [{".id": "*1", "address": "10.0.0.1/24", "interface": "ether1"}]
    assert isinstance(rows[0], dict)


def test_path_unknown_segment_returns_empty(client: MikrotikClient):
    assert client.path("does", "not", "exist") == []


def test_update_mutates_underlying_data(client: MikrotikClient, fake_connection: FakeConnection):
    client.update("system", "identity", name="renamed")
    assert fake_connection.path("system", "identity")._rows == [{"name": "renamed"}]


def test_ping_forwards_structured_params_not_a_command_string(
    client: MikrotikClient, fake_connection: FakeConnection
):
    replies = client.ping("8.8.8.8", count=2)
    assert replies == [
        {"seq": "0", "host": "8.8.8.8", "time": "3ms"},
        {"seq": "1", "host": "8.8.8.8", "time": "4ms"},
    ]
    # Exactly one structured call was made, with address/count as kwargs -
    # never concatenated into the command string itself.
    assert fake_connection.calls == [("/ping", {"address": "8.8.8.8", "count": "2"})]


def test_close_is_idempotent(client: MikrotikClient, fake_connection: FakeConnection):
    client.close()
    assert fake_connection.closed is True
    client.close()  # second call must not raise


def test_get_client_rejects_unknown_device():
    settings = Settings(allow_write=False, devices={})
    with pytest.raises(DeviceNotFoundError):
        get_client(settings, "ghost")


def test_get_client_rejects_disabled_device():
    device = Device(name="d1", host="10.0.0.1", disabled=True)
    settings = Settings(allow_write=False, devices={"d1": device})
    with pytest.raises(DeviceNotFoundError):
        get_client(settings, "d1")


def test_get_client_returns_wired_client():
    device = Device(name="d1", host="10.0.0.1")
    settings = Settings(allow_write=False, devices={"d1": device})
    client = get_client(settings, "d1")
    assert isinstance(client, MikrotikClient)
    assert client.device is device
