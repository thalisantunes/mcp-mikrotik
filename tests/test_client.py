from __future__ import annotations

import ssl

import pytest
from librouteros.exceptions import LibRouterosError

from mcp_mikrotik.client import (
    DEFAULT_TIMEOUT,
    ClientPool,
    MikrotikClient,
    _build_ssl_context,
    _connect,
    _resolve_timeout,
    get_client,
)
from mcp_mikrotik.config import Device, Settings
from mcp_mikrotik.exceptions import DeviceCommandError, DeviceConnectionError, DeviceNotFoundError

from .fakes import FakeConnection, TransportErrorConnection


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


# --- N1: transport errors (OSError, not just LibRouterosError) must be
# wrapped as DeviceCommandError, with the device name, instead of escaping
# as an opaque error. ---------------------------------------------------


@pytest.mark.parametrize("exc", [OSError("link down"), LibRouterosError("boom")])
def test_path_wraps_transport_errors_as_device_command_error(device: Device, exc: Exception):
    client = MikrotikClient(device, connection=TransportErrorConnection(exc))
    with pytest.raises(DeviceCommandError) as exc_info:
        client.path("ip", "address")
    assert device.name in str(exc_info.value)


@pytest.mark.parametrize("exc", [OSError("link down"), LibRouterosError("boom")])
def test_ping_wraps_transport_errors_as_device_command_error(device: Device, exc: Exception):
    client = MikrotikClient(device, connection=TransportErrorConnection(exc))
    with pytest.raises(DeviceCommandError) as exc_info:
        client.ping("8.8.8.8")
    assert device.name in str(exc_info.value)


@pytest.mark.parametrize("exc", [OSError("link down"), LibRouterosError("boom")])
def test_update_wraps_transport_errors_as_device_command_error(device: Device, exc: Exception):
    client = MikrotikClient(device, connection=TransportErrorConnection(exc))
    with pytest.raises(DeviceCommandError) as exc_info:
        client.update("system", "identity", name="x")
    assert device.name in str(exc_info.value)


@pytest.mark.parametrize("exc", [OSError("link down"), LibRouterosError("boom")])
def test_add_wraps_transport_errors_as_device_command_error(device: Device, exc: Exception):
    client = MikrotikClient(device, connection=TransportErrorConnection(exc))
    with pytest.raises(DeviceCommandError) as exc_info:
        client.add("ip", "address", address="10.0.0.9/24")
    assert device.name in str(exc_info.value)


@pytest.mark.parametrize("exc", [OSError("link down"), LibRouterosError("boom")])
def test_remove_wraps_transport_errors_as_device_command_error(device: Device, exc: Exception):
    client = MikrotikClient(device, connection=TransportErrorConnection(exc))
    with pytest.raises(DeviceCommandError) as exc_info:
        client.remove("ip", "address", ids=("*1",))
    assert device.name in str(exc_info.value)


# --- T1: _connect()/SSL layer, never exercised via the fakes above -------


def test_connect_passes_ssl_wrapper_when_use_ssl(monkeypatch: pytest.MonkeyPatch):
    device = Device(name="ssl-dev", host="10.0.0.5", use_ssl=True, password="s3cret")
    captured: dict = {}

    def fake_connect(**kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr("mcp_mikrotik.client.librouteros.connect", fake_connect)
    _connect(device)
    assert "ssl_wrapper" in captured
    assert callable(captured["ssl_wrapper"])


def test_connect_no_ssl_wrapper_when_not_use_ssl(monkeypatch: pytest.MonkeyPatch):
    device = Device(name="plain-dev", host="10.0.0.5", use_ssl=False)
    captured: dict = {}

    def fake_connect(**kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr("mcp_mikrotik.client.librouteros.connect", fake_connect)
    _connect(device)
    assert "ssl_wrapper" not in captured


def test_connect_wraps_lib_routeros_error_without_leaking_password(monkeypatch: pytest.MonkeyPatch):
    device = Device(name="d1", host="10.0.0.1", password="s3cret")

    def raiser(**kwargs):
        raise LibRouterosError("bad login")

    monkeypatch.setattr("mcp_mikrotik.client.librouteros.connect", raiser)
    with pytest.raises(DeviceConnectionError) as exc_info:
        _connect(device)
    assert "s3cret" not in str(exc_info.value)
    assert "d1" in str(exc_info.value)


def test_connect_wraps_os_error_without_leaking_password(monkeypatch: pytest.MonkeyPatch):
    device = Device(name="d1", host="10.0.0.1", password="s3cret")

    def raiser(**kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr("mcp_mikrotik.client.librouteros.connect", raiser)
    with pytest.raises(DeviceConnectionError) as exc_info:
        _connect(device)
    assert "s3cret" not in str(exc_info.value)
    assert "d1" in str(exc_info.value)


# --- SSL1: tls_verify controls certificate validation --------------------


def test_build_ssl_context_tls_verify_true_validates_by_default():
    device = Device(name="d1", host="10.0.0.1", use_ssl=True, tls_verify=True)
    context = _build_ssl_context(device)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_build_ssl_context_tls_verify_false_disables_verification():
    device = Device(name="d1", host="10.0.0.1", use_ssl=True, tls_verify=False)
    context = _build_ssl_context(device)
    assert context.verify_mode == ssl.CERT_NONE
    assert context.check_hostname is False


# --- N4: per-device / env / default timeout resolution --------------------


def test_resolve_timeout_prefers_device_value(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("MIKROTIK_TIMEOUT", raising=False)
    device = Device(name="d1", host="10.0.0.1", timeout=45)
    assert _resolve_timeout(device) == 45


def test_resolve_timeout_falls_back_to_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MIKROTIK_TIMEOUT", "77")
    device = Device(name="d1", host="10.0.0.1")
    assert _resolve_timeout(device) == 77.0


def test_resolve_timeout_falls_back_to_default(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("MIKROTIK_TIMEOUT", raising=False)
    device = Device(name="d1", host="10.0.0.1")
    assert _resolve_timeout(device) == DEFAULT_TIMEOUT


# --- N2+N3: ClientPool reuses one MikrotikClient per device and closes ---
# --- every pooled connection deterministically ----------------------------


def test_client_pool_reuses_client_per_device(device: Device):
    calls: list[str] = []

    def factory(settings: Settings, name: str) -> MikrotikClient:
        calls.append(name)
        return MikrotikClient(settings.get_device(name), connection=FakeConnection())

    settings = Settings(allow_write=False, devices={device.name: device})
    pool = ClientPool(settings, factory)

    first = pool.get(device.name)
    second = pool.get(device.name)

    assert first is second
    assert calls == [device.name]  # factory invoked once, not per .get() call


def test_client_pool_close_all_closes_every_pooled_connection_and_clears_cache(device: Device):
    calls: list[str] = []

    def factory(settings: Settings, name: str) -> MikrotikClient:
        calls.append(name)
        return MikrotikClient(settings.get_device(name), connection=FakeConnection())

    settings = Settings(allow_write=False, devices={device.name: device})
    pool = ClientPool(settings, factory)

    first = pool.get(device.name)
    pool.close_all()

    assert first._connection is None  # MikrotikClient.close() clears its cached connection
    assert calls == [device.name]

    # Cache was cleared by close_all(), so the next .get() builds a fresh
    # client via the factory instead of returning the closed one.
    second = pool.get(device.name)
    assert second is not first
    assert calls == [device.name, device.name]
