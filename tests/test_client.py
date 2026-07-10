from __future__ import annotations

import ssl

import pytest
from librouteros.exceptions import LibRouterosError

from mcp_mikrotik.client import (
    DEFAULT_BREAKER_COOLDOWN,
    DEFAULT_BREAKER_THRESHOLD,
    DEFAULT_READ_RETRIES,
    DEFAULT_TIMEOUT,
    ClientPool,
    MikrotikClient,
    _breaker_cooldown,
    _breaker_threshold,
    _build_ssl_context,
    _connect,
    _read_retries,
    _read_retry_delay,
    _resolve_timeout,
    get_client,
)
from mcp_mikrotik.config import Device, Settings
from mcp_mikrotik.exceptions import (
    CircuitOpenError,
    DeviceCommandError,
    DeviceConnectionError,
    DeviceNotFoundError,
)

from .fakes import FakeConnection, FlakyConnection, TransportErrorConnection


def test_path_returns_plain_dicts(client: MikrotikClient):
    rows = client.path("ip", "address")
    assert rows == [{".id": "*1", "address": "10.0.0.1/24", "interface": "ether1"}]
    assert isinstance(rows[0], dict)


def test_path_unknown_segment_returns_empty(client: MikrotikClient):
    assert client.path("does", "not", "exist") == []


def test_update_mutates_underlying_data(client: MikrotikClient, fake_connection: FakeConnection):
    client.update("system", "identity", name="renamed")
    assert fake_connection.path("system", "identity")._rows == [{"name": "renamed"}]


def test_ping_forwards_structured_params_not_a_command_string(client: MikrotikClient, fake_connection: FakeConnection):
    replies = client.ping("8.8.8.8", count=2)
    assert replies == [
        {"seq": "0", "host": "8.8.8.8", "time": "3ms"},
        {"seq": "1", "host": "8.8.8.8", "time": "4ms"},
    ]
    # Exactly one structured call was made, with address/count as kwargs -
    # never concatenated into the command string itself.
    assert fake_connection.calls == [("/ping", {"address": "8.8.8.8", "count": "2"})]


def test_monitor_traffic_forwards_structured_params_not_a_command_string(
    client: MikrotikClient, fake_connection: FakeConnection
):
    reply = client.monitor_traffic("ether1")
    assert reply["rx-bits-per-second"] == "1000000"
    assert reply["tx-bits-per-second"] == "500000"
    # once="" mirrors RouterOS's own `once=yes` CLI flag - a structured kwarg,
    # never concatenated into the command string itself.
    assert fake_connection.calls == [("/interface/monitor-traffic", {"interface": "ether1", "once": ""})]


def test_monitor_traffic_returns_empty_dict_when_device_replies_nothing(
    client: MikrotikClient, fake_connection: FakeConnection
):
    assert client.monitor_traffic("sfp1") == {}


def test_poe_monitor_forwards_structured_params_not_a_command_string(
    client: MikrotikClient, fake_connection: FakeConnection
):
    reply = client.poe_monitor("ether1")
    assert reply["poe-out-status"] == "powered-on"
    assert reply["poe-out-voltage"] == "48.0"
    assert fake_connection.calls == [("/interface/ethernet/poe/monitor", {"interface": "ether1", "once": ""})]


def test_poe_monitor_returns_empty_dict_when_device_replies_nothing(
    client: MikrotikClient, fake_connection: FakeConnection
):
    assert client.poe_monitor("sfp1") == {}


# --- v0.7: lte_monitor -------------------------------------------------


def test_lte_monitor_forwards_structured_params_not_a_command_string(
    client: MikrotikClient, fake_connection: FakeConnection
):
    reply = client.lte_monitor("lte1")
    assert reply["current-operator"] == "Vivo"
    assert reply["access-technology"] == "lte"
    assert fake_connection.calls == [("/interface/lte/monitor", {"interface": "lte1", "once": ""})]


def test_lte_monitor_returns_empty_dict_when_device_replies_nothing(
    client: MikrotikClient, fake_connection: FakeConnection
):
    assert client.lte_monitor("lte99") == {}


@pytest.mark.parametrize("exc", [OSError("link down"), LibRouterosError("boom")])
def test_lte_monitor_wraps_transport_errors_as_device_command_error(device: Device, exc: Exception):
    client = MikrotikClient(device, connection=TransportErrorConnection(exc))
    with pytest.raises(DeviceCommandError) as exc_info:
        client.lte_monitor("lte1")
    assert device.name in str(exc_info.value)


def test_lte_monitor_retries_on_transient_oserror_and_succeeds(device: Device):
    flaky = FlakyConnection(OSError("link blip"), fail_times=1)
    client = MikrotikClient(device, connection=flaky)

    reply = client.lte_monitor("lte1")

    assert reply == {}
    assert flaky.calls_made == 2


# --- v0.14: torch (live traffic snapshot - a MULTI-row "once" command) -----


def test_torch_forwards_structured_params_not_a_command_string(client: MikrotikClient, fake_connection: FakeConnection):
    rows = client.torch("ether1")
    assert len(rows) == 2
    assert rows[0]["src-address"] == "10.0.0.50"
    assert fake_connection.calls == [("/tool/torch", {"interface": "ether1", "once": ""})]


def test_torch_sends_optional_filters_as_structured_params(client: MikrotikClient, fake_connection: FakeConnection):
    client.torch("ether1", src_address="10.0.0.50", dst_address="8.8.8.8", port=443)
    assert fake_connection.calls == [
        (
            "/tool/torch",
            {
                "interface": "ether1",
                "once": "",
                "src-address": "10.0.0.50",
                "dst-address": "8.8.8.8",
                "port": "443",
            },
        )
    ]


def test_torch_omits_filters_that_were_not_given(client: MikrotikClient, fake_connection: FakeConnection):
    client.torch("ether1")
    _cmd, kwargs = fake_connection.calls[-1]
    assert "src-address" not in kwargs
    assert "dst-address" not in kwargs
    assert "port" not in kwargs


def test_torch_returns_empty_list_when_device_replies_nothing(client: MikrotikClient, fake_connection: FakeConnection):
    assert client.torch("ether2") == []


def test_fake_connection_returns_a_generator_not_a_list_for_torch(fake_connection: FakeConnection):
    """Same v0.7.1-style regression guard as monitor_traffic/poe_monitor/
    lte_monitor above, but for torch's MULTI-row reply: the fake must hand
    back a generator (truthy-but-empty, not subscriptable), never a real
    list - otherwise a regression to unmaterialized indexing in client.py's
    torch() couldn't be caught by this suite."""
    import types

    result = fake_connection("/tool/torch", interface="ether1", once="")
    assert isinstance(result, types.GeneratorType)
    assert bool(result) is True
    with pytest.raises(TypeError):
        result[0]


@pytest.mark.parametrize("exc", [OSError("link down"), LibRouterosError("boom")])
def test_torch_wraps_transport_errors_as_device_command_error(device: Device, exc: Exception):
    client = MikrotikClient(device, connection=TransportErrorConnection(exc))
    with pytest.raises(DeviceCommandError) as exc_info:
        client.torch("ether1")
    assert device.name in str(exc_info.value)


def test_torch_retries_on_transient_oserror_and_succeeds(device: Device):
    flaky = FlakyConnection(OSError("link blip"), fail_times=1)
    client = MikrotikClient(device, connection=flaky)

    rows = client.torch("ether1")

    assert rows == []
    assert flaky.calls_made == 2


# --- Regression: librouteros' callable connection form returns a GENERATOR,
# not a list, for monitor-once commands. `replies[0] if replies else {}` on
# the raw generator raised `TypeError: 'generator' object is not
# subscriptable` on every call against real hardware (confirmed against ROS7
# mANTBox and ROS6 OmniTik) - a generator is always truthy (so `if replies`
# never caught the empty case) and never subscriptable (so `replies[0]`
# always raised). client.py now materializes with list(...) first, exactly
# like ping/traceroute already did; these tests pin both (a) that the fakes
# actually hand back a generator - so a regression to `list` in the fakes
# can't hide a regression to `replies[0]` in client.py - and (b) that
# monitor_traffic/poe_monitor/lte_monitor handle both an empty and a
# non-empty generator without raising.


def test_fake_connection_returns_a_generator_not_a_list_for_monitor_once_commands(
    fake_connection: FakeConnection,
):
    """Pin the fakes' contract: a `once=` monitor command must hand back a
    generator (truthy-but-empty, not subscriptable) - a real `list` here
    would let client.py regress to `replies[0]` without any test catching
    it."""
    import types

    for cmd, interface in (
        ("/interface/monitor-traffic", "ether1"),
        ("/interface/ethernet/poe/monitor", "ether1"),
        ("/interface/lte/monitor", "lte1"),
    ):
        result = fake_connection(cmd, interface=interface, once="")
        assert isinstance(result, types.GeneratorType)
        assert bool(result) is True  # a generator object is always truthy
        with pytest.raises(TypeError):
            result[0]  # not subscriptable, unlike a list


@pytest.mark.parametrize(
    "method_name,interface",
    [("monitor_traffic", "ether1"), ("poe_monitor", "ether1"), ("lte_monitor", "lte1")],
)
def test_monitor_once_methods_handle_a_non_empty_generator_reply(
    client: MikrotikClient, method_name: str, interface: str
):
    """Non-empty generator case: must not raise, and must return the one
    reply as a plain dict."""
    reply = getattr(client, method_name)(interface)
    assert isinstance(reply, dict)
    assert reply != {}


@pytest.mark.parametrize(
    "method_name,interface",
    [("monitor_traffic", "sfp1"), ("poe_monitor", "sfp1"), ("lte_monitor", "lte99")],
)
def test_monitor_once_methods_handle_an_empty_generator_reply(client: MikrotikClient, method_name: str, interface: str):
    """Empty generator case (device has nothing to report for this
    interface): must not raise TypeError, must return {}."""
    reply = getattr(client, method_name)(interface)
    assert reply == {}


# --- v0.7: start/stop (RouterOS ACTION commands, not update/add/remove) ----


def test_start_dispatches_as_action_command_with_structured_id(client: MikrotikClient, fake_connection: FakeConnection):
    fake_connection._data[("container",)] = [{".id": "*1", "name": "grafana", "status": "stopped"}]
    client.start("container", id="*1")
    rows = fake_connection.path("container")._rows
    assert rows[0]["status"] == "running"


def test_stop_dispatches_as_action_command_with_structured_id(client: MikrotikClient, fake_connection: FakeConnection):
    fake_connection._data[("container",)] = [{".id": "*1", "name": "grafana", "status": "running"}]
    client.stop("container", id="*1")
    rows = fake_connection.path("container")._rows
    assert rows[0]["status"] == "stopped"


def test_start_only_touches_the_targeted_row(client: MikrotikClient, fake_connection: FakeConnection):
    fake_connection._data[("container",)] = [
        {".id": "*1", "name": "grafana", "status": "stopped"},
        {".id": "*2", "name": "alpine", "status": "stopped"},
    ]
    client.start("container", id="*2")
    rows = {row["name"]: row["status"] for row in fake_connection.path("container")._rows}
    assert rows == {"grafana": "stopped", "alpine": "running"}


@pytest.mark.parametrize("exc", [OSError("link down"), LibRouterosError("boom")])
def test_start_wraps_transport_errors_as_device_command_error(device: Device, exc: Exception):
    client = MikrotikClient(device, connection=TransportErrorConnection(exc))
    with pytest.raises(DeviceCommandError) as exc_info:
        client.start("container", id="*1")
    assert device.name in str(exc_info.value)


@pytest.mark.parametrize("exc", [OSError("link down"), LibRouterosError("boom")])
def test_stop_wraps_transport_errors_as_device_command_error(device: Device, exc: Exception):
    client = MikrotikClient(device, connection=TransportErrorConnection(exc))
    with pytest.raises(DeviceCommandError) as exc_info:
        client.stop("container", id="*1")
    assert device.name in str(exc_info.value)


# --- v0.10: flush/wol (RouterOS ACTION commands, callable form - no .id) ---


def test_flush_sends_the_fixed_command_string(client: MikrotikClient, fake_connection: FakeConnection):
    client.flush("ip", "dns", "cache")
    assert fake_connection.calls == [("/ip/dns/cache/flush", {})]


def test_wol_forwards_structured_params_not_a_command_string(client: MikrotikClient, fake_connection: FakeConnection):
    client.wol("tool", mac_address="AA:BB:CC:DD:EE:FF", interface="ether1")
    assert fake_connection.calls == [("/tool/wol", {"mac-address": "AA:BB:CC:DD:EE:FF", "interface": "ether1"})]


@pytest.mark.parametrize("exc", [OSError("link down"), LibRouterosError("boom")])
def test_flush_wraps_transport_errors_as_device_command_error(device: Device, exc: Exception):
    client = MikrotikClient(device, connection=TransportErrorConnection(exc))
    with pytest.raises(DeviceCommandError) as exc_info:
        client.flush("ip", "dns", "cache")
    assert device.name in str(exc_info.value)


@pytest.mark.parametrize("exc", [OSError("link down"), LibRouterosError("boom")])
def test_wol_wraps_transport_errors_as_device_command_error(device: Device, exc: Exception):
    client = MikrotikClient(device, connection=TransportErrorConnection(exc))
    with pytest.raises(DeviceCommandError) as exc_info:
        client.wol("tool", mac_address="AA:BB:CC:DD:EE:FF", interface="ether1")
    assert device.name in str(exc_info.value)


# --- v0.14: save (RouterOS ACTION command - backup creation, callable form) -


def test_save_forwards_structured_params_not_a_command_string(client: MikrotikClient, fake_connection: FakeConnection):
    client.save("system", "backup", name="core-switch-2026-01-01")
    assert fake_connection.calls == [("/system/backup/save", {"name": "core-switch-2026-01-01"})]


def test_save_forwards_password_as_structured_param_when_given(client: MikrotikClient, fake_connection: FakeConnection):
    client.save("system", "backup", name="core-switch-2026-01-01", password="s3cr3t-file-key")
    assert fake_connection.calls == [
        (
            "/system/backup/save",
            {"name": "core-switch-2026-01-01", "password": "s3cr3t-file-key"},
        )
    ]


def test_save_omits_password_field_when_not_given(client: MikrotikClient, fake_connection: FakeConnection):
    client.save("system", "backup", name="core-switch-2026-01-01")
    _cmd, kwargs = fake_connection.calls[-1]
    assert "password" not in kwargs


@pytest.mark.parametrize("exc", [OSError("link down"), LibRouterosError("boom")])
def test_save_wraps_transport_errors_as_device_command_error(device: Device, exc: Exception):
    client = MikrotikClient(device, connection=TransportErrorConnection(exc))
    with pytest.raises(DeviceCommandError) as exc_info:
        client.save("system", "backup", name="core-switch-2026-01-01")
    assert device.name in str(exc_info.value)


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
def test_monitor_traffic_wraps_transport_errors_as_device_command_error(device: Device, exc: Exception):
    client = MikrotikClient(device, connection=TransportErrorConnection(exc))
    with pytest.raises(DeviceCommandError) as exc_info:
        client.monitor_traffic("ether1")
    assert device.name in str(exc_info.value)


@pytest.mark.parametrize("exc", [OSError("link down"), LibRouterosError("boom")])
def test_poe_monitor_wraps_transport_errors_as_device_command_error(device: Device, exc: Exception):
    client = MikrotikClient(device, connection=TransportErrorConnection(exc))
    with pytest.raises(DeviceCommandError) as exc_info:
        client.poe_monitor("ether1")
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


def test_resolve_timeout_falls_back_to_default_on_unparseable_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MIKROTIK_TIMEOUT", "not-a-number")
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


# --- v0.5: read retry (path/ping/traceroute only, never writes) -----------


def test_path_retries_on_transient_oserror_and_succeeds(device: Device):
    flaky = FlakyConnection(OSError("link blip"), fail_times=1, data={("system", "identity"): [{"name": "MikroTik"}]})
    client = MikrotikClient(device, connection=flaky)

    rows = client.path("system", "identity")

    assert rows == [{"name": "MikroTik"}]
    assert flaky.calls_made == 2  # 1 failure + 1 successful retry


def test_path_gives_up_after_read_retries_exhausted(device: Device, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MIKROTIK_READ_RETRIES", "1")
    flaky = FlakyConnection(OSError("link blip"), fail_times=99)
    client = MikrotikClient(device, connection=flaky)

    with pytest.raises(DeviceCommandError):
        client.path("system", "identity")

    assert flaky.calls_made == 2  # 1 initial attempt + 1 retry, then give up


def test_path_never_retries_a_non_transient_lib_routeros_error(device: Device):
    flaky = FlakyConnection(LibRouterosError("no such command"), fail_times=99)
    client = MikrotikClient(device, connection=flaky)

    with pytest.raises(DeviceCommandError):
        client.path("system", "identity")

    assert flaky.calls_made == 1  # RouterOS-level rejection - retrying would just fail again


def test_ping_retries_on_transient_oserror_and_succeeds(device: Device):
    flaky = FlakyConnection(OSError("link blip"), fail_times=2, ping_replies=[{"seq": "0", "time": "3ms"}])
    client = MikrotikClient(device, connection=flaky)

    replies = client.ping("8.8.8.8")

    assert replies == [{"seq": "0", "time": "3ms"}]
    assert flaky.calls_made == 3  # 2 failures (default MIKROTIK_READ_RETRIES=2) + 1 success


def test_traceroute_retries_on_transient_oserror_and_succeeds(device: Device):
    flaky = FlakyConnection(
        OSError("link blip"), fail_times=1, traceroute_replies=[{"address": "10.0.0.254", "hop": "1"}]
    )
    client = MikrotikClient(device, connection=flaky)

    replies = client.traceroute("10.0.0.254")

    assert replies == [{"address": "10.0.0.254", "hop": "1"}]
    assert flaky.calls_made == 2


def test_monitor_traffic_retries_on_transient_oserror_and_succeeds(device: Device):
    flaky = FlakyConnection(OSError("link blip"), fail_times=1)
    client = MikrotikClient(device, connection=flaky)

    reply = client.monitor_traffic("ether1")

    assert reply == {}  # FlakyConnection's inner FakeConnection has no monitor_traffic_replies wired
    assert flaky.calls_made == 2


def test_poe_monitor_retries_on_transient_oserror_and_succeeds(device: Device):
    flaky = FlakyConnection(OSError("link blip"), fail_times=1)
    client = MikrotikClient(device, connection=flaky)

    reply = client.poe_monitor("ether1")

    assert reply == {}
    assert flaky.calls_made == 2


def test_read_retries_env_var_zero_disables_retry_entirely(device: Device, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MIKROTIK_READ_RETRIES", "0")
    flaky = FlakyConnection(OSError("link blip"), fail_times=1)
    client = MikrotikClient(device, connection=flaky)

    with pytest.raises(DeviceCommandError):
        client.path("system", "identity")

    assert flaky.calls_made == 1


@pytest.mark.parametrize(
    "write_call",
    [
        lambda client: client.update("system", "identity", name="x"),
        lambda client: client.add("ip", "address", address="10.0.0.9/24"),
        lambda client: client.remove("ip", "address", ids=("*1",)),
        lambda client: client.start("container", id="*1"),
        lambda client: client.stop("container", id="*1"),
        lambda client: client.flush("ip", "dns", "cache"),
        lambda client: client.wol("tool", mac_address="AA:BB:CC:DD:EE:FF", interface="ether1"),
    ],
)
def test_writes_never_retry_on_transient_oserror(device: Device, write_call):
    flaky = FlakyConnection(OSError("link blip"), fail_times=99)
    client = MikrotikClient(device, connection=flaky)

    with pytest.raises(DeviceCommandError):
        write_call(client)

    assert flaky.calls_made == 1  # writes get exactly one attempt, ever


# --- N5: env-var parsing fallbacks (read retries / breaker threshold+cooldown) --


def test_read_retries_falls_back_to_default_when_unset(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("MIKROTIK_READ_RETRIES", raising=False)
    assert _read_retries() == DEFAULT_READ_RETRIES


def test_read_retries_falls_back_to_default_on_unparseable_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MIKROTIK_READ_RETRIES", "not-a-number")
    assert _read_retries() == DEFAULT_READ_RETRIES


def test_read_retries_negative_env_clamped_to_zero(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MIKROTIK_READ_RETRIES", "-5")
    assert _read_retries() == 0


def test_breaker_threshold_falls_back_to_default_when_unset(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("MIKROTIK_BREAKER_THRESHOLD", raising=False)
    assert _breaker_threshold() == DEFAULT_BREAKER_THRESHOLD


def test_breaker_threshold_falls_back_to_default_on_unparseable_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MIKROTIK_BREAKER_THRESHOLD", "not-a-number")
    assert _breaker_threshold() == DEFAULT_BREAKER_THRESHOLD


def test_breaker_threshold_falls_back_to_default_on_non_positive_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MIKROTIK_BREAKER_THRESHOLD", "0")
    assert _breaker_threshold() == DEFAULT_BREAKER_THRESHOLD


def test_breaker_cooldown_falls_back_to_default_when_unset(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("MIKROTIK_BREAKER_COOLDOWN", raising=False)
    assert _breaker_cooldown() == DEFAULT_BREAKER_COOLDOWN


def test_breaker_cooldown_falls_back_to_default_on_unparseable_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MIKROTIK_BREAKER_COOLDOWN", "not-a-number")
    assert _breaker_cooldown() == DEFAULT_BREAKER_COOLDOWN


def test_breaker_cooldown_falls_back_to_default_on_negative_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MIKROTIK_BREAKER_COOLDOWN", "-1")
    assert _breaker_cooldown() == DEFAULT_BREAKER_COOLDOWN


def test_breaker_cooldown_accepts_zero(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MIKROTIK_BREAKER_COOLDOWN", "0")
    assert _breaker_cooldown() == 0.0


def test_read_retry_delay_within_schedule():
    assert _read_retry_delay(0) == 0.5
    assert _read_retry_delay(1) == 1.0


def test_read_retry_delay_reuses_last_delay_past_schedule_length():
    # MIKROTIK_READ_RETRIES can be set higher than the number of hardcoded
    # backoff delays - every attempt beyond the schedule reuses the last one
    # rather than indexing out of range.
    assert _read_retry_delay(2) == _read_retry_delay(99) == 1.0


def test_close_swallows_an_exception_from_the_underlying_connection(device: Device):
    class RaisingCloseConnection:
        def close(self) -> None:
            raise RuntimeError("already gone")

    client = MikrotikClient(device, connection=RaisingCloseConnection())
    client.close()  # must not raise, even though the underlying close() does


# --- v0.5: circuit breaker --------------------------------------------------


def test_breaker_fails_fast_after_threshold_consecutive_connect_failures(
    device: Device, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("MIKROTIK_BREAKER_THRESHOLD", "3")
    monkeypatch.setenv("MIKROTIK_READ_RETRIES", "0")  # isolate breaker accounting from read-retry loop
    attempts: list[Device] = []

    def fake_connect(dev: Device):
        attempts.append(dev)
        raise DeviceConnectionError(dev.name, "connection refused")

    monkeypatch.setattr("mcp_mikrotik.client._connect", fake_connect)
    client = MikrotikClient(device, connection=None)

    for _ in range(3):
        with pytest.raises(DeviceConnectionError):
            client.path("system", "identity")
    assert len(attempts) == 3
    assert client._breaker.is_open is True

    # Circuit now open: the next call fails immediately, with a clear
    # message, and never attempts a connection at all.
    with pytest.raises(CircuitOpenError) as exc_info:
        client.path("system", "identity")
    assert len(attempts) == 3  # no new connect attempt was made
    assert f"circuit open for {device.name!r}" in str(exc_info.value)
    assert "retry after" in str(exc_info.value)


def test_breaker_stays_closed_below_threshold(device: Device, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MIKROTIK_BREAKER_THRESHOLD", "3")
    monkeypatch.setenv("MIKROTIK_READ_RETRIES", "0")

    def fake_connect(dev: Device):
        raise DeviceConnectionError(dev.name, "connection refused")

    monkeypatch.setattr("mcp_mikrotik.client._connect", fake_connect)
    client = MikrotikClient(device, connection=None)

    for _ in range(2):  # below the threshold of 3
        with pytest.raises(DeviceConnectionError) as exc_info:
            client.path("system", "identity")
        assert not isinstance(exc_info.value, CircuitOpenError)

    assert client._breaker.is_open is False


def test_breaker_closes_on_a_success(device: Device, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MIKROTIK_BREAKER_THRESHOLD", "2")
    monkeypatch.setenv("MIKROTIK_READ_RETRIES", "0")
    calls = {"n": 0}

    def fake_connect(dev: Device):
        calls["n"] += 1
        if calls["n"] == 1:
            raise DeviceConnectionError(dev.name, "connection refused")
        return FakeConnection(data={("system", "identity"): [{"name": "MikroTik"}]})

    monkeypatch.setattr("mcp_mikrotik.client._connect", fake_connect)
    client = MikrotikClient(device, connection=None)

    with pytest.raises(DeviceConnectionError):
        client.path("system", "identity")  # 1 failure, below threshold of 2
    assert client._breaker.is_open is False

    rows = client.path("system", "identity")  # succeeds - resets the failure count
    assert rows == [{"name": "MikroTik"}]
    assert client._breaker.is_open is False

    # A fresh run of (threshold - 1) failures after a success must NOT open
    # the circuit - record_success() really reset the consecutive count.
    def fake_connect_fail_once_more(dev: Device):
        raise DeviceConnectionError(dev.name, "connection refused")

    client._connection = None
    monkeypatch.setattr("mcp_mikrotik.client._connect", fake_connect_fail_once_more)
    with pytest.raises(DeviceConnectionError) as exc_info:
        client.path("system", "identity")
    assert not isinstance(exc_info.value, CircuitOpenError)


def test_breaker_allows_a_trial_connection_after_cooldown_elapses(device: Device, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MIKROTIK_BREAKER_THRESHOLD", "1")
    monkeypatch.setenv("MIKROTIK_BREAKER_COOLDOWN", "0")  # elapses immediately
    monkeypatch.setenv("MIKROTIK_READ_RETRIES", "0")
    attempts = {"n": 0}

    def fake_connect(dev: Device):
        attempts["n"] += 1
        raise DeviceConnectionError(dev.name, "connection refused")

    monkeypatch.setattr("mcp_mikrotik.client._connect", fake_connect)
    client = MikrotikClient(device, connection=None)

    with pytest.raises(DeviceConnectionError):
        client.path("system", "identity")
    assert attempts["n"] == 1
    assert client._breaker.is_open is True

    # Cooldown is 0s, so the very next call is allowed a fresh trial connect
    # (half-open) instead of failing fast with CircuitOpenError.
    with pytest.raises(DeviceConnectionError) as exc_info:
        client.path("system", "identity")
    assert attempts["n"] == 2
    assert not isinstance(exc_info.value, CircuitOpenError)


def test_breaker_applies_to_writes_too_but_never_skips_a_gate_check(device: Device, monkeypatch: pytest.MonkeyPatch):
    """The breaker fails a write fast once open - but this is purely about
    the CONNECTION step. guard.py's read-only gate + allowlist check
    (guard._require_allowed) always runs first, entirely before
    MikrotikClient is touched, so the breaker can never be used to skip it -
    see guard.py's module docstring and ALLOWLIST comment."""
    monkeypatch.setenv("MIKROTIK_BREAKER_THRESHOLD", "1")
    monkeypatch.setenv("MIKROTIK_READ_RETRIES", "0")
    attempts = {"n": 0}

    def fake_connect(dev: Device):
        attempts["n"] += 1
        raise DeviceConnectionError(dev.name, "connection refused")

    monkeypatch.setattr("mcp_mikrotik.client._connect", fake_connect)
    client = MikrotikClient(device, connection=None)

    with pytest.raises(DeviceConnectionError):
        client.update("system", "identity", name="x")
    assert attempts["n"] == 1

    with pytest.raises(CircuitOpenError):
        client.update("system", "identity", name="x")
    assert attempts["n"] == 1  # fast fail - no second connect attempt


def test_breaker_is_scoped_per_client_instance(device: Device):
    """Sanity check on the "per device_name" framing: since ClientPool
    caches exactly one MikrotikClient per device_name for the server's
    lifetime, a fresh MikrotikClient naturally gets a fresh breaker - two
    independent instances never share breaker state."""
    client_a = MikrotikClient(device, connection=FakeConnection())
    client_b = MikrotikClient(device, connection=FakeConnection())
    assert client_a._breaker is not client_b._breaker
