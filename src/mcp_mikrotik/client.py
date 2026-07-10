"""RouterOS API connection layer.

All device I/O goes through librouteros' structured API: `path().select()`
for reads and `path().add()/.update()/.remove()` for writes, plus the
callable form (`connection("/ping", address=...)`) for one-off commands like
ping. Nothing in this module (or anywhere else in this package) builds a
command by concatenating strings from user input - librouteros takes
structured parameters, which rules out command injection by construction.

`RouterosConnection` is the minimal interface MikrotikClient depends on. In
production it is satisfied by `librouteros.connect(...)`; tests satisfy it
with an in-memory fake (tests/fakes.py) so the suite never needs a real
router.

A second entrypoint (a Firebase exporter/collector) is planned to reuse this
same MikrotikClient layer - see the TODO at the bottom of this file.
"""

from __future__ import annotations

import os
import ssl
from functools import partial
from typing import Any, Callable, Iterable, Protocol

import librouteros
from librouteros.exceptions import LibRouterosError

from .config import Device, Settings
from .exceptions import DeviceCommandError, DeviceConnectionError

DEFAULT_TIMEOUT = 10.0


class RouterosConnection(Protocol):
    """Shape of a connected RouterOS API session that MikrotikClient needs."""

    def path(self, *path: str) -> Iterable[dict[str, Any]]:
        """Return an object that, when iterated, yields rows (dicts) and that
        also supports .add(**fields) / .update(**fields) / .remove(*ids)."""
        ...

    def __call__(self, cmd: str, **kwargs: Any) -> Iterable[dict[str, Any]]:
        """Run a one-off command (e.g. "/ping") and return its replies."""
        ...

    def close(self) -> None: ...


def _resolve_timeout(device: Device) -> float:
    """Resolve the connect timeout for a device (N4).

    Precedence: per-device `timeout` in devices.yaml, then the
    MIKROTIK_TIMEOUT env var, then DEFAULT_TIMEOUT. Some fleet links have a
    15-40s RouterOS banner, so the old hardcoded 10s was too tight for them.
    """
    if device.timeout is not None:
        return device.timeout
    env_value = os.environ.get("MIKROTIK_TIMEOUT")
    if env_value:
        try:
            return float(env_value)
        except ValueError:
            pass
    return DEFAULT_TIMEOUT


def _build_ssl_context(device: Device) -> ssl.SSLContext:
    """Build the SSL context for api-ssl devices (SSL1).

    Default (tls_verify=True) keeps the previously-existing safe behaviour:
    ssl.create_default_context() validates against the system trust store
    (or an explicit tls_ca_cert, if given). Only when a device explicitly
    opts out with tls_verify=False do we fall back to an unverified context
    (RouterOS api-ssl commonly uses a self-signed cert) - this is a
    documented, explicit, per-device trade-off (see README "Security model"
    and devices.yaml.example), never the default.
    """
    if device.tls_verify:
        return ssl.create_default_context(cafile=device.tls_ca_cert)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _connect(device: Device) -> RouterosConnection:
    kwargs: dict[str, Any] = {
        "username": device.username,
        "password": device.password,
        "host": device.host,
        "port": device.port,
        "timeout": _resolve_timeout(device),
    }
    if device.use_ssl:
        context = _build_ssl_context(device)
        kwargs["ssl_wrapper"] = partial(context.wrap_socket, server_hostname=device.host)
    try:
        return librouteros.connect(**kwargs)
    except LibRouterosError as exc:
        raise DeviceConnectionError(device.name, str(exc)) from exc
    except OSError as exc:
        raise DeviceConnectionError(device.name, str(exc)) from exc


class MikrotikClient:
    """Wraps a single device's RouterOS API connection.

    Connections are made lazily on first use and cached for the client's
    lifetime. A connection (real or fake) can also be injected directly,
    which is how tests avoid ever calling librouteros.connect().
    """

    def __init__(self, device: Device, connection: RouterosConnection | None = None):
        self.device = device
        self._connection = connection

    def _conn(self) -> RouterosConnection:
        if self._connection is None:
            self._connection = _connect(self.device)
        return self._connection

    def path(self, *segments: str) -> list[dict[str, Any]]:
        """Read all rows at an API path (e.g. path("ip", "address"))."""
        try:
            return [dict(row) for row in self._conn().path(*segments)]
        except (LibRouterosError, OSError) as exc:
            raise DeviceCommandError(self.device.name, "/".join(segments), str(exc)) from exc

    def ping(self, address: str, count: int = 4) -> list[dict[str, Any]]:
        """Run /ping from the device. `address` is expected to already be validated
        (see validation.validate_ping_address) - this method just forwards it as a
        structured parameter, never as part of a command string."""
        try:
            replies = self._conn()("/ping", address=address, count=str(count))
            return [dict(reply) for reply in replies]
        except (LibRouterosError, OSError) as exc:
            raise DeviceCommandError(self.device.name, "ping", str(exc)) from exc

    # --- Write primitives -------------------------------------------------
    # These are intentionally NOT exposed as MCP tools directly. The only
    # caller allowed to invoke them is guard.py, which maps each write
    # operation to one fixed path via its ALLOWLIST. Do not call these from
    # server.py directly - go through guard.py so every write stays subject
    # to the read-only gate, the allowlist, and the confirm/preview flow.

    def update(self, *segments: str, **fields: Any) -> None:
        try:
            self._conn().path(*segments).update(**fields)
        except (LibRouterosError, OSError) as exc:
            raise DeviceCommandError(self.device.name, "/".join(segments), str(exc)) from exc

    def add(self, *segments: str, **fields: Any) -> Any:
        try:
            return self._conn().path(*segments).add(**fields)
        except (LibRouterosError, OSError) as exc:
            raise DeviceCommandError(self.device.name, "/".join(segments), str(exc)) from exc

    def remove(self, *segments: str, ids: tuple[str, ...]) -> None:
        try:
            self._conn().path(*segments).remove(*ids)
        except (LibRouterosError, OSError) as exc:
            raise DeviceCommandError(self.device.name, "/".join(segments), str(exc)) from exc

    def close(self) -> None:
        if self._connection is not None:
            try:
                self._connection.close()
            except Exception:
                pass
            self._connection = None


def get_client(settings: Settings, device_name: str) -> MikrotikClient:
    """Default client factory: resolves a configured device and wraps it.

    Raises DeviceNotFoundError (via Settings.get_device) if the name is
    unknown or the device is marked disabled in devices.yaml.
    """
    device = settings.get_device(device_name)
    return MikrotikClient(device)


ClientFactory = Callable[[Settings, str], "MikrotikClient"]


class ClientPool:
    """Caches one MikrotikClient (and its underlying connection) per device name.

    N2+N3: without this, every MCP tool call - and every poll iteration once
    the planned collector exists (see TODO(collector) below) - opened a fresh
    TCP+login per call and never closed it. RouterOS enforces a limit on
    concurrent API sessions, so on a poller hitting ~14 devices every 60s
    that leaks sockets fast enough to wedge the whole fleet. A pool with a
    single deterministic close_all() (called from the server's shutdown
    hook, see server.py's lifespan) is simpler than a per-call
    connect/close: it keeps the "one connection per device, reused, closed
    once at shutdown" invariant in one place instead of scattering
    try/finally around every tool.

    Not thread-safe - callers (build_server()'s single asyncio task today,
    the planned collector's single poll loop later) must use one pool from
    one task at a time.
    """

    def __init__(self, settings: Settings, client_factory: ClientFactory = get_client):
        self._settings = settings
        self._factory = client_factory
        self._clients: dict[str, MikrotikClient] = {}

    def get(self, device_name: str) -> MikrotikClient:
        client = self._clients.get(device_name)
        if client is None:
            client = self._factory(self._settings, device_name)
            self._clients[device_name] = client
        return client

    def close_all(self) -> None:
        """Close every pooled connection and clear the cache. Idempotent."""
        for client in self._clients.values():
            client.close()
        self._clients.clear()


# TODO(collector): a second entrypoint (e.g. `mcp_mikrotik.collector`) is
# planned to periodically poll all configured devices and push metrics to
# Firebase. It should reuse MikrotikClient/get_client/ClientPool exactly as
# the MCP tools do, rather than opening its own librouteros connections. Not
# implemented in this v0.
