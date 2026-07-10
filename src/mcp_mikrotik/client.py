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

import ssl
from functools import partial
from typing import Any, Iterable, Protocol

import librouteros
from librouteros.exceptions import LibRouterosError

from .config import Device, Settings
from .exceptions import DeviceCommandError, DeviceConnectionError

DEFAULT_TIMEOUT = 10


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


def _connect(device: Device) -> RouterosConnection:
    kwargs: dict[str, Any] = {
        "username": device.username,
        "password": device.password,
        "host": device.host,
        "port": device.port,
        "timeout": DEFAULT_TIMEOUT,
    }
    if device.use_ssl:
        context = ssl.create_default_context()
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
        except LibRouterosError as exc:
            raise DeviceCommandError(self.device.name, "/".join(segments), str(exc)) from exc

    def ping(self, address: str, count: int = 4) -> list[dict[str, Any]]:
        """Run /ping from the device. `address` is expected to already be validated
        (see validation.validate_ping_address) - this method just forwards it as a
        structured parameter, never as part of a command string."""
        try:
            replies = self._conn()("/ping", address=address, count=str(count))
            return [dict(reply) for reply in replies]
        except LibRouterosError as exc:
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
        except LibRouterosError as exc:
            raise DeviceCommandError(self.device.name, "/".join(segments), str(exc)) from exc

    def add(self, *segments: str, **fields: Any) -> Any:
        try:
            return self._conn().path(*segments).add(**fields)
        except LibRouterosError as exc:
            raise DeviceCommandError(self.device.name, "/".join(segments), str(exc)) from exc

    def remove(self, *segments: str, ids: tuple[str, ...]) -> None:
        try:
            self._conn().path(*segments).remove(*ids)
        except LibRouterosError as exc:
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


# TODO(collector): a second entrypoint (e.g. `mcp_mikrotik.collector`) is
# planned to periodically poll all configured devices and push metrics to
# Firebase. It should reuse MikrotikClient/get_client exactly as the MCP
# tools do, rather than opening its own librouteros connections. Not
# implemented in this v0.
