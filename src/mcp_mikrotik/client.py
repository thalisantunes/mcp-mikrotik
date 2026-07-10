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
import threading
import time
from functools import partial
from typing import Any, Callable, Iterable, Protocol, TypeVar

import librouteros
from librouteros.exceptions import LibRouterosError

from .config import Device, Settings
from .exceptions import CircuitOpenError, DeviceCommandError, DeviceConnectionError

DEFAULT_TIMEOUT = 10.0

T = TypeVar("T")

# --- Read retry (robustness on slow/flaky links) ---------------------------
#
# Applies only to read primitives (path/ping/traceroute - see
# MikrotikClient._run_read). Writes (update/add/remove) never retry:
# idempotency isn't guaranteed for an add/update/remove, so a retried write
# could duplicate or reapply a change - see MikrotikClient._execute_once,
# used by writes with no retry loop around it at all.

DEFAULT_READ_RETRIES = 2
# Backoff before the 1st and 2nd retry; a MIKROTIK_READ_RETRIES value beyond
# len(_READ_RETRY_DELAYS) reuses the last delay rather than growing further.
_READ_RETRY_DELAYS: tuple[float, ...] = (0.5, 1.0)


def _read_retries() -> int:
    raw = os.environ.get("MIKROTIK_READ_RETRIES")
    if raw is None:
        return DEFAULT_READ_RETRIES
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_READ_RETRIES
    return max(0, value)


def _read_retry_delay(attempt: int) -> float:
    if attempt < len(_READ_RETRY_DELAYS):
        return _READ_RETRY_DELAYS[attempt]
    return _READ_RETRY_DELAYS[-1]


# --- Circuit breaker (fail fast against a known-dead device) ---------------

DEFAULT_BREAKER_THRESHOLD = 3
DEFAULT_BREAKER_COOLDOWN = 30.0


def _breaker_threshold() -> int:
    raw = os.environ.get("MIKROTIK_BREAKER_THRESHOLD")
    if raw is None:
        return DEFAULT_BREAKER_THRESHOLD
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_BREAKER_THRESHOLD
    return value if value > 0 else DEFAULT_BREAKER_THRESHOLD


def _breaker_cooldown() -> float:
    raw = os.environ.get("MIKROTIK_BREAKER_COOLDOWN")
    if raw is None:
        return DEFAULT_BREAKER_COOLDOWN
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_BREAKER_COOLDOWN
    # 0 is a legitimate (if unusual) value - "always half-open, retry on the
    # very next call" - only a negative or unparseable value is rejected.
    return value if value >= 0 else DEFAULT_BREAKER_COOLDOWN


class CircuitBreaker:
    """Circuit breaker guarding one device's connection attempts.

    One instance lives on each MikrotikClient (`self._breaker`), scoped to
    that single device - ClientPool caches one MikrotikClient per
    device_name for the life of the server, so this instance's lifetime
    naturally gives one breaker per device_name, with no separate keyed
    registry needed.

    After MIKROTIK_BREAKER_THRESHOLD consecutive connection failures
    (record_failure()), the circuit opens: before_connect() raises
    CircuitOpenError immediately - no socket is attempted - until
    MIKROTIK_BREAKER_COOLDOWN seconds have passed. A single success
    (record_success()) at any point resets the failure count and closes the
    circuit.

    Thread-safe via an internal lock: ClientPool/the MCP server may have
    more than one tool call for the same device in flight concurrently.
    """

    def __init__(self, device_name: str, threshold: int | None = None, cooldown: float | None = None):
        self._device_name = device_name
        self._threshold_override = threshold
        self._cooldown_override = cooldown
        self._lock = threading.Lock()
        self._consecutive_failures = 0
        self._opened_at: float | None = None

    def _threshold(self) -> int:
        return self._threshold_override if self._threshold_override is not None else _breaker_threshold()

    def _cooldown(self) -> float:
        return self._cooldown_override if self._cooldown_override is not None else _breaker_cooldown()

    def before_connect(self) -> None:
        """Raise CircuitOpenError if the circuit is open and still within
        its cooldown window. Called only from MikrotikClient._connect_guarded,
        which itself is only ever reached AFTER guard.py's read-only
        gate/allowlist check for any write - see that module's docstring -
        so this can never be used to skip the guard, only to fail fast once
        the guard has already allowed the call through."""
        with self._lock:
            if self._opened_at is None:
                return
            elapsed = time.time() - self._opened_at
            cooldown = self._cooldown()
            if elapsed < cooldown:
                raise CircuitOpenError(self._device_name, cooldown - elapsed)
            # Cooldown elapsed: let exactly one trial connection through
            # (half-open). record_success()/record_failure() below decides
            # whether the circuit stays closed or re-opens.
            self._opened_at = None

    def record_success(self) -> None:
        with self._lock:
            self._consecutive_failures = 0
            self._opened_at = None

    def record_failure(self) -> None:
        with self._lock:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self._threshold():
                self._opened_at = time.time()

    @property
    def is_open(self) -> bool:
        with self._lock:
            return self._opened_at is not None


class RouterosConnection(Protocol):
    """Shape of a connected RouterOS API session that MikrotikClient needs."""

    def path(self, *path: str) -> Iterable[dict[str, Any]]:
        """Return an object that, when iterated, yields rows (dicts) and that
        also supports .add(**fields) / .update(**fields) / .remove(*ids), plus
        the callable action-command form used by MikrotikClient.start/.stop
        (e.g. `path("container")("start", **{".id": id})`, mirroring
        librouteros' own Path.__call__)."""
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
        self._breaker = CircuitBreaker(device.name)

    def _connect_guarded(self) -> RouterosConnection:
        """Return the cached connection, or establish one - honoring the
        circuit breaker (CircuitOpenError if it's currently open; no socket
        attempted). Every read/write primitive below goes through this
        (directly, or via _execute_once/_run_read) instead of ever calling
        _connect() itself, so breaker accounting stays centralized here."""
        if self._connection is not None:
            return self._connection
        self._breaker.before_connect()
        try:
            self._connection = _connect(self.device)
        except DeviceConnectionError:
            self._breaker.record_failure()
            raise
        self._breaker.record_success()
        return self._connection

    def _execute_once(self, description: str, fn: Callable[[RouterosConnection], T]) -> T:
        """Run one command against the device exactly once: connect
        (breaker-checked - see _connect_guarded), invoke `fn`, and translate
        any transport failure into DeviceCommandError. No retry happens here
        - used directly by the write primitives (update/add/remove) for a
        single guaranteed-once attempt, and as the per-attempt body of
        _run_read's retry loop for reads.

        The circuit breaker only ever accounts for the CONNECT step
        (_connect_guarded), not for a failure of `fn` itself once connected
        - a rejected/failed command on an otherwise-live connection is a
        RouterOS/command-level problem, not "can't reach this device",
        which is what the breaker exists to fail fast on."""
        connection = self._connect_guarded()
        try:
            result = fn(connection)
        except (LibRouterosError, OSError) as exc:
            raise DeviceCommandError(self.device.name, description, str(exc)) from exc
        return result

    def _run_read(self, description: str, fn: Callable[[RouterosConnection], T]) -> T:
        """Run a read primitive (path/ping/traceroute) with automatic retry
        on transient network errors: up to MIKROTIK_READ_RETRIES extra
        attempts (default 2), with a short backoff (0.5s, then 1s; further
        retries reuse 1s), retrying `fn` against the SAME connection object
        (no reconnect attempt is forced - see _execute_once). Only retried
        when the failure looks transient - a fresh CircuitOpenError (breaker
        already deliberately failing fast) is never retried, a
        DeviceConnectionError from an actual failed connect attempt is
        always retried (each retry re-attempts the connect too, through the
        breaker), and a DeviceCommandError is retried only when its cause
        was an OSError (a dropped socket, a timeout) rather than a
        LibRouterosError (RouterOS itself rejected the command - retrying
        would just get rejected again).
        """
        retries = _read_retries()
        attempt = 0
        while True:
            try:
                return self._execute_once(description, fn)
            except CircuitOpenError:
                raise
            except DeviceConnectionError:
                if attempt >= retries:
                    raise
            except DeviceCommandError as exc:
                transient = isinstance(exc.__cause__, OSError)
                if not transient or attempt >= retries:
                    raise
            time.sleep(_read_retry_delay(attempt))
            attempt += 1

    def path(self, *segments: str) -> list[dict[str, Any]]:
        """Read all rows at an API path (e.g. path("ip", "address")). Retried
        automatically on a transient network error - see _run_read."""

        def _do(connection: RouterosConnection) -> list[dict[str, Any]]:
            return [dict(row) for row in connection.path(*segments)]

        return self._run_read("/".join(segments), _do)

    def ping(self, address: str, count: int = 4) -> list[dict[str, Any]]:
        """Run /ping from the device. `address` is expected to already be validated
        (see validation.validate_ping_address) - this method just forwards it as a
        structured parameter, never as part of a command string. Retried
        automatically on a transient network error - see _run_read."""

        def _do(connection: RouterosConnection) -> list[dict[str, Any]]:
            replies = connection("/ping", address=address, count=str(count))
            return [dict(reply) for reply in replies]

        return self._run_read("ping", _do)

    def traceroute(self, address: str, count: int = 1, max_hops: int = 10) -> list[dict[str, Any]]:
        """Run /tool/traceroute from the device. `address` is expected to already
        be validated (see validation.validate_ping_address), and `count`/`max_hops`
        already capped by the caller (see server.py's `traceroute` tool) - this
        method just forwards them as structured parameters, never as part of a
        command string.

        A fixed short per-hop `timeout` ("00:00:01") is always sent too, so the
        worst case (max_hops * count unanswered probes) stays comfortably under
        RouterOS's own ~60s API command timeout regardless of what the caller
        passed for count/max_hops. Retried automatically on a transient network
        error - see _run_read.
        """

        def _do(connection: RouterosConnection) -> list[dict[str, Any]]:
            replies = connection(
                "/tool/traceroute",
                address=address,
                count=str(count),
                **{"max-hops": str(max_hops), "timeout": "00:00:01"},
            )
            return [dict(reply) for reply in replies]

        return self._run_read("traceroute", _do)

    def monitor_traffic(self, interface: str) -> dict[str, Any]:
        """Run /interface/monitor-traffic once=yes for a single interface,
        returning one reply dict (rx-bits-per-second/tx-bits-per-second, and
        packet counters).

        `interface` is expected to already be validated (see
        validation.validate_interface_name) - forwarded as a structured
        parameter, never as part of a command string.

        `once=""` mirrors RouterOS's CLI `once=yes` flag (RouterOS API
        booleans/flags are sent as an empty value, not the string "yes" -
        same convention librouteros itself uses): the device answers with
        exactly one reply sentence and the command is done, instead of the
        continuous/streaming form monitor-traffic runs in when `once` is
        omitted entirely (which would keep the API session open waiting for
        further replies and never return). Combined with the connection's
        own timeout (see _resolve_timeout/_connect), this can't hang.
        Retried automatically on a transient network error - see _run_read.
        """

        def _do(connection: RouterosConnection) -> dict[str, Any]:
            replies = connection("/interface/monitor-traffic", interface=interface, once="")
            return dict(replies[0]) if replies else {}

        return self._run_read("interface/monitor-traffic", _do)

    def poe_monitor(self, interface: str) -> dict[str, Any]:
        """Run /interface/ethernet/poe/monitor once=yes for a single
        interface, returning one reply dict (poe-out-status, voltage,
        current, power fields - see server.py's `poe_status` tool for how
        these are mapped).

        Same "once" semantics as monitor_traffic above: `once=""` gets
        exactly one reply back instead of opening a continuous stream, so
        this returns promptly. `interface` is expected to already be
        validated. Retried automatically on a transient network error - see
        _run_read.
        """

        def _do(connection: RouterosConnection) -> dict[str, Any]:
            replies = connection("/interface/ethernet/poe/monitor", interface=interface, once="")
            return dict(replies[0]) if replies else {}

        return self._run_read("interface/ethernet/poe/monitor", _do)

    def lte_monitor(self, interface: str) -> dict[str, Any]:
        """Run /interface/lte/monitor once=yes for a single LTE interface,
        returning one reply dict (current-operator, access-technology,
        rsrp/rsrq/sinr/rssi, band, registration-status, cell-id - see
        server.py's `lte_status` tool for how these are surfaced).

        Same "once" construction and semantics as monitor_traffic/poe_monitor
        above, reused as instructed for this round: `once=""` gets exactly
        one reply back instead of opening a continuous stream, and
        `interface` is forwarded as a structured parameter (expected to
        already be validated by validation.validate_interface_name) rather
        than part of a command string. Retried automatically on a transient
        network error - see _run_read. A device with no LTE interface/package
        at all raises DeviceCommandError, same as any other unknown RouterOS
        menu - see server.py's `lte_status`, which treats that as "no LTE
        here" rather than a hard failure.
        """

        def _do(connection: RouterosConnection) -> dict[str, Any]:
            replies = connection("/interface/lte/monitor", interface=interface, once="")
            return dict(replies[0]) if replies else {}

        return self._run_read("interface/lte/monitor", _do)

    # --- Write primitives -------------------------------------------------
    # These are intentionally NOT exposed as MCP tools directly. The only
    # caller allowed to invoke them is guard.py, which maps each write
    # operation to one fixed path via its ALLOWLIST. Do not call these from
    # server.py directly - go through guard.py so every write stays subject
    # to the read-only gate, the allowlist, and the confirm/preview flow.
    #
    # No retry: idempotency isn't guaranteed for add/update/remove/start/stop,
    # so a retried write could duplicate or reapply a change. Each still goes
    # through the circuit breaker (via _execute_once/_connect_guarded), so a
    # write to a known-dead device still fails fast instead of hanging on a
    # connect attempt - the breaker only ever affects the connection step,
    # never whether the write itself is allowed (that's the read-only
    # gate/allowlist in guard.py, checked before this is ever reached).

    def update(self, *segments: str, **fields: Any) -> None:
        def _do(connection: RouterosConnection) -> None:
            connection.path(*segments).update(**fields)

        self._execute_once("/".join(segments), _do)

    def add(self, *segments: str, **fields: Any) -> Any:
        def _do(connection: RouterosConnection) -> Any:
            return connection.path(*segments).add(**fields)

        return self._execute_once("/".join(segments), _do)

    def remove(self, *segments: str, ids: tuple[str, ...]) -> None:
        def _do(connection: RouterosConnection) -> None:
            connection.path(*segments).remove(*ids)

        self._execute_once("/".join(segments), _do)

    # --- v0.7: action commands (start/stop) --------------------------------
    #
    # RouterOS's /container/start and /container/stop are ACTION commands,
    # not the update/add/remove trio above - the RouterOS console syntax is
    # `/container start <numbers>` / `/container stop <numbers>`, not a
    # `set`. There is no new generic "run any action" entrypoint here: each
    # of these two methods only ever sends the one fixed command word its
    # name says (`"start"`/`"stop"`), never a command supplied by the
    # caller - guard.py's ALLOWLIST is the only thing that decides which of
    # `start`/`stop` gets dispatched (via `getattr(client, op.action)`, same
    # as update/add/remove), and it only ever does so for the fixed
    # `("container",)` path, never an arbitrary one.
    #
    # `id` is forwarded as the structured `.id` parameter - the same
    # RouterOS API convention `remove()` above already relies on for
    # targeting one specific row by its `.id` (see librouteros' own
    # `Path.remove()`), not part of a command string. No retry, same
    # reasoning as update/add/remove.

    def start(self, *segments: str, id: str) -> None:
        def _do(connection: RouterosConnection) -> None:
            connection.path(*segments)("start", **{".id": id})

        self._execute_once("/".join(segments) + "/start", _do)

    def stop(self, *segments: str, id: str) -> None:
        def _do(connection: RouterosConnection) -> None:
            connection.path(*segments)("stop", **{".id": id})

        self._execute_once("/".join(segments) + "/stop", _do)

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
