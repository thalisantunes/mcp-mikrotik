"""In-memory fake RouterOS connection used by tests instead of a real device.

Mirrors the shape MikrotikClient depends on (see client.RouterosConnection):
`.path(*segments)` returns an iterable that also supports add/update/remove,
`__call__(cmd, **kwargs)` runs a one-off command (used for ping), and
`.close()` tears the connection down. This is what real librouteros.Api/Path
objects look like - see client.py's module docstring.
"""

from __future__ import annotations

from typing import Any, Callable

from librouteros.exceptions import LibRouterosError


# v0.13: real RouterOS generates a WireGuard interface's private/public key
# pair itself on `/interface/wireguard add` - a caller never supplies (or
# gets back from add()) a private key. Simulated here, keyed by path
# segments, so tests can prove guard.add_wireguard_interface's redaction
# (see guard._redact_wireguard_row) actually strips a private-key that a
# real device would otherwise hand back on the very next read - without this,
# a fake add() that only echoes back the fields it was given would never
# produce a private-key for the redaction to strip in the first place, and
# the leak test would be vacuous.
_WIREGUARD_INTERFACE_PATH = ("interface", "wireguard")
FAKE_WIREGUARD_PRIVATE_KEY_MARKER = "FAKE-PRIVATE-KEY-MUST-NEVER-LEAK-mZ9k1q2r3s4t5u6v7w8x9y0z1A2B3C4D5E="
FAKE_WIREGUARD_PUBLIC_KEY_MARKER = "FAKE-PUBLIC-KEY-OK-TO-SHOW-1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8="


class FakePath:
    def __init__(self, rows: list[dict[str, Any]], segments: tuple[str, ...] = ()):
        self._rows = rows
        self._segments = segments

    def __iter__(self):
        return iter(self._rows)

    def update(self, **fields: Any) -> None:
        """Mirror librouteros' Path.update(): a `set` with the given fields.

        A `.id` field (present for multi-row menus like /interface, where a
        write must target one specific row among several) selects which row
        gets updated; no match raises, like a real device would for an
        unknown id. Single-row menus (e.g. /system/identity) never send a
        `.id`, so that case keeps the original "just update row 0" behaviour.
        """
        row_id = fields.get(".id")
        if row_id is not None:
            for row in self._rows:
                if row.get(".id") == row_id:
                    row.update(fields)
                    return
            raise LibRouterosError(f"no such item (id={row_id!r})")
        if self._rows:
            self._rows[0].update(fields)
        else:
            self._rows.append(dict(fields))

    def add(self, **fields: Any) -> str:
        row = dict(fields)
        if self._segments == _WIREGUARD_INTERFACE_PATH:
            # See module note above: mirror RouterOS generating a WireGuard
            # interface's key pair server-side, so a private-key genuinely
            # exists on this row for guard.add_wireguard_interface's
            # redaction to have to strip.
            row.setdefault("private-key", FAKE_WIREGUARD_PRIVATE_KEY_MARKER)
            row.setdefault("public-key", FAKE_WIREGUARD_PUBLIC_KEY_MARKER)
            row.setdefault("running", "true")
            row.setdefault("disabled", "false")
        self._rows.append(row)
        return str(len(self._rows))

    def remove(self, *ids: str) -> None:
        self._rows[:] = [row for row in self._rows if row.get(".id") not in ids]

    def __call__(self, cmd: str, **kwargs: Any) -> list[dict[str, Any]]:
        """Mirror librouteros' Path.__call__, used for RouterOS ACTION
        commands like /container/start and /container/stop (see
        client.MikrotikClient.start/.stop) - as opposed to the
        print/set/add/remove verbs the other methods on this class model.

        `.id` selects which row the action targets, same convention as
        update() above; no match raises, like a real device would for an
        unknown id. Mutates a `status` field on the matching row so tests can
        observe the transition, exactly like update() mutates whichever
        field was set.
        """
        row_id = kwargs.get(".id")
        for row in self._rows:
            if row.get(".id") == row_id:
                if cmd == "start":
                    row["status"] = "running"
                elif cmd == "stop":
                    row["status"] = "stopped"
                return []
        raise LibRouterosError(f"no such item (id={row_id!r})")


def _once_reply_stream(reply: dict[str, Any] | None):
    """Mirror librouteros' actual return type for a `once=` monitor-style
    command (/interface/monitor-traffic, /interface/ethernet/poe/monitor,
    /interface/lte/monitor): a GENERATOR, not a list - always truthy (even
    when it yields nothing) and never subscriptable. Real hardware exposed a
    bug where client.py did `replies[0] if replies else {}` directly on this
    - `list` here would have made the fakes lie about that. Callers
    (client.py's monitor_traffic/poe_monitor/lte_monitor) must call
    list(...) on the result before subscripting it, exactly like ping/
    traceroute already do."""
    if reply is not None:
        yield dict(reply)


def _multi_reply_stream(rows: list[dict[str, Any]]):
    """Same generator-not-list shape as `_once_reply_stream`, but for a
    `once=` command that can genuinely reply with MORE than one row -
    v0.14's `/tool/torch` (a live traffic snapshot: one row per flow), as
    opposed to monitor_traffic/poe_monitor/lte_monitor's single-row replies.
    Callers (client.py's `torch`) must call list(...) on the result before
    inspecting it, same v0.7.1 lesson as `_once_reply_stream`."""
    for row in rows:
        yield dict(row)


class FakeConnection:
    """Stand-in for a connected librouteros.Api, entirely in memory."""

    def __init__(
        self,
        data: dict[tuple[str, ...], list[dict[str, Any]]] | None = None,
        ping_replies: list[dict[str, Any]] | None = None,
        traceroute_replies: list[dict[str, Any]] | None = None,
        monitor_traffic_replies: dict[str, dict[str, Any]] | None = None,
        poe_monitor_replies: dict[str, dict[str, Any]] | None = None,
        lte_monitor_replies: dict[str, dict[str, Any]] | None = None,
        torch_replies: dict[str, list[dict[str, Any]]] | None = None,
        on_call: Callable[[str, dict[str, Any]], None] | None = None,
        raise_for: dict[tuple[str, ...], Exception] | None = None,
    ):
        self._data: dict[tuple[str, ...], list[dict[str, Any]]] = dict(data or {})
        self._ping_replies = ping_replies if ping_replies is not None else []
        self._traceroute_replies = traceroute_replies if traceroute_replies is not None else []
        # Keyed by interface name (the "interface" kwarg each command is
        # called with) rather than a flat list, since v0.6's monitor-once
        # commands (interface_traffic, poe_status) are always scoped to one
        # named interface - this lets a test give different fake readings to
        # different ports in the same fake device. v0.7's lte_status reuses
        # the same shape/convention (see client.MikrotikClient.lte_monitor).
        self._monitor_traffic_replies: dict[str, dict[str, Any]] = dict(monitor_traffic_replies or {})
        self._poe_monitor_replies: dict[str, dict[str, Any]] = dict(poe_monitor_replies or {})
        self._lte_monitor_replies: dict[str, dict[str, Any]] = dict(lte_monitor_replies or {})
        # v0.14: keyed by interface name like the three above, but each value
        # is a LIST of flow rows (a torch snapshot can genuinely report many
        # flows for one interface) rather than a single dict.
        self._torch_replies: dict[str, list[dict[str, Any]]] = dict(torch_replies or {})
        self._on_call = on_call
        # Simulates a RouterOS menu that doesn't exist on this device/version
        # (e.g. /interface/wifi on a ROS6-only box, or /system/health on a
        # board with no sensors): path() raises the given exception instead
        # of returning an (empty) FakePath, like a real trap error would.
        self._raise_for: dict[tuple[str, ...], Exception] = dict(raise_for or {})
        self.closed = False
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def path(self, *segments: str) -> FakePath:
        key = tuple(segments)
        if key in self._raise_for:
            raise self._raise_for[key]
        rows = self._data.setdefault(key, [])
        return FakePath(rows, key)

    def __call__(self, cmd: str, **kwargs: Any):
        self.calls.append((cmd, kwargs))
        if self._on_call:
            self._on_call(cmd, kwargs)
        if cmd == "/ping":
            return list(self._ping_replies)
        if cmd == "/tool/traceroute":
            return list(self._traceroute_replies)
        if cmd == "/interface/monitor-traffic":
            return _once_reply_stream(self._monitor_traffic_replies.get(kwargs.get("interface")))
        if cmd == "/interface/ethernet/poe/monitor":
            return _once_reply_stream(self._poe_monitor_replies.get(kwargs.get("interface")))
        if cmd == "/interface/lte/monitor":
            return _once_reply_stream(self._lte_monitor_replies.get(kwargs.get("interface")))
        if cmd == "/tool/torch":
            return _multi_reply_stream(self._torch_replies.get(kwargs.get("interface"), []))
        if cmd == "/system/backup/save":
            # v0.14: MikrotikClient.save() - a fire-and-forget ACTION command
            # with no meaningful reply, same empty-generator shape as the DNS
            # cache flush/WoL below (client.py's create_backup deliberately
            # never re-reads the created file - see guard.create_backup's
            # docstring).
            return _once_reply_stream(None)
        if cmd == "/ip/dns/cache/flush":
            # v0.10: MikrotikClient.flush() - a fire-and-forget ACTION
            # command with no meaningful reply. Reuses _once_reply_stream(None)
            # (yields nothing but is still a real generator, not a list) so a
            # regression to unmaterialized `replies[0]`-style indexing in
            # client.py would fail the suite, exactly like the v0.7.1 lesson
            # for monitor_traffic/poe_monitor/lte_monitor above.
            return _once_reply_stream(None)
        if cmd == "/tool/wol":
            # v0.10: MikrotikClient.wol() - same empty-generator reply shape
            # as the DNS cache flush above.
            return _once_reply_stream(None)
        return []

    def close(self) -> None:
        self.closed = True


class RaisingConnection:
    """Fake connection that raises on any use - for testing that disabled/blocked
    paths never touch the device at all."""

    def path(self, *segments: str):
        raise AssertionError(f"path{segments} should not have been called")

    def __call__(self, cmd: str, **kwargs: Any):
        raise AssertionError(f"call({cmd!r}) should not have been called")

    def close(self) -> None:
        pass


class FlakyConnection:
    """Fake connection whose `.path()`/`__call__` raise a given exception for
    the first `fail_times` invocations, then behave like a normal
    FakeConnection - used to exercise MikrotikClient's read-retry (see
    client.py's MikrotikClient._run_read)."""

    def __init__(
        self,
        exc: Exception,
        fail_times: int,
        data: dict[tuple[str, ...], list[dict[str, Any]]] | None = None,
        ping_replies: list[dict[str, Any]] | None = None,
        traceroute_replies: list[dict[str, Any]] | None = None,
    ):
        self._exc = exc
        self._fail_times = fail_times
        self.calls_made = 0
        self._inner = FakeConnection(data=data, ping_replies=ping_replies, traceroute_replies=traceroute_replies)
        self.closed = False

    def path(self, *segments: str) -> FakePath:
        self.calls_made += 1
        if self.calls_made <= self._fail_times:
            raise self._exc
        return self._inner.path(*segments)

    def __call__(self, cmd: str, **kwargs: Any):
        self.calls_made += 1
        if self.calls_made <= self._fail_times:
            raise self._exc
        return self._inner(cmd, **kwargs)

    def close(self) -> None:
        self.closed = True
        self._inner.close()


class TransportErrorConnection:
    """Fake connection whose every operation raises a given exception.

    Used to verify MikrotikClient wraps transport-layer failures (a mid-call
    OSError from a dropped link, or a LibRouterosError) into
    DeviceCommandError instead of letting them escape raw or get reported as
    an opaque "Internal error" with no device context - see N1.
    """

    def __init__(self, exc: Exception):
        self._exc = exc

    def path(self, *segments: str):
        raise self._exc

    def __call__(self, cmd: str, **kwargs: Any):
        raise self._exc

    def close(self) -> None:
        pass
