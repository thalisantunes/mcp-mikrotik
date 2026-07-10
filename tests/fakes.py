"""In-memory fake RouterOS connection used by tests instead of a real device.

Mirrors the shape MikrotikClient depends on (see client.RouterosConnection):
`.path(*segments)` returns an iterable that also supports add/update/remove,
`__call__(cmd, **kwargs)` runs a one-off command (used for ping), and
`.close()` tears the connection down. This is what real librouteros.Api/Path
objects look like - see client.py's module docstring.
"""

from __future__ import annotations

from typing import Any, Callable


class FakePath:
    def __init__(self, rows: list[dict[str, Any]]):
        self._rows = rows

    def __iter__(self):
        return iter(self._rows)

    def update(self, **fields: Any) -> None:
        if self._rows:
            self._rows[0].update(fields)
        else:
            self._rows.append(dict(fields))

    def add(self, **fields: Any) -> str:
        self._rows.append(dict(fields))
        return str(len(self._rows))

    def remove(self, *ids: str) -> None:
        self._rows[:] = [row for row in self._rows if row.get(".id") not in ids]


class FakeConnection:
    """Stand-in for a connected librouteros.Api, entirely in memory."""

    def __init__(
        self,
        data: dict[tuple[str, ...], list[dict[str, Any]]] | None = None,
        ping_replies: list[dict[str, Any]] | None = None,
        on_call: Callable[[str, dict[str, Any]], None] | None = None,
    ):
        self._data: dict[tuple[str, ...], list[dict[str, Any]]] = dict(data or {})
        self._ping_replies = ping_replies if ping_replies is not None else []
        self._on_call = on_call
        self.closed = False
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def path(self, *segments: str) -> FakePath:
        key = tuple(segments)
        rows = self._data.setdefault(key, [])
        return FakePath(rows)

    def __call__(self, cmd: str, **kwargs: Any):
        self.calls.append((cmd, kwargs))
        if self._on_call:
            self._on_call(cmd, kwargs)
        if cmd == "/ping":
            return list(self._ping_replies)
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
