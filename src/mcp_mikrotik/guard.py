"""Central write-guard: allowlist of write operations + read-only gate + confirm mechanics.

This module is the ONLY place in mcp-mikrotik allowed to call
MikrotikClient.update()/add()/remove(). server.py never calls those methods
directly - a write tool in server.py always calls a dedicated function here
(e.g. set_identity below), so there is no code path through which an LLM (or
any tool caller) can reach an arbitrary API path. Every writable operation is
represented by exactly one WriteOperation entry in ALLOWLIST, naming the
single path+action it is allowed to touch.

Two independent controls apply to every write:
  1. Read-only gate: MIKROTIK_ALLOW_WRITE must be true (Settings.allow_write),
     checked before anything is read or written, regardless of `confirm`.
  2. Confirm/preview: with confirm=False, the operation computes and returns
     a before/after preview without calling the device's write primitive at
     all. Only confirm=True applies the change.

To add a new write tool in a future iteration:
  1. Add a WriteOperation entry to ALLOWLIST below (path tuple + action).
  2. Add a function here (following the shape of set_identity) that builds
     the before/after preview and, when confirm=True, applies it via the
     matching MikrotikClient primitive.
  3. Register a corresponding @mcp.tool() in server.py that calls it and
     passes `confirm` straight through.
Never add a generic "run this path with this action" entry or function -
each write operation must stay individually named and reviewable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .client import MikrotikClient
from .config import Settings
from .exceptions import GuardViolationError, WriteDisabledError


@dataclass(frozen=True)
class WriteOperation:
    name: str
    path: tuple[str, ...]
    action: str  # "update" | "add" | "remove"
    description: str


ALLOWLIST: dict[str, WriteOperation] = {
    "set_identity": WriteOperation(
        name="set_identity",
        path=("system", "identity"),
        action="update",
        description="Set the RouterOS device identity (hostname shown in WinBox/CLI).",
    ),
    # --- Next iteration adds entries here (e.g. wifi, interface enable/disable),
    # each with its own WriteOperation + dedicated function. See module
    # docstring above for the steps.
}


@dataclass(frozen=True)
class WritePreview:
    """Result of a guarded write call: the change it would make (or made)."""

    operation: str
    device: str
    before: dict[str, Any]
    after: dict[str, Any]
    applied: bool


def _require_allowed(settings: Settings, operation_name: str) -> WriteOperation:
    op = ALLOWLIST.get(operation_name)
    if op is None:
        # Defensive only - see module docstring. Every write tool references a
        # fixed ALLOWLIST key, so this should be unreachable in normal use.
        raise GuardViolationError(operation_name)
    if not settings.allow_write:
        raise WriteDisabledError(operation_name)
    return op


def set_identity(client: MikrotikClient, settings: Settings, new_name: str, confirm: bool) -> WritePreview:
    """The v0 exemplary write tool.

    Exercises the full guard mechanism: allowlist lookup, read-only gate,
    confirm/preview, and before/after reporting. Every future write tool
    should follow this same shape.
    """
    op = _require_allowed(settings, "set_identity")

    before_rows = client.path(*op.path)
    before = dict(before_rows[0]) if before_rows else {}
    after = dict(before)
    after["name"] = new_name

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    # A1: dispatch via op.action instead of hardcoding client.update(...), so
    # ALLOWLIST["set_identity"].action actually governs which MikrotikClient
    # primitive is called - if a future edit points this entry at "add" or
    # "remove" instead, this call follows it rather than silently staying on
    # .update(). set_identity itself is (and will stay) an update, so this is
    # a no-op behaviourally today; it only matters for the allowlist's
    # integrity as more operations are added.
    write = getattr(client, op.action)
    write(*op.path, name=new_name)
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)
