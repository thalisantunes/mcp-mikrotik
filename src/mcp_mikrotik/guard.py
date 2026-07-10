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
from .exceptions import DeviceCommandError, GuardViolationError, ResourceNotFoundError, WriteDisabledError


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
    "enable_interface": WriteOperation(
        name="enable_interface",
        path=("interface",),
        action="update",
        description="Enable a network interface by name (sets disabled=no).",
    ),
    "disable_interface": WriteOperation(
        name="disable_interface",
        path=("interface",),
        action="update",
        description="Disable a network interface by name (sets disabled=yes).",
    ),
    # set_wifi_ssid is exposed as ONE server.py tool, but a device may speak
    # either of these two RouterOS generations - see set_wifi_ssid() below,
    # which detects which one the target interface actually lives under and
    # dispatches through that (and only that) allowlisted operation. Both
    # entries stay individually named/reviewable; nothing here accepts an
    # arbitrary path.
    "set_wifi_ssid_ros7": WriteOperation(
        name="set_wifi_ssid_ros7",
        path=("interface", "wifi"),
        action="update",
        description="Set the SSID of a ROS7 wifi-package interface (/interface/wifi).",
    ),
    "set_wifi_ssid_ros6": WriteOperation(
        name="set_wifi_ssid_ros6",
        path=("interface", "wireless"),
        action="update",
        description="Set the SSID of a ROS6 wireless-package interface (/interface/wireless).",
    ),
    # --- Deliberately NOT added yet - each needs extra policy beyond the
    # standard guard before it would be safe to expose:
    #   * reboot ("system/reboot"): no before/after preview is meaningful for
    #     a reboot, and a bad batch reboot across a fleet has no dry-run or
    #     rollback. Needs its own confirmation/cooldown policy first.
    #   * firewall filter writes ("ip/firewall/filter"): a single wrong rule
    #     (e.g. an add/update that blocks the API port itself) can lock out
    #     all management access to the device with no remote recovery. Needs
    #     staged/rollback support (e.g. RouterOS safe mode) before it belongs
    #     in this allowlist.
    # --- Next iteration adds entries here, each with its own WriteOperation
    # + dedicated function. See module docstring above for the steps.
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


def _find_row_by_field(rows: list[dict[str, Any]], field: str, value: str) -> dict[str, Any] | None:
    """First row whose `field` equals `value`, or None. Used to resolve a
    caller-supplied name (interface, wifi/wireless network, ...) to the
    specific RouterOS row a write must target, without ever letting the
    caller supply a raw `.id` or path directly."""
    for row in rows:
        if row.get(field) == value:
            return row
    return None


def _set_interface_disabled(
    client: MikrotikClient,
    settings: Settings,
    operation_name: str,
    interface_name: str,
    disabled: bool,
    confirm: bool,
) -> WritePreview:
    """Shared implementation behind enable_interface/disable_interface.

    Both are the same RouterOS operation (set /interface disabled=yes|no by
    name) with only the target value flipped, so they share this body while
    staying two distinct, individually named ALLOWLIST entries/tools.
    """
    op = _require_allowed(settings, operation_name)

    rows = client.path(*op.path)
    row = _find_row_by_field(rows, "name", interface_name)
    if row is None:
        # Never create an interface - a name that doesn't exist is an error,
        # not an implicit "add".
        raise ResourceNotFoundError(client.device.name, "Interface", interface_name)

    before = dict(row)
    after = dict(row)
    after["disabled"] = "yes" if disabled else "no"

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    write(*op.path, **{".id": row.get(".id"), "disabled": after["disabled"]})
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)


def enable_interface(client: MikrotikClient, settings: Settings, interface_name: str, confirm: bool) -> WritePreview:
    """Enable a network interface by name (sets disabled=no). Errors if the
    interface name doesn't exist on the device; never creates one."""
    return _set_interface_disabled(
        client, settings, "enable_interface", interface_name, disabled=False, confirm=confirm
    )


def disable_interface(client: MikrotikClient, settings: Settings, interface_name: str, confirm: bool) -> WritePreview:
    """Disable a network interface by name (sets disabled=yes). Errors if the
    interface name doesn't exist on the device; never creates one."""
    return _set_interface_disabled(
        client, settings, "disable_interface", interface_name, disabled=True, confirm=confirm
    )


def set_wifi_ssid(
    client: MikrotikClient, settings: Settings, interface_name: str, new_ssid: str, confirm: bool
) -> WritePreview:
    """Set a wireless interface's SSID, on either RouterOS generation.

    The read-only gate is identical for both candidate operations, so it is
    checked once up front (anchored on the ROS7 entry purely to reuse
    _require_allowed's ALLOWLIST/gate check) before anything is read from the
    device, exactly like every other guarded write.

    Which underlying path is actually touched is then decided by looking for
    `interface_name` first under /interface/wifi (ROS7), then under
    /interface/wireless (ROS6) - mirroring server.py's wireless_registrations
    read tool's own ROS7-then-ROS6 fallback. A device that doesn't have a
    given package installed at all raises DeviceCommandError from
    client.path(); that is treated the same as "not found here" and the next
    candidate is tried, so a non-wifi device or a ROS6-only device never
    produces a confusing transport error - only a clear "not found" once both
    candidates are exhausted, or a WritePreview from whichever one matched.
    """
    _require_allowed(settings, "set_wifi_ssid_ros7")

    op = None
    row = None
    for operation_name in ("set_wifi_ssid_ros7", "set_wifi_ssid_ros6"):
        candidate_op = ALLOWLIST[operation_name]
        try:
            candidate_rows = client.path(*candidate_op.path)
        except DeviceCommandError:
            continue
        candidate_row = _find_row_by_field(candidate_rows, "name", interface_name)
        if candidate_row is not None:
            op, row = candidate_op, candidate_row
            break

    if row is None or op is None:
        raise ResourceNotFoundError(client.device.name, "Wireless interface", interface_name)

    before = dict(row)
    after = dict(row)
    after["ssid"] = new_ssid

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    write(*op.path, **{".id": row.get(".id"), "ssid": new_ssid})
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)
