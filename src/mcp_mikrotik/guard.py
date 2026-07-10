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

import functools
import re
from dataclasses import dataclass
from typing import Any, Callable

from . import audit
from .client import MikrotikClient
from .config import Settings
from .correlation import current as current_correlation_id
from .exceptions import (
    DeviceCommandError,
    GuardViolationError,
    ResourceAlreadyExistsError,
    ResourceNotFoundError,
    ValidationError,
    WriteDisabledError,
)
from .validation import (
    validate_address_list_name,
    validate_comment,
    validate_ip_address,
    validate_mac_address,
    validate_rate_pair,
    validate_target,
    validate_timeout,
)


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
    # set_client_bandwidth is exposed as ONE server.py tool, backed by two
    # fixed allowlist entries exactly like set_wifi_ssid above: whichever one
    # applies is decided by set_client_bandwidth() itself (does a Simple
    # Queue already target this `target`?), never by a path the caller
    # supplies directly.
    "set_client_bandwidth_update": WriteOperation(
        name="set_client_bandwidth_update",
        path=("queue", "simple"),
        action="update",
        description="Update an existing Simple Queue's max-limit/limit-at for a client target (bandwidth limit).",
    ),
    "set_client_bandwidth_add": WriteOperation(
        name="set_client_bandwidth_add",
        path=("queue", "simple"),
        action="add",
        description="Create a new Simple Queue to limit a client target's bandwidth (max-limit/limit-at).",
    ),
    "add_static_dhcp_lease": WriteOperation(
        name="add_static_dhcp_lease",
        path=("ip", "dhcp-server", "lease"),
        action="add",
        description="Create a static DHCP lease pinning an IP address to a MAC address.",
    ),
    "remove_simple_queue": WriteOperation(
        name="remove_simple_queue",
        path=("queue", "simple"),
        action="remove",
        description="Remove a Simple Queue by target or name (undoes a bandwidth limit).",
    ),
    "add_to_address_list": WriteOperation(
        name="add_to_address_list",
        path=("ip", "firewall", "address-list"),
        action="add",
        description="Add an IP/subnet to a named firewall address-list entry.",
    ),
    "remove_from_address_list": WriteOperation(
        name="remove_from_address_list",
        path=("ip", "firewall", "address-list"),
        action="remove",
        description="Remove an IP/subnet entry from a named firewall address-list.",
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


def _audited(anchor_operation: str) -> Callable[[Callable[..., WritePreview]], Callable[..., WritePreview]]:
    """Decorator applied to every public write function below (audit
    journal / v0.5).

    Ensures exactly one audit.record() call per invocation, regardless of
    how it ends:
      - Returns a WritePreview with applied=False -> outcome "preview".
      - Returns a WritePreview with applied=True  -> outcome "applied".
      - Raises anything -> outcome "error" (WriteDisabledError from the
        read-only gate, ValidationError, ResourceNotFoundError/
        ResourceAlreadyExistsError, a device-side DeviceCommandError - all
        of it, however early it happens).

    `anchor_operation` is the ALLOWLIST key to report as `operation`/`action`
    when nothing more specific is known yet - which matters for functions
    with dynamic dispatch (set_wifi_ssid, set_client_bandwidth: see their
    docstrings) that may fail before resolving which of their two candidate
    operations actually applies. Once the wrapped function returns a
    WritePreview, that WritePreview's own `.operation` is used instead - the
    more precise choice actually made.

    This is the ONLY place in the package that calls audit.record() -
    keeping every write's audit trail centralized here means a future write
    function only has to follow the existing `@_audited(...)` + `_require_allowed`
    shape to be covered automatically; it never has to remember to journal
    anything itself. Writing the journal never affects the call's own
    outcome: audit.record() is itself best-effort (see audit.py) and never
    raises.
    """

    def decorator(fn: Callable[..., WritePreview]) -> Callable[..., WritePreview]:
        @functools.wraps(fn)
        def inner(client: MikrotikClient, settings: Settings, *args: Any, confirm: bool, **kwargs: Any) -> WritePreview:
            correlation_id = current_correlation_id()
            try:
                result = fn(client, settings, *args, confirm=confirm, **kwargs)
            except Exception as exc:
                audit.record(
                    correlation_id=correlation_id,
                    device_name=client.device.name,
                    tool=fn.__name__,
                    operation=anchor_operation,
                    action=ALLOWLIST[anchor_operation].action,
                    confirm=confirm,
                    outcome="error",
                    summary={"error": str(exc)},
                )
                raise
            audit.record(
                correlation_id=correlation_id,
                device_name=result.device,
                tool=fn.__name__,
                operation=result.operation,
                action=ALLOWLIST[result.operation].action,
                confirm=confirm,
                outcome="applied" if result.applied else "preview",
                summary={"before": result.before, "after": result.after},
            )
            return result

        return inner

    return decorator


@_audited("set_identity")
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


@_audited("enable_interface")
def enable_interface(client: MikrotikClient, settings: Settings, interface_name: str, confirm: bool) -> WritePreview:
    """Enable a network interface by name (sets disabled=no). Errors if the
    interface name doesn't exist on the device; never creates one."""
    return _set_interface_disabled(
        client, settings, "enable_interface", interface_name, disabled=False, confirm=confirm
    )


@_audited("disable_interface")
def disable_interface(client: MikrotikClient, settings: Settings, interface_name: str, confirm: bool) -> WritePreview:
    """Disable a network interface by name (sets disabled=yes). Errors if the
    interface name doesn't exist on the device; never creates one."""
    return _set_interface_disabled(
        client, settings, "disable_interface", interface_name, disabled=True, confirm=confirm
    )


@_audited("set_wifi_ssid_ros7")
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


# --- v0.3: bandwidth control + IP reservation ------------------------------

_QUEUE_NAME_UNSAFE = re.compile(r"[^A-Za-z0-9]+")


def _queue_name_for_target(target: str) -> str:
    """Deterministic Simple Queue `name` derived from a validated `target`.

    RouterOS queue names can't sensibly contain "." or "/", so every
    non-alphanumeric run is collapsed to a single "-", e.g.
    "10.0.0.5" -> "limit-10-0-0-5", "10.0.0.0/24" -> "limit-10-0-0-0-24".
    Deterministic (not random) so calling set_client_bandwidth again for the
    same target reliably finds the queue it created last time via `target`
    matching in set_client_bandwidth itself - this is only used the first
    time a queue is created for a given target.
    """
    slug = _QUEUE_NAME_UNSAFE.sub("-", target).strip("-")
    return f"limit-{slug}"


@_audited("set_client_bandwidth_update")
def set_client_bandwidth(
    client: MikrotikClient,
    settings: Settings,
    target: str,
    max_limit: str,
    confirm: bool,
    limit_at: str | None = None,
) -> WritePreview:
    """Limit a client's bandwidth via a RouterOS Simple Queue (/queue/simple).

    If a Simple Queue already targets `target`, this UPDATES its max-limit
    (and limit-at, if given) - operation "set_client_bandwidth_update". If
    none exists yet, this CREATES one - operation "set_client_bandwidth_add"
    - with a name deterministically derived from `target` (see
    _queue_name_for_target). The returned WritePreview's `operation` field
    tells the caller which of the two happened (or would happen, with
    confirm=False), and `before`/`after` show the values either way (`before`
    is `{}` for a create, since nothing exists yet).

    `max_limit` and the optional `limit_at` are RouterOS rate pairs in
    "upload/download" form (e.g. "10M/5M") - see validate_rate_pair.

    GOTCHA - FastTrack: if the device has a FastTrack rule in its firewall
    (common on RouterOS's own quick-set wizards), fasttracked connections
    bypass queueing entirely, so a queue created/updated here may have no
    visible effect on a client whose traffic is already being fasttracked.
    See README's "Security model" section.
    """
    # Gate check + allowlist presence, anchored on the "_update" entry purely
    # to reuse _require_allowed - both _update and _add share the exact same
    # gate, mirroring set_wifi_ssid's ros7/ros6 anchoring above.
    _require_allowed(settings, "set_client_bandwidth_update")

    validated_target = validate_target(target)
    validated_max_limit = validate_rate_pair(max_limit, "max_limit")
    validated_limit_at = validate_rate_pair(limit_at, "limit_at") if limit_at is not None else None

    update_op = ALLOWLIST["set_client_bandwidth_update"]
    add_op = ALLOWLIST["set_client_bandwidth_add"]

    rows = client.path(*update_op.path)
    row = _find_row_by_field(rows, "target", validated_target)

    if row is not None:
        op = update_op
        before = dict(row)
        after = dict(row)
        after["max-limit"] = validated_max_limit
        if validated_limit_at is not None:
            after["limit-at"] = validated_limit_at

        if not confirm:
            return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

        fields: dict[str, Any] = {".id": row.get(".id"), "max-limit": validated_max_limit}
        if validated_limit_at is not None:
            fields["limit-at"] = validated_limit_at
        write = getattr(client, op.action)
        write(*op.path, **fields)
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)

    op = add_op
    payload: dict[str, Any] = {
        "name": _queue_name_for_target(validated_target),
        "target": validated_target,
        "max-limit": validated_max_limit,
    }
    if validated_limit_at is not None:
        payload["limit-at"] = validated_limit_at

    before = {}
    after = dict(payload)

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    write(*op.path, **payload)
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)


@_audited("add_static_dhcp_lease")
def add_static_dhcp_lease(
    client: MikrotikClient,
    settings: Settings,
    address: str,
    mac_address: str,
    confirm: bool,
    comment: str | None = None,
    server: str | None = None,
) -> WritePreview:
    """Create a static DHCP lease (/ip/dhcp-server/lease), pinning `address`
    to `mac_address`. Useful to give a client a stable, predictable IP -
    e.g. before limiting it with set_client_bandwidth, whose `target` is far
    more useful pinned to one address than following a client around a
    dynamic pool.

    Refuses to create a lease for a `mac_address` that already has one
    (static or dynamic) on the device - raises ResourceAlreadyExistsError
    instead of silently creating a duplicate. This tool only ever adds; it
    never updates or removes an existing lease.
    """
    op = _require_allowed(settings, "add_static_dhcp_lease")

    validated_address = validate_ip_address(address)
    validated_mac = validate_mac_address(mac_address)

    rows = client.path(*op.path)
    existing = _find_row_by_field(rows, "mac-address", validated_mac)
    if existing is not None:
        raise ResourceAlreadyExistsError(client.device.name, "DHCP lease", validated_mac)

    payload: dict[str, Any] = {"address": validated_address, "mac-address": validated_mac}
    if comment:
        payload["comment"] = comment
    if server:
        payload["server"] = server

    before: dict[str, Any] = {}
    after = dict(payload)

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    write(*op.path, **payload)
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)


@_audited("remove_simple_queue")
def remove_simple_queue(
    client: MikrotikClient,
    settings: Settings,
    confirm: bool,
    target: str | None = None,
    name: str | None = None,
) -> WritePreview:
    """Remove a Simple Queue by `target` or by `name` - undoes a bandwidth
    limit previously set with set_client_bandwidth. At least one of
    `target`/`name` must be given and must resolve to an existing queue
    (`name` is tried first if both are given); raises ResourceNotFoundError
    otherwise. Never removes more than the one matching row.
    """
    op = _require_allowed(settings, "remove_simple_queue")

    if not target and not name:
        raise ValidationError("remove_simple_queue requires 'target' or 'name'.")

    # Validate `target` (if given) BEFORE touching the device at all, same
    # as every other write tool's validation - previously this ran after
    # client.path(*op.path), so an invalid target still triggered a device
    # read before failing.
    validated_target = validate_target(target) if target else None

    rows = client.path(*op.path)
    row = _find_row_by_field(rows, "name", name) if name else None
    if row is None and validated_target:
        row = _find_row_by_field(rows, "target", validated_target)

    if row is None:
        raise ResourceNotFoundError(client.device.name, "Simple queue", name or target or "")

    before = dict(row)
    after: dict[str, Any] = {}

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    write(*op.path, ids=(row.get(".id"),))
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)


# --- v0.4: address-list based access control --------------------------------


def _find_address_list_row(rows: list[dict[str, Any]], list_name: str, address: str) -> dict[str, Any] | None:
    """First row whose `list`+`address` both match, or None. An address-list
    entry is identified by that pair, not by name/target alone - the same
    `address` can legitimately appear in more than one list."""
    for row in rows:
        if row.get("list") == list_name and row.get("address") == address:
            return row
    return None


@_audited("add_to_address_list")
def add_to_address_list(
    client: MikrotikClient,
    settings: Settings,
    list_name: str,
    address: str,
    confirm: bool,
    comment: str | None = None,
    timeout: str | None = None,
) -> WritePreview:
    """Add `address` (an IP or subnet) to a named firewall address-list
    (/ip/firewall/address-list). This only manages the *list* - it does NOT
    create or modify any firewall rule. Blocking or allowing traffic based on
    this list requires a separate `/ip/firewall/filter` (or NAT) rule that
    references `list_name` (e.g. `src-address-list=blocked-clients`,
    action=drop); that rule is not created here and must already exist on
    the device - see README's "Blocking/allowing a client via address lists"
    section.

    Refuses to add a duplicate (same `list_name`+`address` pair already
    present) - raises ResourceAlreadyExistsError instead of creating a
    second entry. This tool only ever adds; it never updates or removes an
    existing entry.
    """
    op = _require_allowed(settings, "add_to_address_list")

    validated_list = validate_address_list_name(list_name)
    validated_address = validate_target(address)
    validated_comment = validate_comment(comment) if comment is not None else None
    validated_timeout = validate_timeout(timeout) if timeout is not None else None

    rows = client.path(*op.path)
    existing = _find_address_list_row(rows, validated_list, validated_address)
    if existing is not None:
        raise ResourceAlreadyExistsError(
            client.device.name, "Address-list entry", f"{validated_list}:{validated_address}"
        )

    payload: dict[str, Any] = {"list": validated_list, "address": validated_address}
    if validated_comment:
        payload["comment"] = validated_comment
    if validated_timeout:
        payload["timeout"] = validated_timeout

    before: dict[str, Any] = {}
    after = dict(payload)

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    write(*op.path, **payload)
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)


@_audited("remove_from_address_list")
def remove_from_address_list(
    client: MikrotikClient,
    settings: Settings,
    list_name: str,
    address: str,
    confirm: bool,
) -> WritePreview:
    """Remove the entry matching `list_name`+`address` from a firewall
    address-list (/ip/firewall/address-list). Raises ResourceNotFoundError if
    no such entry exists - never removes more than the one matching row.

    Like add_to_address_list, this only manages the *list* - removing an
    entry stops that specific list membership, but has no effect on
    traffic unless a firewall rule referencing `list_name` also changes or
    is removed separately.
    """
    op = _require_allowed(settings, "remove_from_address_list")

    validated_list = validate_address_list_name(list_name)
    validated_address = validate_target(address)

    rows = client.path(*op.path)
    row = _find_address_list_row(rows, validated_list, validated_address)
    if row is None:
        raise ResourceNotFoundError(
            client.device.name, "Address-list entry", f"{validated_list}:{validated_address}"
        )

    before = dict(row)
    after: dict[str, Any] = {}

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    write(*op.path, ids=(row.get(".id"),))
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)
