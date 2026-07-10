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
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from . import audit
from .client import MikrotikClient
from .config import Settings
from .correlation import current as current_correlation_id
from .exceptions import (
    AmbiguousResourceError,
    DeviceCommandError,
    GuardViolationError,
    ResourceAlreadyExistsError,
    ResourceNotFoundError,
    ValidationError,
    WriteDisabledError,
)
from .formatting import WIREGUARD_SENSITIVE_FIELDS, coerce_ros_bool, strip_sensitive_fields
from .validation import (
    is_literal_ip_address,
    validate_address_list_name,
    validate_allowed_address_list,
    validate_backup_name,
    validate_backup_password,
    validate_byte_count,
    validate_comment,
    validate_container_identifier,
    validate_dns_name,
    validate_dns_record_type,
    validate_dst_address,
    validate_firewall_chain,
    validate_firewall_rule_comment,
    validate_firewall_rule_position,
    validate_hotspot_password,
    validate_hotspot_profile,
    validate_hotspot_username,
    validate_interface_name,
    validate_ip_address,
    validate_mac_address,
    validate_mtu,
    validate_ping_address,
    validate_poe_out,
    validate_port,
    validate_ppp_profile,
    validate_ppp_secret_name,
    validate_ppp_secret_password,
    validate_ppp_service,
    validate_rate_pair,
    validate_route_distance,
    validate_route_gateway,
    validate_target,
    validate_timeout,
    validate_vlan_id,
    validate_wireguard_key,
)


@dataclass(frozen=True)
class WriteOperation:
    name: str
    path: tuple[str, ...]
    action: str  # "update" | "add" | "remove" | "start" | "stop" | "flush" | "wol" | "save" | "move"
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
    # either RouterOS generation, and ROS7 itself may store the ssid in
    # either of two places - see set_wifi_ssid()/_resolve_wifi_ssid_target()
    # below, which detect which of the three entries below the target
    # interface actually lives under and dispatch through that (and only
    # that) allowlisted operation. Every entry stays individually
    # named/reviewable; nothing here accepts an arbitrary path.
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
    # A ROS7 /interface/wifi interface that references a named `configuration`
    # (the standard production layout - confirmed against real ROS7 hardware,
    # a mANTBox) has NO writable `ssid` field of its own; the SSID lives on
    # the referenced /interface/wifi/configuration row instead. set_wifi_ssid()
    # below resolves the interface's own `configuration` field server-side and
    # dispatches here - never on a path the caller supplies.
    "set_wifi_ssid_ros7_configuration": WriteOperation(
        name="set_wifi_ssid_ros7_configuration",
        path=("interface", "wifi", "configuration"),
        action="update",
        description="Set the SSID on a named ROS7 wifi configuration profile (/interface/wifi/configuration).",
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
    "set_poe_out": WriteOperation(
        name="set_poe_out",
        path=("interface", "ethernet"),
        action="update",
        description="Set a PoE-capable ethernet port's PoE output mode (auto-on/forced-on/off).",
    ),
    # start_container/stop_container (v0.7) are the first ALLOWLIST entries
    # whose `action` is neither update/add/remove: /container/start and
    # /container/stop are RouterOS ACTION commands (see
    # client.MikrotikClient.start/.stop), not a field `set`. Dispatch still
    # goes through the exact same `getattr(client, op.action)` mechanism as
    # every other write - see start_container/stop_container below - just
    # naming a different (still fixed, still reviewed) MikrotikClient method.
    "start_container": WriteOperation(
        name="start_container",
        path=("container",),
        action="start",
        description="Start a container by name/tag (/container/start).",
    ),
    "stop_container": WriteOperation(
        name="stop_container",
        path=("container",),
        action="stop",
        description="Stop a container by name/tag (/container/stop).",
    ),
    # v0.9: atomic failover writes. Each of these adjusts one piece of a
    # RouterOS failover setup (route priority, a route's enabled state, a
    # Netwatch monitor) - deliberately small, composable, individually
    # previewable steps rather than one black-box "do a failover" command.
    # See set_route_distance/_resolve_route below for why routes are
    # resolved by (dst-address, gateway) - stable RouterOS identifiers -
    # rather than a dynamic .id/index, and why that resolution can raise
    # AmbiguousResourceError instead of guessing.
    "set_route_distance": WriteOperation(
        name="set_route_distance",
        path=("ip", "route"),
        action="update",
        description="Adjust an existing route's distance (failover priority - lower wins); resolved by dst-address+gateway.",
    ),
    "enable_route": WriteOperation(
        name="enable_route",
        path=("ip", "route"),
        action="update",
        description="Enable a route (disabled=no); resolved by dst-address, narrowed by gateway/comment if ambiguous.",
    ),
    "disable_route": WriteOperation(
        name="disable_route",
        path=("ip", "route"),
        action="update",
        description=(
            "Disable a route (disabled=yes); resolved by dst-address, narrowed by gateway/comment if ambiguous. "
            "Disabling the default route (0.0.0.0/0 or ::/0) cuts outbound traffic through that gateway."
        ),
    ),
    # v1.5: closes Tier 1 of the route family - add/remove a static route,
    # alongside the v0.9 set_route_distance/enable_route/disable_route
    # trio. Both reuse _resolve_route/_DEFAULT_ROUTE_DST_ADDRESSES below.
    "add_route": WriteOperation(
        name="add_route",
        path=("ip", "route"),
        action="add",
        description=(
            "Add a static route (dst-address+gateway, optional distance/comment). Never refuses a duplicate "
            "dst-address - multiple routes sharing one is the normal failover shape. Adding/overriding the "
            "default route (0.0.0.0/0 or ::/0) redirects all traffic through the new gateway."
        ),
    ),
    "remove_route": WriteOperation(
        name="remove_route",
        path=("ip", "route"),
        action="remove",
        description=(
            "Remove a static route; resolved by dst-address, narrowed by gateway if ambiguous. Refuses to "
            "remove a dynamic/connected route (dynamic=true) outright. Removing the default route "
            "(0.0.0.0/0 or ::/0) cuts outbound traffic through that gateway."
        ),
    ),
    "add_netwatch": WriteOperation(
        name="add_netwatch",
        path=("tool", "netwatch"),
        action="add",
        description=(
            "Create a Netwatch host monitor (host/interval/comment only - never accepts an "
            "up-script/down-script; those are configured manually on the device)."
        ),
    ),
    "remove_netwatch": WriteOperation(
        name="remove_netwatch",
        path=("tool", "netwatch"),
        action="remove",
        description="Remove a Netwatch host monitor by host or comment.",
    ),
    # v0.10: static DNS, DNS cache flush, DHCP lease removal, Wake-on-LAN.
    # clear_dns_cache/wake_on_lan are the second pair of ALLOWLIST entries
    # (after start_container/stop_container in v0.7) whose `action` is
    # neither update/add/remove - "flush"/"wol" are RouterOS's own literal
    # command words for /ip/dns/cache/flush and /tool/wol. Unlike start/stop
    # (which target one specific /container row's .id), neither of these
    # targets a row at all - see MikrotikClient.flush/.wol's docstrings.
    "add_static_dns": WriteOperation(
        name="add_static_dns",
        path=("ip", "dns", "static"),
        action="add",
        description="Add a static DNS entry (/ip/dns/static) - name to an address (A) or a CNAME target.",
    ),
    "remove_static_dns": WriteOperation(
        name="remove_static_dns",
        path=("ip", "dns", "static"),
        action="remove",
        description="Remove a static DNS entry by name, optionally narrowed by record type.",
    ),
    "clear_dns_cache": WriteOperation(
        name="clear_dns_cache",
        path=("ip", "dns", "cache"),
        action="flush",
        description="Flush the device's DNS resolver cache (/ip/dns/cache/flush, no arguments).",
    ),
    "remove_dhcp_lease": WriteOperation(
        name="remove_dhcp_lease",
        path=("ip", "dhcp-server", "lease"),
        action="remove",
        description=(
            "Remove a DHCP lease (dynamic or static) by address or mac-address - typically to force a "
            "client to renew its IP. Removing a STATIC lease also deletes its pinned IP<->MAC mapping."
        ),
    ),
    "wake_on_lan": WriteOperation(
        name="wake_on_lan",
        path=("tool",),
        action="wol",
        description="Send a Wake-on-LAN magic packet to a MAC address via an interface (/tool/wol).",
    ),
    # v0.11: firewall rule TOGGLE - never create, never touch any field but
    # `disabled`. See the module comment above enable_firewall_rule/
    # disable_firewall_rule below for the full admin-creates/LLM-enables
    # workflow this is built for, and README's "Firewall rule toggle (by
    # comment)". Resolved by the rule's `comment` (optionally narrowed by
    # `chain`) - a STABLE, admin-controlled identifier, never a dynamic
    # `.id`/list index.
    "enable_firewall_rule": WriteOperation(
        name="enable_firewall_rule",
        path=("ip", "firewall", "filter"),
        action="update",
        description=(
            "Enable an EXISTING firewall filter rule (disabled=no), resolved by its comment "
            "(optionally narrowed by chain) - never creates a rule."
        ),
    ),
    "disable_firewall_rule": WriteOperation(
        name="disable_firewall_rule",
        path=("ip", "firewall", "filter"),
        action="update",
        description=(
            "Disable an EXISTING firewall filter rule (disabled=yes), resolved by its comment "
            "(optionally narrowed by chain) - never creates a rule."
        ),
    ),
    # v0.13: WireGuard VPN management - the most sensitive round yet, since
    # WireGuard uses private keys. add_wireguard_interface never accepts (or
    # returns) a private-key: RouterOS generates one internally, and every
    # row this section's functions ever return has been through
    # _redact_wireguard_row (formatting.strip_sensitive_fields) BEFORE the
    # WritePreview is constructed - see the module note above
    # add_wireguard_interface below for why that ordering matters for the
    # audit journal too.
    "add_wireguard_interface": WriteOperation(
        name="add_wireguard_interface",
        path=("interface", "wireguard"),
        action="add",
        description=(
            "Create a WireGuard tunnel interface (name, optional listen-port). RouterOS generates "
            "the private key internally - never supplied or returned by this tool."
        ),
    ),
    "add_wireguard_peer": WriteOperation(
        name="add_wireguard_peer",
        path=("interface", "wireguard", "peers"),
        action="add",
        description=(
            "Add a WireGuard peer (remote public-key, allowed-address, optional endpoint/keepalive) "
            "to an existing tunnel interface. Never accepts a private-key or preshared-key."
        ),
    ),
    "remove_wireguard_peer": WriteOperation(
        name="remove_wireguard_peer",
        path=("interface", "wireguard", "peers"),
        action="remove",
        description="Remove a WireGuard peer from an interface, resolved by public-key or comment.",
    ),
    # v0.14: hotspot vouchers + backup - the last feature round before 1.0.
    # add_hotspot_user creates a visitor login (/ip/hotspot/user add) - see
    # the module note above add_hotspot_user below for the deliberate
    # password asymmetry (in the tool RESULT, never in the audit journal).
    # create_backup is a third ACTION-command entry (after start/stop and
    # flush/wol above) - "save" is RouterOS's own literal command word for
    # `/system/backup/save`, dispatched via the same
    # `getattr(client, op.action)` mechanism as every other guarded write.
    "add_hotspot_user": WriteOperation(
        name="add_hotspot_user",
        path=("ip", "hotspot", "user"),
        action="add",
        description=(
            "Create a hotspot voucher user (name, password, optional profile/limit-uptime/"
            "limit-bytes-total) for a visitor. Refuses to create a duplicate name."
        ),
    ),
    "create_backup": WriteOperation(
        name="create_backup",
        path=("system", "backup"),
        action="save",
        description=(
            "Create a RouterOS system backup file (/system/backup/save name=<name>, optional "
            "encryption password - never journaled). Refuses to overwrite an existing file of "
            "the same name."
        ),
    ),
    # v1.2: VLAN management + firewall rule reorder. add_vlan/remove_vlan
    # manage /interface/vlan rows - an ordinary named-resource add/remove
    # pair, following add_static_dns/remove_static_dns's shape exactly (
    # resolved by `name`, refuses a duplicate on add, refuses a missing name
    # on remove). move_firewall_rule is the more novel one: it's the first
    # ALLOWLIST entry whose `action` is "move" - RouterOS's own literal
    # command word for /ip/firewall/filter move, a fourth kind of ACTION
    # command alongside start/stop (v0.7), flush/wol (v0.10), and save
    # (v0.14) - dispatched through the exact same `getattr(client,
    # op.action)` mechanism as every other guarded write (see set_identity's
    # A1 comment above), just naming client.MikrotikClient.move instead.
    # Like enable_firewall_rule/disable_firewall_rule (v0.11), it NEVER
    # creates or otherwise edits a rule's fields - only its position in the
    # chain's evaluation order changes, resolved by the rule's `comment`
    # (the same STABLE, admin-controlled identifier those two tools use),
    # never a dynamic `.id`/list index supplied directly by a caller.
    "add_vlan": WriteOperation(
        name="add_vlan",
        path=("interface", "vlan"),
        action="add",
        description=(
            "Create a VLAN interface (/interface/vlan add): name, vlan-id (1-4094), parent "
            "interface, optional mtu/comment. Refuses to create a duplicate name."
        ),
    ),
    "remove_vlan": WriteOperation(
        name="remove_vlan",
        path=("interface", "vlan"),
        action="remove",
        description="Remove a VLAN interface by name (/interface/vlan remove).",
    ),
    "move_firewall_rule": WriteOperation(
        name="move_firewall_rule",
        path=("ip", "firewall", "filter"),
        action="move",
        description=(
            "Reorder an EXISTING firewall filter rule (/ip/firewall/filter move), resolved by its "
            "comment (optionally narrowed by chain) - never creates or otherwise edits a rule; only "
            "its position in the chain's evaluation order changes."
        ),
    ),
    # v1.3: PPP/PPPoE secrets (/ppp/secret) - a *service* credential (dial-in
    # network access only, never router admin - a different, lower risk
    # class than a /user login), so it follows add_hotspot_user's (v0.14)
    # precedent exactly: password DELIBERATELY present in the tool's own
    # result, never in the audit journal (audit._SENSITIVE_KEY already
    # matches "password" - no new redaction code needed). add_ppp_secret/
    # remove_ppp_secret are otherwise an ordinary named-resource add/remove
    # pair, following add_static_dns/add_vlan's shape (resolved by `name`,
    # refuses a duplicate on add, raises AmbiguousResourceError on remove if
    # more than one row somehow shares a `name`).
    "add_ppp_secret": WriteOperation(
        name="add_ppp_secret",
        path=("ppp", "secret"),
        action="add",
        description=(
            "Create a PPP/PPPoE secret (name, password, service, optional profile/remote-address/"
            "comment) - a dial-in service credential. Refuses to create a duplicate name."
        ),
    ),
    "remove_ppp_secret": WriteOperation(
        name="remove_ppp_secret",
        path=("ppp", "secret"),
        action="remove",
        description="Remove a PPP/PPPoE secret by name (/ppp/secret remove).",
    ),
    # v1.4: NAT & mangle rule TOGGLE - the exact same "never create, never
    # touch any field but `disabled`" pattern v0.11's enable_firewall_rule/
    # disable_firewall_rule established for /ip/firewall/filter, extended to
    # the other two firewall menus. Resolved by the rule's `comment`
    # (optionally narrowed by `chain`) - see the module comment above
    # enable_nat_rule/enable_mangle_rule below for the full rationale.
    "enable_nat_rule": WriteOperation(
        name="enable_nat_rule",
        path=("ip", "firewall", "nat"),
        action="update",
        description=(
            "Enable an EXISTING firewall NAT rule (disabled=no), resolved by its comment "
            "(optionally narrowed by chain) - never creates a rule."
        ),
    ),
    "disable_nat_rule": WriteOperation(
        name="disable_nat_rule",
        path=("ip", "firewall", "nat"),
        action="update",
        description=(
            "Disable an EXISTING firewall NAT rule (disabled=yes), resolved by its comment "
            "(optionally narrowed by chain) - never creates a rule."
        ),
    ),
    "enable_mangle_rule": WriteOperation(
        name="enable_mangle_rule",
        path=("ip", "firewall", "mangle"),
        action="update",
        description=(
            "Enable an EXISTING firewall mangle rule (disabled=no), resolved by its comment "
            "(optionally narrowed by chain) - never creates a rule."
        ),
    ),
    "disable_mangle_rule": WriteOperation(
        name="disable_mangle_rule",
        path=("ip", "firewall", "mangle"),
        action="update",
        description=(
            "Disable an EXISTING firewall mangle rule (disabled=yes), resolved by its comment "
            "(optionally narrowed by chain) - never creates a rule."
        ),
    ),
    # v1.8: NTP client servers. Unlike set_wifi_ssid's genuinely different
    # /interface/wifi vs /interface/wireless menus, /system/ntp/client is the
    # SAME RouterOS path on both generations - only the field SHAPE differs
    # (ROS7's single `servers` list vs ROS6's fixed `primary-ntp`/
    # `secondary-ntp` slots), so one allowlist entry covers both; see
    # set_ntp_servers below for how it detects and targets whichever shape a
    # given device actually speaks.
    "set_ntp_servers": WriteOperation(
        name="set_ntp_servers",
        path=("system", "ntp", "client"),
        action="update",
        description=(
            "Set the NTP server(s) a device syncs its clock against (/system/ntp/client). "
            "Never enables/disables the NTP client itself, only its server list."
        ),
    ),
    # --- Deliberately NOT added yet - each needs extra policy beyond the
    # standard guard before it would be safe to expose:
    #   * reboot ("system/reboot"): no before/after preview is meaningful for
    #     a reboot, and a bad batch reboot across a fleet has no dry-run or
    #     rollback. Needs its own confirmation/cooldown policy first.
    #   * firewall filter/NAT/mangle rule CREATION or general modification
    #     ("ip/firewall/filter|nat|mangle" add, or update of any field other
    #     than `disabled`): a single wrong rule (e.g. one that blocks the API
    #     port, or disables the masquerade rule providing a LAN's Internet
    #     access) can lock out management access or connectivity with no
    #     remote recovery. v0.11 (filter) and v1.4 (NAT/mangle) deliberately
    #     only expose toggling `disabled` on a rule an admin already created
    #     and reviewed themselves (see enable_firewall_rule/
    #     disable_firewall_rule, enable_nat_rule/disable_nat_rule, and
    #     enable_mangle_rule/disable_mangle_rule above) - authoring or
    #     otherwise editing a rule still needs staged/rollback support (e.g.
    #     RouterOS safe mode) before it belongs in this allowlist.
    #   * backup RESTORE ("system/backup/load"): same class of risk as
    #     reboot - loading a backup overwrites the device's ENTIRE running
    #     configuration and reboots it, with no meaningful before/after
    #     preview and no rollback if the wrong file (or the right file, at
    #     the wrong time) is loaded. v0.14 only ever exposes CREATING a
    #     backup (create_backup) and listing existing ones (list_backups) -
    #     restoring one stays a manual, on-device (WinBox/CLI) operation
    #     until it has its own confirmation/cooldown policy, same as reboot.
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
    # v0.9: optional risk callout surfaced alongside before/after - e.g.
    # disable_route sets this when the route being disabled is the default
    # route (0.0.0.0/0 / ::/0), so a caller reading only `applied`/`after`
    # still can't miss that this write cuts outbound traffic. None for
    # every write that carries no special risk (i.e. every write before
    # v0.9, and most of v0.9's own writes too) - existing callers/tests that
    # construct or compare a WritePreview without `warning` are unaffected.
    warning: str | None = None


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
                # `warning` (e.g. disable_route's default-route callout,
                # remove_dhcp_lease's static-lease callout - see
                # WritePreview.warning) is included here so the audit journal
                # can reconstruct the same risk callout a caller saw, not
                # just the raw before/after values. It is plain text about
                # the OPERATION (which route/lease, why it's risky) - never a
                # device credential - so this carries no new secret-handling
                # risk on top of before/after, which audit.record() already
                # sanitizes via its own key-based redaction.
                summary={"before": result.before, "after": result.after, "warning": result.warning},
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


def _resolve_wifi_ssid_target(
    client: MikrotikClient, interface_row: dict[str, Any]
) -> tuple[WriteOperation, dict[str, Any]]:
    """Resolve where a matched ROS7 /interface/wifi interface's SSID
    actually lives, and return the (WriteOperation, row) to read/write it.

    Confirmed against real ROS7 hardware (mANTBox) running a named
    `configuration` - the standard production layout: the wifi interface row
    itself has NO writable `ssid` field at all; writing one there is
    rejected by RouterOS ("unknown parameter ssid"). The SSID lives on the
    /interface/wifi/configuration row the interface references (its own
    `configuration` field, e.g. `configuration=cfg1`) instead - that row,
    resolved here by name, is the real write target and the honest
    before/after source.

    Only a wifi interface with NO named `configuration` at all (rare/legacy)
    still carries a genuinely inline `ssid` field - that case is unchanged
    from before this fix: written directly on /interface/wifi.

    Raises DeviceCommandError with a clear explanation - never a device
    command RouterOS would itself reject - if neither shape is recognized:
    a `configuration` name that doesn't resolve to any
    /interface/wifi/configuration row, or an interface row with neither a
    `configuration` reference nor an inline `ssid` field.
    """
    configuration_name = interface_row.get("configuration")
    if configuration_name:
        config_op = ALLOWLIST["set_wifi_ssid_ros7_configuration"]
        try:
            config_rows = client.path(*config_op.path)
        except DeviceCommandError as exc:
            raise DeviceCommandError(
                client.device.name,
                "/".join(config_op.path),
                f"interface references configuration {configuration_name!r} but "
                f"/interface/wifi/configuration could not be read: {exc}",
            ) from exc
        config_row = _find_row_by_field(config_rows, "name", configuration_name)
        if config_row is None:
            raise ResourceNotFoundError(client.device.name, "Wifi configuration", configuration_name)
        return config_op, config_row

    if "ssid" in interface_row:
        return ALLOWLIST["set_wifi_ssid_ros7"], interface_row

    raise DeviceCommandError(
        client.device.name,
        "/".join(ALLOWLIST["set_wifi_ssid_ros7"].path),
        "wifi interface has neither a 'configuration' reference nor an inline "
        "'ssid' field - cannot determine where its SSID is stored.",
    )


@_audited("set_wifi_ssid_ros7")
def set_wifi_ssid(
    client: MikrotikClient, settings: Settings, interface_name: str, new_ssid: str, confirm: bool
) -> WritePreview:
    """Set a wireless interface's SSID, on either RouterOS generation.

    The read-only gate is identical for every candidate operation, so it is
    checked once up front (anchored on the ROS7 interface entry purely to
    reuse _require_allowed's ALLOWLIST/gate check) before anything is read
    from the device, exactly like every other guarded write.

    Which underlying interface is targeted is decided by looking for
    `interface_name` first under /interface/wifi (ROS7), then under
    /interface/wireless (ROS6) - mirroring server.py's wireless_registrations
    read tool's own ROS7-then-ROS6 fallback. A device that doesn't have a
    given package installed at all raises DeviceCommandError from
    client.path(); that is treated the same as "not found here" and the next
    candidate is tried, so a non-wifi device or a ROS6-only device never
    produces a confusing transport error - only a clear "not found" once both
    candidates are exhausted.

    For a ROS7 match, WHERE the ssid is actually written is then resolved
    separately by _resolve_wifi_ssid_target: a production ROS7 interface
    referencing a named `configuration` has no inline `ssid` field at all -
    the real write target is that /interface/wifi/configuration row (see
    that function's docstring, confirmed against real hardware). A ROS6
    match always writes inline on /interface/wireless, unchanged.
    """
    _require_allowed(settings, "set_wifi_ssid_ros7")

    interface_op = None
    interface_row = None
    for operation_name in ("set_wifi_ssid_ros7", "set_wifi_ssid_ros6"):
        candidate_op = ALLOWLIST[operation_name]
        try:
            candidate_rows = client.path(*candidate_op.path)
        except DeviceCommandError:
            continue
        candidate_row = _find_row_by_field(candidate_rows, "name", interface_name)
        if candidate_row is not None:
            interface_op, interface_row = candidate_op, candidate_row
            break

    if interface_row is None or interface_op is None:
        raise ResourceNotFoundError(client.device.name, "Wireless interface", interface_name)

    if interface_op.name == "set_wifi_ssid_ros7":
        op, row = _resolve_wifi_ssid_target(client, interface_row)
    else:
        op, row = interface_op, interface_row

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
        raise ResourceNotFoundError(client.device.name, "Address-list entry", f"{validated_list}:{validated_address}")

    before = dict(row)
    after: dict[str, Any] = {}

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    write(*op.path, ids=(row.get(".id"),))
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)


# --- v0.6: physical layer / PoE control -------------------------------------


@_audited("set_poe_out")
def set_poe_out(
    client: MikrotikClient, settings: Settings, interface_name: str, poe_out: str, confirm: bool
) -> WritePreview:
    """Set a PoE-capable ethernet port's `poe-out` mode
    (/interface/ethernet set [interface] poe-out=<auto-on|forced-on|off>).

    Primary use case on this fleet: resetting a locked-up antenna/camera/AP
    powered over PoE by cycling its power - set poe_out="off" (confirm=true),
    then once it's confirmed down, set poe_out="auto-on" again to bring it
    back up.

    Errors (never creates/coerces anything) if `interface_name` doesn't
    exist on the device at all, OR if it exists but isn't PoE-capable (its
    /interface/ethernet row has no `poe-out` field at all - e.g. an SFP
    port, or any port on a device with no PoE hardware) - both cases raise
    ResourceNotFoundError.
    """
    op = _require_allowed(settings, "set_poe_out")

    validated_interface = validate_interface_name(interface_name)
    validated_poe_out = validate_poe_out(poe_out)

    rows = client.path(*op.path)
    row = _find_row_by_field(rows, "name", validated_interface)
    if row is None or "poe-out" not in row:
        raise ResourceNotFoundError(client.device.name, "PoE-capable interface", validated_interface)

    before = dict(row)
    after = dict(row)
    after["poe-out"] = validated_poe_out

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    write(*op.path, **{".id": row.get(".id"), "poe-out": validated_poe_out})
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)


# --- v0.7: LTE/5G + containers + USB -----------------------------------------


def _find_container_row(rows: list[dict[str, Any]], identifier: str) -> dict[str, Any] | None:
    """Resolve a container by `name` first - RouterOS only populates
    /container's `name` field when the container was explicitly given one -
    falling back to `tag` (the image tag, always present, e.g.
    "alpine:latest") otherwise. Mirrors set_wifi_ssid's ROS7-then-ROS6
    fallback shape above: two fixed, ordered candidate fields, never one
    supplied by the caller."""
    row = _find_row_by_field(rows, "name", identifier)
    if row is not None:
        return row
    return _find_row_by_field(rows, "tag", identifier)


def _set_container_running(
    client: MikrotikClient,
    settings: Settings,
    operation_name: str,
    container: str,
    target_status: str,
    confirm: bool,
) -> WritePreview:
    """Shared implementation behind start_container/stop_container - both
    resolve `container` (by name, then tag - see _find_container_row) to one
    /container row and dispatch through ALLOWLIST[operation_name].action
    (`getattr(client, op.action)` - "start" or "stop", never a caller-chosen
    command), exactly the same `op.action`-driven dispatch shape as every
    other guarded write (see set_identity's A1 comment above) - just with a
    fixed action-command MikrotikClient method (client.start/.stop) instead
    of update/add/remove.

    Raises ResourceNotFoundError if `container` doesn't match any row on the
    device - this never creates a container.

    `target_status` in the returned preview's `after` is the RouterOS
    `status` value the start/stop command sets *immediately* ("starting"/
    "stopping"), not a guaranteed final state: RouterOS transitions a
    container's status asynchronously (image extraction, process startup) as
    it settles into "running"/"stopped" - re-read via the `containers` tool
    to see the settled status.
    """
    op = _require_allowed(settings, operation_name)

    validated_container = validate_container_identifier(container)

    try:
        rows = client.path(*op.path)
    except DeviceCommandError:
        # A device with no container package/hardware support at all (e.g. a
        # ROS6-only box, or a board without the container feature) raises a
        # raw DeviceCommandError from client.path() - same underlying
        # condition the read tool `containers()` already degrades
        # gracefully from (returns [] rather than erroring; see
        # server.py). A write can't silently no-op the same way, but it
        # must not leak that raw device-side error text either - treat it
        # the same as "no such container here", exactly like an unmatched
        # name/tag below.
        raise ResourceNotFoundError(client.device.name, "Container", validated_container) from None
    row = _find_container_row(rows, validated_container)
    if row is None:
        raise ResourceNotFoundError(client.device.name, "Container", validated_container)

    before = dict(row)
    after = dict(row)
    after["status"] = target_status

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    write(*op.path, id=row.get(".id"))
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)


@_audited("start_container")
def start_container(client: MikrotikClient, settings: Settings, container: str, confirm: bool) -> WritePreview:
    """Start a container by `name` or `tag` (/container/start). Errors
    (never creates anything) if `container` doesn't match any /container row
    on the device."""
    return _set_container_running(
        client, settings, "start_container", container, target_status="starting", confirm=confirm
    )


@_audited("stop_container")
def stop_container(client: MikrotikClient, settings: Settings, container: str, confirm: bool) -> WritePreview:
    """Stop a container by `name` or `tag` (/container/stop). Errors (never
    creates anything) if `container` doesn't match any /container row on the
    device."""
    return _set_container_running(
        client, settings, "stop_container", container, target_status="stopping", confirm=confirm
    )


# --- v0.9: atomic failover writes -------------------------------------------
#
# Three routing tools (set_route_distance/enable_route/disable_route) plus
# two Netwatch tools (add_netwatch/remove_netwatch) - each a small, atomic
# step an LLM caller composes to build or adjust a failover setup, not one
# black-box "do a failover" command. See README's "Failover control" for the
# recommended step-by-step flow (netwatch observes a gateway; distance/
# enable/disable actually switches traffic to a different route).
#
# All three route writes share _resolve_route below: a route is identified
# by the STABLE (dst-address, gateway) pair (optionally narrowed further by
# `comment`) - never by a dynamic `.id` or a list index, both of which can
# silently shift as routes are added/removed elsewhere on the device between
# a preview (confirm=False) and the confirmed apply (confirm=True). This
# matters more here than for any other write tool in this package: routes
# govern where traffic actually goes, so resolving the wrong row - or
# guessing among several equally-matching ones - is the one mistake this
# round cannot afford to make silently.

_DEFAULT_ROUTE_DST_ADDRESSES = frozenset({"0.0.0.0/0", "::/0"})


def _resolve_route(
    client: MikrotikClient,
    op: WriteOperation,
    dst_address: str,
    gateway: str | None = None,
    comment: str | None = None,
) -> dict[str, Any]:
    """Resolve exactly one /ip/route row by its STABLE identifiers -
    `dst-address`, optionally narrowed by `gateway` and/or `comment`.

    Raises ResourceNotFoundError if nothing matches `dst_address` (further
    narrowed by `gateway`/`comment`, if given). Raises AmbiguousResourceError
    if MORE THAN ONE row still matches after narrowing - the most common
    real case is two routes sharing the same `dst-address` for failover
    (e.g. two `0.0.0.0/0` default routes pointing at different gateways with
    different `distance`), which is exactly why `gateway`/`comment` exist as
    disambiguators here instead of this function falling back to "just use
    the first match".
    """
    rows = client.path(*op.path)
    matches = [row for row in rows if row.get("dst-address") == dst_address]
    if gateway is not None:
        matches = [row for row in matches if row.get("gateway") == gateway]
    if comment is not None:
        matches = [row for row in matches if row.get("comment") == comment]

    if not matches:
        identifier = dst_address if gateway is None else f"{dst_address} via {gateway}"
        raise ResourceNotFoundError(client.device.name, "Route", identifier)
    if len(matches) > 1:
        raise AmbiguousResourceError(
            client.device.name,
            "Route",
            dst_address,
            [row.get("gateway", "") for row in matches],
        )
    return matches[0]


@_audited("set_route_distance")
def set_route_distance(
    client: MikrotikClient,
    settings: Settings,
    dst_address: str,
    gateway: str,
    distance: int,
    confirm: bool,
) -> WritePreview:
    """Adjust a route's `distance` (failover priority - the lower distance
    wins) via `/ip/route set distance=<distance>`.

    Resolved by the STABLE (`dst_address`, `gateway`) pair - see
    _resolve_route. Raises ResourceNotFoundError if no route matches that
    pair, or AmbiguousResourceError if more than one still does (a
    duplicate dst-address+gateway pair on the device itself - rare, but
    never silently guessed).
    """
    op = _require_allowed(settings, "set_route_distance")

    validated_dst = validate_dst_address(dst_address)
    validated_gateway = validate_route_gateway(gateway)
    validated_distance = validate_route_distance(distance)

    row = _resolve_route(client, op, validated_dst, gateway=validated_gateway)

    before = dict(row)
    after = dict(row)
    after["distance"] = str(validated_distance)

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    write(*op.path, **{".id": row.get(".id"), "distance": str(validated_distance)})
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)


def _set_route_disabled(
    client: MikrotikClient,
    settings: Settings,
    operation_name: str,
    dst_address: str,
    disabled: bool,
    confirm: bool,
    gateway: str | None,
    comment: str | None,
) -> WritePreview:
    """Shared implementation behind enable_route/disable_route - both
    resolve `dst_address` (narrowed by `gateway`/`comment` - see
    _resolve_route) to one /ip/route row and flip its `disabled` field.

    When `disabled=True` and the resolved route's `dst-address` is a default
    route (`0.0.0.0/0` or `::/0` - see _DEFAULT_ROUTE_DST_ADDRESSES), the
    returned WritePreview's `warning` field is set to a clear, non-null
    message: disabling the default route cuts outbound traffic through that
    gateway. This is set on BOTH the preview (`confirm=False`) and the
    applied result (`confirm=True`) - a caller reading only `applied`/`after`
    still cannot miss it. No warning is generated for re-enabling
    (`disabled=False`) a route - that direction restores traffic rather than
    cutting it.
    """
    op = _require_allowed(settings, operation_name)

    validated_dst = validate_dst_address(dst_address)
    validated_gateway = validate_route_gateway(gateway) if gateway is not None else None
    validated_comment = validate_comment(comment) if comment is not None else None

    row = _resolve_route(client, op, validated_dst, gateway=validated_gateway, comment=validated_comment)

    before = dict(row)
    after = dict(row)
    after["disabled"] = "yes" if disabled else "no"

    warning: str | None = None
    if disabled and validated_dst in _DEFAULT_ROUTE_DST_ADDRESSES:
        warning = (
            f"{validated_dst} is the DEFAULT ROUTE - disabling it will cut outbound traffic that "
            f"relies on gateway {row.get('gateway', '?')!r}. Confirm a working alternate route/gateway "
            "is already active before applying this with confirm=true."
        )

    if not confirm:
        return WritePreview(
            operation=op.name, device=client.device.name, before=before, after=after, applied=False, warning=warning
        )

    write = getattr(client, op.action)
    write(*op.path, **{".id": row.get(".id"), "disabled": after["disabled"]})
    return WritePreview(
        operation=op.name, device=client.device.name, before=before, after=after, applied=True, warning=warning
    )


@_audited("enable_route")
def enable_route(
    client: MikrotikClient,
    settings: Settings,
    dst_address: str,
    confirm: bool,
    gateway: str | None = None,
    comment: str | None = None,
) -> WritePreview:
    """Enable a route (sets disabled=no), resolved by `dst_address` -
    narrowed by `gateway`/`comment` when more than one route shares that
    `dst_address`. Raises ResourceNotFoundError if nothing matches, or
    AmbiguousResourceError if the match is still ambiguous after narrowing."""
    return _set_route_disabled(
        client, settings, "enable_route", dst_address, disabled=False, confirm=confirm, gateway=gateway, comment=comment
    )


@_audited("disable_route")
def disable_route(
    client: MikrotikClient,
    settings: Settings,
    dst_address: str,
    confirm: bool,
    gateway: str | None = None,
    comment: str | None = None,
) -> WritePreview:
    """Disable a route (sets disabled=yes), resolved by `dst_address` -
    narrowed by `gateway`/`comment` when more than one route shares that
    `dst_address`. Raises ResourceNotFoundError if nothing matches, or
    AmbiguousResourceError if the match is still ambiguous after narrowing.

    RISK: if the resolved route's `dst-address` is the default route
    (`0.0.0.0/0`/`::/0`), the returned preview's `warning` field explains
    that applying this cuts outbound traffic - see _set_route_disabled.
    """
    return _set_route_disabled(
        client, settings, "disable_route", dst_address, disabled=True, confirm=confirm, gateway=gateway, comment=comment
    )


# v1.5: static route add/remove - closes ROADMAP.md's Tier 1. Extends the
# same /ip/route family as set_route_distance/enable_route/disable_route
# above; add_route/remove_route reuse _resolve_route/_DEFAULT_ROUTE_DST_ADDRESSES
# defined earlier in this file rather than re-deriving route resolution.


@_audited("add_route")
def add_route(
    client: MikrotikClient,
    settings: Settings,
    dst_address: str,
    gateway: str,
    confirm: bool,
    distance: int | None = None,
    comment: str | None = None,
) -> WritePreview:
    """Add a static route (`/ip/route add`): `dst_address` and `gateway`
    are required, `distance` (failover priority - lower wins) and `comment`
    are optional.

    Never refuses a duplicate `dst_address`+`gateway` pair (unlike
    add_vlan/add_static_dns) - multiple routes sharing a `dst-address` is
    the normal failover shape (see _resolve_route's own docstring), so this
    tool never raises ResourceAlreadyExistsError.

    If `dst_address` is the default route (`0.0.0.0/0`/`::/0` - see
    _DEFAULT_ROUTE_DST_ADDRESSES), the returned WritePreview's `warning`
    field is set to a clear, non-null message: adding/overriding the
    default route redirects all traffic through the new gateway. This is
    set on BOTH the preview (`confirm=False`) and the applied result
    (`confirm=True`), same pattern as disable_route's default-route
    warning.
    """
    op = _require_allowed(settings, "add_route")

    validated_dst = validate_dst_address(dst_address)
    validated_gateway = validate_route_gateway(gateway)
    validated_distance = validate_route_distance(distance) if distance is not None else None
    validated_comment = validate_comment(comment) if comment is not None else None

    payload: dict[str, Any] = {"dst-address": validated_dst, "gateway": validated_gateway}
    if validated_distance is not None:
        payload["distance"] = str(validated_distance)
    if validated_comment:
        payload["comment"] = validated_comment

    before: dict[str, Any] = {}
    after = dict(payload)

    warning: str | None = None
    if validated_dst in _DEFAULT_ROUTE_DST_ADDRESSES:
        warning = (
            f"{validated_dst} is the DEFAULT ROUTE - adding/overriding it redirects all traffic through "
            f"gateway {validated_gateway!r}. Confirm this is the intended gateway before applying this "
            "with confirm=true."
        )

    if not confirm:
        return WritePreview(
            operation=op.name, device=client.device.name, before=before, after=after, applied=False, warning=warning
        )

    write = getattr(client, op.action)
    write(*op.path, **payload)
    return WritePreview(
        operation=op.name, device=client.device.name, before=before, after=after, applied=True, warning=warning
    )


@_audited("remove_route")
def remove_route(
    client: MikrotikClient,
    settings: Settings,
    dst_address: str,
    confirm: bool,
    gateway: str | None = None,
) -> WritePreview:
    """Remove a static route (`/ip/route remove`), resolved by `dst_address`
    - narrowed by `gateway` when more than one route shares that
    `dst_address` (see _resolve_route). Raises ResourceNotFoundError if
    nothing matches, or AmbiguousResourceError if the match is still
    ambiguous after narrowing.

    REFUSES to remove a DYNAMIC route: if the resolved row's `dynamic`
    field coerces to `True` (see `coerce_ros_bool`) - a connected/DHCP/
    OSPF/BGP-installed route, not one an operator created by hand - this
    raises ValidationError instead of removing anything - a hard refusal,
    not just a warning. Removing a device's connected/dynamic route can
    sever the network, and this tool only ever manages static,
    admin-created routes. Remove a dynamic route manually on the device if
    that is genuinely intended.

    SECURITY NOTE (fixed in 1.5.0, confirmed against real ROS6/ROS7
    hardware): librouteros returns RouterOS boolean fields as Python `bool`
    (or omits them entirely, `None`) - NEVER the strings "true"/"false". An
    earlier version of this refusal compared `row.get("dynamic")` directly
    against the string `"true"`; since `True == "true"` is `False` in
    Python, that comparison never matched on a real device, so this
    refusal silently never fired outside the test suite's own
    string-typed fakes - a dynamic/connected/default route could be
    removed outright. See `coerce_ros_bool`'s docstring (formatting.py) for
    the full ROS6/ROS7 split (ROS6 omits `dynamic` entirely when false;
    ROS7 sends `False` explicitly) this fix accounts for.

    If the resolved (static) route's `dst_address` is the default route
    (`0.0.0.0/0`/`::/0` - see _DEFAULT_ROUTE_DST_ADDRESSES), the returned
    WritePreview's `warning` field is set to a clear, non-null message
    (this direction is a warning, not a refusal - removing a static
    default route is a legitimate operation). Set on BOTH the preview
    (`confirm=False`) and the applied result (`confirm=True`).
    """
    op = _require_allowed(settings, "remove_route")

    validated_dst = validate_dst_address(dst_address)
    validated_gateway = validate_route_gateway(gateway) if gateway is not None else None

    row = _resolve_route(client, op, validated_dst, gateway=validated_gateway)

    if coerce_ros_bool(row.get("dynamic")) is True:
        raise ValidationError(
            f"refuses to remove {validated_dst} via {row.get('gateway', '?')!r}: this route is dynamic "
            "(dynamic=true) - a connected/DHCP/OSPF/BGP-installed route, not one this tool creates. Only "
            "static, admin-created routes can be removed by this tool; remove a connected/DHCP/OSPF/"
            "BGP-installed route manually on the device if that is genuinely intended."
        )

    before = dict(row)
    after: dict[str, Any] = {}

    warning: str | None = None
    if validated_dst in _DEFAULT_ROUTE_DST_ADDRESSES:
        warning = (
            f"{validated_dst} is the DEFAULT ROUTE - removing it will cut outbound traffic that relies on "
            f"gateway {row.get('gateway', '?')!r}. Confirm a working alternate route/gateway is already "
            "active before applying this with confirm=true."
        )

    if not confirm:
        return WritePreview(
            operation=op.name, device=client.device.name, before=before, after=after, applied=False, warning=warning
        )

    write = getattr(client, op.action)
    write(*op.path, ids=(row.get(".id"),))
    return WritePreview(
        operation=op.name, device=client.device.name, before=before, after=after, applied=True, warning=warning
    )


@_audited("add_netwatch")
def add_netwatch(
    client: MikrotikClient,
    settings: Settings,
    host: str,
    confirm: bool,
    interval: str | None = None,
    comment: str | None = None,
) -> WritePreview:
    """Create a Netwatch host monitor (`/tool/netwatch add`): `host`
    (validated as a plain IPv4/IPv6 address - see `validate_ip_address`),
    optional `interval` (a RouterOS duration, e.g. "10s"/"00:00:10" -
    reuses `validate_timeout`) and optional `comment`.

    SECURITY: this deliberately does NOT accept an up-script/down-script
    parameter - a Netwatch script body can run arbitrary RouterOS commands
    (route changes, credential changes, ...), exactly the class of
    caller-controlled-arbitrary-command vector this package's write guard
    exists to rule out (see module docstring). This round only creates the
    observable host/status/interval/comment row; up/down scripts are
    configured manually on the device (WinBox/CLI) once the monitor exists
    - see README's "Failover control". The read-only `netwatch` tool already
    only ever surfaces `has-up-script`/`has-down-script` as presence
    booleans, never a script body, for the same reason.

    Refuses to create a second monitor for a `host` that already has one -
    raises ResourceAlreadyExistsError instead of creating a duplicate. This
    tool only ever adds; it never updates or removes an existing monitor.
    """
    op = _require_allowed(settings, "add_netwatch")

    validated_host = validate_ip_address(host)
    validated_interval = validate_timeout(interval, "interval") if interval is not None else None
    validated_comment = validate_comment(comment) if comment is not None else None

    rows = client.path(*op.path)
    existing = _find_row_by_field(rows, "host", validated_host)
    if existing is not None:
        raise ResourceAlreadyExistsError(client.device.name, "Netwatch host monitor", validated_host)

    payload: dict[str, Any] = {"host": validated_host}
    if validated_interval:
        payload["interval"] = validated_interval
    if validated_comment:
        payload["comment"] = validated_comment

    before: dict[str, Any] = {}
    after = dict(payload)

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    write(*op.path, **payload)
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)


def _find_netwatch_rows(rows: list[dict[str, Any]], field: str, value: str) -> list[dict[str, Any]]:
    """All /tool/netwatch rows whose `field` equals `value`. Returns every
    match (not just the first) so remove_netwatch can tell a clean single
    match from an ambiguous one - see its AmbiguousResourceError, mirroring
    _find_firewall_rule_rows/_find_static_dns_rows/_resolve_route above."""
    return [row for row in rows if row.get(field) == value]


@_audited("remove_netwatch")
def remove_netwatch(
    client: MikrotikClient,
    settings: Settings,
    confirm: bool,
    host: str | None = None,
    comment: str | None = None,
) -> WritePreview:
    """Remove a Netwatch host monitor by `host` or `comment`
    (`/tool/netwatch remove`). At least one of `host`/`comment` must be
    given and must resolve to an existing monitor (`host` is tried first if
    both are given); raises ResourceNotFoundError if nothing matches.

    Raises AmbiguousResourceError if MORE THAN ONE row still matches `host`
    (or, when no row matches `host`, `comment`) - this never falls back to
    "just remove the first match": add_netwatch itself refuses to create a
    second monitor for the same `host` (see ResourceAlreadyExistsError
    there), but a device can still end up with more than one row sharing a
    `host` or `comment` via manual (WinBox/CLI) configuration outside this
    tool, exactly the same class of case _resolve_route/
    _find_firewall_rule_rows/_find_static_dns_rows already guard against.
    Never removes more than the one matching row.
    """
    op = _require_allowed(settings, "remove_netwatch")

    if not host and not comment:
        raise ValidationError("remove_netwatch requires 'host' or 'comment'.")

    # Validate `host` (if given) BEFORE touching the device at all, same as
    # every other write tool's validation (see remove_simple_queue's
    # equivalent comment).
    validated_host = validate_ip_address(host) if host else None

    rows = client.path(*op.path)
    if validated_host:
        matches = _find_netwatch_rows(rows, "host", validated_host)
        identifier, candidate_field = validated_host, "comment"
    else:
        matches, identifier, candidate_field = [], "", "host"
    if not matches and comment:
        matches = _find_netwatch_rows(rows, "comment", comment)
        identifier, candidate_field = comment, "host"

    if not matches:
        raise ResourceNotFoundError(client.device.name, "Netwatch host monitor", host or comment or "")
    if len(matches) > 1:
        raise AmbiguousResourceError(
            client.device.name,
            "Netwatch host monitor",
            identifier,
            [row.get(candidate_field, "") for row in matches],
        )

    row = matches[0]
    before = dict(row)
    after: dict[str, Any] = {}

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    write(*op.path, ids=(row.get(".id"),))
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)


# --- v0.10: static DNS, DNS cache flush, DHCP lease removal, Wake-on-LAN ----
#
# Five more guarded writes: `add_static_dns`/`remove_static_dns` (a named
# `/ip/dns/static` row), `clear_dns_cache` (a fire-and-forget flush of
# `/ip/dns/cache`), `remove_dhcp_lease` (removes an existing - dynamic OR
# static - `/ip/dhcp-server/lease` row, e.g. to force a client to renew its
# IP), and `wake_on_lan` (sends a `/tool/wol` magic packet). None of these
# need any ROS6/ROS7 branching - static DNS, DNS cache, DHCP leases, and
# /tool/wol are all present, at the same path, on both RouterOS generations.


def _dns_record_type_of(row: dict[str, Any]) -> str:
    """RouterOS omits the `type` field entirely on a plain address record
    (the implicit default) - only a CNAME (or other non-address) row carries
    an explicit `type`. Normalizes both to "A" so add_static_dns's duplicate
    check and remove_static_dns's lookup compare the way RouterOS itself
    treats an entry, not like an absent field."""
    return row.get("type") or "A"


def _find_static_dns_rows(
    rows: list[dict[str, Any]], name: str, record_type: str | None = None
) -> list[dict[str, Any]]:
    """All /ip/dns/static rows matching `name`, optionally narrowed further
    by `record_type`. More than one row can legitimately share a `name` -
    e.g. two "A" records for round-robin, or an "A" and a "CNAME" that
    happen to share a name - which is exactly why this returns every match
    rather than just the first one; callers decide what "more than one"
    means for their own operation (a duplicate for add, an ambiguity for
    remove - see add_static_dns/remove_static_dns below)."""
    matches = [row for row in rows if row.get("name") == name]
    if record_type is not None:
        matches = [row for row in matches if _dns_record_type_of(row) == record_type]
    return matches


@_audited("add_static_dns")
def add_static_dns(
    client: MikrotikClient,
    settings: Settings,
    name: str,
    address: str,
    confirm: bool,
    record_type: str = "A",
    ttl: str | None = None,
    comment: str | None = None,
) -> WritePreview:
    """Create a static DNS entry (`/ip/dns/static add`) resolving `name` to
    `address`.

    `record_type` (default `"A"`) selects what `address` means:
      - `"A"` (default): `address` is a literal IPv4/IPv6 address
        (`validate_ip_address`), written to RouterOS's `address` field.
        Useful to block a malicious domain (point it at `0.0.0.0`) or set up
        an internal DNS override.
      - `"CNAME"`: `address` is itself another hostname (`validate_dns_name`
        - the alias TARGET, not a literal IP), written to RouterOS's `cname`
        field - RouterOS's own `/ip/dns/static` menu has no `address` field
        on a CNAME row, only `cname`.

    Refuses to create a duplicate: ANY row already matching this `name`+
    `record_type` pair - raises ResourceAlreadyExistsError instead of
    creating a second one, regardless of whether `address` also matches.
    (RouterOS round-robin DNS - two "A" records sharing a `name` but
    pointing at different addresses - is therefore a configuration this
    tool does not create; add the second record manually on the device if
    that is genuinely intended.) This tool only ever adds; it never updates
    or removes an existing entry.
    """
    op = _require_allowed(settings, "add_static_dns")

    validated_name = validate_dns_name(name)
    validated_type = validate_dns_record_type(record_type)
    validated_ttl = validate_timeout(ttl, "ttl") if ttl is not None else None
    validated_comment = validate_comment(comment) if comment is not None else None
    validated_target = validate_dns_name(address) if validated_type == "CNAME" else validate_ip_address(address)

    rows = client.path(*op.path)
    if _find_static_dns_rows(rows, validated_name, validated_type):
        raise ResourceAlreadyExistsError(client.device.name, "Static DNS entry", f"{validated_name} ({validated_type})")

    payload: dict[str, Any] = {"name": validated_name, "type": validated_type}
    if validated_type == "CNAME":
        payload["cname"] = validated_target
    else:
        payload["address"] = validated_target
    if validated_ttl:
        payload["ttl"] = validated_ttl
    if validated_comment:
        payload["comment"] = validated_comment

    before: dict[str, Any] = {}
    after = dict(payload)

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    write(*op.path, **payload)
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)


@_audited("remove_static_dns")
def remove_static_dns(
    client: MikrotikClient,
    settings: Settings,
    name: str,
    confirm: bool,
    record_type: str | None = None,
) -> WritePreview:
    """Remove a static DNS entry (`/ip/dns/static remove`) by `name`,
    optionally narrowed by `record_type` ("A"/"CNAME").

    Raises ResourceNotFoundError if nothing matches `name` (narrowed by
    `record_type`, if given). Raises AmbiguousResourceError if MORE THAN ONE
    row still matches after narrowing - e.g. two "A" records sharing a
    `name` (round-robin DNS) - the tool never guesses which one to remove;
    the caller must supply `record_type`, or the device's `name` is simply
    not unique enough on its own and must be corrected on the device first.
    """
    op = _require_allowed(settings, "remove_static_dns")

    validated_name = validate_dns_name(name)
    validated_type = validate_dns_record_type(record_type) if record_type is not None else None

    rows = client.path(*op.path)
    matches = _find_static_dns_rows(rows, validated_name, validated_type)

    if not matches:
        identifier = validated_name if validated_type is None else f"{validated_name} ({validated_type})"
        raise ResourceNotFoundError(client.device.name, "Static DNS entry", identifier)
    if len(matches) > 1:
        raise AmbiguousResourceError(
            client.device.name,
            "Static DNS entry",
            validated_name,
            [_dns_record_type_of(row) for row in matches],
        )

    row = matches[0]
    before = dict(row)
    after: dict[str, Any] = {}

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    write(*op.path, ids=(row.get(".id"),))
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)


@_audited("clear_dns_cache")
def clear_dns_cache(client: MikrotikClient, settings: Settings, confirm: bool) -> WritePreview:
    """Flush the device's DNS resolver cache (`/ip/dns/cache/flush`) - a
    fire-and-forget RouterOS ACTION command that takes no arguments and
    targets no specific row (it clears the whole cache at once, not one
    entry).

    Benign (it never changes device *configuration*, only cached DNS
    answers, which repopulate on the next resolution), but still a guarded,
    confirm-gated write like every other tool here, since it does change
    device state (an LLM caller should not flush a cache "by accident" any
    more than it should flip an interface). `before`/`after` report the
    number of currently cached entries (`cached_entries`) as an informative
    count, read fresh each call - not a specific row's fields, since there
    is no specific row this operation targets. `after.cached_entries` is the
    INTENDED post-flush count (`0`), not a verified re-read - RouterOS may
    already have repopulated the cache with a new answer by the time a
    caller reads it back.
    """
    op = _require_allowed(settings, "clear_dns_cache")

    rows = client.path(*op.path)
    before = {"cached_entries": len(rows)}
    after = {"cached_entries": 0}

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    write(*op.path)
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)


@_audited("remove_dhcp_lease")
def remove_dhcp_lease(
    client: MikrotikClient,
    settings: Settings,
    confirm: bool,
    address: str | None = None,
    mac_address: str | None = None,
) -> WritePreview:
    """Remove a DHCP lease (`/ip/dhcp-server/lease remove`) by `address` or
    `mac_address` - typically used to force a client to renew its IP (its
    existing lease is deleted; the device requests/is offered a new one on
    its next DHCP exchange). At least one of `address`/`mac_address` must be
    given and must resolve to an existing lease (`mac_address` is tried
    first if both are given, since a MAC is the more stable identifier - an
    `address` can legitimately be reused by a different lease over time,
    a MAC cannot); raises ResourceNotFoundError otherwise. Never removes
    more than the one matching row.

    STATIC vs DYNAMIC: this removes EITHER kind of lease - RouterOS's
    `dynamic` field on the matched row (`True` for a normal DHCP-assigned
    lease, `False` - or absent, on ROS6 - for one pinned by
    add_static_dhcp_lease; see `coerce_ros_bool`) tells you which. Removing
    a DYNAMIC lease is this tool's primary use case (forces a renewal - a
    new dynamic lease is typically re-created on the client's next DHCP
    request). Removing a STATIC lease is also allowed - it is not blocked
    outright - but it deletes the pinned IP<->MAC mapping itself, not just
    a transient cache entry, so the returned WritePreview's `warning` field
    is set to a clear, non-null message whenever the resolved lease is NOT
    definitely dynamic (`coerce_ros_bool(row.get("dynamic")) is not True`
    - i.e. `False` or unknown/absent, deliberately erring toward showing
    the warning when it can't be told apart from a genuine static lease),
    on BOTH the preview (`confirm=False`) and the applied result
    (`confirm=True`) - exactly the same pattern `disable_route`'s
    default-route warning uses (see v0.9). `warning` is `None` only when
    the lease is confirmably dynamic - removing one is unremarkable,
    exactly what this tool is for.

    1.5.0 fix: this used to compare `row.get("dynamic")` against the
    literal string `"false"`, which - like `remove_route`'s dynamic-route
    refusal (see that function's docstring) - never matches librouteros'
    real `bool`/absent values, so a static lease's warning could silently
    fail to fire on real hardware. Now goes through `coerce_ros_bool`.
    """
    op = _require_allowed(settings, "remove_dhcp_lease")

    if not address and not mac_address:
        raise ValidationError("remove_dhcp_lease requires 'address' or 'mac_address'.")

    # Validate before touching the device at all, same as every other write
    # tool's validation (see remove_simple_queue's equivalent comment).
    validated_address = validate_ip_address(address) if address else None
    validated_mac = validate_mac_address(mac_address) if mac_address else None

    rows = client.path(*op.path)
    row = _find_row_by_field(rows, "mac-address", validated_mac) if validated_mac else None
    if row is None and validated_address:
        row = _find_row_by_field(rows, "address", validated_address)

    if row is None:
        raise ResourceNotFoundError(client.device.name, "DHCP lease", mac_address or address or "")

    before = dict(row)
    after: dict[str, Any] = {}

    warning: str | None = None
    if coerce_ros_bool(row.get("dynamic")) is not True:
        warning = (
            f"{before.get('address', '?')} <-> {before.get('mac-address', '?')} is a STATIC DHCP lease "
            "(dynamic=false) - removing it deletes the pinned mapping itself, not just a renewable "
            "cache entry. If you only meant to force a renewal, target a dynamic lease instead; if "
            "removing this static pin is intended, confirm with confirm=true."
        )

    if not confirm:
        return WritePreview(
            operation=op.name, device=client.device.name, before=before, after=after, applied=False, warning=warning
        )

    write = getattr(client, op.action)
    write(*op.path, ids=(row.get(".id"),))
    return WritePreview(
        operation=op.name, device=client.device.name, before=before, after=after, applied=True, warning=warning
    )


@_audited("wake_on_lan")
def wake_on_lan(
    client: MikrotikClient, settings: Settings, mac_address: str, interface: str, confirm: bool
) -> WritePreview:
    """Send a Wake-on-LAN magic packet (`/tool/wol`) for `mac_address`, out
    `interface`.

    Benign - it never changes device configuration or targets any existing
    RouterOS row (there is nothing to resolve/verify on the device first,
    unlike every other write tool above) - but still guarded/confirm-gated
    like every other write here, so an LLM caller can't wake a machine "by
    accident" any more than it can flip an interface. `mac_address`/
    `interface` are validated for shape only (`validate_mac_address`/
    `validate_interface_name`) - this does NOT verify `interface` exists on
    the device first; RouterOS itself rejects an unknown interface name at
    send time.
    """
    op = _require_allowed(settings, "wake_on_lan")

    validated_mac = validate_mac_address(mac_address)
    validated_interface = validate_interface_name(interface)

    before: dict[str, Any] = {}
    after = {"mac_address": validated_mac, "interface": validated_interface}

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    write(*op.path, mac_address=validated_mac, interface=validated_interface)
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)


# --- v0.11: firewall rule toggle (by comment, never create) ----------------
#
# enable_firewall_rule/disable_firewall_rule are the SAFE alternative to a
# general firewall-filter write tool - still deliberately absent, see
# ALLOWLIST's comment above. They only ever flip an EXISTING rule's
# `disabled` field, resolved by the rule's `comment` - a STABLE identifier
# the ADMIN controls, never a dynamic `.id`/list index that can silently
# shift as rules are added/removed elsewhere on the device between a preview
# and a confirmed apply.
#
# The workflow this is built for (the community-suggested design this round
# follows, given the lockout risk a wrong firewall write carries - see
# README's "Roadmap / non-goals"): an admin creates a rule ahead of time on
# the device itself, e.g.
#
#   /ip firewall filter add chain=forward src-address-list=attacker-x \
#     action=drop comment="Bloqueio_Ataque_X" disabled=yes
#
# reviews it once, and leaves it disabled. An LLM caller later enables it via
# enable_firewall_rule(comment="Bloqueio_Ataque_X") when it detects the
# condition the rule exists to guard against - never by asking this package
# to author a new rule itself. If something goes wrong, the admin knows
# EXACTLY which rule was toggled: the same one they already wrote and
# reviewed, never one this package created on its own judgment.
#
# Resolution never falls back to "just pick one": a `comment` that matches
# no row raises ResourceNotFoundError (never creates a rule as a fallback);
# a `comment` that still matches more than one row (optionally narrowed by
# `chain`) raises AmbiguousResourceError instead of guessing - the caller
# must supply `chain`, or the device's rule comments simply aren't unique
# enough and must be fixed there first.


def _find_firewall_rule_rows(
    rows: list[dict[str, Any]], comment: str, chain: str | None = None
) -> list[dict[str, Any]]:
    """All /ip/firewall/filter rows matching `comment` exactly, optionally
    narrowed further by `chain`. Returns every match (not just the first) so
    callers can tell a clean single match from an ambiguous one - see
    enable_firewall_rule/disable_firewall_rule's AmbiguousResourceError."""
    matches = [row for row in rows if row.get("comment") == comment]
    if chain is not None:
        matches = [row for row in matches if row.get("chain") == chain]
    return matches


def _set_firewall_rule_disabled(
    client: MikrotikClient,
    settings: Settings,
    operation_name: str,
    comment: str,
    disabled: bool,
    confirm: bool,
    chain: str | None,
    resource_label: str = "Firewall filter rule",
) -> WritePreview:
    """Shared implementation behind enable_firewall_rule/disable_firewall_rule
    - see this section's module comment above for the full design rationale.

    v1.4: also the shared implementation behind enable_nat_rule/
    disable_nat_rule and enable_mangle_rule/disable_mangle_rule (see the
    "v1.4: NAT & mangle rule toggle" section further below) - the resolution
    and toggle logic below never referenced anything filter-specific (it
    already only ever touches `op.path`, whatever ALLOWLIST entry
    `operation_name` names), so the SAME function is reused rather than
    duplicated per menu. `resource_label` is the only thing that varies
    between the three - it's what ResourceNotFoundError/AmbiguousResourceError
    call the resolved thing in their error message (e.g. "Firewall filter
    rule" vs "Firewall NAT rule" vs "Firewall mangle rule"), so an error for
    one menu is never confused for another. The filter pair's own behavior is
    UNCHANGED: `resource_label` defaults to "Firewall filter rule", exactly
    what this function always raised before v1.4.

    Resolves EXACTLY one row (in the ALLOWLIST entry's `op.path` menu -
    /ip/firewall/filter, /ip/firewall/nat, or /ip/firewall/mangle) by
    `comment` (optionally narrowed by `chain`). Raises ResourceNotFoundError
    if nothing matches - NEVER creates a rule as a fallback. Raises
    AmbiguousResourceError if more than one row still matches after
    narrowing.

    The returned WritePreview's `before`/`after` are full copies of the
    matched row (every field RouterOS returned for it, not just `disabled`)
    - deliberately, so a caller reading the preview can confirm WHICH rule
    (its `chain`/`action`/every other field) it is about to toggle before
    ever passing `confirm=true`, not just see the one field being written.
    That is exactly the "the operator knows which rule this is" safeguard
    this family of tools exists to provide.
    """
    op = _require_allowed(settings, operation_name)

    validated_comment = validate_firewall_rule_comment(comment)
    validated_chain = validate_firewall_chain(chain) if chain is not None else None

    rows = client.path(*op.path)
    matches = _find_firewall_rule_rows(rows, validated_comment, validated_chain)

    if not matches:
        raise ResourceNotFoundError(client.device.name, resource_label, validated_comment)
    if len(matches) > 1:
        raise AmbiguousResourceError(
            client.device.name,
            resource_label,
            validated_comment,
            [row.get("chain", "") for row in matches],
        )

    row = matches[0]
    before = dict(row)
    after = dict(row)
    after["disabled"] = "yes" if disabled else "no"

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    write(*op.path, **{".id": row.get(".id"), "disabled": after["disabled"]})
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)


@_audited("enable_firewall_rule")
def enable_firewall_rule(
    client: MikrotikClient, settings: Settings, comment: str, confirm: bool, chain: str | None = None
) -> WritePreview:
    """Enable an EXISTING firewall filter rule (`disabled=no`), resolved by
    its `comment` - optionally narrowed by `chain` if more than one rule
    shares that comment. NEVER creates a rule - see this section's module
    comment above for the full admin-creates/LLM-enables workflow."""
    return _set_firewall_rule_disabled(
        client, settings, "enable_firewall_rule", comment, disabled=False, confirm=confirm, chain=chain
    )


@_audited("disable_firewall_rule")
def disable_firewall_rule(
    client: MikrotikClient, settings: Settings, comment: str, confirm: bool, chain: str | None = None
) -> WritePreview:
    """Disable an EXISTING firewall filter rule (`disabled=yes`), resolved by
    its `comment` - optionally narrowed by `chain` if more than one rule
    shares that comment. NEVER creates a rule."""
    return _set_firewall_rule_disabled(
        client, settings, "disable_firewall_rule", comment, disabled=True, confirm=confirm, chain=chain
    )


# --- v1.4: NAT & mangle rule toggle (by comment, never create) -----------
#
# enable_nat_rule/disable_nat_rule and enable_mangle_rule/disable_mangle_rule
# extend v0.11's enable_firewall_rule/disable_firewall_rule pattern to the
# other two firewall menus RouterOS exposes read-only today (`firewall_nat`,
# and this round's new `firewall_mangle`): same "admin creates the rule ahead
# of time, disabled, on the device; an LLM caller only ever flips its
# `disabled` field later, resolved by the STABLE `comment` it was given" -
# same lockout reasoning (a wrong NAT/mangle write can be just as disruptive
# as a wrong filter rule - e.g. disabling the masquerade rule that provides a
# whole LAN's Internet access), same never-guesses-which-row resolution
# (ResourceNotFoundError / AmbiguousResourceError), same never-creates
# guarantee. See ROADMAP.md's "Explicitly NOT on the roadmap" table entry -
# rule creation/free-form edit stays out of scope for filter, NAT, AND mangle
# alike, for the identical reason.
#
# `chain` narrows an ambiguous `comment` match exactly like the filter pair -
# NAT's real chains are `srcnat`/`dstnat`, mangle's are `prerouting`/
# `postrouting`/`forward`/`input`/`output` (plus custom jump-target chains on
# either menu), but `validate_firewall_chain` is shape-only, not a fixed
# enum, for the same reason it already isn't for filter: RouterOS allows
# arbitrary custom chains there too.
#
# All four functions below are thin wrappers around the SAME
# `_set_firewall_rule_disabled` helper the filter pair uses (see that
# function's docstring above for why one shared implementation was kept
# instead of copy-pasting it three times) - only `operation_name` (which
# ALLOWLIST entry, and therefore which `op.path` menu) and `resource_label`
# (what an error calls the resolved row) differ per menu.


@_audited("enable_nat_rule")
def enable_nat_rule(
    client: MikrotikClient, settings: Settings, comment: str, confirm: bool, chain: str | None = None
) -> WritePreview:
    """Enable an EXISTING firewall NAT rule (`disabled=no`), resolved by its
    `comment` - optionally narrowed by `chain` (`srcnat`/`dstnat`) if more
    than one rule shares that comment. NEVER creates a rule - see this
    section's module comment above for the full admin-creates/LLM-enables
    workflow (the same one enable_firewall_rule uses for /ip/firewall/filter)."""
    return _set_firewall_rule_disabled(
        client,
        settings,
        "enable_nat_rule",
        comment,
        disabled=False,
        confirm=confirm,
        chain=chain,
        resource_label="Firewall NAT rule",
    )


@_audited("disable_nat_rule")
def disable_nat_rule(
    client: MikrotikClient, settings: Settings, comment: str, confirm: bool, chain: str | None = None
) -> WritePreview:
    """Disable an EXISTING firewall NAT rule (`disabled=yes`), resolved by
    its `comment` - optionally narrowed by `chain`. Same resolution/
    never-creates guarantee as `enable_nat_rule`."""
    return _set_firewall_rule_disabled(
        client,
        settings,
        "disable_nat_rule",
        comment,
        disabled=True,
        confirm=confirm,
        chain=chain,
        resource_label="Firewall NAT rule",
    )


@_audited("enable_mangle_rule")
def enable_mangle_rule(
    client: MikrotikClient, settings: Settings, comment: str, confirm: bool, chain: str | None = None
) -> WritePreview:
    """Enable an EXISTING firewall mangle rule (`disabled=no`), resolved by
    its `comment` - optionally narrowed by `chain` (e.g. `prerouting`/
    `postrouting`/`forward`/`input`/`output`) if more than one rule shares
    that comment. NEVER creates a rule."""
    return _set_firewall_rule_disabled(
        client,
        settings,
        "enable_mangle_rule",
        comment,
        disabled=False,
        confirm=confirm,
        chain=chain,
        resource_label="Firewall mangle rule",
    )


@_audited("disable_mangle_rule")
def disable_mangle_rule(
    client: MikrotikClient, settings: Settings, comment: str, confirm: bool, chain: str | None = None
) -> WritePreview:
    """Disable an EXISTING firewall mangle rule (`disabled=yes`), resolved by
    its `comment` - optionally narrowed by `chain`. Same resolution/
    never-creates guarantee as `enable_mangle_rule`."""
    return _set_firewall_rule_disabled(
        client,
        settings,
        "disable_mangle_rule",
        comment,
        disabled=True,
        confirm=confirm,
        chain=chain,
        resource_label="Firewall mangle rule",
    )


# --- v0.13: WireGuard VPN management -----------------------------------
#
# The most security-sensitive round in this package's history: WireGuard
# uses PRIVATE KEYS. Absolute rule, enforced here (not just in server.py):
# no WritePreview this section returns may EVER carry a `private-key` or
# `preshared-key` field.
#
# WHY the redaction happens HERE, inside guard.py, and not one layer up in
# server.py: the `_audited` decorator wraps every function below and calls
# audit.record() with exactly `result.before`/`result.after` - whatever the
# wrapped function returns, BEFORE server.py (the tool wrapper) ever sees it.
# If a private-key were only stripped in server.py, it would already be
# sitting in the audit journal (a file on disk, or a log line) by the time
# server.py got a chance to redact it. So every function below builds its
# `before`/`after` through `_redact_wireguard_row` (which applies
# `formatting.strip_sensitive_fields` with `formatting.WIREGUARD_SENSITIVE_FIELDS`
# - `{"private-key", "preshared-key"}`) BEFORE constructing the WritePreview
# that `_audited` will log. `audit._SENSITIVE_KEY` (extended this round to
# also match `private`) is a SECOND, independent line of defense on top of
# that - not a substitute for it.
#
# add_wireguard_interface never accepts a private-key parameter at all (there
# is no code path through which a caller could ever supply one - RouterOS
# generates it internally on creation, exactly the same "genuinely absent
# parameter" pattern v0.9's add_netwatch used for up-script/down-script -
# see test_add_wireguard_interface_never_accepts_a_private_key_parameter).
# add_wireguard_peer never accepts a private-key OR preshared-key parameter
# either - the remote peer's own private key, and any preshared key, are
# both entirely out of this tool's scope.


def _redact_wireguard_row(row: dict[str, Any]) -> dict[str, Any]:
    """Strip `private-key`/`preshared-key` from one WireGuard row - see this
    section's module note above for why this must run before a WritePreview
    is ever constructed, not after."""
    return strip_sensitive_fields([row], WIREGUARD_SENSITIVE_FIELDS)[0]


@_audited("add_wireguard_interface")
def add_wireguard_interface(
    client: MikrotikClient, settings: Settings, name: str, confirm: bool, listen_port: int | None = None
) -> WritePreview:
    """Create a WireGuard tunnel interface (`/interface/wireguard add`).

    RouterOS generates the interface's private-key internally - this
    function has no `private_key` parameter at all, and never returns one
    (see module note above).

    The `confirm=False` preview's `after` deliberately does NOT invent a
    `public-key` value: RouterOS hasn't generated the key pair yet at
    preview time, so `after` only describes what will be created (`name`,
    `listen-port` if given). Only the `confirm=True` applied result re-reads
    the newly created interface and reports its real `public-key` - with
    `private-key` (and any `preshared-key`-shaped field, defensively)
    stripped via `_redact_wireguard_row`.

    Refuses to create a second interface sharing `name` - raises
    ResourceAlreadyExistsError instead of creating a duplicate.
    """
    op = _require_allowed(settings, "add_wireguard_interface")

    validated_name = validate_interface_name(name)
    validated_listen_port = validate_port(listen_port, "listen_port") if listen_port is not None else None

    rows = client.path(*op.path)
    if _find_row_by_field(rows, "name", validated_name) is not None:
        raise ResourceAlreadyExistsError(client.device.name, "WireGuard interface", validated_name)

    payload: dict[str, Any] = {"name": validated_name}
    if validated_listen_port is not None:
        payload["listen-port"] = str(validated_listen_port)

    before: dict[str, Any] = {}
    after = dict(payload)

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    write(*op.path, **payload)

    new_rows = client.path(*op.path)
    new_row = _find_row_by_field(new_rows, "name", validated_name)
    after = _redact_wireguard_row(dict(new_row)) if new_row is not None else dict(payload)

    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)


@_audited("add_wireguard_peer")
def add_wireguard_peer(
    client: MikrotikClient,
    settings: Settings,
    interface: str,
    public_key: str,
    allowed_address: str,
    confirm: bool,
    endpoint_address: str | None = None,
    endpoint_port: int | None = None,
    persistent_keepalive: str | None = None,
    comment: str | None = None,
) -> WritePreview:
    """Add a WireGuard peer (`/interface/wireguard/peers add`) to an
    existing tunnel `interface`.

    `public_key` is the REMOTE peer's own public key (base64, 44 chars -
    `validate_wireguard_key`). `allowed_address` is a comma-separated list of
    CIDR ranges routed through this peer (`validate_allowed_address_list`).
    `endpoint_address`/`endpoint_port` (the peer's reachable address, if it
    has one) and `persistent_keepalive` (a RouterOS duration, e.g. "25s") are
    optional.

    Has NO `private_key`/`preshared_key` parameter at all - there is no code
    path through which either could ever be sent to the device via this
    function (see module note above); the remote peer's own private key is
    entirely out of scope.

    `interface` must already exist (`/interface/wireguard`) - raises
    ResourceNotFoundError otherwise; this function never creates one (use
    add_wireguard_interface first). Refuses to add a duplicate peer - the
    same `public_key` already registered on the same `interface` - raises
    ResourceAlreadyExistsError instead.
    """
    op = _require_allowed(settings, "add_wireguard_peer")

    validated_interface = validate_interface_name(interface)
    validated_public_key = validate_wireguard_key(public_key, "public_key")
    validated_allowed_address = validate_allowed_address_list(allowed_address)
    validated_endpoint_address = validate_ping_address(endpoint_address) if endpoint_address is not None else None
    validated_endpoint_port = validate_port(endpoint_port, "endpoint_port") if endpoint_port is not None else None
    validated_keepalive = (
        validate_timeout(persistent_keepalive, "persistent_keepalive") if persistent_keepalive is not None else None
    )
    validated_comment = validate_comment(comment) if comment is not None else None

    interface_rows = client.path("interface", "wireguard")
    if _find_row_by_field(interface_rows, "name", validated_interface) is None:
        raise ResourceNotFoundError(client.device.name, "WireGuard interface", validated_interface)

    rows = client.path(*op.path)
    duplicate = [
        row
        for row in rows
        if row.get("interface") == validated_interface and row.get("public-key") == validated_public_key
    ]
    if duplicate:
        raise ResourceAlreadyExistsError(client.device.name, "WireGuard peer", validated_public_key)

    payload: dict[str, Any] = {
        "interface": validated_interface,
        "public-key": validated_public_key,
        "allowed-address": validated_allowed_address,
    }
    if validated_endpoint_address is not None:
        payload["endpoint-address"] = validated_endpoint_address
    if validated_endpoint_port is not None:
        payload["endpoint-port"] = str(validated_endpoint_port)
    if validated_keepalive is not None:
        payload["persistent-keepalive"] = validated_keepalive
    if validated_comment is not None:
        payload["comment"] = validated_comment

    before: dict[str, Any] = {}
    after = _redact_wireguard_row(dict(payload))

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    write(*op.path, **payload)
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)


@_audited("remove_wireguard_peer")
def remove_wireguard_peer(
    client: MikrotikClient,
    settings: Settings,
    interface: str,
    confirm: bool,
    public_key: str | None = None,
    comment: str | None = None,
) -> WritePreview:
    """Remove a WireGuard peer (`/interface/wireguard/peers remove`) from
    `interface`, resolved by `public_key` or `comment` (`public_key` tried
    first if both are given). At least one of the two must be given.

    Raises ResourceNotFoundError if nothing matches. Raises
    AmbiguousResourceError if more than one row still matches (e.g. two
    peers sharing the same `comment` on the same interface) - never guesses
    which one to remove.
    """
    op = _require_allowed(settings, "remove_wireguard_peer")

    validated_interface = validate_interface_name(interface)

    if not public_key and not comment:
        raise ValidationError("remove_wireguard_peer requires 'public_key' or 'comment'.")

    validated_public_key = validate_wireguard_key(public_key, "public_key") if public_key else None
    validated_comment = validate_comment(comment) if comment is not None else None

    rows = client.path(*op.path)
    matches = [row for row in rows if row.get("interface") == validated_interface]
    if validated_public_key is not None:
        matches = [row for row in matches if row.get("public-key") == validated_public_key]
    elif validated_comment is not None:
        matches = [row for row in matches if row.get("comment") == validated_comment]

    identifier = validated_public_key or validated_comment or ""
    if not matches:
        raise ResourceNotFoundError(client.device.name, "WireGuard peer", identifier)
    if len(matches) > 1:
        raise AmbiguousResourceError(
            client.device.name,
            "WireGuard peer",
            identifier,
            [row.get("comment") or row.get("public-key", "") for row in matches],
        )

    row = matches[0]
    before = _redact_wireguard_row(dict(row))
    after: dict[str, Any] = {}

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    write(*op.path, ids=(row.get(".id"),))
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)


# --- v0.14: hotspot vouchers + backup ---------------------------------------
#
# The last feature round before 1.0. Two independent tools, neither touching
# any menu a previous round already guards:
#   - add_hotspot_user creates a `/ip/hotspot/user` row - a VISITOR login
#     voucher, not a device/API credential. Its password is deliberately
#     handled the OPPOSITE way v0.13's WireGuard private-key is: WireGuard's
#     private-key must never reach the CALLER (RouterOS-internal only,
#     stripped from every return value); a voucher's password is the whole
#     POINT of the tool - the caller needs it to hand to a visitor - so it
#     DOES appear in this function's returned WritePreview.after (and, one
#     layer up, in server.py's `qr_payload`). It must still never reach the
#     audit journal, though - see add_hotspot_user's own docstring below for
#     exactly how that asymmetry is enforced (spoiler: no new code was
#     needed - audit._SENSITIVE_KEY already matches "password", and it
#     applies to ANY dict key at ANY depth in the summary `_audited` logs,
#     not just a device's own connection password).
#   - create_backup is a third ACTION-command entry (after start/stop, v0.7,
#     and flush/wol, v0.10) - "save" is RouterOS's own literal command word
#     for /system/backup/save. Its optional `password` (encrypts the backup
#     FILE - unrelated to a device/API credential) is redacted BEFORE the
#     WritePreview is constructed, the same "redact before constructing the
#     preview" rule v0.13 established for WireGuard's private/preshared
#     keys - see _redact_wireguard_row's usage above - so it can never reach
#     the journal even as a first line of defense, on top of
#     audit._SENSITIVE_KEY's second one.


@_audited("add_hotspot_user")
def add_hotspot_user(
    client: MikrotikClient,
    settings: Settings,
    name: str,
    password: str,
    confirm: bool,
    profile: str | None = None,
    limit_uptime: str | None = None,
    limit_bytes_total: int | None = None,
) -> WritePreview:
    """Create a hotspot voucher user (`/ip/hotspot/user add`) for a visitor.

    `profile` (an existing `/ip/hotspot/user/profile` name - not verified to
    exist here; RouterOS itself rejects an unknown one at write time),
    `limit_uptime` (a RouterOS duration, e.g. "01:00:00" -
    `validate_timeout`), and `limit_bytes_total` (a positive integer byte
    quota - `validate_byte_count`) are all optional.

    PASSWORD ASYMMETRY (read this before touching this function): the
    plaintext `password` is the whole point of a voucher - the visitor needs
    it - so it DOES appear in this function's returned `WritePreview.after`
    (both on `confirm=false` preview and `confirm=true` applied - see
    server.py's `add_hotspot_user` tool, which builds `qr_payload` straight
    from it). This is the OPPOSITE of v0.13's WireGuard private-key handling
    (never returned to any caller at all) - deliberately, because a voucher
    password's only purpose is to be handed to someone.

    It must still NEVER reach the audit journal. `_audited` (this function's
    decorator) journals exactly whatever this function returns - so if
    `password` merely stayed out of the RETURN value, it would already be
    safe from the journal too; the fact that it's deliberately IN the return
    value makes this the one write tool in this package where "safe in the
    result" and "safe in the journal" pull in opposite directions. The
    journal side is still covered: `audit._SENSITIVE_KEY` matches "password"
    case-insensitively and `audit._sanitize` drops any dict key matching it
    at ANY depth of the `{"before": ..., "after": ...}` summary `_audited`
    logs - so the exact same `after` dict returned here gets its `password`
    key silently dropped before it ever reaches `audit.record()`'s caller.
    No new redaction code was needed for this - it falls out of the existing
    device-password protection `_SENSITIVE_KEY` already provided. See
    `tests/test_guard_audit.py`'s
    `test_add_hotspot_user_password_never_in_audit_journal` for the proof.

    Refuses to create a duplicate `name` - raises ResourceAlreadyExistsError
    instead of creating a second voucher (or silently resetting the first
    one's password). This tool only ever adds; it never updates or removes
    an existing hotspot user.
    """
    op = _require_allowed(settings, "add_hotspot_user")

    validated_name = validate_hotspot_username(name)
    validated_password = validate_hotspot_password(password)
    validated_profile = validate_hotspot_profile(profile) if profile is not None else None
    validated_limit_uptime = validate_timeout(limit_uptime, "limit_uptime") if limit_uptime is not None else None
    validated_limit_bytes = (
        validate_byte_count(limit_bytes_total, "limit_bytes_total") if limit_bytes_total is not None else None
    )

    rows = client.path(*op.path)
    if _find_row_by_field(rows, "name", validated_name) is not None:
        raise ResourceAlreadyExistsError(client.device.name, "Hotspot user", validated_name)

    payload: dict[str, Any] = {"name": validated_name, "password": validated_password}
    if validated_profile:
        payload["profile"] = validated_profile
    if validated_limit_uptime:
        payload["limit-uptime"] = validated_limit_uptime
    if validated_limit_bytes is not None:
        payload["limit-bytes-total"] = validated_limit_bytes

    before: dict[str, Any] = {}
    after = dict(payload)

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    write(*op.path, **payload)
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)


@_audited("create_backup")
def create_backup(
    client: MikrotikClient, settings: Settings, name: str, confirm: bool, password: str | None = None
) -> WritePreview:
    """Create a RouterOS system backup file (`/system/backup/save
    name=<name>`) - captures the device's FULL configuration (interfaces,
    firewall, users, ...) into one binary `.backup` file on the device's own
    storage. Use the read-only `list_backups` tool afterward to confirm it
    landed and see its real size/creation-time.

    `password`, if given, is RouterOS's own `/system/backup/save
    password=<password>` option - it encrypts the backup FILE itself, and is
    entirely unrelated to any device/API credential. It is redacted (never
    included in `before`/`after`) BEFORE the `WritePreview` this returns is
    ever constructed - the same "redact before constructing the preview"
    rule v0.13's WireGuard round established for private/preshared keys (see
    the module note above `_redact_wireguard_row`) - so it can't reach the
    audit journal even as a first line of defense, on top of
    `audit._SENSITIVE_KEY` (which already matches "password" too) as a
    second, independent one.

    The `after` preview only describes the (validated) file `name` that WILL
    be created - RouterOS decides the real on-device size/creation-time
    itself, which `list_backups` surfaces afterward; this write does not
    re-read the file it just created.

    Refuses to overwrite: if a `.backup` file matching `name` already exists
    on the device (`/file`, the same menu `list_backups` reads and filters),
    raises `ResourceAlreadyExistsError` instead of silently overwriting it -
    RouterOS's own `/system/backup/save` WOULD silently overwrite an
    existing file of the same name; this check exists purely in this
    package, before the command is ever sent.
    """
    op = _require_allowed(settings, "create_backup")

    validated_name = validate_backup_name(name)
    validated_password = validate_backup_password(password) if password is not None else None

    full_name = validated_name if validated_name.endswith(".backup") else f"{validated_name}.backup"
    file_rows = client.path("file")
    if any(row.get("name") == full_name for row in file_rows):
        raise ResourceAlreadyExistsError(client.device.name, "Backup file", full_name)

    before: dict[str, Any] = {}
    after: dict[str, Any] = {"name": validated_name}

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    if validated_password is not None:
        write(*op.path, name=validated_name, password=validated_password)
    else:
        write(*op.path, name=validated_name)
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)


# --- v1.2: VLAN management + firewall rule reorder ---------------------------
#
# Three more guarded writes: add_vlan/remove_vlan (an ordinary named-resource
# add/remove pair against /interface/vlan, following add_static_dns/
# remove_static_dns's shape) and move_firewall_rule (a reorder-only write
# against /ip/firewall/filter, following enable_firewall_rule/
# disable_firewall_rule's comment-based resolution - see ALLOWLIST's own
# comment above these three entries for the "move" action's dispatch shape).


@_audited("add_vlan")
def add_vlan(
    client: MikrotikClient,
    settings: Settings,
    name: str,
    vlan_id: int,
    interface: str,
    confirm: bool,
    mtu: int | None = None,
    comment: str | None = None,
) -> WritePreview:
    """Create a VLAN interface (`/interface/vlan add`): `name` (the new
    RouterOS interface name, e.g. "vlan100"), `vlan_id` (1-4094, the IEEE
    802.1Q tag), and `interface` (the parent interface it rides on top of,
    e.g. "bridge1"/"ether2" - NOT verified to exist here; RouterOS itself
    rejects an unknown parent interface at write time, same as every other
    tool in this package that names an existing-elsewhere resource by string
    - e.g. `add_hotspot_user`'s `profile`). `mtu`/`comment` are optional.

    Refuses to create a duplicate `name` - raises ResourceAlreadyExistsError
    instead of creating a second VLAN interface (or silently reconfiguring
    the first one). This tool only ever adds; it never updates or removes an
    existing VLAN interface.
    """
    op = _require_allowed(settings, "add_vlan")

    validated_name = validate_interface_name(name)
    validated_vlan_id = validate_vlan_id(vlan_id)
    validated_interface = validate_interface_name(interface)
    validated_mtu = validate_mtu(mtu) if mtu is not None else None
    validated_comment = validate_comment(comment) if comment is not None else None

    rows = client.path(*op.path)
    if _find_row_by_field(rows, "name", validated_name) is not None:
        raise ResourceAlreadyExistsError(client.device.name, "VLAN interface", validated_name)

    payload: dict[str, Any] = {
        "name": validated_name,
        "vlan-id": str(validated_vlan_id),
        "interface": validated_interface,
    }
    if validated_mtu is not None:
        payload["mtu"] = str(validated_mtu)
    if validated_comment:
        payload["comment"] = validated_comment

    before: dict[str, Any] = {}
    after = dict(payload)

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    write(*op.path, **payload)
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)


@_audited("remove_vlan")
def remove_vlan(client: MikrotikClient, settings: Settings, name: str, confirm: bool) -> WritePreview:
    """Remove a VLAN interface (`/interface/vlan remove`) by `name`. Raises
    ResourceNotFoundError if no VLAN interface matches - never removes more
    than the one matching row."""
    op = _require_allowed(settings, "remove_vlan")

    validated_name = validate_interface_name(name)

    rows = client.path(*op.path)
    row = _find_row_by_field(rows, "name", validated_name)
    if row is None:
        raise ResourceNotFoundError(client.device.name, "VLAN interface", validated_name)

    before = dict(row)
    after: dict[str, Any] = {}

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    write(*op.path, ids=(row.get(".id"),))
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)


@_audited("move_firewall_rule")
def move_firewall_rule(
    client: MikrotikClient,
    settings: Settings,
    comment: str,
    confirm: bool,
    chain: str | None = None,
    before_comment: str | None = None,
    position: int | None = None,
) -> WritePreview:
    """Reorder an EXISTING firewall filter rule (`/ip/firewall/filter move`),
    resolved by its `comment` - optionally narrowed by `chain` - via the same
    `_find_firewall_rule_rows` resolution `enable_firewall_rule`/
    `disable_firewall_rule` use (see that section's module comment above for
    the full rationale). NEVER creates or otherwise edits a rule's fields -
    only its position in the chain's evaluation order changes.

    Exactly one of `before_comment` (move the rule to appear immediately
    before the EXISTING rule with this comment) or `position` (move the rule
    to this 0-based index among the OTHER rules, i.e. after removing the
    rule being moved from consideration - a `position` at or beyond the end
    of that list moves the rule to the very end) must be given; raises
    ValidationError if both or neither are given.

    Raises ResourceNotFoundError if `comment` (narrowed by `chain`) matches
    no rule, or if `before_comment` is given but matches no rule. Raises
    AmbiguousResourceError if `comment` (or `before_comment`) still matches
    more than one rule - never guesses which one to move, or which one to
    insert before.
    """
    op = _require_allowed(settings, "move_firewall_rule")

    validated_comment = validate_firewall_rule_comment(comment)
    validated_chain = validate_firewall_chain(chain) if chain is not None else None

    if (before_comment is None) == (position is None):
        raise ValidationError("move_firewall_rule requires exactly one of 'before_comment' or 'position'.")

    validated_before_comment = validate_firewall_rule_comment(before_comment) if before_comment is not None else None
    validated_position = validate_firewall_rule_position(position) if position is not None else None

    rows = client.path(*op.path)
    matches = _find_firewall_rule_rows(rows, validated_comment, validated_chain)
    if not matches:
        raise ResourceNotFoundError(client.device.name, "Firewall filter rule", validated_comment)
    if len(matches) > 1:
        raise AmbiguousResourceError(
            client.device.name,
            "Firewall filter rule",
            validated_comment,
            [row.get("chain", "") for row in matches],
        )

    target_row = matches[0]
    target_id = target_row.get(".id")
    current_index = next(i for i, row in enumerate(rows) if row.get(".id") == target_id)
    remaining = [row for row in rows if row.get(".id") != target_id]

    destination_id: str | None
    if validated_before_comment is not None:
        dest_matches = _find_firewall_rule_rows(remaining, validated_before_comment, validated_chain)
        if not dest_matches:
            raise ResourceNotFoundError(client.device.name, "Firewall filter rule", validated_before_comment)
        if len(dest_matches) > 1:
            raise AmbiguousResourceError(
                client.device.name,
                "Firewall filter rule",
                validated_before_comment,
                [row.get("chain", "") for row in dest_matches],
            )
        destination_id = dest_matches[0].get(".id")
        new_index = next(i for i, row in enumerate(remaining) if row.get(".id") == destination_id)
    else:
        assert validated_position is not None  # exactly-one check above guarantees this
        new_index = min(validated_position, len(remaining))
        destination_id = remaining[new_index].get(".id") if new_index < len(remaining) else None

    before = {"comment": target_row.get("comment"), "chain": target_row.get("chain"), "position": current_index}
    after = {"comment": target_row.get("comment"), "chain": target_row.get("chain"), "position": new_index}

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    write(*op.path, id=target_id, destination=destination_id)
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)


# --- v1.3: PPP/PPPoE secrets --------------------------------------------------
#
# add_ppp_secret/remove_ppp_secret manage `/ppp/secret` rows - RouterOS's
# configured dial-in credentials for PPP-based services (PPPoE, PPTP, L2TP,
# OpenVPN, SSTP), as opposed to `ppp_active` (server.py, read-only), which
# lists currently-CONNECTED sessions. A `/ppp/secret` is a *service*
# credential - it only grants network/dial-in access, never router admin
# (unlike a `/user` login, which is deliberately NOT on this package's
# roadmap - see ROADMAP.md's non-goal note) - the same risk class
# `add_hotspot_user` (v0.14) already established a pattern for.
#
# PASSWORD ASYMMETRY (read this before touching add_ppp_secret): exactly
# like `add_hotspot_user`'s voucher password, the plaintext `password` this
# function is given DOES appear in its returned `WritePreview.after` (both
# on `confirm=false` preview and `confirm=true` applied) - the caller
# supplied it themselves, and gets it echoed back as confirmation of exactly
# what was written, the same shape `add_hotspot_user` uses. It must still
# NEVER reach the audit journal: no new redaction code is needed for that -
# `audit._SENSITIVE_KEY` already matches "password" case-insensitively and
# strips it from the `_audited` decorator's journaled summary regardless of
# which function produced it (see add_hotspot_user's own module note above
# for the full mechanism). See tests/test_guard_audit.py's
# `test_add_ppp_secret_password_never_in_audit_journal` for the proof.
#
# remove_ppp_secret redacts the opposite way `add_ppp_secret` does: unlike
# an add (which never reads back an existing row - it only ever proposes a
# fresh `payload`), remove looks up an EXISTING row first, and that row's
# own `password` field must never leak into `before` either - so it is
# stripped here, in guard.py, before the WritePreview is ever constructed
# (the same "redact before constructing the preview" rule v0.13's WireGuard
# round established), on top of `audit._SENSITIVE_KEY` as a second,
# independent line of defense.


def _find_ppp_secret_rows(rows: list[dict[str, Any]], name: str) -> list[dict[str, Any]]:
    """All /ppp/secret rows matching `name`. RouterOS itself expects a
    secret `name` to be unique, but this returns every match rather than
    just the first one - same defensive shape as `_find_static_dns_rows` -
    so `remove_ppp_secret` can raise `AmbiguousResourceError` instead of
    guessing, if the device somehow has more than one."""
    return [row for row in rows if row.get("name") == name]


@_audited("add_ppp_secret")
def add_ppp_secret(
    client: MikrotikClient,
    settings: Settings,
    name: str,
    password: str,
    confirm: bool,
    service: str = "any",
    profile: str | None = None,
    remote_address: str | None = None,
    comment: str | None = None,
) -> WritePreview:
    """Create a PPP/PPPoE secret (`/ppp/secret add`) - a dial-in service
    credential for PPPoE/PPTP/L2TP/OpenVPN/SSTP.

    `service` (default `"any"`) restricts which PPP service the secret may
    authenticate for - must be one of "pppoe"/"pptp"/"l2tp"/"ovpn"/"sstp"/
    "any" (`validate_ppp_service`). `profile` (an existing `/ppp/profile`
    name, e.g. to assign an address pool or rate limit - not verified to
    exist here; RouterOS itself rejects an unknown profile at write time)
    and `remote_address` (a literal IP handed to the client on connect -
    `validate_ip_address`) and `comment` are all optional.

    PASSWORD ASYMMETRY: see the module note above this section - the
    plaintext `password` DOES appear in this function's returned
    `WritePreview.after`, mirroring `add_hotspot_user`'s voucher password,
    but never reaches the audit journal (`audit._SENSITIVE_KEY`).

    Refuses to create a duplicate `name` - raises ResourceAlreadyExistsError
    instead of creating a second secret (or silently resetting the first
    one's password). This tool only ever adds; it never updates or removes
    an existing secret.
    """
    op = _require_allowed(settings, "add_ppp_secret")

    validated_name = validate_ppp_secret_name(name)
    validated_password = validate_ppp_secret_password(password)
    validated_service = validate_ppp_service(service)
    validated_profile = validate_ppp_profile(profile) if profile is not None else None
    validated_remote_address = validate_ip_address(remote_address) if remote_address is not None else None
    validated_comment = validate_comment(comment) if comment is not None else None

    rows = client.path(*op.path)
    if _find_ppp_secret_rows(rows, validated_name):
        raise ResourceAlreadyExistsError(client.device.name, "PPP secret", validated_name)

    payload: dict[str, Any] = {"name": validated_name, "password": validated_password, "service": validated_service}
    if validated_profile:
        payload["profile"] = validated_profile
    if validated_remote_address:
        payload["remote-address"] = validated_remote_address
    if validated_comment:
        payload["comment"] = validated_comment

    before: dict[str, Any] = {}
    after = dict(payload)

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    write(*op.path, **payload)
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)


@_audited("remove_ppp_secret")
def remove_ppp_secret(client: MikrotikClient, settings: Settings, name: str, confirm: bool) -> WritePreview:
    """Remove a PPP/PPPoE secret (`/ppp/secret remove`) by `name`.

    Raises ResourceNotFoundError if no secret matches. Raises
    AmbiguousResourceError if more than one row matches `name` - never
    guesses which one to remove.

    SECURITY: the matched row's `password` field is stripped from `before`
    here, in guard.py, BEFORE the WritePreview is ever constructed - see the
    module note above this section - so a remove_ppp_secret preview/journal
    entry can never carry the secret being removed, on top of
    `audit._SENSITIVE_KEY`'s own independent redaction.
    """
    op = _require_allowed(settings, "remove_ppp_secret")

    validated_name = validate_ppp_secret_name(name)

    rows = client.path(*op.path)
    matches = _find_ppp_secret_rows(rows, validated_name)

    if not matches:
        raise ResourceNotFoundError(client.device.name, "PPP secret", validated_name)
    if len(matches) > 1:
        raise AmbiguousResourceError(
            client.device.name,
            "PPP secret",
            validated_name,
            [row.get("service", "") for row in matches],
        )

    row = matches[0]
    before = strip_sensitive_fields([dict(row)], {"password"})[0]
    after: dict[str, Any] = {}

    if not confirm:
        return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=False)

    write = getattr(client, op.action)
    write(*op.path, ids=(row.get(".id"),))
    return WritePreview(operation=op.name, device=client.device.name, before=before, after=after, applied=True)


# --- v1.8: NTP client servers -----------------------------------------------


@_audited("set_ntp_servers")
def set_ntp_servers(client: MikrotikClient, settings: Settings, servers: list[str], confirm: bool) -> WritePreview:
    """Set the NTP server(s) a device syncs its clock against
    (`/system/ntp/client`). See `server.py`'s `ntp_client` read tool for the
    field shapes this reads back afterward.

    `servers` must have at least one entry; each is validated as an IPv4/
    IPv6 address OR hostname (`validate_ping_address`, same shape `ping`/
    `add_wireguard_peer`'s `endpoint_address` already accept) BEFORE
    anything is read from the device - fail fast on a caller mistake rather
    than partway through resolving which RouterOS generation is in play.

    GENERATION DETECTION: `/system/ntp/client` is the SAME RouterOS path on
    both generations (unlike `set_wifi_ssid`'s genuinely different
    `/interface/wifi` vs `/interface/wireless` menus) - only the FIELD SHAPE
    differs. This reads the row once and checks which field is present -
    `servers` (ROS7's single comma-joined list) or `primary-ntp` (ROS6's
    fixed two-slot form) - mirroring `set_wifi_ssid`'s own "read first, then
    decide" detection. A device with neither field yet (e.g. a completely
    default/never-configured NTP client) is treated as ROS7 - the newer,
    more common shape - since there is nothing on the row to detect ROS6
    from.

    ROS7: writes the full comma-joined `servers` list, e.g. "1.2.3.4,pool.
    ntp.org" - the raw device string is never split into a list on the read
    side either (see `ntp_client`'s docstring), so this stays symmetric.

    ROS6: has no `servers` list at all - only two fixed slots. `servers[0]`
    maps to `primary-ntp`, `servers[1]` (if given) to `secondary-ntp`; any
    entries beyond the first two are DROPPED, never silently - `warning`
    names exactly which ones were ignored. Older ROS6 firmware only accepts
    a literal IP in either slot (`validation.is_literal_ip_address`); a
    hostname destined for one of those two slots is instead folded into
    `server-dns-names` (RouterOS's own DNS-name field for this menu) IF the
    device's row shows that field exists - never guessed at otherwise. If it
    doesn't exist, that hostname is NOT applied at all (never sent as a
    value RouterOS would likely reject) and `warning` says so. If nothing at
    all ends up applicable (every given server is a hostname the device has
    no way to accept), this raises `ValidationError` rather than silently
    performing a no-op write.

    Never enables/disables the NTP client itself - only the server
    field(s) change. If the client's `enabled` field (`formatting.
    coerce_ros_bool`) reads as `False`, `warning` says so too: new servers
    configured on a disabled client won't actually be used until it's
    enabled separately (out of scope for this tool - see `ROADMAP.md`).
    """
    op = _require_allowed(settings, "set_ntp_servers")

    if not servers:
        raise ValidationError("At least one NTP server must be given.")
    validated_servers = [validate_ping_address(server) for server in servers]

    rows = client.path(*op.path)
    before = dict(rows[0]) if rows else {}
    after = dict(before)

    warnings: list[str] = []
    if coerce_ros_bool(before.get("enabled")) is False:
        warnings.append(
            "NTP client is currently disabled (enabled=no) - servers will be set, "
            "but won't be used until the client is enabled separately."
        )

    fields: dict[str, Any] = {}
    is_ros6 = "servers" not in before and "primary-ntp" in before

    if is_ros6:
        if len(validated_servers) > 2:
            ignored = validated_servers[2:]
            warnings.append(
                f"ROS6 only has two NTP server slots (primary-ntp/secondary-ntp) - "
                f"ignoring {len(ignored)} extra server(s): {', '.join(ignored)}."
            )
        slots = [("primary-ntp", validated_servers[0])]
        if len(validated_servers) > 1:
            slots.append(("secondary-ntp", validated_servers[1]))

        dns_names: list[str] = []
        for field_name, value in slots:
            if is_literal_ip_address(value):
                fields[field_name] = value
                after[field_name] = value
            elif "server-dns-names" in before:
                dns_names.append(value)
            else:
                warnings.append(
                    f"{field_name}={value!r} is a hostname, but this ROS6 device has no "
                    "server-dns-names field and older ROS6 firmware only accepts a literal "
                    f"IP in {field_name} - not applied."
                )

        if dns_names:
            joined = ",".join(dns_names)
            fields["server-dns-names"] = joined
            after["server-dns-names"] = joined

        if not fields:
            raise ValidationError(
                "None of the given NTP servers could be applied to this ROS6 device "
                "(all hostnames, no server-dns-names field, and no literal IP given)."
            )
    else:
        joined = ",".join(validated_servers)
        fields["servers"] = joined
        after["servers"] = joined

    warning = " ".join(warnings) if warnings else None

    if not confirm:
        return WritePreview(
            operation=op.name, device=client.device.name, before=before, after=after, applied=False, warning=warning
        )

    write = getattr(client, op.action)
    write(*op.path, **fields)
    return WritePreview(
        operation=op.name, device=client.device.name, before=before, after=after, applied=True, warning=warning
    )
