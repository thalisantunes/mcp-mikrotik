"""MCP server entrypoint.

Registers the read tools plus every guarded write tool (set_identity,
enable_interface/disable_interface, set_wifi_ssid, set_client_bandwidth,
add_static_dhcp_lease, remove_simple_queue, add_to_address_list,
remove_from_address_list, set_poe_out, start_container/stop_container - see
guard.py's ALLOWLIST for the full write-tool inventory). Transport is stdio only - this process is meant to run on the
operator's own machine, launched by an MCP client (e.g. Claude Code) over
stdio, with no network exposure at all.

TODO(http-transport): if a streamable-http transport is added later, it
MUST default to binding 127.0.0.1 (never 0.0.0.0) and MUST require a bearer
token supplied via an environment variable, checked on every request. Do not
add HTTP transport without both of those in place.
"""

from __future__ import annotations

import contextlib
import functools
import logging
import os
from dataclasses import asdict
from typing import Any, AsyncIterator

from mcp.server.fastmcp import FastMCP

from . import correlation, guard
from .client import ClientFactory, ClientPool, MikrotikClient, get_client
from .config import Settings, load_settings
from .exceptions import DeviceCommandError, MikrotikMCPError
from .formatting import filter_disabled, rows_to_list
from .validation import validate_interface_name, validate_ping_address, validate_positive_limit

logger = logging.getLogger("mcp_mikrotik")

DEFAULT_LOG_LIMIT = 50
MAX_LOG_LIMIT = 500
DEFAULT_PING_COUNT = 4
MAX_PING_COUNT = 20
MAX_ROUTE_LIMIT = 500
# Traceroute is capped tightly (count, max_hops, and a fixed 1s per-hop
# timeout baked into MikrotikClient.traceroute) so the worst case - every
# hop timing out - stays well under RouterOS's own ~60s API command timeout:
# MAX_TRACEROUTE_MAX_HOPS * MAX_TRACEROUTE_COUNT * 1s = 20s.
DEFAULT_TRACEROUTE_COUNT = 1
MAX_TRACEROUTE_COUNT = 2
DEFAULT_TRACEROUTE_MAX_HOPS = 10
MAX_TRACEROUTE_MAX_HOPS = 10

_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_DEFAULT_LOG_LEVEL = "INFO"


def build_server(settings: Settings | None = None, client_factory: ClientFactory = get_client) -> FastMCP:
    """Build the FastMCP server and register every tool.

    `settings` and `client_factory` are injectable so tests can run the
    exact tool functions registered here against a fake device layer,
    without touching environment variables or a real router.
    """
    settings = settings or load_settings()
    # N2+N3: one MikrotikClient (and its underlying connection) per device
    # name, reused across tool calls instead of reconnecting every time, and
    # closed deterministically by the lifespan hook below rather than
    # leaking sockets until GC - see client.ClientPool's docstring.
    pool = ClientPool(settings, client_factory)

    @contextlib.asynccontextmanager
    async def _lifespan(_server: FastMCP) -> AsyncIterator[dict[str, Any]]:
        try:
            yield {}
        finally:
            pool.close_all()

    mcp = FastMCP("mikrotik", lifespan=_lifespan)

    def _client(device_name: str) -> MikrotikClient:
        return pool.get(device_name)

    def _safe(fn):
        """Make sure nothing unexpected leaks a raw traceback or a secret,
        and give every call (read or write) a short correlation id (v0.5)
        that ties its logs - and, for write tools, its audit journal entry
        (see guard.py's `_audited`) - back to one specific call end to end.

        Deliberately re-raises rather than returning an error dict: each
        tool's return type is annotated (e.g. `list[dict[str, Any]]`) and
        FastMCP validates successful results against that schema, so an
        error path can't return a different shape without tripping output
        validation. Letting a clean exception propagate instead lets
        FastMCP/MCP's own error path turn it into a proper isError tool
        result carrying just the exception's message - see
        MikrotikMCPError subclasses in exceptions.py, whose messages are
        already safe to show a caller. The correlation id is prefixed onto
        the server-side log line only - never appended to the exception's
        own message - so no caller-facing error text changes shape.

        Uses functools.wraps (not just __name__/__doc__) so FastMCP's schema
        introspection - which follows __wrapped__ - still sees the original
        function's parameter names/types instead of a generic (*args, **kwargs).
        """

        @functools.wraps(fn)
        def inner(*args: Any, **kwargs: Any) -> Any:
            with correlation.bind() as correlation_id:
                try:
                    return fn(*args, **kwargs)
                except MikrotikMCPError as exc:
                    logger.info("[%s] tool %s failed: %s", correlation_id, fn.__name__, exc)
                    raise
                except Exception:
                    logger.exception("[%s] Unhandled error in tool %s", correlation_id, fn.__name__)
                    raise RuntimeError("Internal error handling this tool call; see server logs.") from None

        return inner

    # --- Read tools ---------------------------------------------------

    @mcp.tool()
    @_safe
    def list_devices() -> list[dict[str, Any]]:
        """List configured MikroTik devices. Read-only; passwords are never included."""
        return [device.to_public_dict() for device in settings.devices.values()]

    @mcp.tool()
    @_safe
    def system_info(device_name: str) -> dict[str, Any]:
        """Get RouterOS identity + resource info (board, version, uptime, CPU/memory)."""
        client = _client(device_name)
        identity = client.path("system", "identity")
        resource = client.path("system", "resource")
        return {
            "identity": identity[0] if identity else {},
            "resource": resource[0] if resource else {},
        }

    @mcp.tool()
    @_safe
    def interfaces(device_name: str, include_disabled: bool = False) -> list[dict[str, Any]]:
        """List network interfaces on a device."""
        client = _client(device_name)
        return filter_disabled(client.path("interface"), include_disabled)

    @mcp.tool()
    @_safe
    def ip_addresses(device_name: str) -> list[dict[str, Any]]:
        """List IPv4 addresses configured on a device."""
        client = _client(device_name)
        return rows_to_list(client.path("ip", "address"))

    @mcp.tool()
    @_safe
    def ip_routes(device_name: str, limit: int | None = None) -> list[dict[str, Any]]:
        """List the IPv4 routing table of a device.

        `limit`, if given, caps the number of rows returned (capped at 500);
        omit it to get the full table, mirroring `logs`' `limit` parameter.
        """
        client = _client(device_name)
        rows = rows_to_list(client.path("ip", "route"))
        if limit is not None:
            capped_limit = validate_positive_limit(limit, MAX_ROUTE_LIMIT, "limit")
            rows = rows[:capped_limit]
        return rows

    @mcp.tool()
    @_safe
    def neighbors(device_name: str) -> list[dict[str, Any]]:
        """List neighbors discovered via RouterOS neighbor discovery (CDP/MNDP/LLDP)."""
        client = _client(device_name)
        return rows_to_list(client.path("ip", "neighbor"))

    @mcp.tool()
    @_safe
    def dhcp_leases(device_name: str) -> list[dict[str, Any]]:
        """List DHCP server leases (address, mac, host-name, status, server, comment)."""
        client = _client(device_name)
        return rows_to_list(client.path("ip", "dhcp-server", "lease"))

    @mcp.tool()
    @_safe
    def simple_queues(device_name: str) -> list[dict[str, Any]]:
        """List Simple Queue entries (/queue/simple): name, target, max-limit,
        limit-at, bytes counters, disabled. Use this to see which clients
        already have a bandwidth limit and how much traffic they've moved
        (the `bytes` counter), before deciding who to limit with
        set_client_bandwidth.
        """
        client = _client(device_name)
        return rows_to_list(client.path("queue", "simple"))

    @mcp.tool()
    @_safe
    def address_lists(device_name: str) -> list[dict[str, Any]]:
        """List firewall address-list entries (/ip/firewall/address-list):
        list, address, timeout, dynamic, disabled. See who's currently in
        which named list (e.g. a "blocked-clients" list a firewall rule
        drops), before adding/removing entries with add_to_address_list /
        remove_from_address_list.
        """
        client = _client(device_name)
        return rows_to_list(client.path("ip", "firewall", "address-list"))

    @mcp.tool()
    @_safe
    def firewall_nat(device_name: str) -> list[dict[str, Any]]:
        """List IPv4 firewall NAT rules (/ip/firewall/nat): chain, action,
        to-addresses, etc. Read-only - does not add/modify/remove rules.
        """
        client = _client(device_name)
        return rows_to_list(client.path("ip", "firewall", "nat"))

    @mcp.tool()
    @_safe
    def scheduler(device_name: str) -> list[dict[str, Any]]:
        """List scheduled tasks (/system/scheduler): name, on-event,
        interval, next-run, disabled. Read-only.
        """
        client = _client(device_name)
        return rows_to_list(client.path("system", "scheduler"))

    @mcp.tool()
    @_safe
    def ip_pools(device_name: str) -> list[dict[str, Any]]:
        """List IP pools (/ip/pool): name, ranges. Read-only."""
        client = _client(device_name)
        return rows_to_list(client.path("ip", "pool"))

    @mcp.tool()
    @_safe
    def wireless_registrations(device_name: str) -> list[dict[str, Any]]:
        """List wireless clients currently associated to the device (mac, signal, interface, uptime).

        RouterOS exposes this under two different paths depending on
        generation: ROS7's wifi package (/interface/wifi/registration-table)
        or ROS6's wireless package (/interface/wireless/registration-table).
        This tries ROS7 first, falls back to ROS6, and returns an empty list
        - rather than raising - for a device with no wireless radio at all
        (or the relevant package not installed), since that is a completely
        normal, expected state for a wired-only device.
        """
        client = _client(device_name)
        for segments in (
            ("interface", "wifi", "registration-table"),
            ("interface", "wireless", "registration-table"),
        ):
            try:
                return rows_to_list(client.path(*segments))
            except DeviceCommandError:
                continue
        return []

    @mcp.tool()
    @_safe
    def dns_cache(device_name: str) -> list[dict[str, Any]]:
        """List cached DNS records on the device (name, type, data, ttl)."""
        client = _client(device_name)
        return rows_to_list(client.path("ip", "dns", "cache"))

    @mcp.tool()
    @_safe
    def firewall_filter(device_name: str) -> list[dict[str, Any]]:
        """List IPv4 firewall filter rules (chain, action, etc). Read-only - does not add/modify/remove rules."""
        client = _client(device_name)
        return rows_to_list(client.path("ip", "firewall", "filter"))

    @mcp.tool()
    @_safe
    def system_health(device_name: str) -> list[dict[str, Any]]:
        """Read system health metrics (e.g. voltage, temperature), if the device exposes them.

        Not every RouterOS device/board type has health sensors (e.g. some
        CHR/virtual instances have none) - in that case this returns an
        empty list instead of raising.
        """
        client = _client(device_name)
        try:
            return rows_to_list(client.path("system", "health"))
        except DeviceCommandError:
            return []

    @mcp.tool()
    @_safe
    def logs(device_name: str, limit: int = DEFAULT_LOG_LIMIT, topics: str | None = None) -> list[dict[str, Any]]:
        """Read recent RouterOS log entries (most recent last).

        `limit` must be positive and is capped at 500. `topics`, if given, is
        matched as a plain substring against each entry's topics field - no
        regex, no unbounded scans - and is applied BEFORE the `limit` cut:
        the full log is filtered by `topics` first, then the last `limit`
        matching entries are returned (not the last `limit` raw entries,
        then filtered - that would silently drop matches).

        R1: this reads the whole `/log` table via librouteros' path().select()
        and slices in Python rather than asking RouterOS for only the last
        `limit` rows. librouteros' structured API doesn't expose a clean
        "give me only the tail" query for /log (RouterOS's own count-only
        print flags aren't reachable through path().select() the way a
        `.limit()`/offset would be), so a "request fewer rows" optimization
        here would mean building a fragile ad-hoc workaround for a table
        that is small in practice (a few hundred to low thousands of rows on
        RouterOS's own ring buffer). Left as-is; revisit if a real device
        turns out to have a much larger log buffer than expected.
        """
        client = _client(device_name)
        capped_limit = validate_positive_limit(limit, MAX_LOG_LIMIT, "limit")
        rows = rows_to_list(client.path("log"))
        if topics:
            rows = [row for row in rows if topics in row.get("topics", "")]
        return rows[-capped_limit:]

    @mcp.tool()
    @_safe
    def ping(device_name: str, address: str, count: int = DEFAULT_PING_COUNT) -> list[dict[str, Any]]:
        """Ping an address from a device. `address` must be a valid IPv4/IPv6 address or hostname."""
        validated_address = validate_ping_address(address)
        capped_count = validate_positive_limit(count, MAX_PING_COUNT, "count")
        client = _client(device_name)
        return client.ping(validated_address, count=capped_count)

    @mcp.tool()
    @_safe
    def traceroute(
        device_name: str,
        address: str,
        count: int = DEFAULT_TRACEROUTE_COUNT,
        max_hops: int = DEFAULT_TRACEROUTE_MAX_HOPS,
    ) -> list[dict[str, Any]]:
        """Traceroute to an address from a device; returns the list of hops.

        `address` must be a valid IPv4/IPv6 address or hostname (validated
        exactly like `ping`'s). `count` (probes per hop) and `max_hops` are
        both capped low (see MAX_TRACEROUTE_COUNT/MAX_TRACEROUTE_MAX_HOPS)
        and a fixed short per-hop timeout is used internally, so the command
        can't run long enough to hit RouterOS's own ~60s API command
        timeout.

        Diagnostic only - this never changes device state, so it is not
        gated by MIKROTIK_ALLOW_WRITE and needs no confirm/preview.
        """
        validated_address = validate_ping_address(address)
        capped_count = validate_positive_limit(count, MAX_TRACEROUTE_COUNT, "count")
        capped_max_hops = validate_positive_limit(max_hops, MAX_TRACEROUTE_MAX_HOPS, "max_hops")
        client = _client(device_name)
        return client.traceroute(validated_address, count=capped_count, max_hops=capped_max_hops)

    @mcp.tool()
    @_safe
    def arp_table(device_name: str) -> list[dict[str, Any]]:
        """List the IPv4 ARP table (/ip/arp): address, mac-address,
        interface, dynamic, complete.

        Use this to cross-reference an IP to a MAC (or vice versa) for a
        statically-addressed device that never shows up in `dhcp_leases`
        (it never requested a DHCP lease, so it has no lease entry - but it
        does get an ARP entry once it has exchanged traffic with the
        device).
        """
        client = _client(device_name)
        return rows_to_list(client.path("ip", "arp"))

    @mcp.tool()
    @_safe
    def bridge_hosts(device_name: str) -> list[dict[str, Any]]:
        """List /interface/bridge/host entries: mac-address, on-interface
        (the physical bridge port), bridge, dynamic, local.

        Use this to find which physical port of a bridge a given MAC is
        currently learned on - e.g. to identify which PoE-capable ethernet
        port a locked-up device is plugged into, before using `poe_status`/
        `set_poe_out` on it (see "Physical layer & PoE control" in the
        README).
        """
        client = _client(device_name)
        return rows_to_list(client.path("interface", "bridge", "host"))

    @mcp.tool()
    @_safe
    def interface_traffic(device_name: str, interface: str) -> dict[str, Any]:
        """Current rx/tx traffic rate of one interface
        (/interface/monitor-traffic interface=<interface> once=yes).

        `interface` is validated for shape (validate_interface_name) before
        it is ever sent to the device - existence isn't checked separately
        here (unlike the guarded write tools), so a typo'd/unknown interface
        name simply produces whatever error RouterOS itself returns.

        Returns a single reply dict - typically rx-bits-per-second/
        tx-bits-per-second and rx-packets-per-second/tx-packets-per-second -
        or an empty dict if the device returned nothing. `once=yes` makes
        this a single instantaneous reading, not a continuous stream, so the
        call always returns promptly.
        """
        validated_interface = validate_interface_name(interface)
        client = _client(device_name)
        return client.monitor_traffic(validated_interface)

    @mcp.tool()
    @_safe
    def poe_status(device_name: str) -> list[dict[str, Any]]:
        """PoE status/consumption per port, for every PoE-capable ethernet
        port on the device.

        Reads /interface/ethernet and keeps only rows that have a `poe-out`
        field (i.e. are PoE-capable on this hardware - e.g. the CRS318-16P's
        high/low PoE ports), then reads
        /interface/ethernet/poe/monitor once=yes for each one to get its
        live voltage/current/power/poe-out-status. Each entry looks like
        {"interface", "poe-out" (configured mode), "poe-out-status",
        "voltage", "current", "power"} - the monitor fields are omitted for
        a port whose live monitor call fails (kept resilient rather than
        failing the whole tool for one bad port).

        Returns an empty list (never an error) for a device with no PoE
        hardware at all - that's a completely normal state, same as
        `wireless_registrations` for a wired-only device.
        """
        client = _client(device_name)
        ethernet_rows = rows_to_list(client.path("interface", "ethernet"))
        poe_rows = [row for row in ethernet_rows if "poe-out" in row]

        result: list[dict[str, Any]] = []
        for row in poe_rows:
            name = row.get("name", "")
            entry: dict[str, Any] = {"interface": name, "poe-out": row.get("poe-out")}
            try:
                monitor = client.poe_monitor(name)
            except DeviceCommandError:
                monitor = {}
            if monitor:
                entry["poe-out-status"] = monitor.get("poe-out-status")
                entry["voltage"] = monitor.get("poe-out-voltage")
                entry["current"] = monitor.get("poe-out-current")
                entry["power"] = monitor.get("poe-out-power")
            result.append(entry)
        return result

    @mcp.tool()
    @_safe
    def lte_status(device_name: str, interface: str) -> dict[str, Any]:
        """Signal/status of one LTE/5G modem interface
        (`/interface/lte/monitor <interface> once=yes`).

        Returns a single reply dict - typically operator (`current-operator`),
        technology (`access-technology`: 3G/LTE/5G), signal
        (`rsrp`/`rsrq`/`sinr`/`rssi`), `band`, `registration-status`,
        `cell-id` - or an empty dict if the device has no LTE hardware/package
        at all, or `interface` doesn't match one (same "empty, not an error"
        convention as `poe_status`/`system_health` for optional hardware).

        `interface` is validated for shape (`validate_interface_name`) before
        it is ever sent to the device.
        """
        validated_interface = validate_interface_name(interface)
        client = _client(device_name)
        try:
            return client.lte_monitor(validated_interface)
        except DeviceCommandError:
            return {}

    @mcp.tool()
    @_safe
    def lte_interfaces(device_name: str) -> list[dict[str, Any]]:
        """List LTE/5G modem interfaces (`/interface/lte`): name, running,
        disabled, apn-profiles, etc. Returns an empty list (never an error)
        for a device with no LTE hardware/package at all.
        """
        client = _client(device_name)
        try:
            return rows_to_list(client.path("interface", "lte"))
        except DeviceCommandError:
            return []

    @mcp.tool()
    @_safe
    def containers(device_name: str) -> list[dict[str, Any]]:
        """List containers (`/container`): name/tag, status, ram-usage,
        root-dir, interface, os, etc. Returns an empty list (never an error)
        for a device with no container package/hardware support at all.
        """
        client = _client(device_name)
        try:
            return rows_to_list(client.path("container"))
        except DeviceCommandError:
            return []

    @mcp.tool()
    @_safe
    def container_config(device_name: str) -> dict[str, Any]:
        """Container subsystem configuration (`/container/config`):
        registry-url, tmpdir, ram-high, etc - a single-row menu. Returns an
        empty dict (never an error) for a device with no container package.
        """
        client = _client(device_name)
        try:
            rows = rows_to_list(client.path("container", "config"))
        except DeviceCommandError:
            return {}
        return rows[0] if rows else {}

    @mcp.tool()
    @_safe
    def usb_devices(device_name: str) -> dict[str, Any]:
        """USB hardware on a device: physical USB ports
        (`/system/routerboard/usb`, if the board exposes them) plus attached
        storage (`/disk` - USB flash drives, and USB LTE/5G modems that
        surface as a disk rather than under routerboard/usb). Combined into
        one read since which of the two a given USB device shows up under
        depends on the hardware.

        Returns `{"usb_ports": [...], "disks": [...]}` - either or both
        lists empty (never an error) if the board doesn't expose that
        menu/hardware at all.
        """
        client = _client(device_name)
        try:
            usb_ports = rows_to_list(client.path("system", "routerboard", "usb"))
        except DeviceCommandError:
            usb_ports = []
        try:
            disks = rows_to_list(client.path("disk"))
        except DeviceCommandError:
            disks = []
        return {"usb_ports": usb_ports, "disks": disks}

    @mcp.tool()
    @_safe
    def list_write_operations() -> list[dict[str, Any]]:
        """List every guarded write operation and the RouterOS path/action it maps to.

        Read-only: this only surfaces guard.ALLOWLIST's metadata (D3) - it
        does not perform or preview a write, and is not gated by
        MIKROTIK_ALLOW_WRITE.
        """
        return [
            {
                "name": op.name,
                "path": "/".join(op.path),
                "action": op.action,
                "description": op.description,
            }
            for op in guard.ALLOWLIST.values()
        ]

    # --- Write tools ---------------------------------------------------
    # Every write tool must call a dedicated function in guard.py - never
    # MikrotikClient.update/add/remove directly. See guard.py's module
    # docstring for how to add the next one.

    @mcp.tool()
    @_safe
    def set_identity(device_name: str, new_name: str, confirm: bool = False) -> dict[str, Any]:
        """Set a device's RouterOS identity (hostname).

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it.
        """
        client = _client(device_name)
        preview = guard.set_identity(client, settings, new_name=new_name, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def enable_interface(device_name: str, interface_name: str, confirm: bool = False) -> dict[str, Any]:
        """Enable a network interface by name (sets disabled=no).

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Errors clearly if
        `interface_name` does not exist on the device - it is never created.
        """
        client = _client(device_name)
        preview = guard.enable_interface(client, settings, interface_name=interface_name, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def disable_interface(device_name: str, interface_name: str, confirm: bool = False) -> dict[str, Any]:
        """Disable a network interface by name (sets disabled=yes).

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Errors clearly if
        `interface_name` does not exist on the device - it is never created.
        """
        client = _client(device_name)
        preview = guard.disable_interface(client, settings, interface_name=interface_name, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def set_wifi_ssid(
        device_name: str, interface_name: str, new_ssid: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Set a wireless interface's SSID.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Works against
        either RouterOS generation - it looks for `interface_name` under the
        ROS7 wifi package first, then the ROS6 wireless package - and errors
        clearly if it isn't found under either; it is never created.
        """
        client = _client(device_name)
        preview = guard.set_wifi_ssid(
            client, settings, interface_name=interface_name, new_ssid=new_ssid, confirm=confirm
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def set_client_bandwidth(
        device_name: str, target: str, max_limit: str, limit_at: str | None = None, confirm: bool = False
    ) -> dict[str, Any]:
        """Limit a client's bandwidth via a RouterOS Simple Queue (/queue/simple).

        `target` is the client's IP address or subnet (e.g. "10.0.0.5" or
        "10.0.0.0/24"). `max_limit` is a RouterOS rate pair in
        "upload/download" form (e.g. "10M/5M"); `limit_at` is the optional
        guaranteed-rate (CIR) pair in the same form. If a Simple Queue
        already targets `target`, its max-limit/limit-at is UPDATED;
        otherwise a new one is CREATED with a name derived from `target` -
        the returned `operation` field ("set_client_bandwidth_update" vs
        "set_client_bandwidth_add") tells you which happened (or would
        happen, with confirm=False).

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it.

        GOTCHA - FastTrack: if the device has a FastTrack rule in its
        firewall (common on RouterOS's own quick-set wizards), fasttracked
        connections bypass queueing entirely, so this queue may have no
        visible effect on a client whose traffic is already fasttracked -
        see README's "Security model" section.
        """
        client = _client(device_name)
        preview = guard.set_client_bandwidth(
            client, settings, target=target, max_limit=max_limit, limit_at=limit_at, confirm=confirm
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def add_static_dhcp_lease(
        device_name: str,
        address: str,
        mac_address: str,
        comment: str | None = None,
        server: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Create a static DHCP lease (/ip/dhcp-server/lease), pinning
        `address` to `mac_address`. Useful to give a client a stable,
        predictable IP - e.g. before limiting it with set_client_bandwidth.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Errors clearly
        (without creating anything) if a lease for `mac_address` already
        exists on the device - it never creates a duplicate.
        """
        client = _client(device_name)
        preview = guard.add_static_dhcp_lease(
            client,
            settings,
            address=address,
            mac_address=mac_address,
            comment=comment,
            server=server,
            confirm=confirm,
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def remove_simple_queue(
        device_name: str, target: str | None = None, name: str | None = None, confirm: bool = False
    ) -> dict[str, Any]:
        """Remove a Simple Queue by `target` or by `name` - undoes a
        bandwidth limit previously set with set_client_bandwidth. At least
        one of `target`/`name` must be given and must match an existing
        queue.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a preview of what would be removed; call again with
        confirm=True to actually remove it.
        """
        client = _client(device_name)
        preview = guard.remove_simple_queue(client, settings, target=target, name=name, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def add_to_address_list(
        device_name: str,
        list_name: str,
        address: str,
        comment: str | None = None,
        timeout: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Add `address` (an IP or subnet) to a named firewall address-list
        (/ip/firewall/address-list).

        IMPORTANT: this only manages the *list* - it does NOT create or
        modify any firewall rule. Adding an address here only blocks or
        allows traffic if a `/ip/firewall/filter` (or NAT) rule on the
        device already references `list_name` (e.g.
        `src-address-list=list_name`, action=drop). See README's
        "Blocking/allowing a client via address lists" section.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Errors clearly
        (without creating anything) if this exact `list_name`+`address` pair
        already exists on the device - it never creates a duplicate.
        """
        client = _client(device_name)
        preview = guard.add_to_address_list(
            client,
            settings,
            list_name=list_name,
            address=address,
            comment=comment,
            timeout=timeout,
            confirm=confirm,
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def remove_from_address_list(
        device_name: str, list_name: str, address: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Remove the entry matching `list_name`+`address` from a firewall
        address-list (/ip/firewall/address-list).

        Like add_to_address_list, this only manages the *list* - see that
        tool's docstring and README's "Blocking/allowing a client via
        address lists" section for why this alone doesn't guarantee a
        change in blocking/allowing behavior.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a preview of what would be removed; call again with
        confirm=True to actually remove it. Errors clearly if no entry
        matches `list_name`+`address`.
        """
        client = _client(device_name)
        preview = guard.remove_from_address_list(
            client, settings, list_name=list_name, address=address, confirm=confirm
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def set_poe_out(
        device_name: str, interface_name: str, poe_out: str, confirm: bool = False
    ) -> dict[str, Any]:
        """Set a PoE-capable ethernet port's PoE output mode
        (/interface/ethernet set [interface_name] poe-out=<poe_out>).

        `poe_out` must be one of "auto-on", "forced-on", "off".

        Primary use case: reset a locked-up antenna/camera/AP powered over
        PoE by cycling its power - call with poe_out="off" (confirm=true),
        wait for it to actually power down, then call again with
        poe_out="auto-on" to bring it back up.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Errors clearly
        (without changing anything) if `interface_name` doesn't exist on the
        device, or exists but isn't PoE-capable - it never creates or
        coerces anything.
        """
        client = _client(device_name)
        preview = guard.set_poe_out(
            client, settings, interface_name=interface_name, poe_out=poe_out, confirm=confirm
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def start_container(device_name: str, container: str, confirm: bool = False) -> dict[str, Any]:
        """Start a container by `name` or `tag` (`/container/start`).

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Errors clearly
        (without creating anything) if `container` doesn't match any
        `/container` row's `name` or `tag` on the device - it is never
        created.

        The `after.status` in the preview is the status RouterOS sets
        immediately ("starting"), not a guaranteed final state - the
        container transitions to "running" asynchronously; use `containers`
        again afterward to see the settled status.
        """
        client = _client(device_name)
        preview = guard.start_container(client, settings, container=container, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def stop_container(device_name: str, container: str, confirm: bool = False) -> dict[str, Any]:
        """Stop a container by `name` or `tag` (`/container/stop`).

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Errors clearly
        (without changing anything) if `container` doesn't match any
        `/container` row's `name` or `tag` on the device - it is never
        created.

        The `after.status` in the preview is the status RouterOS sets
        immediately ("stopping"), not a guaranteed final state - use
        `containers` again afterward to see the settled status.
        """
        client = _client(device_name)
        preview = guard.stop_container(client, settings, container=container, confirm=confirm)
        return asdict(preview)

    return mcp


def _resolve_log_level(raw: str | None) -> str:
    """Validate MIKROTIK_LOG_LEVEL against Python logging's level names (E4).

    An invalid value used to be passed straight to logging.basicConfig(),
    which raises ValueError and crashes the server before it even starts.
    Falls back to INFO (with a warning) instead.
    """
    level = (raw or _DEFAULT_LOG_LEVEL).strip().upper()
    if level not in _VALID_LOG_LEVELS:
        logger.warning(
            "Invalid MIKROTIK_LOG_LEVEL %r; falling back to %s. Valid values: %s",
            raw,
            _DEFAULT_LOG_LEVEL,
            ", ".join(sorted(_VALID_LOG_LEVELS)),
        )
        return _DEFAULT_LOG_LEVEL
    return level


def main() -> None:
    logging.basicConfig(level=_resolve_log_level(os.environ.get("MIKROTIK_LOG_LEVEL")))
    server = build_server()
    server.run()


if __name__ == "__main__":
    main()
