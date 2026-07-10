"""MCP server entrypoint.

Registers the read tools plus every guarded write tool (set_identity,
enable_interface/disable_interface, set_wifi_ssid, set_client_bandwidth,
add_static_dhcp_lease, remove_simple_queue, add_to_address_list,
remove_from_address_list, set_poe_out, start_container/stop_container,
set_route_distance, enable_route/disable_route, add_netwatch/remove_netwatch,
add_static_dns/remove_static_dns, clear_dns_cache, remove_dhcp_lease,
wake_on_lan, enable_firewall_rule/disable_firewall_rule,
add_wireguard_interface/add_wireguard_peer/remove_wireguard_peer - see
guard.py's ALLOWLIST for the full write-tool inventory), plus the read-only
connection_tracking tool (v0.11), the read-only security_audit/
security_events tools (v0.12 - see security.py), and the read-only
wireguard_interfaces tool (v0.13). Transport is stdio only - this process is
meant to run on the operator's own machine, launched by an MCP client (e.g.
Claude Code) over stdio, with no network exposure at all.

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

from . import correlation, guard, security
from .client import ClientFactory, ClientPool, MikrotikClient, get_client
from .config import Settings, load_settings
from .exceptions import DeviceCommandError, MikrotikMCPError, ValidationError
from .formatting import (
    WIREGUARD_SENSITIVE_FIELDS,
    filter_disabled,
    rows_to_list,
    split_address_port,
    strip_sensitive_fields,
)
from .validation import (
    validate_conntrack_dst_port,
    validate_conntrack_protocol,
    validate_interface_name,
    validate_ip_address,
    validate_ping_address,
    validate_positive_limit,
)

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
# v0.11: connection_tracking's hard result cap - regardless of how many rows
# actually match the caller's filter, at most this many are ever returned;
# `truncated` in the result signals when more matched than were returned.
# See connection_tracking's own docstring for why a filter is mandatory in
# the first place.
MAX_CONNTRACK_LIMIT = 100
# v0.12: security_events' limit, same cap/default shape as logs' own
# limit (DEFAULT_LOG_LIMIT/MAX_LOG_LIMIT) - it reads the same /log table,
# just pre-filtered to security-relevant rows (see security.py).
DEFAULT_SECURITY_EVENTS_LIMIT = 50
MAX_SECURITY_EVENTS_LIMIT = 500

_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_DEFAULT_LOG_LEVEL = "INFO"

# v0.8/v0.13: WireGuard private/preshared keys must never be returned by any
# read tool - see wireguard_peers/wireguard_interfaces below,
# strip_sensitive_fields' docstring, and formatting.WIREGUARD_SENSITIVE_FIELDS
# (the same constant guard.py's write-preview redaction uses, so read and
# write paths can never drift out of sync).
_WIREGUARD_REDACTED_FIELDS = WIREGUARD_SENSITIVE_FIELDS


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
    def wireguard_peers(device_name: str) -> list[dict[str, Any]]:
        """List WireGuard VPN peers (/interface/wireguard/peers): name,
        interface, public-key, endpoint-address/endpoint-port,
        current-endpoint-address/current-endpoint-port, last-handshake,
        rx/tx byte counters, allowed-address, disabled.

        SECURITY: a `private-key` field never appears in RouterOS's own
        /interface/wireguard/peers reply (only /interface/wireguard - the
        tunnel interfaces themselves - carries one; see wireguard_interfaces
        below), but this strips it defensively anyway, along with any
        `preshared-key` a configured peer may genuinely carry (a real, if
        optional, RouterOS field on this menu) - see
        formatting.WIREGUARD_SENSITIVE_FIELDS and
        test_wireguard_peers_never_exposes_private_key/
        test_wireguard_peers_never_exposes_preshared_key.

        Returns an empty list (never an error) for a device with no
        WireGuard package/interfaces at all - same "empty, not an error"
        convention as wireless_registrations/system_health for optional
        features.
        """
        client = _client(device_name)
        try:
            rows = rows_to_list(client.path("interface", "wireguard", "peers"))
        except DeviceCommandError:
            return []
        return strip_sensitive_fields(rows, _WIREGUARD_REDACTED_FIELDS)

    @mcp.tool()
    @_safe
    def wireguard_interfaces(device_name: str) -> list[dict[str, Any]]:
        """List WireGuard tunnel interfaces (/interface/wireguard): name,
        listen-port, public-key, running, disabled, mtu.

        SECURITY: RouterOS's own /interface/wireguard reply carries the
        interface's `private-key` - this is ALWAYS stripped before
        returning (formatting.strip_sensitive_fields with
        formatting.WIREGUARD_SENSITIVE_FIELDS), the same mechanism
        wireguard_peers (v0.8) already used defensively for a peer's
        private-key/preshared-key. A private-key never leaves this process.
        See test_wireguard_interfaces_never_exposes_private_key.

        Returns an empty list (never an error) for a device with no
        WireGuard package/interfaces at all - same convention as
        wireguard_peers.
        """
        client = _client(device_name)
        try:
            rows = rows_to_list(client.path("interface", "wireguard"))
        except DeviceCommandError:
            return []
        return strip_sensitive_fields(rows, _WIREGUARD_REDACTED_FIELDS)

    @mcp.tool()
    @_safe
    def ppp_active(device_name: str) -> list[dict[str, Any]]:
        """List active PPP sessions (/ppp/active): name, service
        (l2tp/pptp/sstp/ovpn/pppoe), caller-id, address, uptime - VPN
        server sessions currently connected to this device.

        Returns an empty list (never an error) for a device with no PPP
        server configured, or simply no sessions active right now.
        """
        client = _client(device_name)
        try:
            return rows_to_list(client.path("ppp", "active"))
        except DeviceCommandError:
            return []

    @mcp.tool()
    @_safe
    def ipsec_active_peers(device_name: str) -> list[dict[str, Any]]:
        """List active IPsec peers (/ip/ipsec/active-peers): remote-address,
        state, uptime, rx/tx byte counters, side (initiator/responder).

        Returns an empty list (never an error) for a device that doesn't
        use IPsec at all - a completely normal state.
        """
        client = _client(device_name)
        try:
            return rows_to_list(client.path("ip", "ipsec", "active-peers"))
        except DeviceCommandError:
            return []

    @mcp.tool()
    @_safe
    def bgp_sessions(device_name: str) -> list[dict[str, Any]]:
        """List BGP session status: remote-address/remote-as, state
        (established/idle/...), uptime, prefix-count.

        RouterOS exposes this under two different paths depending on
        generation, the same split wireless_registrations already handles
        for wifi: ROS7's routing package (/routing/bgp/session) or ROS6's
        (/routing/bgp/peer). This tries ROS7 first, falls back to ROS6, and
        returns an empty list - rather than raising - for a device that
        doesn't run BGP at all.
        """
        client = _client(device_name)
        for segments in (
            ("routing", "bgp", "session"),
            ("routing", "bgp", "peer"),
        ):
            try:
                return rows_to_list(client.path(*segments))
            except DeviceCommandError:
                continue
        return []

    @mcp.tool()
    @_safe
    def ospf_neighbors(device_name: str) -> list[dict[str, Any]]:
        """List OSPF neighbor adjacencies (/routing/ospf/neighbor):
        address, state (Full/Down/...), router-id, adjacency.

        Returns an empty list (never an error) for a device that doesn't
        run OSPF at all.
        """
        client = _client(device_name)
        try:
            return rows_to_list(client.path("routing", "ospf", "neighbor"))
        except DeviceCommandError:
            return []

    @mcp.tool()
    @_safe
    def netwatch(device_name: str) -> list[dict[str, Any]]:
        """List Netwatch host monitors (/tool/netwatch): host, status
        (up/down), interval, since, comment, disabled, plus
        `has-up-script`/`has-down-script` booleans.

        Netwatch is the usual way a RouterOS device itself watches a
        gateway or peer's reachability (e.g. to drive a failover script on
        down/up) - this is read-only groundwork for future failover
        tooling; see README's "VPN & routing diagnostics".

        The up-script/down-script fields are surfaced only as presence
        booleans (`has-up-script`/`has-down-script`), never as the raw
        script body, which can contain arbitrary RouterOS commands (e.g.
        route/credential changes) that don't belong in a read tool's
        output.

        Returns an empty list (never an error) for a device with no
        Netwatch entries configured.
        """
        client = _client(device_name)
        try:
            rows = rows_to_list(client.path("tool", "netwatch"))
        except DeviceCommandError:
            return []
        result: list[dict[str, Any]] = []
        for row in rows:
            entry = dict(row)
            entry["has-up-script"] = bool(entry.pop("up-script", ""))
            entry["has-down-script"] = bool(entry.pop("down-script", ""))
            result.append(entry)
        return result

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
    def connection_tracking(
        device_name: str,
        src_address: str | None = None,
        dst_address: str | None = None,
        dst_port: int | None = None,
        protocol: str | None = None,
    ) -> dict[str, Any]:
        """List active connections from RouterOS's connection tracking table
        (/ip/firewall/connection) - FILTERED. At least ONE of `src_address`,
        `dst_address`, `dst_port`, `protocol` is REQUIRED.

        WHY a filter is mandatory (unlike every other read tool in this
        package): on a production router, the full connection-tracking table
        can be large enough to blow past an LLM caller's context/token
        budget on its own. Calling this with no filter at all raises a
        ValidationError instead of returning the whole table.

        Filtering happens in Python after reading the table - the same
        reasoning `logs`' `topics` filter already documents (RouterOS's
        structured API doesn't expose a query-by-field read here either).
        `src_address`/`dst_address` match a row's IP, ignoring the port
        RouterOS packs into the same field (e.g. "192.0.2.1:80" ->
        address "192.0.2.1"); `dst_port` matches the destination's port
        component. `protocol` is a RouterOS protocol name (e.g.
        "tcp"/"udp"/"icmp", case-insensitive) or a numeric IP protocol
        number (0-255).

        Regardless of how many rows match, the result is capped at
        MAX_CONNTRACK_LIMIT (100) entries - `truncated` is `true` whenever
        more rows matched than were returned, and `total_matched` always
        reports the real (pre-truncation) match count, so a caller always
        knows whether it's seeing everything that matched.

        Each returned entry: `protocol`, `src-address`/`src-port`,
        `dst-address`/`dst-port` (address and port split apart - see
        formatting.split_address_port), `tcp-state` (populated for TCP
        connections), `timeout`, and the `assured`/`confirmed`/`seen-reply`
        flags - RouterOS's own closest equivalent to a generic "connection
        state" for this table.
        """
        if not any([src_address, dst_address, dst_port is not None, protocol]):
            raise ValidationError(
                "connection_tracking requires at least one of 'src_address', 'dst_address', "
                "'dst_port', 'protocol' - the full connection-tracking table on a production "
                "router is too large to return unfiltered."
            )

        validated_src = validate_ip_address(src_address) if src_address else None
        validated_dst = validate_ip_address(dst_address) if dst_address else None
        validated_port = validate_conntrack_dst_port(dst_port) if dst_port is not None else None
        validated_protocol = validate_conntrack_protocol(protocol) if protocol else None

        client = _client(device_name)
        rows = rows_to_list(client.path("ip", "firewall", "connection"))

        matches: list[dict[str, Any]] = []
        for row in rows:
            src_ip, src_port = split_address_port(row.get("src-address", ""))
            dst_ip, matched_dst_port = split_address_port(row.get("dst-address", ""))
            if validated_src is not None and src_ip != validated_src:
                continue
            if validated_dst is not None and dst_ip != validated_dst:
                continue
            if validated_port is not None and matched_dst_port != str(validated_port):
                continue
            if validated_protocol is not None and (row.get("protocol") or "").lower() != validated_protocol:
                continue
            matches.append(
                {
                    "protocol": row.get("protocol"),
                    "src-address": src_ip,
                    "src-port": src_port,
                    "dst-address": dst_ip,
                    "dst-port": matched_dst_port,
                    "tcp-state": row.get("tcp-state"),
                    "timeout": row.get("timeout"),
                    "assured": row.get("assured"),
                    "confirmed": row.get("confirmed"),
                    "seen-reply": row.get("seen-reply"),
                }
            )

        total_matched = len(matches)
        truncated = total_matched > MAX_CONNTRACK_LIMIT
        return {
            "connections": matches[:MAX_CONNTRACK_LIMIT],
            "total_matched": total_matched,
            "truncated": truncated,
        }

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

    # --- v0.12: security audit + security-relevant log events ----------

    @mcp.tool()
    @_safe
    def security_audit(device_name: str) -> dict[str, Any]:
        """Read-only security audit of a device's configuration - gives an
        LLM caller (or operator) a structured list of findings to review, so
        it can "look at the security of this router" without an operator
        manually walking every menu.

        Aggregates several independent, defensive checks - see
        `src/mcp_mikrotik/security.py` for the full list and reasoning:
        insecure management services (`/ip/service`: telnet/ftp/www/api
        enabled, and whether they're open to any address), whether the
        firewall's input chain ends in a drop/reject rule (heuristic),
        SNMP community exposure (`/snmp/community`), an open DNS resolver
        (`/ip/dns` allow-remote-requests), outdated RouterOS
        (`/system/package/update`), open wireless/wifi networks (no
        security profile / no passphrase), and a count of users with a
        write/full policy.

        Each check reads its own menu(s) and skips itself (contributing no
        findings) if that menu doesn't exist on this device/RouterOS
        generation - one missing/unsupported menu never fails the whole
        audit. NEVER a scanner, NEVER definitive - this is a heuristic,
        best-effort read meant to prompt a human decision, not to replace
        one; see README's "Security audit" section for the full disclaimer.

        READ-ONLY: does not change anything on the device, and is not gated
        by MIKROTIK_ALLOW_WRITE.

        NO SECRET IS EVER RETURNED: no finding ever includes a password,
        passphrase, or SNMP community string - see security.py's module
        docstring for exactly how each check avoids that.

        Returns `{"findings": [{"severity", "category", "title", "detail",
        "recommendation"}, ...], "summary": {"high", "medium", "low",
        "info"}}` - `findings` sorted by severity (high first), `summary`
        always including all four keys (0 for a severity with no findings).
        """
        client = _client(device_name)
        return security.run_security_audit(client)

    @mcp.tool()
    @_safe
    def security_events(
        device_name: str, limit: int = DEFAULT_SECURITY_EVENTS_LIMIT
    ) -> list[dict[str, Any]]:
        """Recent RouterOS log entries filtered down to security-relevant
        ones - login/logout/authentication-failure events (topic
        "account"), "critical"/"error" topic entries, and generic
        "system,info" rows whose message looks like a login/logout - so a
        caller can correlate access attempts/anomalies without reading the
        entire (often much larger) unfiltered log via `logs`.

        Filtering happens in Python, same reasoning `logs`' `topics` filter
        already documents (RouterOS's structured API doesn't expose a
        query-by-field read here either) - and is applied BEFORE the
        `limit` cut, so this returns the most recent `limit` MATCHING
        entries (not the last `limit` raw entries filtered afterward, which
        would silently drop matches on a busy log).

        `limit` must be positive and is capped at 500 (default 50), the same
        shape as `logs`' own `limit`.

        READ-ONLY: not gated by MIKROTIK_ALLOW_WRITE.
        """
        client = _client(device_name)
        capped_limit = validate_positive_limit(limit, MAX_SECURITY_EVENTS_LIMIT, "limit")
        rows = rows_to_list(client.path("log"))
        return security.filter_security_events(rows, capped_limit)

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

        On ROS7, a wifi interface running the standard production layout (a
        named `configuration`) has no ssid field of its own - the actual
        write lands on the referenced /interface/wifi/configuration profile
        instead, resolved automatically. The before/after preview always
        reflects the real location the ssid is read from and written to.
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

    # --- v0.9: atomic failover writes -----------------------------------

    @mcp.tool()
    @_safe
    def set_route_distance(
        device_name: str, dst_address: str, gateway: str, distance: int, confirm: bool = False
    ) -> dict[str, Any]:
        """Adjust an existing route's `distance` (failover priority - lower
        distance wins) via `/ip/route set distance=<distance>`.

        Resolved by the STABLE (`dst_address`, `gateway`) pair - never a
        dynamic `.id`/list index, which can silently shift as routes are
        added/removed elsewhere on the device between a preview and the
        confirmed apply. Errors clearly (without changing anything) if no
        route matches that pair, or if more than one still does
        (`AmbiguousResourceError`) - this never guesses which route to
        touch.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. See README's
        "Failover control" section for the recommended step-by-step flow.
        """
        client = _client(device_name)
        preview = guard.set_route_distance(
            client, settings, dst_address=dst_address, gateway=gateway, distance=distance, confirm=confirm
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def enable_route(
        device_name: str,
        dst_address: str,
        gateway: str | None = None,
        comment: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Enable a route (`/ip/route set disabled=no`), resolved by
        `dst_address` - narrowed by `gateway`/`comment` when more than one
        route shares that `dst_address` (e.g. two default routes to
        different gateways, the standard failover shape). Errors clearly if
        nothing matches, or if the match is still ambiguous after
        narrowing.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it.
        """
        client = _client(device_name)
        preview = guard.enable_route(
            client, settings, dst_address=dst_address, gateway=gateway, comment=comment, confirm=confirm
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def disable_route(
        device_name: str,
        dst_address: str,
        gateway: str | None = None,
        comment: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Disable a route (`/ip/route set disabled=yes`), resolved by
        `dst_address` - narrowed by `gateway`/`comment` when more than one
        route shares that `dst_address`. Errors clearly if nothing matches,
        or if the match is still ambiguous after narrowing.

        RISK: disabling the default route (`dst_address="0.0.0.0/0"` or
        `"::/0"`) cuts all outbound traffic that relies on this gateway. The
        returned preview's `warning` field is non-null whenever this is the
        case - always check it before calling again with `confirm=true`.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview (including the `warning`
        field) without changing anything; call again with confirm=True to
        actually apply it.
        """
        client = _client(device_name)
        preview = guard.disable_route(
            client, settings, dst_address=dst_address, gateway=gateway, comment=comment, confirm=confirm
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def add_netwatch(
        device_name: str,
        host: str,
        interval: str | None = None,
        comment: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Create a Netwatch host monitor (`/tool/netwatch add`): `host`
        (a plain IPv4/IPv6 address), optional `interval` (a RouterOS
        duration, e.g. "10s"/"00:00:10") and optional `comment`.

        SECURITY: this tool does NOT accept an up-script/down-script - a
        Netwatch script body can run arbitrary RouterOS commands (route or
        credential changes, ...), so it is deliberately outside what this
        guarded write tool will ever send to a device. Configure up/down
        scripts manually on the device once the monitor exists (WinBox/CLI)
        - see README's "Failover control" section. The read-only `netwatch`
        tool already only ever surfaces `has-up-script`/`has-down-script` as
        presence booleans, never a script body, for the same reason.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Errors clearly
        (without creating anything) if a monitor for `host` already exists -
        it never creates a duplicate.
        """
        client = _client(device_name)
        preview = guard.add_netwatch(
            client, settings, host=host, interval=interval, comment=comment, confirm=confirm
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def remove_netwatch(
        device_name: str, host: str | None = None, comment: str | None = None, confirm: bool = False
    ) -> dict[str, Any]:
        """Remove a Netwatch host monitor by `host` or `comment`
        (`/tool/netwatch remove`). At least one of `host`/`comment` must be
        given and must match an existing monitor (`host` is tried first if
        both are given).

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a preview of what would be removed; call again with
        confirm=True to actually remove it.
        """
        client = _client(device_name)
        preview = guard.remove_netwatch(client, settings, host=host, comment=comment, confirm=confirm)
        return asdict(preview)

    # --- v0.10: static DNS, DNS cache flush, DHCP lease removal, WoL -----

    @mcp.tool()
    @_safe
    def add_static_dns(
        device_name: str,
        name: str,
        address: str,
        record_type: str = "A",
        ttl: str | None = None,
        comment: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Create a static DNS entry (`/ip/dns/static add`) resolving `name`
        to `address`.

        `record_type` is `"A"` (default) or `"CNAME"`: for `"A"`, `address`
        is a literal IPv4/IPv6 address; for `"CNAME"`, `address` is itself
        another hostname (the alias target), written to RouterOS's `cname`
        field. Useful to block a malicious domain (point it at `0.0.0.0`) or
        set up an internal DNS override.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Errors clearly
        (without creating anything) if a row already matches this exact
        `name`+`record_type` pair - it never creates a duplicate.
        """
        client = _client(device_name)
        preview = guard.add_static_dns(
            client,
            settings,
            name=name,
            address=address,
            record_type=record_type,
            ttl=ttl,
            comment=comment,
            confirm=confirm,
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def remove_static_dns(
        device_name: str, name: str, record_type: str | None = None, confirm: bool = False
    ) -> dict[str, Any]:
        """Remove a static DNS entry (`/ip/dns/static remove`) by `name`,
        optionally narrowed by `record_type` (`"A"`/`"CNAME"`).

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a preview of what would be removed; call again with
        confirm=True to actually remove it. Errors clearly if nothing
        matches `name` (narrowed by `record_type`), or if more than one row
        still matches after narrowing (`AmbiguousResourceError`) - never
        guesses which one to remove.
        """
        client = _client(device_name)
        preview = guard.remove_static_dns(client, settings, name=name, record_type=record_type, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def clear_dns_cache(device_name: str, confirm: bool = False) -> dict[str, Any]:
        """Flush the device's DNS resolver cache (`/ip/dns/cache/flush`) -
        no arguments, clears every cached DNS answer at once.

        Benign (only cached answers are cleared - repopulated on the next
        resolution - never device configuration), but still guarded/
        confirm-gated like every other write tool here.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to preview the current cached-entry count without changing
        anything; call again with confirm=True to actually flush it.
        """
        client = _client(device_name)
        preview = guard.clear_dns_cache(client, settings, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def remove_dhcp_lease(
        device_name: str, address: str | None = None, mac_address: str | None = None, confirm: bool = False
    ) -> dict[str, Any]:
        """Remove a DHCP lease (`/ip/dhcp-server/lease remove`) by `address`
        or `mac_address` - typically to force a client to renew its IP. At
        least one of `address`/`mac_address` must be given and must match an
        existing lease (`mac_address` is tried first if both are given).

        Removes EITHER a dynamic or a static lease. **If the resolved lease
        is STATIC** (`dynamic=false` - i.e. it was pinned with
        `add_static_dhcp_lease`), the returned preview's `warning` field is
        non-null: removing it deletes the pinned IP<->MAC mapping itself,
        not just a renewable cache entry. Always check `warning` before
        calling again with `confirm=true`. No warning for a dynamic lease -
        that is this tool's ordinary use case.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a preview (including the `warning` field) without
        changing anything; call again with confirm=True to actually remove
        it. Errors clearly if nothing matches.
        """
        client = _client(device_name)
        preview = guard.remove_dhcp_lease(
            client, settings, address=address, mac_address=mac_address, confirm=confirm
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def wake_on_lan(device_name: str, mac_address: str, interface: str, confirm: bool = False) -> dict[str, Any]:
        """Send a Wake-on-LAN magic packet (`/tool/wol`) for `mac_address`,
        out `interface`.

        Benign - it never changes device configuration and targets no
        existing RouterOS row - but still guarded/confirm-gated like every
        other write tool here, so an LLM caller can't wake a machine "by
        accident". Does NOT verify `interface` exists on the device first;
        RouterOS itself rejects an unknown interface name at send time.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a preview of what would be sent without changing
        anything; call again with confirm=True to actually send it.
        """
        client = _client(device_name)
        preview = guard.wake_on_lan(
            client, settings, mac_address=mac_address, interface=interface, confirm=confirm
        )
        return asdict(preview)

    # --- v0.11: firewall rule toggle (by comment, never create) ---------

    @mcp.tool()
    @_safe
    def enable_firewall_rule(
        device_name: str, comment: str, chain: str | None = None, confirm: bool = False
    ) -> dict[str, Any]:
        """Enable an EXISTING firewall filter rule (`/ip/firewall/filter set
        disabled=no`), resolved by its `comment` - optionally narrowed by
        `chain` if more than one rule shares that comment.

        SAFE BY DESIGN: this NEVER creates a rule. Intended workflow: an
        admin creates a rule ahead of time on the device with a descriptive
        `comment` (e.g. `comment="Bloqueio_Ataque_X"`), reviews it once, and
        leaves it disabled; an LLM caller later enables it via this tool
        when it detects the condition the rule exists to guard against. If
        it goes wrong, the admin knows exactly which rule was toggled - the
        same one they already wrote and reviewed. See README's "Firewall
        rule toggle (by comment)" section.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview - the FULL matched rule, not
        just its `disabled` field, so you can confirm WHICH rule this is -
        without changing anything; call again with confirm=True to actually
        apply it. Errors clearly if no rule matches `comment` (narrowed by
        `chain`), or if more than one still does (`AmbiguousResourceError`)
        - never guesses which one to toggle.
        """
        client = _client(device_name)
        preview = guard.enable_firewall_rule(client, settings, comment=comment, chain=chain, confirm=confirm)
        return asdict(preview)

    @mcp.tool()
    @_safe
    def disable_firewall_rule(
        device_name: str, comment: str, chain: str | None = None, confirm: bool = False
    ) -> dict[str, Any]:
        """Disable an EXISTING firewall filter rule (`/ip/firewall/filter set
        disabled=yes`), resolved by its `comment` - optionally narrowed by
        `chain` if more than one rule shares that comment.

        Same "never creates a rule" guarantee and comment-based resolution
        as `enable_firewall_rule` - see its docstring and README's "Firewall
        rule toggle (by comment)" section.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to get a before/after preview without changing anything;
        call again with confirm=True to actually apply it. Errors clearly if
        no rule matches `comment` (narrowed by `chain`), or if more than one
        still does (`AmbiguousResourceError`).
        """
        client = _client(device_name)
        preview = guard.disable_firewall_rule(client, settings, comment=comment, chain=chain, confirm=confirm)
        return asdict(preview)

    # --- v0.13: WireGuard VPN management ---------------------------------

    @mcp.tool()
    @_safe
    def add_wireguard_interface(
        device_name: str, name: str, listen_port: int | None = None, confirm: bool = False
    ) -> dict[str, Any]:
        """Create a WireGuard tunnel interface (`/interface/wireguard add`).

        RouterOS generates the interface's private-key internally - this
        tool never accepts (or returns) one. The `confirm=False` preview's
        `after` only describes what will be created (`name`, `listen-port`
        if given) - it does not invent a `public-key`, since RouterOS hasn't
        generated the key pair yet at preview time. The `confirm=True`
        applied result re-reads the created interface and reports its real
        `public-key`, with `private-key` always stripped. See README's
        "WireGuard management" section.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to preview without changing anything; call again with
        confirm=True to actually create it. Errors clearly if `name` already
        exists - never creates a duplicate.
        """
        client = _client(device_name)
        preview = guard.add_wireguard_interface(
            client, settings, name=name, listen_port=listen_port, confirm=confirm
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def add_wireguard_peer(
        device_name: str,
        interface: str,
        public_key: str,
        allowed_address: str,
        endpoint_address: str | None = None,
        endpoint_port: int | None = None,
        persistent_keepalive: str | None = None,
        comment: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Add a WireGuard peer (`/interface/wireguard/peers add`) to an
        existing tunnel `interface`.

        `public_key` is the REMOTE peer's own public key (base64, 44 chars).
        `allowed_address` is a comma-separated list of CIDR ranges routed
        through this peer (e.g. "10.0.0.2/32,10.0.0.3/32").
        `endpoint_address`/`endpoint_port` (the peer's reachable
        address/port, if any) and `persistent_keepalive` (a RouterOS
        duration, e.g. "25s") are optional.

        Does NOT accept a private-key or preshared-key parameter - the
        remote peer's own private key, and any preshared key, are entirely
        out of this tool's scope.

        `interface` must already exist - create it first with
        add_wireguard_interface; errors clearly if it doesn't. Refuses to
        add a duplicate peer (same `public_key` already registered on the
        same `interface`) - never creates a duplicate.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to preview without changing anything; call again with
        confirm=True to actually add it.
        """
        client = _client(device_name)
        preview = guard.add_wireguard_peer(
            client,
            settings,
            interface=interface,
            public_key=public_key,
            allowed_address=allowed_address,
            endpoint_address=endpoint_address,
            endpoint_port=endpoint_port,
            persistent_keepalive=persistent_keepalive,
            comment=comment,
            confirm=confirm,
        )
        return asdict(preview)

    @mcp.tool()
    @_safe
    def remove_wireguard_peer(
        device_name: str,
        interface: str,
        public_key: str | None = None,
        comment: str | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        """Remove a WireGuard peer (`/interface/wireguard/peers remove`)
        from `interface`, resolved by `public_key` or `comment` (`public_key`
        tried first if both are given). At least one of the two must be
        given.

        WRITE tool, guarded: blocked entirely unless the server is running
        with MIKROTIK_ALLOW_WRITE=true. Call with confirm=False (the
        default) to preview what would be removed without changing
        anything; call again with confirm=True to actually remove it.
        Errors clearly if nothing matches, or if more than one peer still
        matches (AmbiguousResourceError) - never guesses which one to
        remove.
        """
        client = _client(device_name)
        preview = guard.remove_wireguard_peer(
            client, settings, interface=interface, public_key=public_key, comment=comment, confirm=confirm
        )
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
