"""Shared response-shaping helpers for read tools.

Kept in one place so no two tools reimplement RouterOS's habit of encoding
booleans as the strings "true"/"false", or the "list of rows -> plain dicts"
conversion.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

_TRUE_STRINGS = {"true", "yes"}
_FALSE_STRINGS = {"false", "no"}


def ros_bool(value: Any) -> bool:
    """RouterOS API values are frequently the strings 'true'/'false' rather than bool."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in _TRUE_STRINGS:
            return True
        if lowered in _FALSE_STRINGS:
            return False
    return bool(value)


def rows_to_list(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize an iterable of API rows into a plain list.

    R4: MikrotikClient.path()/ping() already materialize each row as a
    plain dict (client.py), so this used to redundantly re-copy every row
    with a second `dict(row)`. All current callers only ever pass rows that
    are already plain dicts (client.path() results), so this just coerces
    the iterable to a list without a second per-row copy.
    """
    return list(rows)


def filter_disabled(rows: Iterable[dict[str, Any]], include_disabled: bool) -> list[dict[str, Any]]:
    """Drop rows whose 'disabled' field is truthy, unless include_disabled is set."""
    all_rows = rows_to_list(rows)
    if include_disabled:
        return all_rows
    return [row for row in all_rows if not ros_bool(row.get("disabled", False))]


def strip_sensitive_fields(rows: Iterable[dict[str, Any]], keys: Iterable[str]) -> list[dict[str, Any]]:
    """Drop the given field name(s) from every row before it ever reaches a caller.

    v0.8: used by `wireguard_peers` to guarantee a WireGuard private-key can
    never be returned. RouterOS's own `/interface/wireguard/peers` reply
    doesn't carry a `private-key` field in the first place (only
    `/interface/wireguard` - the tunnel interfaces themselves - does), so
    this was originally belt-and-suspenders: it strips the field defensively
    regardless, so a future RouterOS version, firmware quirk, or added read
    tool can't leak one just because the safety net wasn't there yet.

    v0.13 adds a read tool (`wireguard_interfaces`) for `/interface/wireguard`
    itself, whose reply DOES genuinely carry a `private-key` - see
    `WIREGUARD_SENSITIVE_FIELDS` below, and `guard.py`'s
    `_redact_wireguard_row`, which applies this same helper to every
    WireGuard write tool's before/after preview too (interface `private-key`,
    peer `preshared-key`), so the write-guard's audit journal - which logs
    whatever a guard.py function returns - can never carry one either.
    """
    key_set = set(keys)
    return [{field: value for field, value in row.items() if field not in key_set} for row in rows]


# v0.13: the two field names that must NEVER survive in any WireGuard row
# this package returns or journals, from any tool (read or write):
# `private-key` (a tunnel interface's own key, RouterOS-generated, never
# accepted as input) and `preshared-key` (an optional per-peer secret,
# likewise never accepted as input by add_wireguard_peer). One shared
# constant so server.py's read tools and guard.py's write-preview redaction
# can never drift out of sync with each other.
WIREGUARD_SENSITIVE_FIELDS = frozenset({"private-key", "preshared-key"})


def split_address_port(value: str) -> tuple[str, str | None]:
    """Split a RouterOS connection-tracking address field into (address, port).

    v0.11: `/ip/firewall/connection`'s `src-address`/`dst-address` fields
    pack the port into the same string as the address - e.g.
    "192.0.2.1:80" (IPv4:port), "[2001:db8::1]:80" (bracketed IPv6:port).
    Used by `connection_tracking` (server.py) to filter/report address and
    port as separate values instead of a caller having to parse this
    RouterOS-specific packed format itself.

    Best-effort, not an exhaustive RouterOS grammar (same spirit as
    validation.py's shape-only checks): a bracketed IPv6 address is parsed
    by its '[' / ']' delimiters; a value with exactly one ':' is treated as
    "address:port" (always true for an IPv4:port pair, since a bare IPv4
    address never itself contains a ':'); anything else - a bare/unbracketed
    IPv6 address (multiple ':', no brackets), or an empty string - is
    returned as-is with port=None rather than guessed at.
    """
    if not value:
        return "", None
    if value.startswith("["):
        end = value.find("]")
        if end != -1:
            address = value[1:end]
            rest = value[end + 1 :]
            if rest.startswith(":"):
                return address, rest[1:]
            return address, None
        return value, None
    if value.count(":") == 1:
        address, _, port = value.partition(":")
        return address, port
    return value, None
