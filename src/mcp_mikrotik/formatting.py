"""Shared response-shaping helpers for read tools.

Kept in one place so no two tools reimplement RouterOS's habit of encoding
booleans as the strings "true"/"false", or the "list of rows -> plain dicts"
conversion.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime
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


def coerce_ros_bool(value: Any) -> bool | None:
    """Normalize a RouterOS boolean *field value* to `bool | None`, for code
    that branches on it (as opposed to `ros_bool` above, which is for
    read-tool *presentation* - see the difference below).

    CONFIRMED AGAINST REAL HARDWARE (ROS6 .254, ROS7 .237): librouteros (the
    real device transport this package uses) returns a RouterOS boolean
    field as a Python `bool` - `True`/`False` - or omits the field entirely
    when absent, NEVER as the strings "true"/"false". A prior version of
    this package's write-guard compared such a field directly against the
    string `"true"`/`"false"` (e.g. `remove_route`'s dynamic-route refusal);
    since `True == "true"` is `False` in Python, that comparison silently
    never matched on real hardware - see the module note above
    `guard.remove_route` for the security impact.

    ROS6 and ROS7 additionally differ in when a *false* boolean field is
    present at all: ROS6 commonly OMITS the field entirely when it is false
    (e.g. `/ip/route`'s `dynamic` is simply absent on an ordinary static
    route), while ROS7 sends it explicitly as `False`. Both cases must be
    treated as "false" by a caller that only needs to know true-vs-not-true.

    Returns:
      - `True` for `True` (bool) or a case-insensitive "true"/"yes" string.
      - `False` for `False` (bool) or a case-insensitive "false"/"no" string.
      - `None` for `None`, an absent field (`.get(...)` already yields
        `None`), an empty string, or any other unrecognized value - callers
        that need to distinguish "definitely false" from "unknown/absent"
        (e.g. a caller that wants to warn rather than silently skip when it
        can't tell) can branch on `None` separately; a caller that only
        cares about true-vs-not-true can simply check `is True`.

    A string is still accepted (case-insensitively) for robustness against
    any code path or RouterOS version that does send one - but the primary
    shape this exists to handle correctly is the literal `bool`/absent case
    above, which the old string-only comparison got wrong.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in _TRUE_STRINGS:
            return True
        if lowered in _FALSE_STRINGS:
            return False
    return None


def coerce_ros_number(value: Any) -> int | float | None:
    """Normalize a RouterOS numeric field value to `int | float | None`.

    CONFIRMED AGAINST REAL HARDWARE (CRS318-16P-2S+, ROS6.49.20, 2026-07-12):
    `/interface/ethernet/poe/monitor`'s `poe-out-current`/`poe-out-power`/
    `poe-out-voltage` fields do NOT have one consistent type - the SAME
    monitor reply carried `poe-out-current=204` as a Python `int` alongside
    `poe-out-power='4.7'` as a `str` on one port, and `poe-out-power=1` as an
    `int` on another, with `poe-out-voltage='23.5'` as a `str` - int and
    string-decimal mixed within a single reply AND across ports of the same
    device. Same class of lesson as `coerce_ros_bool` above (a RouterOS
    field's type isn't fixed across devices/firmware versions) - any caller
    that does arithmetic or a numeric comparison (e.g. README's "PoE control"
    walkthrough: "confirm it's actually drawing power (voltage/current > 0)")
    needs a value it can rely on being `int`/`float`/`None`, never a string
    that happens to look numeric.

    Returns:
      - The value itself, unchanged, for an `int` or `float` (but see the
        `bool` note below).
      - `int(value)` or `float(value)` for a string that parses as one -
        tried as `int` first (e.g. `"204"` -> `204`), then `float` (e.g.
        `"4.7"` -> `4.7`, `"23.5"` -> `23.5`).
      - `None` for `None`, an absent field (`.get(...)` already yields
        `None`), an empty/whitespace-only string, a string that parses as
        neither, or a `bool` (RouterOS never uses this field shape for a
        boolean-valued field, and `bool` is a Python `int` subclass, so it
        would otherwise pass through the `isinstance(value, int)` check
        below as `True`/`False` rather than the numeric value a caller
        actually wants).
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text)
        except ValueError:
            pass
        try:
            return float(text)
        except ValueError:
            return None
    return None


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


# v1.6: RouterOS's own two observed shapes for a datetime-valued field (e.g.
# /certificate's invalid-before/invalid-after) - "2027-01-15 12:00:00"
# (ISO-ish, seen on some RouterOS builds/locales) and "jan/15/2027 12:00:00"
# (RouterOS's traditional CLI rendering, also used elsewhere in this codebase -
# see the ("system", "scheduler") fixture's "next-run" in tests/conftest.py).
# The month abbreviation is matched against a fixed English table rather than
# via strptime's locale-dependent "%b", because RouterOS always renders it in
# English regardless of the server process's own locale - relying on "%b"
# would make parsing depend on whatever locale this package happens to run
# under, which has nothing to do with the device.
_MONTH_ABBREVIATIONS = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}

_ISO_LIKE_DATETIME_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})(?:[ T](\d{1,2}):(\d{2}):(\d{2}))?$")
_ROS_ABBR_DATETIME_RE = re.compile(r"^([A-Za-z]{3})/(\d{1,2})/(\d{4})(?:\s+(\d{1,2}):(\d{2}):(\d{2}))?$")


def parse_ros_datetime(value: Any) -> datetime | None:
    """Best-effort parse of a RouterOS datetime-shaped field (e.g.
    `/certificate`'s `invalid-before`/`invalid-after`) into a naive
    `datetime`, or `None` if `value` isn't a string or doesn't match either
    known RouterOS shape.

    DEFENSIVE, NEVER RAISES: RouterOS's own date rendering varies by version/
    locale (confirmed shapes: `"2027-01-15 12:00:00"` and
    `"jan/15/2027 12:00:00"`, the latter with English month abbreviations
    regardless of the device's own locale - see module note above). A caller
    that can't parse a given value should treat expiry as unknown - keep the
    raw field, omit any derived value - rather than guess or raise. This is
    the same "shape-only, best-effort" spirit `split_address_port` above and
    `validation.py`'s validators already document.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None

    match = _ISO_LIKE_DATETIME_RE.match(text)
    if match:
        year, month, day, hour, minute, second = match.groups()
        try:
            return datetime(int(year), int(month), int(day), int(hour or 0), int(minute or 0), int(second or 0))
        except ValueError:
            return None

    match = _ROS_ABBR_DATETIME_RE.match(text)
    if match:
        month_name, day, year, hour, minute, second = match.groups()
        month = _MONTH_ABBREVIATIONS.get(month_name.lower())
        if month is None:
            return None
        try:
            return datetime(int(year), month, int(day), int(hour or 0), int(minute or 0), int(second or 0))
        except ValueError:
            return None

    return None


def days_until(value: Any, now: datetime | None = None) -> int | None:
    """`(parsed_datetime - now).days` for a RouterOS datetime-shaped field,
    or `None` if `value` can't be parsed (see `parse_ros_datetime`).

    Used by `certificates` (server.py) and the security-audit certificate-
    expiry check (security.py) so both compute "days until X" the exact same
    way - negative once the date is in the past, positive while still ahead.
    `now` is injectable for deterministic tests; defaults to the real current
    time.
    """
    parsed = parse_ros_datetime(value)
    if parsed is None:
        return None
    return (parsed - (now if now is not None else datetime.now())).days
