"""Input validation applied before any value is sent to a device.

Used for the `ping` tool's `address` parameter, and for the v0.3 bandwidth/
DHCP-reservation write tools' `target`/`address`/`mac_address`/`max_limit`/
`limit_at` parameters. Note this is not an injection defense: every one of
these values is always passed to librouteros as a structured parameter
(never interpolated into a shell/command string), so command injection
through it is already ruled out by construction (see client.py). This
module exists to reject garbage input early and return a clear error
instead of forwarding it to the device.
"""

from __future__ import annotations

import re

from .exceptions import ValidationError

_OCTET = r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4 = re.compile(rf"^{_OCTET}(\.{_OCTET}){{3}}$")

# Simplified IPv6 matcher: 2-8 colon-separated hex groups (each 0-4 hex
# digits, allowing "::" compression) with an optional zone id (%eth0).
# Not a full RFC 5952 validator - it exists to reject non-IPv6 garbage,
# not to certify strict correctness.
_IPV6 = re.compile(r"^([0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(%[\w.-]+)?$")

_HOSTNAME_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOSTNAME = re.compile(rf"^{_HOSTNAME_LABEL}(\.{_HOSTNAME_LABEL})*$")

_MAX_ADDRESS_LENGTH = 253

# Colon-separated hex MAC, RouterOS's own display/accepted format
# (e.g. "AA:BB:CC:DD:EE:FF"). Dash-separated or bare-hex forms are rejected
# rather than normalized, so a caller always sees exactly what they typed
# reflected back on a validation error.
_MAC = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")

# One side of a RouterOS rate pair (max-limit / limit-at): a plain number,
# optionally with a k/M/G (bits-per-second) suffix, e.g. "10M", "512k", "0".
# Case-insensitive on the suffix, matching RouterOS itself.
_RATE = re.compile(r"^\d+(\.\d+)?[kKmMgG]?$")


def _has_numeric_last_label(hostname: str) -> bool:
    """True if the last dot-separated label is purely numeric.

    A hostname regex alone would happily accept malformed/out-of-range IPv4
    look-alikes like "999.1.1.1" or "1.2.3" (each label is individually a
    valid hostname label). Real hostnames don't end in an all-numeric label
    (RFC 1123 discourages purely-numeric TLDs precisely to keep hostnames
    and IP addresses unambiguous), so this rejects that class of garbage
    without weakening the IPv4/IPv6 patterns above.
    """
    return hostname.rsplit(".", 1)[-1].isdigit()


def validate_ping_address(address: str) -> str:
    """Validate that `address` is a plausible IPv4/IPv6 address or hostname.

    Returns the (stripped) address on success, raises ValidationError otherwise.
    """
    if not isinstance(address, str) or not address.strip():
        raise ValidationError("Ping address must be a non-empty string.")

    address = address.strip()
    if len(address) > _MAX_ADDRESS_LENGTH:
        raise ValidationError("Ping address is too long.")

    if _IPV4.match(address):
        return address
    if _IPV6.match(address):
        return address
    if _HOSTNAME.match(address) and not _has_numeric_last_label(address):
        return address

    raise ValidationError(f"Ping address {address!r} is not a valid IPv4/IPv6 address or hostname.")


def validate_positive_limit(value: int, max_value: int, field_name: str) -> int:
    """Validate a caller-supplied row/count limit (R3).

    `value <= 0` is a caller mistake (e.g. limit=0 or count=-1), not a
    "give me nothing" request - reject it with a clear ValidationError
    instead of silently clamping it up to 1, which used to hide the mistake.
    The upper bound (`max_value`) is a legitimate server-side cap, so it is
    still clamped rather than rejected.
    """
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValidationError(f"{field_name!r} must be a positive integer, got {value!r}.")
    return min(value, max_value)


def validate_ip_address(address: str) -> str:
    """Validate that `address` is a plain IPv4 or IPv6 address (no hostname,
    no subnet). Used for the DHCP static lease `address` parameter, which
    must be a literal address the DHCP server can hand out - unlike
    `validate_ping_address`, a hostname is not a valid value here.

    Returns the (stripped) address on success, raises ValidationError otherwise.
    """
    if not isinstance(address, str) or not address.strip():
        raise ValidationError("Address must be a non-empty string.")

    address = address.strip()
    if len(address) > _MAX_ADDRESS_LENGTH:
        raise ValidationError("Address is too long.")

    if _IPV4.match(address):
        return address
    if _IPV6.match(address):
        return address

    raise ValidationError(f"Address {address!r} is not a valid IPv4/IPv6 address.")


def is_literal_ip_address(value: str) -> bool:
    """True if `value` is a literal IPv4/IPv6 address (no hostname) - a
    non-raising boolean cousin of `validate_ip_address`, reusing the same
    `_IPV4`/`_IPV6` matchers rather than a separate check.

    v1.8: used by `guard.set_ntp_servers` to tell a plain IP apart from a
    hostname when mapping onto ROS6's `primary-ntp`/`secondary-ntp` fields,
    which (on older RouterOS versions) only accept a literal IP - not a
    validation failure on its own (the value was already accepted upstream
    by `validate_ping_address`, which allows either shape), just a shape
    check the caller needs to branch on.
    """
    return bool(_IPV4.match(value) or _IPV6.match(value))


def validate_target(target: str) -> str:
    """Validate a Simple Queue `target`: an IPv4/IPv6 address, optionally
    followed by a "/prefix-length" subnet mask (e.g. "10.0.0.5",
    "10.0.0.0/24", "2001:db8::/64"). Reuses the same IPv4/IPv6 address
    matchers as validate_ping_address/validate_ip_address, just with an
    optional CIDR suffix and its own bounds check (0-32 for IPv4, 0-128 for
    IPv6).

    Returns the (stripped) target on success, raises ValidationError otherwise.
    """
    if not isinstance(target, str) or not target.strip():
        raise ValidationError("Target must be a non-empty string.")

    target = target.strip()
    if len(target) > _MAX_ADDRESS_LENGTH:
        raise ValidationError("Target is too long.")

    address_part, sep, prefix_part = target.partition("/")
    prefix: int | None = None
    if sep:
        if not prefix_part.isdigit():
            raise ValidationError(f"Target {target!r} has an invalid subnet prefix.")
        prefix = int(prefix_part)

    if _IPV4.match(address_part):
        if prefix is not None and not (0 <= prefix <= 32):
            raise ValidationError(f"Target {target!r} has an invalid IPv4 subnet prefix (expected 0-32).")
        return target
    if _IPV6.match(address_part):
        if prefix is not None and not (0 <= prefix <= 128):
            raise ValidationError(f"Target {target!r} has an invalid IPv6 subnet prefix (expected 0-128).")
        return target

    raise ValidationError(f"Target {target!r} is not a valid IPv4/IPv6 address or subnet.")


def validate_mac_address(mac: str) -> str:
    """Validate a MAC address in RouterOS's colon-separated hex form
    (e.g. "AA:BB:CC:DD:EE:FF"). Returns it (stripped, upper-cased for a
    consistent lookup/comparison key - RouterOS itself is case-insensitive
    here) on success, raises ValidationError otherwise.
    """
    if not isinstance(mac, str) or not mac.strip():
        raise ValidationError("MAC address must be a non-empty string.")

    mac = mac.strip()
    if not _MAC.match(mac):
        raise ValidationError(f"MAC address {mac!r} is not valid (expected AA:BB:CC:DD:EE:FF format).")
    return mac.upper()


# --- v0.4: address-list access control ---------------------------------

# Firewall address-list `list` name: letters/digits plus '.', '_', '-'
# (RouterOS itself is more permissive - e.g. it allows spaces - but this
# package restricts to a conservative, unambiguous charset rather than
# trying to enumerate everything RouterOS happens to accept).
_LIST_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")

# Control characters (including newline/tab/CR) are rejected from free-text
# `comment` fields so a comment can't be used to smuggle multi-line content
# into router state. Like every other validator here, this is not an
# injection defense (see module docstring) - device communication is always
# structured - it just keeps comments to plain, single-line text.
_COMMENT_UNSAFE = re.compile(r"[\x00-\x1f\x7f]")
_MAX_COMMENT_LENGTH = 255

# RouterOS address-list/queue `timeout` value: either a duration made of
# w/d/h/m/s components in that order (e.g. "1d", "2h30m", "1w2d3h4m5s"), or a
# plain "HH:MM:SS"-style clock value (e.g. "01:30:00", "0:05"). This is a
# best-effort format check, not an exhaustive RouterOS grammar - see
# https://help.mikrotik.com/docs/spaces/ROS/pages/328088/Queues for the
# canonical reference.
_TIMEOUT_DURATION = re.compile(r"^(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$")
_TIMEOUT_CLOCK = re.compile(r"^\d{1,3}(:[0-5]?\d){1,2}$")
_MAX_TIMEOUT_LENGTH = 32


def validate_address_list_name(name: str) -> str:
    """Validate a firewall address-list `list` name (the named list an entry
    belongs to, e.g. "blocked-clients"). Used by add_to_address_list and
    remove_from_address_list.

    Returns the (stripped) name on success, raises ValidationError otherwise.
    """
    if not isinstance(name, str) or not name.strip():
        raise ValidationError("Address-list name must be a non-empty string.")

    name = name.strip()
    if not _LIST_NAME.match(name):
        raise ValidationError(
            f"Address-list name {name!r} is not valid "
            "(letters, digits, '.', '_', '-' only, starting with a letter/digit, max 64 chars)."
        )
    return name


def validate_comment(comment: str, field_name: str = "comment") -> str:
    """Validate a free-text `comment` field: a plain string, no control
    characters (including newlines), within a sane length cap.

    Returns `comment` unchanged on success, raises ValidationError otherwise.
    """
    if not isinstance(comment, str):
        raise ValidationError(f"{field_name} must be a string.")
    if len(comment) > _MAX_COMMENT_LENGTH:
        raise ValidationError(f"{field_name} is too long (max {_MAX_COMMENT_LENGTH} characters).")
    if _COMMENT_UNSAFE.search(comment):
        raise ValidationError(f"{field_name} contains control characters, which are not allowed.")
    return comment


def validate_timeout(value: str, field_name: str = "timeout") -> str:
    """Validate a RouterOS `timeout` value (address-list entry expiry), as
    either a w/d/h/m/s duration (e.g. "1d", "2h30m") or an "HH:MM:SS"-style
    clock value (e.g. "01:30:00"). See _TIMEOUT_DURATION/_TIMEOUT_CLOCK above
    for the exact (best-effort) grammar accepted.

    Returns the (stripped) value on success, raises ValidationError otherwise.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field_name} must be a non-empty string.")

    value = value.strip()
    if len(value) > _MAX_TIMEOUT_LENGTH:
        raise ValidationError(f"{field_name} is too long.")

    if _TIMEOUT_CLOCK.match(value):
        return value

    match = _TIMEOUT_DURATION.match(value)
    if match and any(match.groups()):
        return value

    raise ValidationError(
        f"{field_name} value {value!r} is not a valid RouterOS timeout "
        '(expected a duration like "1d"/"2h30m", or "HH:MM:SS").'
    )


# --- v0.6: physical layer / PoE ------------------------------------------

# RouterOS interface name: letters/digits plus '.', '_', '-' (covers real
# names like "ether1", "sfp-sfpplus1", "wlan1", "bridge1", "vlan100"). Like
# `_LIST_NAME` above, this is a conservative, unambiguous charset rather than
# an attempt to enumerate everything RouterOS itself accepts - it exists to
# reject obviously-wrong input (e.g. a stray "/" or shell metacharacter)
# before ever touching a device, not as an injection defense (see module
# docstring: every value is always sent as a structured API parameter).
_INTERFACE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")

# RouterOS `/interface/ethernet`'s `poe-out` field: exactly these three
# values (RouterOS itself rejects anything else at the CLI too).
_POE_OUT_VALUES = ("auto-on", "forced-on", "off")


def validate_interface_name(name: str) -> str:
    """Validate a RouterOS interface name (e.g. "ether1"), used by
    `interface_traffic` and `set_poe_out`. This only rejects a name whose
    *shape* is implausible - whether it actually exists on a given device is
    checked separately, against the device itself (see server.py/guard.py).

    Returns the (stripped) name on success, raises ValidationError otherwise.
    """
    if not isinstance(name, str) or not name.strip():
        raise ValidationError("Interface name must be a non-empty string.")

    name = name.strip()
    if not _INTERFACE_NAME.match(name):
        raise ValidationError(
            f"Interface name {name!r} is not valid "
            "(letters, digits, '.', '_', '-' only, starting with a letter/digit, max 64 chars)."
        )
    return name


def validate_poe_out(value: str) -> str:
    """Validate a RouterOS `poe-out` mode, used by `set_poe_out`. Must be one
    of "auto-on", "forced-on", "off".

    Returns the (stripped) value on success, raises ValidationError otherwise.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("poe_out must be a non-empty string.")

    value = value.strip()
    if value not in _POE_OUT_VALUES:
        raise ValidationError(f"poe_out value {value!r} is not valid (expected one of {_POE_OUT_VALUES}).")
    return value


# --- v0.7: containers ------------------------------------------------------

# A container identifier (matched against /container's `name` field, then
# its `tag` field - see guard._find_container_row) is deliberately NOT
# restricted to the same conservative charset as _INTERFACE_NAME/_LIST_NAME:
# a RouterOS container `tag` is a Docker-style image reference, e.g.
# "myregistry.example.com:5000/library/alpine:latest", which legitimately
# uses ':', '/', and '.'. This validator only rejects the same class of
# garbage validate_comment already rejects (empty, too long, control
# characters) - not because it's an injection defense (see module docstring:
# every value is always sent as a structured API parameter), but to fail
# clearly before ever touching a device rather than forwarding whatever was
# typed.
_MAX_CONTAINER_IDENTIFIER_LENGTH = 255


def validate_container_identifier(value: str) -> str:
    """Validate a container `name`/`tag` identifier, used by
    `start_container`/`stop_container`. Returns the (stripped) value on
    success, raises ValidationError otherwise.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("Container identifier must be a non-empty string.")

    value = value.strip()
    if len(value) > _MAX_CONTAINER_IDENTIFIER_LENGTH:
        raise ValidationError("Container identifier is too long.")
    if _COMMENT_UNSAFE.search(value):
        raise ValidationError("Container identifier contains control characters, which are not allowed.")
    return value


def validate_rate_pair(value: str, field_name: str) -> str:
    """Validate a RouterOS rate-pair string, as used by Simple Queue's
    `max-limit` and `limit-at` fields. RouterOS's own format is
    "upload/download" (e.g. "10M/5M" = 10 Mbit/s up, 5 Mbit/s down; see
    https://help.mikrotik.com/docs/spaces/ROS/pages/328088/Queues), each side
    a plain number with an optional k/M/G (bits/second) suffix.

    Returns the value unchanged (the suffix's case is not normalized -
    RouterOS accepts either) on success, raises ValidationError otherwise.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field_name} must be a non-empty string.")

    value = value.strip()
    parts = value.split("/")
    if len(parts) != 2 or not all(_RATE.match(part) for part in parts):
        raise ValidationError(
            f"{field_name} value {value!r} is not a valid RouterOS rate pair "
            '(expected "upload/download", e.g. "10M/5M").'
        )
    return value


# --- v0.9: failover route + Netwatch writes ---------------------------------


def validate_dst_address(value: str) -> str:
    """Validate a RouterOS route `dst-address` (IPv4/IPv6, optionally with a
    "/prefix-length" subnet, e.g. "0.0.0.0/0", "10.0.0.0/24", "::/0"). Used
    by set_route_distance/enable_route/disable_route (guard.py) as (part of)
    the STABLE identifier used to resolve one specific `/ip/route` row -
    never a dynamic `.id`/list index. Same shape as `validate_target`, kept
    as its own function since it validates a different field on a different
    RouterOS menu (route `dst-address` vs Simple Queue `target`), not to be
    confused with one another.

    Returns the (stripped) value on success, raises ValidationError otherwise.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("dst_address must be a non-empty string.")

    value = value.strip()
    if len(value) > _MAX_ADDRESS_LENGTH:
        raise ValidationError("dst_address is too long.")

    address_part, sep, prefix_part = value.partition("/")
    prefix: int | None = None
    if sep:
        if not prefix_part.isdigit():
            raise ValidationError(f"dst_address {value!r} has an invalid subnet prefix.")
        prefix = int(prefix_part)

    if _IPV4.match(address_part):
        if prefix is not None and not (0 <= prefix <= 32):
            raise ValidationError(f"dst_address {value!r} has an invalid IPv4 subnet prefix (expected 0-32).")
        return value
    if _IPV6.match(address_part):
        if prefix is not None and not (0 <= prefix <= 128):
            raise ValidationError(f"dst_address {value!r} has an invalid IPv6 subnet prefix (expected 0-128).")
        return value

    raise ValidationError(f"dst_address {value!r} is not a valid IPv4/IPv6 address or subnet.")


def validate_route_gateway(value: str) -> str:
    """Validate a RouterOS route `gateway`: an IPv4/IPv6 address (the common
    case), or a bare interface name - RouterOS also accepts a gateway
    expressed as an outgoing interface (e.g. for point-to-point/PPP links,
    "gateway=ether1" rather than an address). Interface-name shape reuses
    the same conservative charset as `_INTERFACE_NAME`
    (`validate_interface_name`).

    Returns the (stripped) value on success, raises ValidationError otherwise.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("gateway must be a non-empty string.")

    value = value.strip()
    if len(value) > _MAX_ADDRESS_LENGTH:
        raise ValidationError("gateway is too long.")

    if _IPV4.match(value):
        return value
    if _IPV6.match(value):
        return value
    if _INTERFACE_NAME.match(value):
        return value

    raise ValidationError(f"gateway {value!r} is not a valid IPv4/IPv6 address or interface name.")


def validate_route_distance(value: int) -> int:
    """Validate a RouterOS route `distance` (failover priority - the lower
    distance wins): an integer 1-255, RouterOS's own accepted range.

    Returns `value` unchanged on success, raises ValidationError otherwise.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(f"distance must be an integer, got {value!r}.")
    if not (1 <= value <= 255):
        raise ValidationError(f"distance {value!r} is out of range (expected 1-255).")
    return value


# --- v0.10: static DNS + DNS cache + DHCP lease removal + Wake-on-LAN ------


def validate_dns_name(value: str) -> str:
    """Validate a static DNS entry's `name` (the domain/hostname being
    resolved, e.g. "blocked.example.com") - used by add_static_dns/
    remove_static_dns for the entry's `name`, and (when the entry is a
    CNAME) for the `address` parameter's CNAME-target value too.

    Unlike `validate_ping_address`, a DNS static `name` (or CNAME target) is
    never itself a literal IP address - only the hostname shape is accepted
    here, reusing the same `_HOSTNAME`/`_has_numeric_last_label` matchers
    `validate_ping_address` uses for its own hostname branch.

    Returns the (stripped) name on success, raises ValidationError otherwise.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("DNS name must be a non-empty string.")

    value = value.strip()
    if len(value) > _MAX_ADDRESS_LENGTH:
        raise ValidationError("DNS name is too long.")

    if _HOSTNAME.match(value) and not _has_numeric_last_label(value):
        return value

    raise ValidationError(f"DNS name {value!r} is not a valid hostname/domain.")


# RouterOS /ip/dns/static supports several record types (A, AAAA, CNAME,
# MX, NS, TXT, ...); this package only exposes the two simplest and most
# common ones for add_static_dns's `record_type` - a plain address record
# (the default) and a CNAME alias. Extending to other types is a future
# round's decision, not something to widen silently here.
_DNS_RECORD_TYPES = ("A", "CNAME")


def validate_dns_record_type(value: str) -> str:
    """Validate a static DNS entry's `type`, used by add_static_dns/
    remove_static_dns. Must be one of "A" (default, a plain address record)
    or "CNAME" (an alias to another hostname). Case-insensitive on input,
    normalized to upper-case on return (RouterOS's own field is upper-case).

    Returns the normalized value on success, raises ValidationError otherwise.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("DNS record type must be a non-empty string.")

    normalized = value.strip().upper()
    if normalized not in _DNS_RECORD_TYPES:
        raise ValidationError(f"DNS record type {value!r} is not valid (expected one of {_DNS_RECORD_TYPES}).")
    return normalized


# --- v0.11: firewall rule toggle (by comment) + connection tracking --------

# A firewall rule's `chain` (e.g. filter's "input"/"forward"/"output", NAT's
# "srcnat"/"dstnat", mangle's "prerouting"/"postrouting"/"forward"/"input"/
# "output", or a custom jump-target chain on any of the three) - used only as
# an OPTIONAL disambiguator when enable_firewall_rule/disable_firewall_rule
# (filter), enable_nat_rule/disable_nat_rule (NAT), or enable_mangle_rule/
# disable_mangle_rule (mangle)'s `comment` still matches more than one rule
# (see guard._find_firewall_rule_rows, shared by all three menus). Shape-only,
# same conservative charset as `_INTERFACE_NAME`/`_LIST_NAME` - not restricted
# to a fixed enum, since RouterOS allows arbitrary custom chains on every one
# of these menus too.
_CHAIN_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def validate_firewall_rule_comment(value: str) -> str:
    """Validate a firewall rule's `comment` - the STABLE, MANDATORY
    identifier the filter/NAT/mangle rule-toggle pairs (enable_firewall_rule/
    disable_firewall_rule, enable_nat_rule/disable_nat_rule,
    enable_mangle_rule/disable_mangle_rule) all resolve a rule by (never a
    dynamic `.id`/list index - see guard.py's module docstring for why that
    matters). Unlike `validate_comment` (used elsewhere for an OPTIONAL
    free-text field on a write that creates something new), an EMPTY comment
    is rejected here outright: it can never reliably identify one specific
    EXISTING rule on a device that may have several undecorated ones.

    Returns the (stripped) value on success, raises ValidationError otherwise.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(
            "comment must be a non-empty string - it identifies which existing firewall rule to toggle."
        )
    value = value.strip()
    if len(value) > _MAX_COMMENT_LENGTH:
        raise ValidationError(f"comment is too long (max {_MAX_COMMENT_LENGTH} characters).")
    if _COMMENT_UNSAFE.search(value):
        raise ValidationError("comment contains control characters, which are not allowed.")
    return value


def validate_firewall_chain(value: str) -> str:
    """Validate a firewall rule's `chain`, used only to narrow the
    filter/NAT/mangle rule-toggle pairs' `comment` match when it is still
    ambiguous after matching on `comment` alone. Shape-only (see
    `_CHAIN_NAME`) - not restricted to a fixed set of built-in chains, since
    RouterOS allows arbitrary custom jump-target chains on every one of these
    menus.

    Returns the (stripped) value on success, raises ValidationError otherwise.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("chain must be a non-empty string.")
    value = value.strip()
    if not _CHAIN_NAME.match(value):
        raise ValidationError(
            f"chain {value!r} is not valid "
            "(letters, digits, '_', '-' only, starting with a letter/digit, max 64 chars)."
        )
    return value


def validate_conntrack_dst_port(value: int) -> int:
    """Validate `connection_tracking`'s `dst_port` filter: an integer
    1-65535, the standard TCP/UDP port range.

    Returns `value` unchanged on success, raises ValidationError otherwise.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(f"dst_port must be an integer, got {value!r}.")
    if not (1 <= value <= 65535):
        raise ValidationError(f"dst_port {value!r} is out of range (expected 1-65535).")
    return value


# RouterOS connection-tracking `protocol` values: a protocol name (e.g.
# "tcp", "udp", "icmp", "gre", "ipsec-esp", ...) or a numeric IP protocol
# number (0-255). Like `_CHAIN_NAME`/`validate_container_identifier`, the
# name form is checked for a conservative shape only - not exhaustively
# enumerated against RouterOS's own (long) protocol name list.
_PROTOCOL_NAME = re.compile(r"^[a-z][a-z0-9-]{0,31}$")


def validate_conntrack_protocol(value: str) -> str:
    """Validate `connection_tracking`'s `protocol` filter: a RouterOS
    protocol name (case-insensitive, normalized to lower-case - e.g. "tcp",
    "TCP", and "Tcp" all return "tcp") or a numeric IP protocol number as a
    string ("0"-"255").

    Returns the normalized value on success, raises ValidationError otherwise.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("protocol must be a non-empty string.")
    value = value.strip().lower()
    if value.isdigit():
        number = int(value)
        if not (0 <= number <= 255):
            raise ValidationError(f"protocol {value!r} is out of range (expected 0-255 for a numeric protocol).")
        return value
    if _PROTOCOL_NAME.match(value):
        return value
    raise ValidationError(f"protocol {value!r} is not a valid RouterOS protocol name or number (0-255).")


# --- v0.13: WireGuard VPN management -----------------------------------
#
# This is the most sensitive round yet: WireGuard uses private keys. Every
# validator below is deliberately scoped to what a caller is ALLOWED to
# supply - a WireGuard interface's own private-key is generated by RouterOS
# itself (add_wireguard_interface never accepts one - there is no
# `private_key` parameter anywhere in this package), and a peer's
# preshared-key is likewise never a parameter add_wireguard_peer accepts.
# validate_wireguard_key below validates a *public* key shape only (the one
# thing this package ever asks a caller to supply) - see guard.py's module
# note for how the private-key/preshared-key redaction itself is enforced.


def validate_port(value: int, field_name: str = "port") -> int:
    """Validate a TCP/UDP port number (1-65535) - used by
    `add_wireguard_interface`'s `listen_port` and `add_wireguard_peer`'s
    `endpoint_port`.

    Returns `value` unchanged on success, raises ValidationError otherwise.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(f"{field_name} must be an integer, got {value!r}.")
    if not (1 <= value <= 65535):
        raise ValidationError(f"{field_name} {value!r} is out of range (expected 1-65535).")
    return value


# A WireGuard key (public, private, or preshared) is always exactly 32 raw
# bytes, base64-encoded: 43 base64 characters plus one '=' padding character,
# 44 total. This package only ever asks a caller to supply a PUBLIC key (the
# remote peer's) - see module note above - but the shape is identical for
# all three key kinds, so this validator's name deliberately says "key", not
# "public key", to avoid implying it would be safe to reuse for a secret one.
_WIREGUARD_KEY = re.compile(r"^[A-Za-z0-9+/]{43}=$")


def validate_wireguard_key(value: str, field_name: str = "public_key") -> str:
    """Validate a WireGuard key's shape: 44-character base64
    (`validate_wireguard_key`'s only caller, `add_wireguard_peer`, uses this
    for the remote peer's PUBLIC key - never a private/preshared key, which
    this package never accepts as a parameter at all).

    Returns the (stripped) value on success, raises ValidationError otherwise.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field_name} must be a non-empty string.")
    value = value.strip()
    if not _WIREGUARD_KEY.match(value):
        raise ValidationError(
            f"{field_name} {value!r} is not a valid WireGuard key "
            "(expected a 44-character base64-encoded value, e.g. 'xTIBA5rboUvnH4htodxbtqE...+bgW3f...='.)"
        )
    return value


_MAX_ALLOWED_ADDRESS_LENGTH = 512


def validate_allowed_address_list(value: str) -> str:
    """Validate `add_wireguard_peer`'s `allowed_address`: a comma-separated
    list of one or more CIDR ranges (e.g. "10.0.0.2/32" or
    "10.0.0.2/32,10.0.0.3/32") - each entry validated the same way as
    `validate_target` (IPv4/IPv6 address, optionally with a "/prefix-length"
    subnet).

    Returns the value with each entry's own (stripped) shape preserved,
    comma-joined, on success; raises ValidationError otherwise.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("allowed_address must be a non-empty string.")
    value = value.strip()
    if len(value) > _MAX_ALLOWED_ADDRESS_LENGTH:
        raise ValidationError("allowed_address is too long.")

    parts = [part.strip() for part in value.split(",")]
    if any(not part for part in parts):
        raise ValidationError(f"allowed_address {value!r} contains an empty entry.")

    return ",".join(validate_target(part) for part in parts)


# --- v0.14: hotspot vouchers + backup ---------------------------------------
#
# add_hotspot_user (guard.py) creates a `/ip/hotspot/user` row - a visitor
# voucher, not a device/API credential - so its `password` validator is
# deliberately more permissive than every other validator in this module: a
# voucher password is commonly short-lived, often machine-generated, and the
# whole point of the tool is to hand it back to the caller (see
# guard.add_hotspot_user's docstring for the "password IS in the tool result,
# NEVER in the audit journal" asymmetry). Only control characters (the same
# class `validate_comment`/`_COMMENT_UNSAFE` already reject) are disallowed -
# still not an injection defense (see module docstring: every value is
# always sent as a structured API parameter), just enough to keep a voucher
# credential to plain, single-line text that renders cleanly in a QR payload.

_HOTSPOT_USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_MAX_HOTSPOT_PASSWORD_LENGTH = 128
_HOTSPOT_PROFILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def validate_hotspot_username(value: str) -> str:
    """Validate a hotspot voucher `name` (RouterOS `/ip/hotspot/user`'s
    `name` field - the login username a visitor types/scans). Same
    conservative charset as `_LIST_NAME`/`_INTERFACE_NAME`: letters, digits,
    '.', '_', '-' only, starting with a letter/digit, max 64 chars -
    deliberately restrictive since this value is also embedded verbatim in
    `qr_payload` (see guard.add_hotspot_user).

    Returns the (stripped) value on success, raises ValidationError otherwise.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("Hotspot username must be a non-empty string.")
    value = value.strip()
    if not _HOTSPOT_USERNAME.match(value):
        raise ValidationError(
            f"Hotspot username {value!r} is not valid "
            "(letters, digits, '.', '_', '-' only, starting with a letter/digit, max 64 chars)."
        )
    return value


def validate_hotspot_password(value: str) -> str:
    """Validate a hotspot voucher `password`. Deliberately more permissive
    than `validate_hotspot_username` (see module note above) - any printable
    text is accepted, only control characters (newlines, tabs, ...) are
    rejected, within a sane length cap.

    Returns `value` unchanged (not stripped - a voucher password is an exact
    credential, not free text) on success, raises ValidationError otherwise.
    """
    if not isinstance(value, str) or not value:
        raise ValidationError("Hotspot password must be a non-empty string.")
    if len(value) > _MAX_HOTSPOT_PASSWORD_LENGTH:
        raise ValidationError(f"Hotspot password is too long (max {_MAX_HOTSPOT_PASSWORD_LENGTH} characters).")
    if _COMMENT_UNSAFE.search(value):
        raise ValidationError("Hotspot password contains control characters, which are not allowed.")
    return value


def validate_hotspot_profile(value: str) -> str:
    """Validate a hotspot user `profile` name (`/ip/hotspot/user/profile`'s
    `name` - an existing profile this voucher is assigned to, e.g. to cap
    its shared bandwidth). Shape-only, same conservative charset as
    `validate_hotspot_username` - existence on the device is not checked
    here (RouterOS itself rejects an unknown profile name at write time).

    Returns the (stripped) value on success, raises ValidationError otherwise.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("Hotspot profile must be a non-empty string.")
    value = value.strip()
    if not _HOTSPOT_PROFILE.match(value):
        raise ValidationError(
            f"Hotspot profile {value!r} is not valid "
            "(letters, digits, '.', '_', '-' only, starting with a letter/digit, max 64 chars)."
        )
    return value


def validate_byte_count(value: int, field_name: str = "limit_bytes_total") -> str:
    """Validate a positive byte-count limit (RouterOS's
    `/ip/hotspot/user`'s `limit-bytes-total` field: the total data quota for
    one voucher). RouterOS itself accepts this field as a string; this
    returns it pre-stringified so guard.py never has to remember to convert
    it before sending.

    Returns `str(value)` on success, raises ValidationError otherwise.
    """
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValidationError(f"{field_name!r} must be a positive integer, got {value!r}.")
    return str(value)


# A backup file `name` (RouterOS `/system/backup/save`'s `name` field, and
# the matching `/file` row `list_backups` reads back): conservative charset,
# same spirit as `_LIST_NAME`/`_INTERFACE_NAME`, but allows a literal '.'
# (including a caller-supplied ".backup" suffix - see
# guard.create_backup, which appends one itself only if missing) and a
# longer cap, since a backup name is often a timestamp/site identifier
# (e.g. "core-switch-2026-07-09").
_BACKUP_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_MAX_BACKUP_PASSWORD_LENGTH = 128


def validate_backup_name(value: str) -> str:
    """Validate a backup file `name` (without requiring - but allowing - a
    trailing ".backup"; see `guard.create_backup`, which appends the
    extension itself only when the caller didn't already include one).

    Returns the (stripped) value on success, raises ValidationError otherwise.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("Backup name must be a non-empty string.")
    value = value.strip()
    if not _BACKUP_NAME.match(value):
        raise ValidationError(
            f"Backup name {value!r} is not valid "
            "(letters, digits, '.', '_', '-' only, starting with a letter/digit, max 128 chars)."
        )
    return value


def validate_backup_password(value: str) -> str:
    """Validate `create_backup`'s optional encryption `password` (RouterOS's
    own `/system/backup/save password=<password>` option, which encrypts the
    backup FILE itself - unrelated to any device/API credential). Same
    "reject only control characters" permissiveness as
    `validate_hotspot_password` - see that function's docstring - since this
    too is a credential the caller must be free to choose, not free text.

    Returns `value` unchanged on success, raises ValidationError otherwise.
    """
    if not isinstance(value, str) or not value:
        raise ValidationError("Backup password must be a non-empty string.")
    if len(value) > _MAX_BACKUP_PASSWORD_LENGTH:
        raise ValidationError(f"Backup password is too long (max {_MAX_BACKUP_PASSWORD_LENGTH} characters).")
    if _COMMENT_UNSAFE.search(value):
        raise ValidationError("Backup password contains control characters, which are not allowed.")
    return value


# --- v1.2: VLAN management + firewall rule reorder --------------------------
#
# add_vlan/remove_vlan (guard.py) manage `/interface/vlan` rows. A VLAN
# interface `name` (the RouterOS-side interface name, e.g. "vlan100") and its
# `interface` (the parent interface it rides on top of, e.g. "bridge1") both
# reuse `validate_interface_name`'s conservative charset - no separate
# validator needed, since a VLAN interface name and any other interface name
# share the exact same RouterOS naming rules. `vlan_id`/`mtu` below are the
# two genuinely new shapes this round introduces.

# IEEE 802.1Q VLAN id range: 1-4094 (0 and 4095 are reserved/not usable as an
# access tag).
_VLAN_ID_MIN = 1
_VLAN_ID_MAX = 4094


def validate_vlan_id(value: int) -> int:
    """Validate a RouterOS VLAN id (`/interface/vlan`'s `vlan-id` field),
    used by `add_vlan`. Must be an integer in the IEEE 802.1Q range
    (1-4094) - RouterOS itself rejects 0 and 4095.

    Returns `value` unchanged on success, raises ValidationError otherwise.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(f"vlan_id must be an integer, got {value!r}.")
    if not (_VLAN_ID_MIN <= value <= _VLAN_ID_MAX):
        raise ValidationError(f"vlan_id {value!r} is out of range (expected {_VLAN_ID_MIN}-{_VLAN_ID_MAX}).")
    return value


# RouterOS accepts an interface MTU from 68 (the minimum guaranteed by IPv4)
# up to 65535; `add_vlan`'s optional `mtu` is checked against the same range
# client-side rather than forwarding an obviously invalid value.
_MTU_MIN = 68
_MTU_MAX = 65535


def validate_mtu(value: int, field_name: str = "mtu") -> int:
    """Validate an interface MTU, used by `add_vlan`'s optional `mtu`.

    Returns `value` unchanged on success, raises ValidationError otherwise.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(f"{field_name} must be an integer, got {value!r}.")
    if not (_MTU_MIN <= value <= _MTU_MAX):
        raise ValidationError(f"{field_name} {value!r} is out of range (expected {_MTU_MIN}-{_MTU_MAX}).")
    return value


def validate_firewall_rule_position(value: int) -> int:
    """Validate `move_firewall_rule`'s optional `position`: a 0-based index
    into the CURRENT firewall filter rule order (after the rule being moved
    is removed from consideration) that the rule should move to. A value at
    or beyond the end of the list is treated as "move to the end" by
    `guard.move_firewall_rule`, not rejected here - this only rejects a
    negative index, which can never be a valid position.

    Returns `value` unchanged on success, raises ValidationError otherwise.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(f"position must be an integer, got {value!r}.")
    if value < 0:
        raise ValidationError(f"position {value!r} must be zero or greater.")
    return value


# --- v1.3: PPP/PPPoE secrets -------------------------------------------------
#
# `/ppp/secret` rows are a *service* credential (dial-in access only, never
# router admin - see ROADMAP.md's non-goal note on `/user`), the same risk
# class `add_hotspot_user` (v0.14) already handles. `name`/`password` below
# deliberately mirror `validate_hotspot_username`/`validate_hotspot_password`
# exactly (own charset/length constants, not a shared function) - same
# convention every other domain in this module follows (compare
# `validate_backup_name` vs `validate_address_list_name`: identical shape,
# separate functions so each keeps its own field-specific error text).

_PPP_SECRET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_MAX_PPP_SECRET_PASSWORD_LENGTH = 128
_PPP_SECRET_PROFILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")

# RouterOS `/ppp/secret`'s `service` field: exactly these six values
# (RouterOS itself rejects anything else at the CLI too) - "any" matches
# every PPP service type, RouterOS's own default.
_PPP_SERVICES = ("pppoe", "pptp", "l2tp", "ovpn", "sstp", "any")


def validate_ppp_secret_name(value: str) -> str:
    """Validate a PPP/PPPoE secret's `name` (RouterOS `/ppp/secret`'s `name`
    field - the dial-in login username), used by `add_ppp_secret`/
    `remove_ppp_secret`. Same conservative charset as
    `validate_hotspot_username`/`_INTERFACE_NAME`: letters, digits, '.',
    '_', '-' only, starting with a letter/digit, max 64 chars.

    Returns the (stripped) value on success, raises ValidationError otherwise.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("PPP secret name must be a non-empty string.")
    value = value.strip()
    if not _PPP_SECRET_NAME.match(value):
        raise ValidationError(
            f"PPP secret name {value!r} is not valid "
            "(letters, digits, '.', '_', '-' only, starting with a letter/digit, max 64 chars)."
        )
    return value


def validate_ppp_secret_password(value: str) -> str:
    """Validate a PPP/PPPoE secret's `password`. Same "reject only control
    characters" permissiveness as `validate_hotspot_password` - see that
    function's docstring - this too is a credential the caller must be free
    to choose, not free text.

    Returns `value` unchanged (not stripped - an exact credential, not free
    text) on success, raises ValidationError otherwise.
    """
    if not isinstance(value, str) or not value:
        raise ValidationError("PPP secret password must be a non-empty string.")
    if len(value) > _MAX_PPP_SECRET_PASSWORD_LENGTH:
        raise ValidationError(f"PPP secret password is too long (max {_MAX_PPP_SECRET_PASSWORD_LENGTH} characters).")
    if _COMMENT_UNSAFE.search(value):
        raise ValidationError("PPP secret password contains control characters, which are not allowed.")
    return value


def validate_ppp_service(value: str) -> str:
    """Validate a PPP/PPPoE secret's `service`, used by `add_ppp_secret`.
    Must be one of "pppoe", "pptp", "l2tp", "ovpn", "sstp", "any"
    (RouterOS's own default). Case-insensitive on input, normalized to
    lower-case on return (RouterOS's own field is lower-case).

    Returns the normalized value on success, raises ValidationError otherwise.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("PPP service must be a non-empty string.")

    normalized = value.strip().lower()
    if normalized not in _PPP_SERVICES:
        raise ValidationError(f"PPP service {value!r} is not valid (expected one of {_PPP_SERVICES}).")
    return normalized


def validate_ppp_profile(value: str) -> str:
    """Validate a PPP/PPPoE secret's `profile` name (`/ppp/profile`'s
    `name` - an existing profile this secret is assigned to, e.g. to set its
    local/remote address pool or rate limit). Shape-only, same conservative
    charset as `validate_ppp_secret_name` - existence on the device is not
    checked here (RouterOS itself rejects an unknown profile name at write
    time).

    Returns the (stripped) value on success, raises ValidationError otherwise.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("PPP profile must be a non-empty string.")
    value = value.strip()
    if not _PPP_SECRET_PROFILE.match(value):
        raise ValidationError(
            f"PPP profile {value!r} is not valid "
            "(letters, digits, '.', '_', '-' only, starting with a letter/digit, max 64 chars)."
        )
    return value


# --- v1.10: IPv6 write parity -----------------------------------------------
#
# add_ipv6_route/remove_ipv6_route and add_to_ipv6_address_list/
# remove_from_ipv6_address_list (guard.py) reuse validate_dst_address/
# validate_route_gateway/validate_target's IPv4-or-IPv6 shape checks for
# everything EXCEPT the address itself - dst_address/gateway/address are
# validated with the three functions below instead, which are the SAME
# parsing as their IPv4-or-IPv6 counterparts but additionally REJECT an
# IPv4 match. This is deliberate: an IPv4 address/subnet is syntactically
# indistinguishable from garbage to /ipv6/route or /ipv6/firewall/
# address-list (neither menu has any IPv4 concept), so failing fast here -
# with a clear ValidationError naming the mistake - is strictly better than
# forwarding it to the device and surfacing whatever RouterOS's own
# rejection looks like.


def validate_ipv6_dst_address(value: str) -> str:
    """Validate an IPv6 route `dst-address` (optionally with a
    "/prefix-length" subnet, e.g. "::/0", "2001:db8::/32") for
    `add_ipv6_route`/`remove_ipv6_route`. Same shape as `validate_dst_address`,
    but rejects an IPv4 address/subnet outright - `/ipv6/route` only accepts
    IPv6 prefixes.

    Returns the (stripped) value on success, raises ValidationError otherwise.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("dst_address must be a non-empty string.")

    value = value.strip()
    if len(value) > _MAX_ADDRESS_LENGTH:
        raise ValidationError("dst_address is too long.")

    address_part, sep, prefix_part = value.partition("/")
    prefix: int | None = None
    if sep:
        if not prefix_part.isdigit():
            raise ValidationError(f"dst_address {value!r} has an invalid subnet prefix.")
        prefix = int(prefix_part)

    if _IPV6.match(address_part):
        if prefix is not None and not (0 <= prefix <= 128):
            raise ValidationError(f"dst_address {value!r} has an invalid IPv6 subnet prefix (expected 0-128).")
        return value

    raise ValidationError(f"dst_address {value!r} is not a valid IPv6 address or subnet.")


def validate_ipv6_route_gateway(value: str) -> str:
    """Validate an IPv6 route `gateway` for `add_ipv6_route`/
    `remove_ipv6_route`: an IPv6 address, or a bare interface name (same
    point-to-point/PPP-link case `validate_route_gateway` allows). Same
    shape as `validate_route_gateway`, but rejects an IPv4 address outright
    - `/ipv6/route` only accepts an IPv6 gateway address.

    The IPv4 check runs BEFORE the interface-name fallback: `_INTERFACE_NAME`
    (digits/letters/dots/underscore/hyphen) is permissive enough to
    otherwise accept an IPv4-shaped string like "10.0.0.254" as if it were a
    plausible interface name, silently letting an IPv4 gateway slip through
    - an explicit IPv4 check first gives a clear, specific error instead.

    Returns the (stripped) value on success, raises ValidationError otherwise.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("gateway must be a non-empty string.")

    value = value.strip()
    if len(value) > _MAX_ADDRESS_LENGTH:
        raise ValidationError("gateway is too long.")

    if _IPV4.match(value):
        raise ValidationError(f"gateway {value!r} is an IPv4 address; ipv6 route tools require an IPv6 gateway.")
    if _IPV6.match(value):
        return value
    if _INTERFACE_NAME.match(value):
        return value

    raise ValidationError(f"gateway {value!r} is not a valid IPv6 address or interface name.")


def validate_ipv6_target(target: str) -> str:
    """Validate an IPv6 firewall address-list `address` for
    `add_to_ipv6_address_list`/`remove_from_ipv6_address_list`: an IPv6
    address, optionally followed by a "/prefix-length" subnet (0-128, e.g.
    "2001:db8::1", "2001:db8::/32"). Same shape as `validate_target`'s IPv6
    branch, but rejects an IPv4 address/subnet outright -
    `/ipv6/firewall/address-list` only accepts IPv6 entries.

    Returns the (stripped) target on success, raises ValidationError otherwise.
    """
    if not isinstance(target, str) or not target.strip():
        raise ValidationError("Target must be a non-empty string.")

    target = target.strip()
    if len(target) > _MAX_ADDRESS_LENGTH:
        raise ValidationError("Target is too long.")

    address_part, sep, prefix_part = target.partition("/")
    prefix: int | None = None
    if sep:
        if not prefix_part.isdigit():
            raise ValidationError(f"Target {target!r} has an invalid subnet prefix.")
        prefix = int(prefix_part)

    if _IPV6.match(address_part):
        if prefix is not None and not (0 <= prefix <= 128):
            raise ValidationError(f"Target {target!r} has an invalid IPv6 subnet prefix (expected 0-128).")
        return target

    raise ValidationError(f"Target {target!r} is not a valid IPv6 address or subnet.")


# --- v1.11: wireless RF tuning + dead-man (lockout-proof writes) -----------
#
# `set_wireless_channel`/`set_wireless_tx_power`/`set_wireless_tuning`
# (guard.py) write RouterOS's legacy `/interface/wireless` menu - confirmed
# against real hardware today (DISC Lite5 ac, LHG XL 5 ac; IPQ4019;
# ROS 7.21.5; nv2 PtP) to be what these devices actually expose (their
# `tx-power-mode`/`frequency-mode`/full registration-table CCQ/SNR/distance
# fields only exist on this legacy menu - RouterOS 7's newer `/interface/wifi`
# package uses a different, incompatible shape - `channel.frequency`/
# `channel.width`, no `tx-power-mode` at all - and is NOT covered by this
# round; see docs/api-notes-wireless-rf.md). Every range/enum below is
# shape-only (same spirit as every other validator in this module - see the
# module docstring): it rejects obviously-wrong input before ever touching a
# device, it does not attempt to model exactly which channel/power a given
# card+regulatory-domain combination actually supports - RouterOS itself is
# the final authority on that.

# RouterOS `/interface/wireless`'s `frequency` field, in MHz. One broad range
# spanning the 2.4GHz band through the 5GHz band plus RouterOS's own
# "superchannel" extension (Atheros cards report usable center frequencies
# from about 2192MHz up to 6100MHz - see
# https://wiki.mikrotik.com/Manual:Wireless_Advanced_Channels). Deliberately
# not split into separate 2.4GHz/5GHz sub-ranges (unlike e.g. `_VLAN_ID_MIN`/
# `_VLAN_ID_MAX`'s single tight range) - a single broad band is simpler and
# still rejects obvious nonsense (e.g. a MHz value that's actually a channel
# number), while leaving RouterOS itself to reject a frequency an actual
# card/regulatory-domain doesn't support.
_WIRELESS_FREQUENCY_MIN = 2192
_WIRELESS_FREQUENCY_MAX = 6100


def validate_wireless_frequency(value: int) -> int:
    """Validate a RouterOS `/interface/wireless` `frequency` (MHz), used by
    `set_wireless_channel`. Must be an integer in `_WIRELESS_FREQUENCY_MIN`-
    `_WIRELESS_FREQUENCY_MAX` (2192-6100 MHz - see that constant's comment).

    Returns `value` unchanged on success, raises ValidationError otherwise.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(f"frequency must be an integer (MHz), got {value!r}.")
    if not (_WIRELESS_FREQUENCY_MIN <= value <= _WIRELESS_FREQUENCY_MAX):
        raise ValidationError(
            f"frequency {value!r} is out of range (expected {_WIRELESS_FREQUENCY_MIN}-{_WIRELESS_FREQUENCY_MAX} MHz)."
        )
    return value


# RouterOS `/interface/wireless`'s `channel-width` field: the fixed set of
# values RouterOS itself accepts (help.mikrotik.com "Wireless Interface" -
# the 20/40/.../160MHz "extension channel" suffixes encode which side(s) the
# secondary channel(s) sit on - "Ce"/"eC" etc. - RouterOS's own notation, not
# invented here). Case-insensitive on input, normalized to lower-case (every
# value RouterOS itself sends/accepts is lower-case).
_WIRELESS_CHANNEL_WIDTHS = (
    "5mhz",
    "10mhz",
    "20mhz",
    "40mhz-turbo",
    "20/40mhz-xx",
    "20/40mhz-ec",
    "20/40mhz-ce",
    "20/40/80mhz-xxxx",
    "20/40/80mhz-eeec",
    "20/40/80mhz-eece",
    "20/40/80mhz-ecee",
    "20/40/80mhz-ceee",
    "20/40/80/160mhz-xxxxxxxx",
    "20/40/80/160mhz-eeeeeeec",
    "20/40/80/160mhz-eeeeecee",
    "20/40/80/160mhz-eeeeceee",
    "20/40/80/160mhz-eeeceeee",
    "20/40/80/160mhz-eeceeeee",
    "20/40/80/160mhz-eceeeeee",
    "20/40/80/160mhz-ceeeeeee",
)


def validate_wireless_channel_width(value: str) -> str:
    """Validate a RouterOS `/interface/wireless` `channel-width`, used by
    `set_wireless_channel`. Must be one of RouterOS's own fixed set of
    values (see `_WIRELESS_CHANNEL_WIDTHS`). Case-insensitive on input,
    normalized to lower-case on return.

    Returns the normalized value on success, raises ValidationError otherwise.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("channel_width must be a non-empty string.")
    normalized = value.strip().lower()
    if normalized not in _WIRELESS_CHANNEL_WIDTHS:
        raise ValidationError(
            f"channel_width {value!r} is not a valid RouterOS channel-width "
            f"(expected one of {_WIRELESS_CHANNEL_WIDTHS})."
        )
    return normalized


# RouterOS `/interface/wireless`'s `tx-power` field: documented range -30..40
# (dBm) - see help.mikrotik.com "Wireless Interface". The actual usable range
# for a given card/regulatory-domain is narrower; RouterOS itself enforces
# that at write time.
_WIRELESS_TX_POWER_MIN = -30
_WIRELESS_TX_POWER_MAX = 40


def validate_wireless_tx_power(value: int) -> int:
    """Validate a RouterOS `/interface/wireless` `tx-power` (dBm), used by
    `set_wireless_tx_power`. Must be an integer in `_WIRELESS_TX_POWER_MIN`-
    `_WIRELESS_TX_POWER_MAX` (-30..40 dBm, RouterOS's own documented range).

    Returns `value` unchanged on success, raises ValidationError otherwise.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(f"tx_power must be an integer (dBm), got {value!r}.")
    if not (_WIRELESS_TX_POWER_MIN <= value <= _WIRELESS_TX_POWER_MAX):
        raise ValidationError(
            f"tx_power {value!r} is out of range (expected {_WIRELESS_TX_POWER_MIN}..{_WIRELESS_TX_POWER_MAX} dBm)."
        )
    return value


_ADAPTIVE_NOISE_IMMUNITY_VALUES = ("none", "client-mode", "ap-and-client-mode")


def validate_adaptive_noise_immunity(value: str) -> str:
    """Validate a RouterOS `/interface/wireless` `adaptive-noise-immunity`,
    used by `set_wireless_tuning`. Must be one of "none", "client-mode",
    "ap-and-client-mode" (RouterOS's own fixed set - Atheros chipsets only,
    but this is a shape check, not a hardware-capability check).

    Returns the (stripped, lower-cased) value on success, raises
    ValidationError otherwise.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("adaptive_noise_immunity must be a non-empty string.")
    normalized = value.strip().lower()
    if normalized not in _ADAPTIVE_NOISE_IMMUNITY_VALUES:
        raise ValidationError(
            f"adaptive_noise_immunity {value!r} is not valid (expected one of {_ADAPTIVE_NOISE_IMMUNITY_VALUES})."
        )
    return normalized


_WIRELESS_DISTANCE_WORDS = ("dynamic", "indoors")
_WIRELESS_DISTANCE_MIN = 1
_WIRELESS_DISTANCE_MAX = 1000


def validate_wireless_distance(value: int | str) -> str:
    """Validate a RouterOS `/interface/wireless` `distance`, used by
    `set_wireless_tuning`. Either the literal string "dynamic" or "indoors"
    (RouterOS's own two named ACK-timeout modes), or an integer 1-1000 (km) -
    RouterOS computes the ACK timeout from it
    (`((distance * 1000) + 299) / 300` microseconds); this is a sanity cap on
    the input shape, not a claim that every value in range is achievable on a
    real link.

    Returns a string ready to send to RouterOS (the word unchanged, or
    `str(value)` for a number) on success, raises ValidationError otherwise.
    """
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in _WIRELESS_DISTANCE_WORDS:
            return normalized
        raise ValidationError(
            f"distance {value!r} is not valid (expected {_WIRELESS_DISTANCE_WORDS!r} or an integer number of km)."
        )
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(
            f"distance must be an integer (km) or one of {_WIRELESS_DISTANCE_WORDS!r}, got {value!r}."
        )
    if not (_WIRELESS_DISTANCE_MIN <= value <= _WIRELESS_DISTANCE_MAX):
        raise ValidationError(
            f"distance {value!r} is out of range (expected {_WIRELESS_DISTANCE_MIN}-{_WIRELESS_DISTANCE_MAX} km)."
        )
    return str(value)


# --- v1.11: dead-man (arm_dead_man/cancel_dead_man) ------------------------
#
# The dead-man primitive is deliberately NOT wireless-specific (see
# guard.py's module note on arm_dead_man/cancel_dead_man) - it is a reusable
# safety net for ANY lockout-risk write. `minutes` and `name` below are its
# only two caller-facing shapes; `revert_commands` (validated per-item by
# `validate_revert_command`) is the RouterOS script guard.py's own callers
# (currently `set_wireless_channel`/`set_wireless_tx_power`) build FROM
# already-read, already-validated device state - never raw free text typed
# by an end user - but is still shape-checked here for defense in depth.

_DEAD_MAN_MINUTES_MIN = 1
# 60 minutes is a deliberately generous upper bound for a "how long until
# this device heals itself" window - long enough to cover a slow manual
# verification, short enough that an operator who walks away from a botched
# change is never locked out for more than an hour. Not RouterOS-enforced;
# this package's own safety cap.
_DEAD_MAN_MINUTES_MAX = 60


def validate_dead_man_minutes(value: int) -> int:
    """Validate `arm_dead_man`'s `minutes` (how long until the armed
    scheduler fires and reverts, if not cancelled first). Must be an integer
    1-60 - see `_DEAD_MAN_MINUTES_MAX`'s comment for the rationale.

    Returns `value` unchanged on success, raises ValidationError otherwise.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(f"minutes must be an integer, got {value!r}.")
    if not (_DEAD_MAN_MINUTES_MIN <= value <= _DEAD_MAN_MINUTES_MAX):
        raise ValidationError(
            f"minutes {value!r} is out of range (expected {_DEAD_MAN_MINUTES_MIN}-{_DEAD_MAN_MINUTES_MAX})."
        )
    return value


# Every dead-man scheduler this package ever creates is named
# "deadman-<10 lower-case hex chars>" by arm_dead_man itself (guard.py) -
# never a caller-supplied name. This validator's charset is deliberately
# narrow (not the general `_LIST_NAME`/`_INTERFACE_NAME` charset) specifically
# so `cancel_dead_man` can NEVER be pointed at an arbitrary, unrelated
# `/system/scheduler` entry (e.g. an admin's own "backup-daily" task) -
# a caller-supplied `name` that doesn't match this shape is rejected before
# the device is ever read, let alone written to.
_DEAD_MAN_NAME = re.compile(r"^deadman-[0-9a-f]{1,32}$")


def validate_dead_man_name(value: str) -> str:
    """Validate `cancel_dead_man`'s `name`: must match the fixed
    "deadman-<hex>" shape `arm_dead_man` itself always generates (see
    `_DEAD_MAN_NAME`'s comment for why this is deliberately narrow - a safety
    boundary, not just a format check).

    Returns the (stripped) value on success, raises ValidationError otherwise.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("name must be a non-empty string.")
    value = value.strip()
    if not _DEAD_MAN_NAME.match(value):
        raise ValidationError(
            f"name {value!r} is not a dead-man scheduler name "
            '(expected the shape "deadman-<hex>", as returned by arm_dead_man - '
            "cancel_dead_man can only ever target a scheduler this package itself armed)."
        )
    return value


_MAX_REVERT_COMMAND_LENGTH = 500
_MAX_REVERT_COMMANDS = 10

# finding 2(a) of the 2026-07 hardening review: characters that could let a
# revert command break out of the fixed script structure
# guard._build_dead_man_script embeds it in, or smuggle a SECOND statement
# past the per-item validation/denylist below (e.g. `;` inside one list
# item, defeating both the max-10-items cap and the verb denylist scan).
# Blocked: `$` (RouterOS script variable substitution), `;` (statement
# separator - guard._build_dead_man_script itself is the only place that
# should ever join multiple statements, via "; ".join(revert_commands), not
# a single caller-supplied item), backtick, `\` (escape sequences), `{`/`}`
# (RouterOS script block/loop syntax - not needed by a simple `set`
# statement).
#
# Deliberately NOT blocked: `"` and `[`/`]`. RouterOS script's own
# `[find name="X"]` idiom - this package's established, documented,
# EVERYWHERE-used convention for addressing a row by stable name instead of
# a raw `.id` (see guard.py's module docstring) - requires exactly these
# three characters. `_arm_wireless_revert` (guard.py) itself builds every
# internal revert command with this idiom
# (`/interface/wireless set [find name="{interface_name}"] ...`); blocking
# `"`/`[`/`]` here would make set_wireless_channel/set_wireless_tx_power's
# own dead-man arming fail validation on every call. The verb denylist
# below is the intended defense against a `[...]`-wrapped dangerous nested
# command (e.g. `comment=[/system reboot]`), rather than banning the
# bracket/quote syntax outright.
_REVERT_COMMAND_UNSAFE_CHARS = re.compile(r"[$;{}\\`]")

# finding 2(d), HARDENED after an opus re-review (2026-07-13): a denylist of
# dangerous verbs does not actually uphold this package's "no generic
# command path" invariant for a standalone MCP tool with caller-supplied
# `revert_commands` - anything NOT on the denylist still passed, and each
# of these is a genuine, distinct lockout vector, not a theoretical one:
#   `/ip/address remove [find ...]`        - removes a management IP
#   `/ip/route remove [find ...]`          - removes a route (e.g. the only
#                                             route back across an 8.8km PtP
#                                             link)
#   `/ip/firewall/filter remove [find ...]` - drops firewall state entirely
# A denylist also cannot catch a malformed-but-safe-charset string like
# `/interface/wireless set [find name="x` (unbalanced quote/bracket) -
# RouterOS aborts the WHOLE on-event script at that kind of parse error
# (see guard.py's module note above arm_dead_man / finding 2 of the
# original 2026-07 hardening review), so a broken "set" that still passes a
# denylist scan can silently defeat the dead-man's own self-remove too -
# a false sense of safety net.
#
# Replaced below (`_REVERT_COMMAND_SET_FIND_RE`) with a POSITIVE structural
# allowlist instead of an enumerated-verb denylist: every `revert_commands`
# item MUST be exactly the "restore one row's fields" shape every internal
# caller (`guard._arm_wireless_revert` - confirmed the only builder of
# `revert_commands` in this codebase, and it ALWAYS uses this exact shape)
# already produces:
#   /<path> set [find <field>="<value>"] <field>=<value> [<field>=<value> ...]
# `set` is the only verb ever accepted - never `remove`/`add`/`reboot`/
# anything else. `[find <field>="<value>"]` (a single selector, BALANCED
# quote and bracket) is mandatory - never a bare `.id`, matching this
# package's stable-identifier convention everywhere else (see guard.py's
# module docstring). At least one `field=value` assignment is required - a
# `set` with nothing to set restores nothing. Anything not matching this
# exact shape is rejected: the 3 destructive commands above (wrong verb,
# and `[find]` with no selector field/value), the unbalanced-quote parse-
# abort vector (the quoted selector value has no matching closing `"]`), a
# bare `/system reboot` (no `set`/`[find ...]` at all), and a dangerous verb
# smuggled inside a field VALUE (e.g. `comment=[/system reboot]` - the
# value charset below excludes `[`/`]`/spaces, so nested command
# substitution inside a value cannot match either) are all rejected
# structurally, not because a maintainer enumerated them in advance.
#
# LIMITATION (documented, not fixed speculatively - this package is
# deliberately restrictive by design): a revert that needs to RECREATE a
# removed resource (`add`, not `set`) cannot be expressed via
# `revert_commands` today. No current caller needs this - see ROADMAP.md.
_REVERT_COMMAND_SET_FIND_RE = re.compile(
    r"^/[A-Za-z][A-Za-z0-9_-]*(?:[ /][A-Za-z][A-Za-z0-9_-]*)*"
    r'\s+set\s+\[find\s+[A-Za-z][A-Za-z0-9_-]*="[A-Za-z0-9 _.:/-]*"\]'
    r"(?:\s+[A-Za-z][A-Za-z0-9_-]*=[A-Za-z0-9_./:-]+)+$"
)

# Kept as an additional, cheap, redundant layer alongside the structural
# allowlist above (belt-and-suspenders, not the primary control anymore) -
# a case-insensitive substring match so a denied verb smuggled inside a
# `[...]` nested expression is still caught even if the structural allowlist
# above were ever loosened by a future change.
_REVERT_COMMAND_DENIED_VERBS = (
    "/system reboot",
    "/system backup load",
    "/user",
    "/system reset-configuration",
    "/system routerboard",
)


def validate_revert_command(value: str) -> str:
    """Validate one item of `arm_dead_man`'s `revert_commands` list: a single
    RouterOS script statement restoring already-read, known-good state.

    `revert_commands` is a structurally-restricted channel, not a generic
    command-execution one: every item MUST match
    `/<path> set [find <field>="<value>"] <field>=<value> [...]`
    (`_REVERT_COMMAND_SET_FIND_RE`) - the `set`-one-row-by-`[find ...]`-
    selector shape every internal caller (`guard._arm_wireless_revert`)
    already produces. `remove`/`add`/`reboot`/any other verb, a bare path
    with no `set [find ...]`, or an unbalanced quote/bracket (which would
    otherwise abort RouterOS's on-event script mid-way - see guard.py's
    module note above `arm_dead_man`) are all rejected by this shape check
    alone, structurally rather than by an enumerated denylist. See
    `_REVERT_COMMAND_SET_FIND_RE`'s comment for the full rationale
    (including the specific destructive commands - `/ip/address remove`,
    `/ip/route remove`, `/ip/firewall/filter remove` - a denylist-only
    approach let through).

    Also rejects: control characters (including newlines - same
    `_COMMENT_UNSAFE` class every other free-text validator in this module
    rejects, so one revert step can't smuggle a hidden second statement via
    an embedded newline); a fixed set of script-structure-breaking
    characters (`_REVERT_COMMAND_UNSAFE_CHARS`); a fixed denylist of
    dangerous verbs (`_REVERT_COMMAND_DENIED_VERBS`, now a redundant extra
    layer under the shape check above); a sane length cap.

    This is NOT a RouterOS script parser/validator - it cannot confirm the
    command is syntactically valid RouterOS script beyond the fixed shape
    above (see guard.py's module note: full syntax can only be confirmed
    when the scheduler actually fires). It only rejects the same class of
    obviously-wrong or obviously-dangerous input every other validator in
    this module rejects before ever touching a device.

    Returns `value` unchanged on success, raises ValidationError otherwise.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("Each revert command must be a non-empty string.")
    if len(value) > _MAX_REVERT_COMMAND_LENGTH:
        raise ValidationError(f"Revert command is too long (max {_MAX_REVERT_COMMAND_LENGTH} characters).")
    if _COMMENT_UNSAFE.search(value):
        raise ValidationError("Revert command contains control characters, which are not allowed.")
    match = _REVERT_COMMAND_UNSAFE_CHARS.search(value)
    if match:
        raise ValidationError(
            f"Revert command contains {match.group()!r}, which is not allowed (could break out of the "
            "dead-man script template or smuggle a second statement into one revert_commands item)."
        )
    if not _REVERT_COMMAND_SET_FIND_RE.match(value):
        raise ValidationError(
            f"Revert command {value!r} does not match the required "
            "'/<path> set [find <field>=\"<value>\"] <field>=<value> ...' shape: revert_commands restores state "
            "already read from the device before a risky write - only a `set` on one row selected by "
            "`[find ...]` (with a balanced quote/bracket) is allowed, never `remove`/`add`/any other verb or "
            "command."
        )
    lowered = value.lower()
    for verb in _REVERT_COMMAND_DENIED_VERBS:
        if verb in lowered:
            raise ValidationError(
                f"Revert command must not contain {verb!r}: revert_commands restores state already read from "
                "the device before a risky write - it is not a channel for arbitrary or dangerous RouterOS "
                "commands (reboot, backup restore, user management, factory reset, routerboard firmware)."
            )
    return value


def validate_revert_commands(value: list[str]) -> list[str]:
    """Validate `arm_dead_man`'s `revert_commands` list as a whole: must be a
    non-empty list (an unarmed dead-man that reverts nothing defeats the
    point), each item validated by `validate_revert_command`, capped at
    `_MAX_REVERT_COMMANDS` items (a revert script restores state, it does not
    need to be an arbitrarily long program).

    Returns the validated list on success, raises ValidationError otherwise.
    """
    if not isinstance(value, list) or not value:
        raise ValidationError("revert_commands must be a non-empty list of RouterOS script statements.")
    if len(value) > _MAX_REVERT_COMMANDS:
        raise ValidationError(f"revert_commands has too many items (max {_MAX_REVERT_COMMANDS}).")
    return [validate_revert_command(item) for item in value]
