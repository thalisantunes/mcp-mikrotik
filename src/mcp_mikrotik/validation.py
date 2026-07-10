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
