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
