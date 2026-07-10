"""Input validation applied before any value is sent to a device.

Currently used for the `ping` tool's `address` parameter. Note this is not
an injection defense: `address` is always passed to librouteros as a
structured parameter (never interpolated into a shell/command string), so
command injection through it is already ruled out by construction (see
client.py). This module exists to reject garbage input early and return a
clear error instead of forwarding it to the device.
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
