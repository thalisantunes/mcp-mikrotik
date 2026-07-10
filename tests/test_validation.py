from __future__ import annotations

import pytest

from mcp_mikrotik.exceptions import ValidationError
from mcp_mikrotik.validation import validate_ping_address


@pytest.mark.parametrize(
    "address",
    [
        "8.8.8.8",
        "10.0.0.1",
        "255.255.255.255",
        "0.0.0.0",
        "::1",
        "2001:db8::1",
        "fe80::1%eth0",
        "router.lab.local",
        "core-switch-1",
        "a",
    ],
)
def test_validate_ping_address_accepts_valid(address: str):
    assert validate_ping_address(address) == address


def test_validate_ping_address_strips_whitespace():
    assert validate_ping_address("  8.8.8.8  ") == "8.8.8.8"


@pytest.mark.parametrize(
    "address",
    [
        "",
        "   ",
        "8.8.8.8; rm -rf /",
        "$(reboot)",
        "`whoami`",
        "8.8.8.8 && echo hi",
        "999.1.1.1",
        "1.2.3",
        "-badhost",
        "bad_host!name",
        "a" * 300,
        "8.8.8.8\nreboot",
    ],
)
def test_validate_ping_address_rejects_invalid(address: str):
    with pytest.raises(ValidationError):
        validate_ping_address(address)


def test_validate_ping_address_rejects_non_string():
    with pytest.raises(ValidationError):
        validate_ping_address(None)  # type: ignore[arg-type]
