from __future__ import annotations

import pytest

from mcp_mikrotik.exceptions import ValidationError
from mcp_mikrotik.validation import (
    validate_ip_address,
    validate_mac_address,
    validate_ping_address,
    validate_rate_pair,
    validate_target,
)


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


# --- validate_ip_address (DHCP lease address: plain address, no hostname) --


@pytest.mark.parametrize("address", ["10.0.0.50", "192.168.88.1", "::1", "2001:db8::1"])
def test_validate_ip_address_accepts_valid(address: str):
    assert validate_ip_address(address) == address


@pytest.mark.parametrize(
    "address",
    ["", "   ", "router.lab.local", "10.0.0.50/24", "999.1.1.1", "8.8.8.8; rm -rf /"],
)
def test_validate_ip_address_rejects_invalid(address: str):
    with pytest.raises(ValidationError):
        validate_ip_address(address)


def test_validate_ip_address_rejects_non_string():
    with pytest.raises(ValidationError):
        validate_ip_address(None)  # type: ignore[arg-type]


# --- validate_target (Simple Queue target: address or address/prefix) -----


@pytest.mark.parametrize(
    "target",
    ["10.0.0.50", "10.0.0.0/24", "10.0.0.0/0", "10.0.0.0/32", "2001:db8::", "2001:db8::/64", "::1/128"],
)
def test_validate_target_accepts_valid(target: str):
    assert validate_target(target) == target


@pytest.mark.parametrize(
    "target",
    [
        "",
        "   ",
        "10.0.0.0/33",
        "10.0.0.0/-1",
        "10.0.0.0/abc",
        "2001:db8::/129",
        "not-an-ip",
        "10.0.0.50; reboot",
        "10.0.0.50/24/8",
    ],
)
def test_validate_target_rejects_invalid(target: str):
    with pytest.raises(ValidationError):
        validate_target(target)


def test_validate_target_rejects_non_string():
    with pytest.raises(ValidationError):
        validate_target(None)  # type: ignore[arg-type]


# --- validate_mac_address --------------------------------------------------


@pytest.mark.parametrize("mac", ["AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55"])
def test_validate_mac_address_accepts_valid(mac: str):
    assert validate_mac_address(mac) == mac.upper()


@pytest.mark.parametrize(
    "mac",
    [
        "",
        "   ",
        "AA-BB-CC-DD-EE-FF",
        "AABBCCDDEEFF",
        "AA:BB:CC:DD:EE",
        "AA:BB:CC:DD:EE:FF:00",
        "GG:BB:CC:DD:EE:FF",
        "AA:BB:CC:DD:EE:FF; reboot",
    ],
)
def test_validate_mac_address_rejects_invalid(mac: str):
    with pytest.raises(ValidationError):
        validate_mac_address(mac)


def test_validate_mac_address_rejects_non_string():
    with pytest.raises(ValidationError):
        validate_mac_address(None)  # type: ignore[arg-type]


# --- validate_rate_pair (max-limit / limit-at) -----------------------------


@pytest.mark.parametrize("value", ["10M/5M", "512k/512k", "1G/1G", "0/0", "100/100", "10m/5M", "1.5M/1.5M"])
def test_validate_rate_pair_accepts_valid(value: str):
    assert validate_rate_pair(value, "max_limit") == value


@pytest.mark.parametrize(
    "value",
    ["", "   ", "10M", "10M/5M/1M", "10M/", "/5M", "10X/5M", "10M/5M; reboot", "abc/def"],
)
def test_validate_rate_pair_rejects_invalid(value: str):
    with pytest.raises(ValidationError):
        validate_rate_pair(value, "max_limit")


def test_validate_rate_pair_rejects_non_string():
    with pytest.raises(ValidationError):
        validate_rate_pair(None, "max_limit")  # type: ignore[arg-type]


def test_validate_rate_pair_error_message_includes_field_name():
    with pytest.raises(ValidationError, match="max_limit"):
        validate_rate_pair("bad", "max_limit")
