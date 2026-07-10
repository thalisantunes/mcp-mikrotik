from __future__ import annotations

import pytest

from mcp_mikrotik.exceptions import ValidationError
from mcp_mikrotik.validation import (
    validate_address_list_name,
    validate_allowed_address_list,
    validate_backup_name,
    validate_backup_password,
    validate_byte_count,
    validate_comment,
    validate_conntrack_dst_port,
    validate_conntrack_protocol,
    validate_container_identifier,
    validate_dns_name,
    validate_dns_record_type,
    validate_dst_address,
    validate_firewall_chain,
    validate_firewall_rule_comment,
    validate_firewall_rule_position,
    validate_hotspot_password,
    validate_hotspot_profile,
    validate_hotspot_username,
    validate_interface_name,
    validate_ip_address,
    validate_mac_address,
    validate_mtu,
    validate_ping_address,
    validate_poe_out,
    validate_port,
    validate_rate_pair,
    validate_route_distance,
    validate_route_gateway,
    validate_target,
    validate_timeout,
    validate_vlan_id,
    validate_wireguard_key,
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


def test_validate_ip_address_rejects_too_long():
    with pytest.raises(ValidationError, match="too long"):
        validate_ip_address("1" * 254)


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


def test_validate_target_rejects_too_long():
    with pytest.raises(ValidationError, match="too long"):
        validate_target("1" * 254)


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


# --- validate_address_list_name (v0.4) -------------------------------------


@pytest.mark.parametrize("name", ["blocked-clients", "allowed_clients", "list.1", "A", "9-clients", "a" * 64])
def test_validate_address_list_name_accepts_valid(name: str):
    assert validate_address_list_name(name) == name


@pytest.mark.parametrize(
    "name",
    ["", "   ", "blocked clients", "blocked;clients", "blocked/clients", "blocked$clients", "a" * 65],
)
def test_validate_address_list_name_rejects_invalid(name: str):
    with pytest.raises(ValidationError):
        validate_address_list_name(name)


def test_validate_address_list_name_rejects_non_string():
    with pytest.raises(ValidationError):
        validate_address_list_name(None)  # type: ignore[arg-type]


def test_validate_address_list_name_strips_whitespace():
    assert validate_address_list_name("  blocked-clients  ") == "blocked-clients"


# --- validate_comment (v0.4) -------------------------------------------------


@pytest.mark.parametrize("comment", ["", "reserved for guest wifi", "a" * 255])
def test_validate_comment_accepts_valid(comment: str):
    assert validate_comment(comment) == comment


@pytest.mark.parametrize("comment", ["bad\ncomment", "bad\tcomment", "bad\rcomment", "a" * 256])
def test_validate_comment_rejects_invalid(comment: str):
    with pytest.raises(ValidationError):
        validate_comment(comment)


def test_validate_comment_rejects_non_string():
    with pytest.raises(ValidationError):
        validate_comment(None)  # type: ignore[arg-type]


def test_validate_comment_error_message_includes_field_name():
    with pytest.raises(ValidationError, match="comment"):
        validate_comment("a" * 300, "comment")


# --- validate_timeout (v0.4) -------------------------------------------------


@pytest.mark.parametrize("value", ["1d", "2h30m", "1w2d3h4m5s", "10s", "0s", "01:30:00", "0:05", "00:00:10"])
def test_validate_timeout_accepts_valid(value: str):
    assert validate_timeout(value) == value


@pytest.mark.parametrize("value", ["", "   ", "not-a-timeout", "1x", "10s; reboot", "a" * 40, "1h2w"])
def test_validate_timeout_rejects_invalid(value: str):
    with pytest.raises(ValidationError):
        validate_timeout(value)


def test_validate_timeout_rejects_non_string():
    with pytest.raises(ValidationError):
        validate_timeout(None)  # type: ignore[arg-type]


# --- validate_interface_name (v0.6) ------------------------------------------


@pytest.mark.parametrize("name", ["ether1", "sfp-sfpplus1", "wlan1", "bridge1", "vlan100", "ether1-poe", "a", "A0"])
def test_validate_interface_name_accepts_valid(name: str):
    assert validate_interface_name(name) == name


def test_validate_interface_name_strips_whitespace():
    assert validate_interface_name("  ether1  ") == "ether1"


@pytest.mark.parametrize("name", ["", "   ", "ether1; reboot", "ether 1", "ether/1", "ether\n1", "a" * 65])
def test_validate_interface_name_rejects_invalid(name: str):
    with pytest.raises(ValidationError):
        validate_interface_name(name)


def test_validate_interface_name_rejects_non_string():
    with pytest.raises(ValidationError):
        validate_interface_name(None)  # type: ignore[arg-type]


# --- validate_poe_out (v0.6) --------------------------------------------------


@pytest.mark.parametrize("value", ["auto-on", "forced-on", "off"])
def test_validate_poe_out_accepts_valid(value: str):
    assert validate_poe_out(value) == value


@pytest.mark.parametrize("value", ["", "   ", "on", "AUTO-ON", "auto_on", "true"])
def test_validate_poe_out_rejects_invalid(value: str):
    with pytest.raises(ValidationError):
        validate_poe_out(value)


def test_validate_poe_out_rejects_non_string():
    with pytest.raises(ValidationError):
        validate_poe_out(None)  # type: ignore[arg-type]


# --- validate_container_identifier (v0.7) -------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "grafana",
        "alpine:latest",
        "grafana/grafana:latest",
        "myregistry.example.com:5000/library/alpine:latest",
        "a",
    ],
)
def test_validate_container_identifier_accepts_valid(value: str):
    assert validate_container_identifier(value) == value


def test_validate_container_identifier_strips_whitespace():
    assert validate_container_identifier("  grafana  ") == "grafana"


@pytest.mark.parametrize("value", ["", "   ", "grafana\nrm -rf /", "grafana\ttag", "a" * 256])
def test_validate_container_identifier_rejects_invalid(value: str):
    with pytest.raises(ValidationError):
        validate_container_identifier(value)


def test_validate_container_identifier_rejects_non_string():
    with pytest.raises(ValidationError):
        validate_container_identifier(None)  # type: ignore[arg-type]


# --- validate_dst_address (v0.9) ----------------------------------------------


@pytest.mark.parametrize(
    "value",
    ["0.0.0.0/0", "10.0.0.0/24", "10.0.0.5", "192.168.1.0/24", "::/0", "2001:db8::/64", "2001:db8::1"],
)
def test_validate_dst_address_accepts_valid(value: str):
    assert validate_dst_address(value) == value


@pytest.mark.parametrize(
    "value",
    ["", "   ", "not-an-ip", "10.0.0.0/33", "10.0.0.0/-1", "2001:db8::/129", "999.1.1.1", "10.0.0.0/abc"],
)
def test_validate_dst_address_rejects_invalid(value: str):
    with pytest.raises(ValidationError):
        validate_dst_address(value)


def test_validate_dst_address_rejects_non_string():
    with pytest.raises(ValidationError):
        validate_dst_address(None)  # type: ignore[arg-type]


def test_validate_dst_address_strips_whitespace():
    assert validate_dst_address("  0.0.0.0/0  ") == "0.0.0.0/0"


def test_validate_dst_address_rejects_too_long():
    with pytest.raises(ValidationError, match="too long"):
        validate_dst_address("1" * 254)


# --- validate_route_gateway (v0.9) --------------------------------------------


@pytest.mark.parametrize("value", ["10.0.0.254", "192.168.1.1", "2001:db8::1", "ether1", "pppoe-out1", "vlan100"])
def test_validate_route_gateway_accepts_valid(value: str):
    assert validate_route_gateway(value) == value


@pytest.mark.parametrize("value", ["", "   ", "gateway with spaces", "gateway;drop", "gateway/slash"])
def test_validate_route_gateway_rejects_invalid(value: str):
    with pytest.raises(ValidationError):
        validate_route_gateway(value)


def test_validate_route_gateway_accepts_dotted_digit_string_as_interface_shape():
    """ "999.1.1.1" is not a valid IPv4 (999 is out of range), but it IS a
    valid interface-name shape (letters/digits/'.'/'_'/'-') - gateway is
    validated as "IP OR interface name" (see validate_route_gateway's
    docstring: RouterOS accepts a gateway expressed as an outgoing
    interface), so this is accepted here. A gateway that's actually wrong
    (a typo'd IP, or a name that doesn't match any real interface) is
    rejected by RouterOS itself as a clear device-side error when the write
    is applied - not silently accepted as correct, just not rejected by this
    shape-only check."""
    assert validate_route_gateway("999.1.1.1") == "999.1.1.1"


def test_validate_route_gateway_rejects_non_string():
    with pytest.raises(ValidationError):
        validate_route_gateway(None)  # type: ignore[arg-type]


def test_validate_route_gateway_rejects_too_long():
    with pytest.raises(ValidationError, match="too long"):
        validate_route_gateway("1" * 254)


# --- validate_route_distance (v0.9) -------------------------------------------


@pytest.mark.parametrize("value", [1, 2, 100, 255])
def test_validate_route_distance_accepts_valid(value: int):
    assert validate_route_distance(value) == value


@pytest.mark.parametrize("value", [0, -1, 256, 1000])
def test_validate_route_distance_rejects_out_of_range(value: int):
    with pytest.raises(ValidationError):
        validate_route_distance(value)


@pytest.mark.parametrize("value", ["1", None, 1.5, True, False])
def test_validate_route_distance_rejects_non_int(value):
    with pytest.raises(ValidationError):
        validate_route_distance(value)  # type: ignore[arg-type]


# --- validate_dns_name (v0.10) -------------------------------------------------


@pytest.mark.parametrize("value", ["example.com", "blocked.example.com", "a.b.c.example.co", "xn--80ak6aa92e.com", "a"])
def test_validate_dns_name_accepts_valid(value: str):
    assert validate_dns_name(value) == value


def test_validate_dns_name_strips_whitespace():
    assert validate_dns_name("  example.com  ") == "example.com"


@pytest.mark.parametrize(
    "value", ["", "   ", "10.0.0.1", "999.1.1.1", "example.com; reboot", "example .com", "a" * 254]
)
def test_validate_dns_name_rejects_invalid(value: str):
    """ "10.0.0.1"/"999.1.1.1" are rejected - a static DNS entry's `name`
    (or a CNAME target) is a hostname, never a literal IP/IP-look-alike, so
    - unlike validate_route_gateway's deliberate "999.1.1.1 is accepted as
    an interface-name shape" exception - both are rejected here."""
    with pytest.raises(ValidationError):
        validate_dns_name(value)


def test_validate_dns_name_rejects_non_string():
    with pytest.raises(ValidationError):
        validate_dns_name(None)  # type: ignore[arg-type]


# --- validate_dns_record_type (v0.10) ------------------------------------------


@pytest.mark.parametrize("value,expected", [("A", "A"), ("a", "A"), ("CNAME", "CNAME"), ("cname", "CNAME")])
def test_validate_dns_record_type_accepts_valid_and_normalizes_case(value: str, expected: str):
    assert validate_dns_record_type(value) == expected


@pytest.mark.parametrize("value", ["", "   ", "AAAA", "MX", "TXT", "NS"])
def test_validate_dns_record_type_rejects_unsupported(value: str):
    with pytest.raises(ValidationError):
        validate_dns_record_type(value)


def test_validate_dns_record_type_rejects_non_string():
    with pytest.raises(ValidationError):
        validate_dns_record_type(None)  # type: ignore[arg-type]


# --- validate_firewall_rule_comment (v0.11) -------------------------------


def test_validate_firewall_rule_comment_accepts_valid():
    assert validate_firewall_rule_comment("Bloqueio_Ataque_X") == "Bloqueio_Ataque_X"


def test_validate_firewall_rule_comment_strips_whitespace():
    assert validate_firewall_rule_comment("  Bloqueio_Ataque_X  ") == "Bloqueio_Ataque_X"


@pytest.mark.parametrize("value", ["", "   ", "a" * 256, "bad\ncomment", "bad\x00comment"])
def test_validate_firewall_rule_comment_rejects_invalid(value: str):
    """Unlike validate_comment (used for OPTIONAL comment fields elsewhere),
    an empty string is rejected here too - it can never reliably identify
    one specific existing rule."""
    with pytest.raises(ValidationError):
        validate_firewall_rule_comment(value)


def test_validate_firewall_rule_comment_rejects_non_string():
    with pytest.raises(ValidationError):
        validate_firewall_rule_comment(None)  # type: ignore[arg-type]


# --- validate_firewall_chain (v0.11) --------------------------------------


@pytest.mark.parametrize("value", ["input", "forward", "output", "my-custom-chain", "chain_1"])
def test_validate_firewall_chain_accepts_valid(value: str):
    assert validate_firewall_chain(value) == value


@pytest.mark.parametrize("value", ["", "   ", "bad chain", "bad;chain", "a" * 65])
def test_validate_firewall_chain_rejects_invalid(value: str):
    with pytest.raises(ValidationError):
        validate_firewall_chain(value)


def test_validate_firewall_chain_rejects_non_string():
    with pytest.raises(ValidationError):
        validate_firewall_chain(None)  # type: ignore[arg-type]


# --- validate_conntrack_dst_port (v0.11) ----------------------------------


@pytest.mark.parametrize("value", [1, 53, 443, 65535])
def test_validate_conntrack_dst_port_accepts_valid(value: int):
    assert validate_conntrack_dst_port(value) == value


@pytest.mark.parametrize("value", [0, -1, 65536, 100000])
def test_validate_conntrack_dst_port_rejects_out_of_range(value: int):
    with pytest.raises(ValidationError):
        validate_conntrack_dst_port(value)


@pytest.mark.parametrize("value", ["53", None, 1.5, True, False])
def test_validate_conntrack_dst_port_rejects_non_int(value):
    with pytest.raises(ValidationError):
        validate_conntrack_dst_port(value)  # type: ignore[arg-type]


# --- validate_conntrack_protocol (v0.11) ----------------------------------


@pytest.mark.parametrize(
    "value,expected", [("tcp", "tcp"), ("TCP", "tcp"), ("Udp", "udp"), ("icmp", "icmp"), ("ipsec-esp", "ipsec-esp")]
)
def test_validate_conntrack_protocol_accepts_name_and_normalizes_case(value: str, expected: str):
    assert validate_conntrack_protocol(value) == expected


@pytest.mark.parametrize("value,expected", [("6", "6"), ("17", "17"), ("0", "0"), ("255", "255")])
def test_validate_conntrack_protocol_accepts_numeric(value: str, expected: str):
    assert validate_conntrack_protocol(value) == expected


@pytest.mark.parametrize("value", ["", "   ", "256", "-1", "bad protocol", "tcp;drop"])
def test_validate_conntrack_protocol_rejects_invalid(value: str):
    with pytest.raises(ValidationError):
        validate_conntrack_protocol(value)


def test_validate_conntrack_protocol_rejects_non_string():
    with pytest.raises(ValidationError):
        validate_conntrack_protocol(None)  # type: ignore[arg-type]


# --- validate_port (v0.13) --------------------------------------------------


@pytest.mark.parametrize("value", [1, 22, 8728, 8729, 65535])
def test_validate_port_accepts_valid(value: int):
    assert validate_port(value) == value


@pytest.mark.parametrize("value", [0, -1, 65536, 100000])
def test_validate_port_rejects_out_of_range(value: int):
    with pytest.raises(ValidationError, match="out of range"):
        validate_port(value)


@pytest.mark.parametrize("value", ["8728", None, 1.5, True, False])
def test_validate_port_rejects_non_int(value):
    with pytest.raises(ValidationError, match="must be an integer"):
        validate_port(value)  # type: ignore[arg-type]


def test_validate_port_uses_field_name_in_error():
    with pytest.raises(ValidationError, match="listen_port"):
        validate_port(0, "listen_port")


# --- validate_wireguard_key (v0.13) -----------------------------------------


def test_validate_wireguard_key_accepts_valid():
    key = "xTIBA5rboUvnH4htodxbtqE4CE0Rg8v+CFAM6XWQAn8="
    assert validate_wireguard_key(key) == key


def test_validate_wireguard_key_strips_whitespace():
    key = "xTIBA5rboUvnH4htodxbtqE4CE0Rg8v+CFAM6XWQAn8="
    assert validate_wireguard_key(f"  {key}  ") == key


@pytest.mark.parametrize(
    "value",
    [
        "too-short",
        "xTIBA5rboUvnH4htodxbtqE4CE0Rg8v+CFAM6XWQAn8",  # missing '=' padding
        "xTIBA5rboUvnH4htodxbtqE4CE0Rg8v+CFAM6XWQAn8==",  # extra padding
        "xTIBA5rboUvnH4htodxbtqE4CE0Rg8v+CFAM6XWQAn8; rm -rf /=",
    ],
)
def test_validate_wireguard_key_rejects_invalid_shape(value: str):
    with pytest.raises(ValidationError, match="not a valid WireGuard key"):
        validate_wireguard_key(value)


@pytest.mark.parametrize("value", ["", "   ", None])
def test_validate_wireguard_key_rejects_empty_or_non_string(value):
    with pytest.raises(ValidationError, match="non-empty string"):
        validate_wireguard_key(value)  # type: ignore[arg-type]


def test_validate_wireguard_key_uses_field_name_in_error():
    with pytest.raises(ValidationError, match="public_key"):
        validate_wireguard_key("", "public_key")


# --- validate_allowed_address_list (v0.13) ----------------------------------


@pytest.mark.parametrize(
    "value",
    ["10.0.0.2/32", "10.0.0.2/32,10.0.0.3/32", "2001:db8::1/128", "10.0.0.0/24, 10.0.1.0/24"],
)
def test_validate_allowed_address_list_accepts_valid(value: str):
    result = validate_allowed_address_list(value)
    assert isinstance(result, str)
    assert "," in result or "/" in result


@pytest.mark.parametrize("value", ["", "   ", None])
def test_validate_allowed_address_list_rejects_empty_or_non_string(value):
    with pytest.raises(ValidationError, match="non-empty string"):
        validate_allowed_address_list(value)  # type: ignore[arg-type]


def test_validate_allowed_address_list_rejects_too_long():
    with pytest.raises(ValidationError, match="too long"):
        validate_allowed_address_list("10.0.0.0/32," * 100)


def test_validate_allowed_address_list_rejects_empty_entry():
    with pytest.raises(ValidationError, match="empty entry"):
        validate_allowed_address_list("10.0.0.2/32,,10.0.0.3/32")


def test_validate_allowed_address_list_rejects_invalid_entry():
    with pytest.raises(ValidationError):
        validate_allowed_address_list("10.0.0.2/32,not-an-ip")


# --- validate_hotspot_username (v0.14) --------------------------------------


@pytest.mark.parametrize("value", ["visitor-42", "guest.1", "a", "A1_b-c.d"])
def test_validate_hotspot_username_accepts_valid(value: str):
    assert validate_hotspot_username(value) == value


@pytest.mark.parametrize("value", ["", "   ", None])
def test_validate_hotspot_username_rejects_empty_or_non_string(value):
    with pytest.raises(ValidationError, match="non-empty string"):
        validate_hotspot_username(value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", ["-leading-dash", "has space", "has;semicolon", "a" * 65])
def test_validate_hotspot_username_rejects_invalid_shape(value: str):
    with pytest.raises(ValidationError, match="not valid"):
        validate_hotspot_username(value)


# --- validate_hotspot_password (v0.14) --------------------------------------


@pytest.mark.parametrize("value", ["Xk7mQ2p9", "a", "!@#$%^&*()"])
def test_validate_hotspot_password_accepts_valid(value: str):
    assert validate_hotspot_password(value) == value


@pytest.mark.parametrize("value", ["", None])
def test_validate_hotspot_password_rejects_empty_or_non_string(value):
    with pytest.raises(ValidationError, match="non-empty string"):
        validate_hotspot_password(value)  # type: ignore[arg-type]


def test_validate_hotspot_password_rejects_too_long():
    with pytest.raises(ValidationError, match="too long"):
        validate_hotspot_password("a" * 129)


def test_validate_hotspot_password_rejects_control_characters():
    with pytest.raises(ValidationError, match="control characters"):
        validate_hotspot_password("bad\npassword")


# --- validate_hotspot_profile (v0.14) ---------------------------------------


@pytest.mark.parametrize("value", ["default", "5M-limit", "profile.1"])
def test_validate_hotspot_profile_accepts_valid(value: str):
    assert validate_hotspot_profile(value) == value


@pytest.mark.parametrize("value", ["", "   ", None])
def test_validate_hotspot_profile_rejects_empty_or_non_string(value):
    with pytest.raises(ValidationError, match="non-empty string"):
        validate_hotspot_profile(value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", ["-leading-dash", "has space", "has;semicolon", "a" * 65])
def test_validate_hotspot_profile_rejects_invalid_shape(value: str):
    with pytest.raises(ValidationError, match="not valid"):
        validate_hotspot_profile(value)


# --- validate_byte_count (v0.14) --------------------------------------------


@pytest.mark.parametrize("value,expected", [(1, "1"), (1024, "1024"), (1_000_000_000, "1000000000")])
def test_validate_byte_count_accepts_valid(value: int, expected: str):
    assert validate_byte_count(value) == expected


@pytest.mark.parametrize("value", [0, -1, "1024", None, 1.5, True, False])
def test_validate_byte_count_rejects_invalid(value):
    with pytest.raises(ValidationError, match="positive integer"):
        validate_byte_count(value)  # type: ignore[arg-type]


# --- validate_backup_name (v0.14) -------------------------------------------


@pytest.mark.parametrize("value", ["core-switch-2026-07-09", "backup1", "a.backup"])
def test_validate_backup_name_accepts_valid(value: str):
    assert validate_backup_name(value) == value


@pytest.mark.parametrize("value", ["", "   ", None])
def test_validate_backup_name_rejects_empty_or_non_string(value):
    with pytest.raises(ValidationError, match="non-empty string"):
        validate_backup_name(value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", ["-leading-dash", "has space", "has;semicolon", "a" * 129])
def test_validate_backup_name_rejects_invalid_shape(value: str):
    with pytest.raises(ValidationError, match="not valid"):
        validate_backup_name(value)


# --- validate_backup_password (v0.14) ---------------------------------------


@pytest.mark.parametrize("value", ["S3cret!", "a", "!@#$%^&*()"])
def test_validate_backup_password_accepts_valid(value: str):
    assert validate_backup_password(value) == value


@pytest.mark.parametrize("value", ["", None])
def test_validate_backup_password_rejects_empty_or_non_string(value):
    with pytest.raises(ValidationError, match="non-empty string"):
        validate_backup_password(value)  # type: ignore[arg-type]


def test_validate_backup_password_rejects_too_long():
    with pytest.raises(ValidationError, match="too long"):
        validate_backup_password("a" * 129)


def test_validate_backup_password_rejects_control_characters():
    with pytest.raises(ValidationError, match="control characters"):
        validate_backup_password("bad\npassword")


# --- validate_vlan_id (v1.2) -------------------------------------------------


@pytest.mark.parametrize("value", [1, 2, 100, 4094])
def test_validate_vlan_id_accepts_valid(value: int):
    assert validate_vlan_id(value) == value


@pytest.mark.parametrize("value", [0, -1, 4095, 10000])
def test_validate_vlan_id_rejects_out_of_range(value: int):
    with pytest.raises(ValidationError, match="out of range"):
        validate_vlan_id(value)


@pytest.mark.parametrize("value", ["1", None, 1.5, True, False])
def test_validate_vlan_id_rejects_non_int(value):
    with pytest.raises(ValidationError):
        validate_vlan_id(value)  # type: ignore[arg-type]


# --- validate_mtu (v1.2) -----------------------------------------------------


@pytest.mark.parametrize("value", [68, 1500, 9000, 65535])
def test_validate_mtu_accepts_valid(value: int):
    assert validate_mtu(value) == value


@pytest.mark.parametrize("value", [0, 67, -1, 65536])
def test_validate_mtu_rejects_out_of_range(value: int):
    with pytest.raises(ValidationError, match="out of range"):
        validate_mtu(value)


@pytest.mark.parametrize("value", ["1500", None, 1.5, True, False])
def test_validate_mtu_rejects_non_int(value):
    with pytest.raises(ValidationError):
        validate_mtu(value)  # type: ignore[arg-type]


# --- validate_firewall_rule_position (v1.2) ----------------------------------


@pytest.mark.parametrize("value", [0, 1, 100])
def test_validate_firewall_rule_position_accepts_valid(value: int):
    assert validate_firewall_rule_position(value) == value


def test_validate_firewall_rule_position_rejects_negative():
    with pytest.raises(ValidationError, match="zero or greater"):
        validate_firewall_rule_position(-1)


@pytest.mark.parametrize("value", ["0", None, 1.5, True, False])
def test_validate_firewall_rule_position_rejects_non_int(value):
    with pytest.raises(ValidationError):
        validate_firewall_rule_position(value)  # type: ignore[arg-type]
