from __future__ import annotations

from mcp_mikrotik.formatting import (
    filter_disabled,
    ros_bool,
    rows_to_list,
    split_address_port,
    strip_sensitive_fields,
)

# --- ros_bool ----------------------------------------------------------------


def test_ros_bool_passes_through_real_bool():
    assert ros_bool(True) is True
    assert ros_bool(False) is False


def test_ros_bool_parses_routeros_true_strings():
    assert ros_bool("true") is True
    assert ros_bool("yes") is True
    assert ros_bool("  TRUE  ") is True


def test_ros_bool_parses_routeros_false_strings():
    assert ros_bool("false") is False
    assert ros_bool("no") is False
    assert ros_bool("  FALSE  ") is False


def test_ros_bool_falls_back_to_python_bool_for_other_values():
    # Neither a bool nor a recognized "true"/"false" string - falls back to
    # plain Python truthiness rather than raising.
    assert ros_bool("something-else") is True
    assert ros_bool("") is False
    assert ros_bool(None) is False
    assert ros_bool(1) is True
    assert ros_bool(0) is False


# --- rows_to_list / filter_disabled ------------------------------------------


def test_rows_to_list_materializes_an_iterable():
    assert rows_to_list(iter([{"a": 1}, {"b": 2}])) == [{"a": 1}, {"b": 2}]


def test_filter_disabled_drops_disabled_rows_by_default():
    rows = [{"name": "ether1", "disabled": "false"}, {"name": "ether2", "disabled": "true"}]
    assert filter_disabled(rows, include_disabled=False) == [rows[0]]


def test_filter_disabled_keeps_disabled_rows_when_included():
    rows = [{"name": "ether1", "disabled": "false"}, {"name": "ether2", "disabled": "true"}]
    assert filter_disabled(rows, include_disabled=True) == rows


def test_filter_disabled_treats_missing_field_as_enabled():
    rows = [{"name": "ether1"}]
    assert filter_disabled(rows, include_disabled=False) == rows


# --- strip_sensitive_fields ---------------------------------------------------


def test_strip_sensitive_fields_removes_only_named_keys():
    rows = [{"name": "wg1", "private-key": "secret", "public-key": "safe"}]
    result = strip_sensitive_fields(rows, {"private-key"})
    assert result == [{"name": "wg1", "public-key": "safe"}]


def test_strip_sensitive_fields_no_op_when_key_absent():
    rows = [{"name": "wg1", "public-key": "safe"}]
    assert strip_sensitive_fields(rows, {"private-key"}) == rows


# --- split_address_port -------------------------------------------------------


def test_split_address_port_empty_string_returns_none_port():
    assert split_address_port("") == ("", None)


def test_split_address_port_ipv4_with_port():
    assert split_address_port("192.0.2.1:80") == ("192.0.2.1", "80")


def test_split_address_port_ipv4_without_port_returned_as_is():
    # No ':' at all - not an address:port pair, returned unchanged.
    assert split_address_port("192.0.2.1") == ("192.0.2.1", None)


def test_split_address_port_bracketed_ipv6_with_port():
    assert split_address_port("[2001:db8::1]:80") == ("2001:db8::1", "80")


def test_split_address_port_bracketed_ipv6_without_trailing_port():
    # Closing bracket present but nothing after it looks like ":<port>".
    assert split_address_port("[2001:db8::1]") == ("2001:db8::1", None)


def test_split_address_port_unterminated_bracket_returned_as_is():
    # Opens with '[' but never closes - can't be parsed, returned unchanged.
    assert split_address_port("[2001:db8::1") == ("[2001:db8::1", None)


def test_split_address_port_bare_ipv6_multiple_colons_returned_as_is():
    # Multiple ':' and no brackets - ambiguous, not guessed at.
    assert split_address_port("2001:db8::1") == ("2001:db8::1", None)
