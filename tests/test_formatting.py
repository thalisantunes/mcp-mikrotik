from __future__ import annotations

from datetime import datetime

from mcp_mikrotik.formatting import (
    coerce_ros_bool,
    coerce_ros_number,
    days_until,
    filter_disabled,
    parse_ros_datetime,
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


# --- coerce_ros_bool ----------------------------------------------------------
#
# Unlike ros_bool above (read-tool presentation, where "absent" should read
# as False), this is for write-guard LOGIC that needs to tell "definitely
# false" apart from "unknown/absent" - see guard.remove_route/
# remove_dhcp_lease. Confirmed against real ROS6/ROS7 hardware: librouteros
# hands back a RouterOS boolean field as Python bool (True/False) or omits
# it entirely - never the strings "true"/"false".


def test_coerce_ros_bool_passes_through_real_bool():
    assert coerce_ros_bool(True) is True
    assert coerce_ros_bool(False) is False


def test_coerce_ros_bool_parses_routeros_true_strings_case_insensitively():
    assert coerce_ros_bool("true") is True
    assert coerce_ros_bool("yes") is True
    assert coerce_ros_bool("  TRUE  ") is True
    assert coerce_ros_bool("YES") is True


def test_coerce_ros_bool_parses_routeros_false_strings_case_insensitively():
    assert coerce_ros_bool("false") is False
    assert coerce_ros_bool("no") is False
    assert coerce_ros_bool("  FALSE  ") is False
    assert coerce_ros_bool("NO") is False


def test_coerce_ros_bool_none_for_missing_or_unrecognized():
    # None / an absent field (row.get(...) already yields None) / empty
    # string / anything not a recognized bool-ish value - None, never a
    # guessed True/False.
    assert coerce_ros_bool(None) is None
    assert coerce_ros_bool("") is None
    assert coerce_ros_bool("   ") is None
    assert coerce_ros_bool("something-else") is None
    assert coerce_ros_bool(1) is None
    assert coerce_ros_bool(0) is None


def test_coerce_ros_bool_is_never_fooled_by_python_bool_string_equality_trap():
    # The exact bug this helper exists to prevent: True == "true" is False
    # in plain Python, so `value == "true"` never matches a real device's
    # bool True. coerce_ros_bool must still report True here.
    assert coerce_ros_bool(True) != "true"  # sanity: the trap is real
    assert coerce_ros_bool(True) is True
    assert coerce_ros_bool(False) is not None
    assert coerce_ros_bool(False) is False


# --- coerce_ros_number --------------------------------------------------------
#
# Confirmed against real hardware (CRS318-16P-2S+, ROS6.49.20, 2026-07-12):
# /interface/ethernet/poe/monitor's poe-out-current/poe-out-power/
# poe-out-voltage fields mix int and string-decimal types - int and string
# in the SAME reply, and differently across ports of the same device. Same
# "field type isn't fixed across devices/versions" lesson as coerce_ros_bool
# above, for numeric fields instead of booleans.


def test_coerce_ros_number_passes_through_real_int_and_float():
    assert coerce_ros_number(204) == 204
    assert isinstance(coerce_ros_number(204), int)
    assert coerce_ros_number(4.7) == 4.7
    assert isinstance(coerce_ros_number(4.7), float)
    assert coerce_ros_number(0) == 0


def test_coerce_ros_number_parses_integer_strings_as_int():
    assert coerce_ros_number("204") == 204
    assert isinstance(coerce_ros_number("204"), int)
    assert coerce_ros_number("0") == 0
    assert isinstance(coerce_ros_number("0"), int)


def test_coerce_ros_number_parses_decimal_strings_as_float():
    # The exact shape real hardware sent: poe-out-power='4.7',
    # poe-out-voltage='23.5' - string decimals, never int-parseable.
    assert coerce_ros_number("4.7") == 4.7
    assert isinstance(coerce_ros_number("4.7"), float)
    assert coerce_ros_number("23.5") == 23.5
    assert isinstance(coerce_ros_number("23.5"), float)


def test_coerce_ros_number_strips_whitespace_before_parsing():
    assert coerce_ros_number("  204  ") == 204
    assert coerce_ros_number(" 4.7 ") == 4.7


def test_coerce_ros_number_none_for_missing_or_unparseable():
    assert coerce_ros_number(None) is None
    assert coerce_ros_number("") is None
    assert coerce_ros_number("   ") is None
    assert coerce_ros_number("not-a-number") is None


def test_coerce_ros_number_none_for_bool_despite_bool_being_an_int_subclass():
    # bool is a Python int subclass - True/False must NOT pass through as
    # 1/0 just because `isinstance(True, int)` is True. RouterOS never uses
    # this field shape for a genuinely boolean-valued field.
    assert coerce_ros_number(True) is None
    assert coerce_ros_number(False) is None


def test_coerce_ros_number_mixed_types_within_one_reply_all_coerce_correctly():
    """Pin the exact real-hardware shape: int and string-decimal for the
    SAME field class within a single monitor reply, and different types for
    the same field across two ports of the same device - all must resolve
    to a plain int/float, never a leftover string."""
    port_a = {"poe-out-current": 204, "poe-out-power": "4.7", "poe-out-voltage": "48.0"}
    port_b = {"poe-out-current": 0, "poe-out-power": 1, "poe-out-voltage": "23.5"}

    assert coerce_ros_number(port_a["poe-out-current"]) == 204
    assert coerce_ros_number(port_a["poe-out-power"]) == 4.7
    assert coerce_ros_number(port_a["poe-out-voltage"]) == 48.0
    assert coerce_ros_number(port_b["poe-out-current"]) == 0
    assert coerce_ros_number(port_b["poe-out-power"]) == 1
    assert coerce_ros_number(port_b["poe-out-voltage"]) == 23.5


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


# --- parse_ros_datetime / days_until (v1.6) -----------------------------------


def test_parse_ros_datetime_iso_like_shape_with_time():
    assert parse_ros_datetime("2027-01-15 12:30:45") == datetime(2027, 1, 15, 12, 30, 45)


def test_parse_ros_datetime_iso_like_shape_without_time_defaults_midnight():
    assert parse_ros_datetime("2027-01-15") == datetime(2027, 1, 15, 0, 0, 0)


def test_parse_ros_datetime_ros_abbreviated_shape_with_time():
    assert parse_ros_datetime("jan/15/2027 12:30:45") == datetime(2027, 1, 15, 12, 30, 45)


def test_parse_ros_datetime_ros_abbreviated_shape_is_case_insensitive():
    assert parse_ros_datetime("JAN/15/2027 00:00:00") == datetime(2027, 1, 15, 0, 0, 0)


def test_parse_ros_datetime_ros_abbreviated_shape_without_time_defaults_midnight():
    assert parse_ros_datetime("dec/31/2026") == datetime(2026, 12, 31, 0, 0, 0)


def test_parse_ros_datetime_returns_none_for_unrecognized_shape():
    assert parse_ros_datetime("not-a-date") is None
    assert parse_ros_datetime("31/12/2026") is None  # day/month/year, not RouterOS's own shape


def test_parse_ros_datetime_returns_none_for_invalid_calendar_date():
    # Matches the ISO-like shape but Feb 30 doesn't exist - must not raise.
    assert parse_ros_datetime("2027-02-30") is None
    # Matches the RouterOS-abbreviated shape (valid month name) but Feb 30
    # still doesn't exist - must not raise either.
    assert parse_ros_datetime("feb/30/2027 00:00:00") is None
    assert parse_ros_datetime("foo/15/2027 00:00:00") is None  # unrecognized month abbreviation


def test_parse_ros_datetime_returns_none_for_non_string_or_empty():
    assert parse_ros_datetime(None) is None
    assert parse_ros_datetime("") is None
    assert parse_ros_datetime("   ") is None
    assert parse_ros_datetime(12345) is None


def test_days_until_positive_for_future_date():
    now = datetime(2026, 1, 1)
    assert days_until("2026-01-11", now=now) == 10


def test_days_until_negative_for_past_date():
    now = datetime(2026, 1, 11)
    assert days_until("2026-01-01", now=now) == -10


def test_days_until_none_when_unparseable():
    assert days_until("not-a-date") is None
