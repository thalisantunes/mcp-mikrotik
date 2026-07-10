"""Shared response-shaping helpers for read tools.

Kept in one place so no two tools reimplement RouterOS's habit of encoding
booleans as the strings "true"/"false", or the "list of rows -> plain dicts"
conversion.
"""

from __future__ import annotations

from typing import Any, Iterable

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
