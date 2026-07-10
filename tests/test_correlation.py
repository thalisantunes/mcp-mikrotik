from __future__ import annotations

from mcp_mikrotik import correlation


def test_new_id_is_short_and_looks_unique():
    a = correlation.new_id()
    b = correlation.new_id()
    assert isinstance(a, str)
    assert len(a) == 12
    assert a != b


def test_current_without_bind_mints_a_fresh_id_each_time():
    # No bind() active - current() falls back to minting one on the spot,
    # so two calls with nothing bound are two different ids.
    assert correlation.current() != correlation.current()


def test_bind_makes_current_stable_within_the_block():
    with correlation.bind() as bound_id:
        assert correlation.current() == bound_id
        assert correlation.current() == bound_id  # stable across repeated calls


def test_bind_accepts_an_explicit_id():
    with correlation.bind("deadbeef0000") as bound_id:
        assert bound_id == "deadbeef0000"
        assert correlation.current() == "deadbeef0000"


def test_bind_resets_after_the_block():
    with correlation.bind("abc123"):
        pass
    # Outside the block, nothing is bound again - current() mints fresh ids.
    assert correlation.current() != "abc123"


def test_nested_binds_restore_the_outer_id():
    with correlation.bind("outer-id") as outer:
        assert correlation.current() == outer
        with correlation.bind("inner-id") as inner:
            assert correlation.current() == inner
        assert correlation.current() == outer
