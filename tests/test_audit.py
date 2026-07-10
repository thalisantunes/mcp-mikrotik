from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from mcp_mikrotik import audit


def _record(**overrides):
    kwargs = dict(
        correlation_id="cid-0001",
        device_name="core-switch",
        tool="set_identity",
        operation="set_identity",
        action="update",
        confirm=False,
        outcome="preview",
        summary={"before": {"name": "old"}, "after": {"name": "new"}},
    )
    kwargs.update(overrides)
    audit.record(**kwargs)


# --- destination: file vs stderr logging -----------------------------------


def test_record_writes_json_line_to_file_when_audit_log_set(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("MIKROTIK_AUDIT_LOG", str(log_path))

    _record()

    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["correlation_id"] == "cid-0001"
    assert event["device_name"] == "core-switch"
    assert event["tool"] == "set_identity"
    assert event["operation"] == "set_identity"
    assert event["action"] == "update"
    assert event["confirm"] is False
    assert event["outcome"] == "preview"
    assert isinstance(event["timestamp"], (int, float))


def test_record_appends_multiple_events_to_the_same_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("MIKROTIK_AUDIT_LOG", str(log_path))

    _record(outcome="preview")
    _record(outcome="applied", confirm=True)

    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["outcome"] == "preview"
    assert json.loads(lines[1])["outcome"] == "applied"


def test_record_logs_via_stderr_logger_when_no_audit_log_set(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    monkeypatch.delenv("MIKROTIK_AUDIT_LOG", raising=False)

    with caplog.at_level(logging.INFO, logger="mcp_mikrotik.audit"):
        _record()

    assert len(caplog.records) == 1
    event = json.loads(caplog.records[0].message)
    assert event["operation"] == "set_identity"
    assert event["outcome"] == "preview"


# --- three outcomes ----------------------------------------------------


@pytest.mark.parametrize("outcome", ["preview", "applied", "error"])
def test_record_accepts_all_three_outcomes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome: str):
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("MIKROTIK_AUDIT_LOG", str(log_path))

    _record(outcome=outcome, summary={"error": "boom"} if outcome == "error" else {"before": {}, "after": {}})

    event = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert event["outcome"] == outcome


def test_invalid_outcome_falls_back_to_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("MIKROTIK_AUDIT_LOG", str(log_path))

    _record(outcome="bogus")

    event = json.loads(log_path.read_text(encoding="utf-8").strip())
    assert event["outcome"] == "error"


# --- CRITICAL: password/secret never leaks into the journal ----------------


def test_record_never_includes_password_field(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("MIKROTIK_AUDIT_LOG", str(log_path))

    _record(
        summary={
            "before": {"name": "old", "password": "s3cret-device-password"},
            "after": {"name": "new", "password": "s3cret-device-password"},
        }
    )

    raw = log_path.read_text(encoding="utf-8")
    assert "s3cret-device-password" not in raw
    event = json.loads(raw.strip())
    assert "password" not in event["summary"]["before"]
    assert "password" not in event["summary"]["after"]


def test_record_strips_password_like_keys_case_insensitively_and_nested(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("MIKROTIK_AUDIT_LOG", str(log_path))

    _record(
        summary={
            "before": {},
            "after": {
                "PASSWORD": "top-secret",
                "api_secret": "another-secret",
                "auth_token": "tok-123",
                "nested": {"credential": "nested-secret", "name": "safe-value"},
                "list_of_rows": [{"password": "row-secret", "ok": "fine"}],
            },
        }
    )

    raw = log_path.read_text(encoding="utf-8")
    for leaked in ("top-secret", "another-secret", "tok-123", "nested-secret", "row-secret"):
        assert leaked not in raw
    event = json.loads(raw.strip())
    assert event["summary"]["after"]["nested"] == {"name": "safe-value"}
    assert event["summary"]["after"]["list_of_rows"] == [{"ok": "fine"}]


def test_record_never_logs_password_to_stderr_either(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    monkeypatch.delenv("MIKROTIK_AUDIT_LOG", raising=False)

    with caplog.at_level(logging.INFO, logger="mcp_mikrotik.audit"):
        _record(summary={"before": {"password": "stderr-secret"}, "after": {}})

    assert "stderr-secret" not in caplog.text


# --- best-effort: never raises, never blocks the write ----------------------


def test_record_never_raises_on_bad_audit_log_path(monkeypatch: pytest.MonkeyPatch):
    # A directory that can't be opened as a file - open() raises IsADirectoryError,
    # an OSError subclass. record() must swallow it, not propagate.
    monkeypatch.setenv("MIKROTIK_AUDIT_LOG", "/")
    _record()  # must not raise


def test_record_never_raises_on_unserializable_summary(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("MIKROTIK_AUDIT_LOG", raising=False)

    class Unserializable:
        pass

    _record(summary={"before": {}, "after": {"weird": Unserializable()}})  # must not raise, thanks to default=str


def test_record_never_raises_when_json_dumps_itself_fails(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    """Even a serialization failure that _sanitize()/default=str can't paper
    over (e.g. json.dumps raising for some other reason) must not escape
    record() - it is logged as a warning and swallowed."""
    monkeypatch.delenv("MIKROTIK_AUDIT_LOG", raising=False)

    def _raise(*args, **kwargs):
        raise TypeError("cannot serialize")

    monkeypatch.setattr(audit.json, "dumps", _raise)

    with caplog.at_level(logging.WARNING, logger="mcp_mikrotik.audit"):
        _record()  # must not raise

    assert any("failed to serialize" in record.message for record in caplog.records)
