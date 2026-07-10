from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from mcp_mikrotik.config import Device, load_devices, load_settings
from mcp_mikrotik.exceptions import ConfigError, DeviceNotFoundError


def _write(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "devices.yaml"
    path.write_text(textwrap.dedent(content))
    return path


def test_load_devices_parses_all_fields(tmp_path: Path):
    path = _write(
        tmp_path,
        """
        devices:
          - name: core-switch
            host: 10.0.0.1
            port: 8729
            use_ssl: true
            username: admin
            password: hunter2
            disabled: false
            comment: lab core
        """,
    )
    devices = load_devices(path)
    assert set(devices) == {"core-switch"}
    device = devices["core-switch"]
    assert device == Device(
        name="core-switch",
        host="10.0.0.1",
        port=8729,
        use_ssl=True,
        username="admin",
        password="hunter2",
        disabled=False,
        comment="lab core",
    )


def test_load_devices_applies_defaults(tmp_path: Path):
    path = _write(tmp_path, "devices:\n  - name: ap-1\n    host: 10.0.0.2\n")
    device = load_devices(path)["ap-1"]
    assert device.port == 8728
    assert device.use_ssl is False
    assert device.username == "admin"
    assert device.password == ""
    assert device.disabled is False


def test_load_devices_missing_file_returns_empty(tmp_path: Path):
    assert load_devices(tmp_path / "does-not-exist.yaml") == {}


def test_load_devices_rejects_duplicate_names(tmp_path: Path):
    path = _write(
        tmp_path,
        """
        devices:
          - name: dup
            host: 10.0.0.1
          - name: dup
            host: 10.0.0.2
        """,
    )
    with pytest.raises(ConfigError):
        load_devices(path)


def test_load_devices_requires_name_and_host(tmp_path: Path):
    path = _write(tmp_path, "devices:\n  - host: 10.0.0.1\n")
    with pytest.raises(ConfigError):
        load_devices(path)


def test_to_public_dict_omits_password():
    device = Device(name="d1", host="10.0.0.1", password="topsecret")
    public = device.to_public_dict()
    assert "password" not in public
    assert "topsecret" not in str(public)
    assert public["name"] == "d1"


@pytest.mark.parametrize(
    "raw,expected",
    [("true", True), ("1", True), ("yes", True), ("on", True), ("false", False), ("nope", False)],
)
def test_load_settings_allow_write_env_parsing(tmp_path: Path, raw: str, expected: bool):
    path = _write(tmp_path, "devices: []\n")
    settings = load_settings(devices_path=path, env={"MIKROTIK_ALLOW_WRITE": raw})
    assert settings.allow_write is expected


def test_load_settings_defaults_allow_write_false(tmp_path: Path):
    path = _write(tmp_path, "devices: []\n")
    settings = load_settings(devices_path=path, env={})
    assert settings.allow_write is False


def test_settings_get_device_unknown_raises():
    from mcp_mikrotik.config import Settings

    settings = Settings(allow_write=False, devices={})
    with pytest.raises(DeviceNotFoundError):
        settings.get_device("nope")


def test_settings_get_device_disabled_raises():
    from mcp_mikrotik.config import Settings

    device = Device(name="d1", host="10.0.0.1", disabled=True)
    settings = Settings(allow_write=False, devices={"d1": device})
    with pytest.raises(DeviceNotFoundError):
        settings.get_device("d1")
