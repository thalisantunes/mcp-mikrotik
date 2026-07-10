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


# --- S1: neither Device nor Settings' repr may leak a password -----------


def test_device_repr_omits_password():
    device = Device(name="d1", host="10.0.0.1", password="topsecret")
    assert "topsecret" not in repr(device)


def test_settings_repr_omits_devices_and_passwords():
    from mcp_mikrotik.config import Settings

    device = Device(name="d1", host="10.0.0.1", password="topsecret")
    settings = Settings(allow_write=False, devices={"d1": device})
    assert "topsecret" not in repr(settings)


# --- E1: malformed YAML must raise ConfigError, not a raw yaml.YAMLError -


def test_load_devices_rejects_invalid_yaml(tmp_path: Path):
    path = tmp_path / "devices.yaml"
    path.write_text("devices: [\n  - name: broken\n")  # unterminated flow sequence
    with pytest.raises(ConfigError):
        load_devices(path)


# --- E2: non-numeric port must raise ConfigError, not a raw ValueError ---


def test_load_devices_rejects_non_numeric_port(tmp_path: Path):
    path = _write(
        tmp_path,
        """
        devices:
          - name: d1
            host: 10.0.0.1
            port: not-a-number
        """,
    )
    with pytest.raises(ConfigError):
        load_devices(path)


# --- E3: name/host are coerced to str, or rejected if not coercible ------


def test_load_devices_coerces_numeric_name_to_str(tmp_path: Path):
    path = _write(tmp_path, "devices:\n  - name: 14\n    host: 10.0.0.1\n")
    devices = load_devices(path)
    assert set(devices) == {"14"}
    assert devices["14"].name == "14"


def test_load_devices_rejects_non_coercible_name(tmp_path: Path):
    path = _write(tmp_path, "devices:\n  - name: [1, 2]\n    host: 10.0.0.1\n")
    with pytest.raises(ConfigError):
        load_devices(path)


def test_load_devices_rejects_non_coercible_host(tmp_path: Path):
    path = _write(tmp_path, "devices:\n  - name: d1\n    host: {a: 1}\n")
    with pytest.raises(ConfigError):
        load_devices(path)


def test_load_devices_rejects_boolean_name():
    from mcp_mikrotik.config import ConfigError, _coerce_str

    with pytest.raises(ConfigError, match="must be a string"):
        _coerce_str(True, "name", Path("devices.yaml"))


def test_load_devices_rejects_none_host():
    from mcp_mikrotik.config import ConfigError, _coerce_str

    with pytest.raises(ConfigError, match="must be a string"):
        _coerce_str(None, "host", Path("devices.yaml"))


# --- top-level YAML shape validation ---------------------------------------


def test_load_devices_rejects_non_mapping_top_level(tmp_path: Path):
    path = _write(tmp_path, "- just\n- a\n- list\n")
    with pytest.raises(ConfigError, match="top-level YAML must be a mapping"):
        load_devices(path)


def test_load_devices_rejects_non_list_devices_key(tmp_path: Path):
    path = _write(tmp_path, "devices: not-a-list\n")
    with pytest.raises(ConfigError, match="'devices' must be a list"):
        load_devices(path)


def test_load_devices_rejects_non_mapping_device_entry(tmp_path: Path):
    path = _write(tmp_path, "devices:\n  - just-a-string\n")
    with pytest.raises(ConfigError, match="each device entry must be a mapping"):
        load_devices(path)


# --- SSL1: tls_verify / tls_ca_cert parsing --------------------------------


def test_load_devices_tls_verify_defaults_true(tmp_path: Path):
    path = _write(tmp_path, "devices:\n  - name: d1\n    host: 10.0.0.1\n")
    assert load_devices(path)["d1"].tls_verify is True


def test_load_devices_tls_verify_false(tmp_path: Path):
    path = _write(
        tmp_path,
        "devices:\n  - name: d1\n    host: 10.0.0.1\n    use_ssl: true\n    tls_verify: false\n",
    )
    assert load_devices(path)["d1"].tls_verify is False


def test_load_devices_parses_tls_ca_cert(tmp_path: Path):
    path = _write(
        tmp_path,
        "devices:\n  - name: d1\n    host: 10.0.0.1\n    tls_ca_cert: /etc/mcp-mikrotik/ca.pem\n",
    )
    assert load_devices(path)["d1"].tls_ca_cert == "/etc/mcp-mikrotik/ca.pem"


# --- N4: per-device timeout parsing ---------------------------------------


def test_load_devices_timeout_defaults_to_none(tmp_path: Path):
    path = _write(tmp_path, "devices:\n  - name: d1\n    host: 10.0.0.1\n")
    assert load_devices(path)["d1"].timeout is None


def test_load_devices_parses_timeout(tmp_path: Path):
    path = _write(tmp_path, "devices:\n  - name: d1\n    host: 10.0.0.1\n    timeout: 30\n")
    assert load_devices(path)["d1"].timeout == 30.0


def test_load_devices_rejects_invalid_timeout(tmp_path: Path):
    path = _write(tmp_path, "devices:\n  - name: d1\n    host: 10.0.0.1\n    timeout: not-a-number\n")
    with pytest.raises(ConfigError):
        load_devices(path)
