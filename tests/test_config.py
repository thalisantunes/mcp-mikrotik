from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from mcp_mikrotik.config import Device, load_devices, load_settings, normalize_tls_fingerprint
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


# --- tls_fingerprint: per-device certificate pinning for api-ssl ------------

# Generic, made-up SHA-256 fingerprint for config parsing tests (not any real
# certificate's) - the real-TLS behaviour lives in tests/test_tls_pinning.py.
_FP = "0123456789abcdef" * 4
_FP_COLON_UPPER = ":".join(_FP[i : i + 2] for i in range(0, 64, 2)).upper()
_FP_OTHER = "fedcba9876543210" * 4


def _pinned_yaml(fingerprint_yaml: str, extra: str = "") -> str:
    return (
        "devices:\n"
        "  - name: edge-router\n"
        "    host: 192.0.2.10\n"
        "    port: 8729\n"
        "    use_ssl: true\n"
        f"    tls_fingerprint: {fingerprint_yaml}\n"
        f"{extra}"
    )


def test_device_has_no_tls_fingerprints_by_default(tmp_path: Path):
    path = _write(tmp_path, "devices:\n  - name: d1\n    host: 192.0.2.1\n    use_ssl: true\n")
    assert load_devices(path)["d1"].tls_fingerprints == ()


@pytest.mark.parametrize("null_value", ["", " ~", " null"])
def test_load_devices_rejects_a_tls_fingerprint_key_with_no_value(tmp_path: Path, null_value: str):
    """A bare `tls_fingerprint:` (a pasted value missing, a template left
    empty), `~` and `null` all load as None in YAML. Next to
    `tls_verify: false` that must not quietly become an unauthenticated,
    unpinned connection - only an absent key means "no pinning"."""
    path = _write(
        tmp_path,
        "devices:\n  - name: edge-router\n    host: 192.0.2.10\n    port: 8729\n    use_ssl: true\n"
        f"    tls_verify: false\n    tls_fingerprint:{null_value}\n",
    )
    with pytest.raises(ConfigError, match="'edge-router' has a 'tls_fingerprint' key with no value"):
        load_devices(path)


@pytest.mark.parametrize("value", [f' "{_FP}"', f' ["{_FP}"]', "", " null"])
def test_load_devices_rejects_the_plural_tls_fingerprints_key(tmp_path: Path, value: str):
    """`tls_fingerprints` (the Device attribute's name, and the natural
    spelling for a list) is not the YAML key; ignoring it like other unknown
    keys would leave the device unpinned while the config reads as pinned."""
    path = _write(
        tmp_path,
        "devices:\n  - name: edge-router\n    host: 192.0.2.10\n    port: 8729\n    use_ssl: true\n"
        f"    tls_verify: false\n    tls_fingerprints:{value}\n",
    )
    with pytest.raises(ConfigError, match="'edge-router' uses the key 'tls_fingerprints'.*'tls_fingerprint'"):
        load_devices(path)


def test_load_devices_rejects_the_plural_key_even_next_to_a_valid_singular_one(tmp_path: Path):
    path = _write(tmp_path, _pinned_yaml(f'"{_FP}"', f'    tls_fingerprints: ["{_FP_OTHER}"]\n'))
    with pytest.raises(ConfigError, match="'tls_fingerprints'"):
        load_devices(path)


@pytest.mark.parametrize(
    "fingerprint_yaml",
    [
        f'"{_FP}"',  # plain lower-case hex
        f'"{_FP.upper()}"',  # plain upper-case hex
        f'"{_FP_COLON_UPPER}"',  # openssl x509 -fingerprint format
        f'"{_FP_COLON_UPPER.lower()}"',
        f'"sha256:{_FP}"',  # optional prefix ...
        f'"SHA256:{_FP_COLON_UPPER}"',  # ... case-insensitive, with separators too
        f'"  sha256: {_FP}  "',  # surrounding whitespace tolerated
        _FP,  # unquoted plain hex is still a YAML string
    ],
)
def test_load_devices_accepts_and_normalizes_tls_fingerprint_formats(tmp_path: Path, fingerprint_yaml: str):
    path = _write(tmp_path, _pinned_yaml(fingerprint_yaml))
    device = load_devices(path)["edge-router"]
    assert device.tls_fingerprints == (_FP,)
    # Pinning doesn't change what's exposed through tool output.
    assert "tls_fingerprint" not in device.to_public_dict()
    assert "tls_fingerprints" not in device.to_public_dict()


def test_load_devices_accepts_a_list_of_tls_fingerprints_for_rotation(tmp_path: Path):
    path = _write(
        tmp_path, _pinned_yaml(f'\n      - "{_FP_COLON_UPPER}"\n      - "sha256:{_FP_OTHER}"\n      - "{_FP}"')
    )
    # Normalized, order kept, the duplicate (same pin in another format) dropped.
    assert load_devices(path)["edge-router"].tls_fingerprints == (_FP, _FP_OTHER)


@pytest.mark.parametrize(
    "bad_value",
    [
        f'"{_FP[:-1]}"',  # 63 hex chars
        f'"{_FP}0"',  # 65 hex chars
        f'"{_FP[:-1]}g"',  # non-hex character
        f'"{_FP[:40]}"',  # SHA-1-sized
        f'"{_FP_COLON_UPPER[:-3]}"',  # 31 pairs
        f'"{_FP_COLON_UPPER.replace(":", "", 1)}"',  # separators only partly present
        f'"{_FP_COLON_UPPER.replace(":", "-")}"',  # unsupported separator
        f'"md5:{_FP}"',  # unsupported prefix
        '""',
        "12345",  # YAML int, not a string
        "{a: b}",
    ],
)
def test_load_devices_rejects_invalid_tls_fingerprint_naming_the_device(tmp_path: Path, bad_value: str):
    path = _write(tmp_path, _pinned_yaml(bad_value))
    with pytest.raises(ConfigError) as exc_info:
        load_devices(path)
    message = str(exc_info.value)
    assert "'edge-router'" in message
    assert "tls_fingerprint" in message


def test_load_devices_rejects_a_list_with_one_invalid_tls_fingerprint(tmp_path: Path):
    path = _write(tmp_path, _pinned_yaml(f'\n      - "{_FP}"\n      - "not-a-fingerprint"'))
    with pytest.raises(ConfigError, match="'edge-router'.*not-a-fingerprint"):
        load_devices(path)


def test_load_devices_rejects_a_list_with_a_non_string_tls_fingerprint(tmp_path: Path):
    path = _write(tmp_path, _pinned_yaml(f'\n      - "{_FP}"\n      - 42'))
    with pytest.raises(ConfigError, match="'edge-router'"):
        load_devices(path)


def test_load_devices_rejects_an_empty_tls_fingerprint_list(tmp_path: Path):
    path = _write(tmp_path, _pinned_yaml("[]"))
    with pytest.raises(ConfigError, match="'edge-router' has an empty 'tls_fingerprint' list"):
        load_devices(path)


@pytest.mark.parametrize("use_ssl_line", ["", "    use_ssl: false\n"])
def test_load_devices_rejects_tls_fingerprint_without_use_ssl(tmp_path: Path, use_ssl_line: str):
    path = _write(
        tmp_path,
        f'devices:\n  - name: plain-api\n    host: 192.0.2.11\n{use_ssl_line}    tls_fingerprint: "{_FP}"\n',
    )
    with pytest.raises(ConfigError, match="'plain-api' sets 'tls_fingerprint' without 'use_ssl: true'"):
        load_devices(path)


# Design choice under test: a pin REPLACES CA-chain + hostname verification
# (see config._device_from_dict). An explicit tls_verify: true or a
# tls_ca_cert next to it would claim a check that isn't performed, so both
# are rejected as ambiguous; tls_verify omitted or false is pin-only mode.


def test_load_devices_rejects_tls_fingerprint_with_explicit_tls_verify_true(tmp_path: Path):
    path = _write(tmp_path, _pinned_yaml(f'"{_FP}"', "    tls_verify: true\n"))
    with pytest.raises(ConfigError, match="'edge-router' sets both 'tls_fingerprint' and 'tls_verify: true'"):
        load_devices(path)


def test_load_devices_rejects_tls_fingerprint_with_tls_ca_cert(tmp_path: Path):
    path = _write(tmp_path, _pinned_yaml(f'"{_FP}"', "    tls_ca_cert: /etc/mcp-mikrotik/ca.pem\n"))
    with pytest.raises(ConfigError, match="'edge-router' sets both 'tls_fingerprint' and 'tls_ca_cert'"):
        load_devices(path)


def test_load_devices_rejects_tls_fingerprint_with_tls_ca_cert_even_when_tls_verify_false(tmp_path: Path):
    path = _write(
        tmp_path,
        _pinned_yaml(f'"{_FP}"', "    tls_verify: false\n    tls_ca_cert: /etc/mcp-mikrotik/ca.pem\n"),
    )
    with pytest.raises(ConfigError, match="'tls_ca_cert'"):
        load_devices(path)


def test_load_devices_accepts_tls_fingerprint_with_tls_verify_false(tmp_path: Path):
    path = _write(tmp_path, _pinned_yaml(f'"{_FP}"', "    tls_verify: false\n"))
    device = load_devices(path)["edge-router"]
    assert device.tls_fingerprints == (_FP,)
    assert device.tls_verify is False


def test_load_devices_accepts_tls_fingerprint_with_tls_verify_omitted(tmp_path: Path):
    path = _write(tmp_path, _pinned_yaml(f'"{_FP}"'))
    device = load_devices(path)["edge-router"]
    assert device.tls_fingerprints == (_FP,)
    assert device.tls_ca_cert is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (_FP, _FP),
        (_FP_COLON_UPPER, _FP),
        (f"sha256:{_FP_COLON_UPPER}", _FP),
        (_FP[:-2], None),
        (f"{_FP_COLON_UPPER}:", None),
        ("sha256:", None),
    ],
)
def test_normalize_tls_fingerprint(value: str, expected: str | None):
    assert normalize_tls_fingerprint(value) == expected


def test_devices_yaml_example_loads_including_its_pinned_device():
    """Keep the documented example honest: it must load as-is, and its
    tls_fingerprint example must parse as a pin."""
    example = Path(__file__).resolve().parent.parent / "devices.yaml.example"
    devices = load_devices(example)
    pinned = [device for device in devices.values() if device.tls_fingerprints]
    assert pinned, "devices.yaml.example should show a tls_fingerprint example"
    assert all(device.use_ssl and device.tls_ca_cert is None for device in pinned)
