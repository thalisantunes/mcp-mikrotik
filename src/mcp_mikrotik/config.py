"""Device configuration: environment variables + optional devices.yaml.

Devices are described in a YAML file (see devices.yaml.example) that is
git-ignored because it holds credentials. Two environment variables control
server-wide behaviour:

  MIKROTIK_DEVICES_FILE  - path to the devices YAML file (default: devices.yaml)
  MIKROTIK_ALLOW_WRITE   - "true"/"1"/"yes"/"on" to enable write tools (default: false)

See .env.example for the full list.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .exceptions import ConfigError, DeviceNotFoundError

DEFAULT_PORT = 8728
DEFAULT_DEVICES_FILE = "devices.yaml"


@dataclass
class Device:
    """A single MikroTik device from devices.yaml."""

    name: str
    host: str
    port: int = DEFAULT_PORT
    use_ssl: bool = False
    username: str = "admin"
    # repr=False: a stray `logger.debug(device)` / `logger.debug(settings)`
    # must never write a device password to stderr (see docs/REVIEW-FINDINGS.md S1).
    password: str = field(default="", repr=False)
    disabled: bool = False
    comment: str = ""
    # SSL trust: default (True) keeps the existing safe behaviour - a proper
    # certificate chain is validated via ssl.create_default_context(). Set to
    # False only for devices using RouterOS's self-signed api-ssl cert, which
    # trades away MITM protection on that connection; see README "Security
    # model" and devices.yaml.example for the explicit trade-off writeup.
    # Ignored when tls_fingerprints is set (the pin is the authentication);
    # for a self-signed cert, pinning is the authenticated alternative to False.
    tls_verify: bool = True
    # Optional path to a CA bundle to validate the device's cert against,
    # instead of the system trust store. Ignored when tls_verify is False;
    # never combined with tls_fingerprints (the loader rejects both together).
    tls_ca_cert: str | None = None
    # Certificate pinning (devices.yaml key `tls_fingerprint`, a string or a
    # list of strings): the accepted SHA-256 fingerprints of this device's
    # own api-ssl certificate (the DER leaf), normalized by
    # normalize_tls_fingerprint() to 64 lowercase hex chars. Empty = no
    # pinning, which the loader only produces when the key is absent (a
    # present-but-empty key is a ConfigError). When non-empty, the pin REPLACES chain + hostname
    # verification rather than adding to it - client._build_ssl_context()
    # checks this before tls_verify/tls_ca_cert, and the YAML loader
    # rejects an explicit `tls_verify: true` or a `tls_ca_cert` alongside
    # it as ambiguous (see _device_from_dict for why). Not secret, but also
    # not part of to_public_dict(): tool output doesn't need it.
    tls_fingerprints: tuple[str, ...] = ()
    # Per-device connection timeout (seconds). None means "use the
    # MIKROTIK_TIMEOUT env var if set, else client.DEFAULT_TIMEOUT" - see
    # client._resolve_timeout(). Some fleet links are slow enough (15-40s
    # banner) that the old hardcoded 10s was too tight.
    timeout: float | None = None

    def to_public_dict(self) -> dict[str, Any]:
        """Representation safe to return through an MCP tool result: never includes the password."""
        return {
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "use_ssl": self.use_ssl,
            "username": self.username,
            "disabled": self.disabled,
            "comment": self.comment,
        }


@dataclass
class Settings:
    """Server-wide settings resolved from environment + devices.yaml."""

    allow_write: bool
    # repr=False: Settings.devices holds every configured Device (each with a
    # password, even though Device.password itself is repr=False - see S1).
    # Keeping the whole dict out of Settings' repr is a second, independent
    # layer so a future field added to Device without repr=False can't leak
    # through `logger.debug(settings)`.
    devices: dict[str, Device] = field(default_factory=dict, repr=False)

    def get_device(self, name: str) -> Device:
        device = self.devices.get(name)
        if device is None or device.disabled:
            raise DeviceNotFoundError(name)
        return device


def _bool_env(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _coerce_str(value: Any, field_name: str, path: Path) -> str:
    """Coerce a YAML scalar into a str for `name`/`host` (E3).

    A bare numeric YAML value like `name: 14` parses as an int, which would
    silently become an int dict key and make the device unreachable by its
    (string) `device_name` tool argument - see docs/REVIEW-FINDINGS.md E3.
    int/float are coerced; anything else (mapping, list, bool, None) is
    rejected with a clear ConfigError instead of failing later in a
    confusing way.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, bool) or value is None:
        raise ConfigError(f"{path}: device field {field_name!r} must be a string, got {value!r}.")
    if isinstance(value, (int, float)):
        return str(value)
    raise ConfigError(f"{path}: device field {field_name!r} must be a string, got {value!r}.")


_FINGERPRINT_PREFIX = "sha256:"
_FINGERPRINT_PLAIN = re.compile(r"[0-9a-f]{64}")
_FINGERPRINT_COLON_SEPARATED = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){31}")


def normalize_tls_fingerprint(value: str) -> str | None:
    """Normalize one SHA-256 certificate fingerprint to 64 lowercase hex
    chars, or return None if `value` isn't one.

    Accepted, case-insensitively: 64 hex chars (`ab12...`), or 32 ':'
    separated hex pairs (`AB:12:...`, the `openssl x509 -fingerprint
    -sha256` format), either optionally prefixed with `sha256:`.
    Separators are all-or-nothing - a value with only some ':' is
    rejected rather than guessed at, since that usually means a pair was
    dropped or mistyped. Anything else (wrong length, non-hex chars, a
    SHA-1/MD5 fingerprint) returns None.
    """
    text = value.strip().lower()
    if text.startswith(_FINGERPRINT_PREFIX):
        text = text[len(_FINGERPRINT_PREFIX) :].strip()
    if _FINGERPRINT_COLON_SEPARATED.fullmatch(text):
        text = text.replace(":", "")
    return text if _FINGERPRINT_PLAIN.fullmatch(text) else None


def _parse_tls_fingerprints(raw_value: Any, name: str, path: Path) -> tuple[str, ...]:
    """Parse the value of a device's `tls_fingerprint` key (a string, or a
    list of strings to allow certificate rotation) into normalized pins.

    Only called when the key is present - an absent key is the one way to
    say "no pinning". A present key with no usable value (null - which is
    also what a bare `tls_fingerprint:` or `~` loads as - an empty list, an
    empty string) or any invalid entry is a ConfigError naming the device,
    never silently treated as "no pinning": on a device with
    `tls_verify: false` that would quietly downgrade the connection to an
    unauthenticated one while the config still reads as pinned."""
    if raw_value is None:
        raise ConfigError(
            f"{path}: device {name!r} has a 'tls_fingerprint' key with no value (null); put the router's "
            "certificate fingerprint there or remove the key. An empty pin is never treated as 'no pinning'."
        )
    values = raw_value if isinstance(raw_value, list) else [raw_value]
    if not values:
        raise ConfigError(
            f"{path}: device {name!r} has an empty 'tls_fingerprint' list; list at least one "
            "fingerprint or remove the key."
        )
    pins: list[str] = []
    for value in values:
        normalized = normalize_tls_fingerprint(value) if isinstance(value, str) else None
        if normalized is None:
            raise ConfigError(
                f"{path}: device {name!r} has an invalid 'tls_fingerprint' value {value!r}: expected a "
                "SHA-256 certificate fingerprint - 64 hex characters, optionally as ':'-separated pairs "
                "and/or prefixed with 'sha256:' (quote it in YAML)."
            )
        if normalized not in pins:
            pins.append(normalized)
    return tuple(pins)


def _device_from_dict(raw: dict[str, Any], path: Path) -> Device:
    if "name" not in raw or "host" not in raw:
        raise ConfigError(f"{path}: each device entry needs at least 'name' and 'host'.")

    name = _coerce_str(raw["name"], "name", path)
    host = _coerce_str(raw["host"], "host", path)

    try:
        port = int(raw.get("port", DEFAULT_PORT))
    except (ValueError, TypeError) as exc:
        raise ConfigError(f"{path}: device {name!r} has an invalid 'port': {raw.get('port')!r}") from exc

    timeout_raw = raw.get("timeout")
    timeout: float | None
    if timeout_raw is None:
        timeout = None
    else:
        try:
            timeout = float(timeout_raw)
        except (ValueError, TypeError) as exc:
            raise ConfigError(f"{path}: device {name!r} has an invalid 'timeout': {timeout_raw!r}") from exc

    use_ssl = bool(raw.get("use_ssl", False))
    tls_verify = bool(raw.get("tls_verify", True))
    tls_ca_cert = raw.get("tls_ca_cert")
    # `tls_fingerprints` (plural) is the natural spelling for a list and the
    # name of the Device attribute, but it is not the YAML key. Unknown keys
    # are otherwise ignored; this one would silently leave the device
    # unpinned (with `tls_verify: false`, unauthenticated) while the config
    # reads as pinned, so it is rejected rather than ignored. One spelling
    # only - no alias - so there is never a question of which key wins.
    if "tls_fingerprints" in raw:
        raise ConfigError(
            f"{path}: device {name!r} uses the key 'tls_fingerprints'; the key is 'tls_fingerprint' "
            "(singular), for a single fingerprint or a list of them. Rename it."
        )
    tls_fingerprints = _parse_tls_fingerprints(raw["tls_fingerprint"], name, path) if "tls_fingerprint" in raw else ()
    if tls_fingerprints:
        # Pinning only means anything on an api-ssl connection; on the plain
        # API there is no certificate to pin, and silently ignoring the key
        # would leave the operator believing the device is authenticated.
        if not use_ssl:
            raise ConfigError(
                f"{path}: device {name!r} sets 'tls_fingerprint' without 'use_ssl: true'. Certificate "
                "pinning only applies to api-ssl - enable use_ssl (and point port at the api-ssl service, "
                "usually 8729) or remove tls_fingerprint."
            )
        # Design choice: a pin REPLACES CA-chain + hostname verification
        # instead of being checked in addition to it. The case pinning exists
        # for - RouterOS's self-signed / per-device-CA certs, commonly with
        # no subjectAltName for the address the server connects to - can
        # never pass chain + hostname checks, so "pin in addition" would make
        # the pin unusable exactly where it's needed (or force `tls_verify:
        # false` next to it, which reads as "unauthenticated" when it isn't).
        # The pin is also the stronger identity check: it accepts exactly one
        # certificate per pin rather than anything a CA signed for that name.
        # Because chain/hostname checks are then NOT performed, an explicit
        # `tls_verify: true` or a `tls_ca_cert` next to a pin would make the
        # config claim a check that doesn't happen - rejected as ambiguous
        # rather than silently ignored. `tls_verify: false` (or omitting it)
        # is consistent with pin-only mode and accepted.
        if "tls_verify" in raw and tls_verify:
            raise ConfigError(
                f"{path}: device {name!r} sets both 'tls_fingerprint' and 'tls_verify: true'. With a pinned "
                "fingerprint the pin is the authentication and CA-chain/hostname checks are not performed, "
                "so this combination is ambiguous - remove tls_verify (or set it to false), or remove "
                "tls_fingerprint to use CA verification instead."
            )
        if tls_ca_cert:
            raise ConfigError(
                f"{path}: device {name!r} sets both 'tls_fingerprint' and 'tls_ca_cert'. They are not "
                "combined: tls_ca_cert validates the certificate chain against a CA, tls_fingerprint pins "
                "this device's exact certificate instead - keep one of them."
            )

    return Device(
        name=name,
        host=host,
        port=port,
        use_ssl=use_ssl,
        username=raw.get("username", "admin"),
        password=raw.get("password", ""),
        disabled=bool(raw.get("disabled", False)),
        comment=raw.get("comment", ""),
        tls_verify=tls_verify,
        tls_ca_cert=tls_ca_cert,
        tls_fingerprints=tls_fingerprints,
        timeout=timeout,
    )


def load_devices(path: Path) -> dict[str, Device]:
    """Load devices from a YAML file. Returns an empty dict if the file does not exist."""
    if not path.exists():
        return {}

    with path.open("r", encoding="utf-8") as fh:
        try:
            data = yaml.safe_load(fh) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"{path}: invalid YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top-level YAML must be a mapping with a 'devices' key.")

    entries = data.get("devices", [])
    if not isinstance(entries, list):
        raise ConfigError(f"{path}: 'devices' must be a list.")

    devices: dict[str, Device] = {}
    for raw in entries:
        if not isinstance(raw, dict):
            raise ConfigError(f"{path}: each device entry must be a mapping.")
        device = _device_from_dict(raw, path)
        if device.name in devices:
            raise ConfigError(f"{path}: duplicate device name {device.name!r}.")
        devices[device.name] = device
    return devices


def load_settings(devices_path: Path | None = None, env: Mapping[str, str] | None = None) -> Settings:
    """Build Settings from environment variables plus the devices YAML file.

    `env` defaults to os.environ; passing an explicit mapping is mainly useful
    for tests so they never depend on the real process environment. Typed as
    `Mapping` (read-only) rather than `dict` since `os.environ` itself is an
    `_Environ[str]`, not a `dict` - both satisfy `Mapping[str, str]`.
    """
    resolved_env: Mapping[str, str] = env if env is not None else os.environ
    path = devices_path or Path(resolved_env.get("MIKROTIK_DEVICES_FILE", DEFAULT_DEVICES_FILE))
    devices = load_devices(path)
    allow_write = _bool_env(resolved_env.get("MIKROTIK_ALLOW_WRITE"), default=False)
    return Settings(allow_write=allow_write, devices=devices)
