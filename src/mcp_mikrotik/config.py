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
    password: str = ""
    disabled: bool = False
    comment: str = ""

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
    devices: dict[str, Device] = field(default_factory=dict)

    def get_device(self, name: str) -> Device:
        device = self.devices.get(name)
        if device is None or device.disabled:
            raise DeviceNotFoundError(name)
        return device


def _bool_env(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _device_from_dict(raw: dict[str, Any]) -> Device:
    if "name" not in raw or "host" not in raw:
        raise ConfigError("Each device entry needs at least 'name' and 'host'.")
    return Device(
        name=raw["name"],
        host=raw["host"],
        port=int(raw.get("port", DEFAULT_PORT)),
        use_ssl=bool(raw.get("use_ssl", False)),
        username=raw.get("username", "admin"),
        password=raw.get("password", ""),
        disabled=bool(raw.get("disabled", False)),
        comment=raw.get("comment", ""),
    )


def load_devices(path: Path) -> dict[str, Device]:
    """Load devices from a YAML file. Returns an empty dict if the file does not exist."""
    if not path.exists():
        return {}

    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}

    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top-level YAML must be a mapping with a 'devices' key.")

    entries = data.get("devices", [])
    if not isinstance(entries, list):
        raise ConfigError(f"{path}: 'devices' must be a list.")

    devices: dict[str, Device] = {}
    for raw in entries:
        if not isinstance(raw, dict):
            raise ConfigError(f"{path}: each device entry must be a mapping.")
        device = _device_from_dict(raw)
        if device.name in devices:
            raise ConfigError(f"{path}: duplicate device name {device.name!r}.")
        devices[device.name] = device
    return devices


def load_settings(devices_path: Path | None = None, env: dict[str, str] | None = None) -> Settings:
    """Build Settings from environment variables plus the devices YAML file.

    `env` defaults to os.environ; passing an explicit mapping is mainly useful
    for tests so they never depend on the real process environment.
    """
    env = env if env is not None else os.environ
    path = devices_path or Path(env.get("MIKROTIK_DEVICES_FILE", DEFAULT_DEVICES_FILE))
    devices = load_devices(path)
    allow_write = _bool_env(env.get("MIKROTIK_ALLOW_WRITE"), default=False)
    return Settings(allow_write=allow_write, devices=devices)
