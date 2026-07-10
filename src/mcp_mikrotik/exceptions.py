"""Exception hierarchy for mcp-mikrotik.

Every exception here is meant to be caught at the MCP tool boundary
(see server.py) and turned into a clean, structured error for the tool
caller. Messages must never contain a device password, and must never be a
raw stack trace from the underlying transport library.
"""

from __future__ import annotations


class MikrotikMCPError(Exception):
    """Base class for all errors raised by mcp-mikrotik."""


class ConfigError(MikrotikMCPError):
    """Problem loading or validating devices.yaml / environment configuration."""


class DeviceNotFoundError(ConfigError):
    """Requested device name does not exist in the configuration, or is disabled."""

    def __init__(self, name: str):
        super().__init__(f"Unknown or disabled device: {name!r}")
        self.device_name = name


class DeviceConnectionError(MikrotikMCPError):
    """Could not establish or use an API connection to a device."""

    def __init__(self, device_name: str, detail: str):
        super().__init__(f"Could not connect to device {device_name!r}: {detail}")
        self.device_name = device_name


class DeviceCommandError(MikrotikMCPError):
    """A RouterOS API command failed on the device side."""

    def __init__(self, device_name: str, path: str, detail: str):
        super().__init__(f"Command failed on device {device_name!r} at /{path}: {detail}")
        self.device_name = device_name
        self.path = path


class ValidationError(MikrotikMCPError):
    """Input failed validation before ever being sent to a device (e.g. ping address)."""


class WriteDisabledError(MikrotikMCPError):
    """A write tool was called while the server is running in read-only mode."""

    def __init__(self, operation: str):
        super().__init__(
            f"Write operation {operation!r} was blocked: server is running read-only "
            "(set MIKROTIK_ALLOW_WRITE=true to enable writes)."
        )
        self.operation = operation


class ResourceNotFoundError(MikrotikMCPError):
    """A named resource (interface, wireless network, ...) does not exist on the device.

    Raised by guard.py write functions when the caller-supplied name (e.g. an
    interface to enable/disable, or a wifi/wireless interface to rename)
    doesn't match any row on the device. Write tools must never create the
    resource in that case - this signals "no such thing here", not "make
    one".
    """

    def __init__(self, device_name: str, resource_kind: str, resource_name: str):
        super().__init__(f"{resource_kind} {resource_name!r} not found on device {device_name!r}.")
        self.device_name = device_name
        self.resource_kind = resource_kind
        self.resource_name = resource_name


class ResourceAlreadyExistsError(MikrotikMCPError):
    """A write tool refused to create a resource that already exists (e.g. a
    static DHCP lease for a MAC address that already has one).

    Raised instead of silently creating a duplicate row or overwriting the
    existing one - the caller must remove/adjust the existing resource
    explicitly first (this package's add_* write tools never update or
    remove as a side effect of add).
    """

    def __init__(self, device_name: str, resource_kind: str, resource_name: str):
        super().__init__(
            f"{resource_kind} {resource_name!r} already exists on device {device_name!r}; not creating a duplicate."
        )
        self.device_name = device_name
        self.resource_kind = resource_kind
        self.resource_name = resource_name


class GuardViolationError(MikrotikMCPError):
    """A write operation was requested that is not present in the write allowlist.

    This should be unreachable from normal tool use: every write tool exposed
    in server.py calls a dedicated, named function in guard.py that references
    a fixed ALLOWLIST key. It exists as a defensive backstop in case a future
    write tool is wired up incorrectly.
    """

    def __init__(self, operation: str):
        super().__init__(f"Write operation {operation!r} is not in the write allowlist.")
        self.operation = operation
