# Changelog

All notable changes to this project are documented here. Versions follow
[Semantic Versioning](https://semver.org).

## [0.2.0] - Unreleased

### Added

- Read tools: `dhcp_leases`, `wireless_registrations` (ROS7 wifi
  registration table with automatic ROS6 wireless fallback; returns an
  empty list rather than erroring on a device with no radio), `dns_cache`,
  `firewall_filter`, `system_health` (empty list on devices/boards without
  health sensors).
- Guarded write tools: `enable_interface` and `disable_interface` (set
  `/interface disabled=no|yes` by name), and `set_wifi_ssid` (detects the
  ROS7 `/interface/wifi` vs ROS6 `/interface/wireless` path per device and
  writes to whichever matches). All three go through the exact same
  read-only gate + central allowlist + confirm/preview mechanism as
  `set_identity` - see `src/mcp_mikrotik/guard.py`.
- `ResourceNotFoundError` (`src/mcp_mikrotik/exceptions.py`): raised by the
  new write tools when the named interface/wireless network doesn't exist on
  the device, so a typo in the name can never silently create one.
- `.github/workflows/ci.yml`: runs `pytest` on push/PR against Python 3.11
  and 3.12.

### Changed

- README: tools table split further to list every new read/write tool,
  "Security model" section documents the `set_wifi_ssid` two-path allowlist
  exception and the "never creates the target" behavior of the new write
  tools, "Roadmap / non-goals" explains why reboot and firewall writes are
  still intentionally excluded.

## [0.1.0] - Initial public release

### Added

- Read tools: `list_devices`, `system_info`, `interfaces`, `ip_addresses`,
  `ip_routes`, `neighbors`, `logs`, `ping`, `list_write_operations`.
- One guarded write tool, `set_identity`, exercising the full write-guard
  mechanism end to end: read-only gate (`MIKROTIK_ALLOW_WRITE`), a central
  named allowlist (`guard.ALLOWLIST`) with no generic command tool, and
  explicit `confirm` with a before/after preview.
- Structured RouterOS API access via `librouteros` (no shell/string-built
  commands - command injection ruled out by construction), ROS6/ROS7
  compatibility, per-device TLS verification for `api-ssl`, connection
  pooling, and a full pytest suite against an in-memory fake device.
