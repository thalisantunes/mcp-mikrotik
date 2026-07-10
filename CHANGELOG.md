# Changelog

All notable changes to this project are documented here. Versions follow
[Semantic Versioning](https://semver.org).

## [0.4.0] - Unreleased

### Added

- Read tools: `address_lists` (`/ip/firewall/address-list` - list, address,
  timeout, dynamic, disabled), `firewall_nat` (`/ip/firewall/nat`),
  `scheduler` (`/system/scheduler`), `ip_pools` (`/ip/pool`).
- `traceroute`: diagnostic tool (`/tool/traceroute`), returning the list of
  hops. `address` is validated exactly like `ping`'s; `count` and `max_hops`
  are capped low (`MAX_TRACEROUTE_COUNT`/`MAX_TRACEROUTE_MAX_HOPS` in
  `src/mcp_mikrotik/server.py`), and a fixed short per-hop timeout is always
  sent to the device (`src/mcp_mikrotik/client.py`), so the command can't
  run long enough to hit RouterOS's own ~60s API command timeout. Not a
  write - not gated by `MIKROTIK_ALLOW_WRITE`.
- Guarded write tool `add_to_address_list`: adds an IP/subnet to a named
  firewall address-list. Refuses to create a duplicate `list_name`+`address`
  pair - raises `ResourceAlreadyExistsError` instead. Optional `comment`/
  `timeout` fields. **Only manages the list** - it does not create or modify
  any firewall rule; see README's new "Blocking/allowing a client via
  address lists" section for why a filter rule referencing the list is
  still required for this to actually block/allow anything.
- Guarded write tool `remove_from_address_list`: removes a `list_name`+
  `address` entry from a firewall address-list. Raises `ResourceNotFoundError`
  if no such entry exists.
- Validation (`src/mcp_mikrotik/validation.py`): `validate_address_list_name`
  (firewall address-list `list` name), `validate_comment` (free-text
  `comment`, rejects control characters/newlines), `validate_timeout`
  (RouterOS `w/d/h/m/s` duration or `HH:MM:SS` clock value).

### Fixed

- `remove_simple_queue` (`src/mcp_mikrotik/guard.py`): `target` is now
  validated *before* the device is read (`client.path(...)`), matching
  every other write tool's validate-before-touch order. Previously an
  invalid `target` still triggered a device read before the validation
  error was raised.

### Notes

- **Address-list is not a firewall rule.** `add_to_address_list`/
  `remove_from_address_list` manage list membership only; blocking/allowing
  traffic requires a separate `/ip/firewall/filter` (or NAT) rule that
  references the list name (e.g. `src-address-list=list_name action=drop`).
  See README's "Blocking/allowing a client via address lists" section.

## [0.3.0] - Unreleased

### Added

- Read tool: `simple_queues` (`/queue/simple`) - name, target, max-limit,
  limit-at, bytes counters, disabled. Lets an operator see who already has a
  bandwidth limit and how much traffic they've moved before deciding who to
  limit next.
- Guarded write tool `set_client_bandwidth`: limits a client's bandwidth via
  a RouterOS Simple Queue targeting an IP/subnet. Updates the existing queue
  if one already targets `target`, otherwise creates one with a name
  deterministically derived from `target` - backed by two allowlist entries
  (`set_client_bandwidth_update`/`set_client_bandwidth_add`), following the
  same "two fixed, reviewed paths, chosen by the guard function, never by
  the caller" shape as `set_wifi_ssid`. `max_limit`/`limit_at` are validated
  as RouterOS rate pairs (`validate_rate_pair`, `src/mcp_mikrotik/validation.py`).
- Guarded write tool `add_static_dhcp_lease`: creates a static DHCP lease
  (`/ip/dhcp-server/lease`) pinning an IP address to a MAC address (useful
  to give a client a stable target before limiting it). Refuses to create a
  second lease for a MAC that already has one - raises the new
  `ResourceAlreadyExistsError` (`src/mcp_mikrotik/exceptions.py`) instead of
  duplicating.
- Guarded write tool `remove_simple_queue`: removes a Simple Queue by
  `target` or `name`, to undo a bandwidth limit.
- Validation: `validate_target` (IPv4/IPv6 address or `/prefix` subnet, for
  Simple Queue `target`), `validate_ip_address` (plain address, for DHCP
  lease `address` - unlike `validate_ping_address`, no hostname), `validate_mac_address`,
  `validate_rate_pair` (RouterOS `upload/download` rate pairs, e.g. `"10M/5M"`)
  - all in `src/mcp_mikrotik/validation.py`.

### Notes

- **FastTrack gotcha**: if a device has a FastTrack rule in its firewall (a
  common default from RouterOS's own quick-set wizards), fasttracked
  connections bypass Simple Queue entirely - `set_client_bandwidth` may have
  no visible effect on a client whose traffic is already fasttracked. This
  is documented in `set_client_bandwidth`'s docstring (`server.py`/`guard.py`)
  and in README's "Security model" section below.

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
