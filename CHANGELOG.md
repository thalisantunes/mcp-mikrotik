# Changelog

All notable changes to this project are documented here. Versions follow
[Semantic Versioning](https://semver.org).

## [0.7.0] - Unreleased

LTE/5G + containers + USB round: read tools for cellular WAN status,
RouterOS's container subsystem, and USB hardware, plus one new mechanic on
the write-guard - `start_container`/`stop_container`, the first guarded
writes whose RouterOS operation is an ACTION command (`/container/start`,
`/container/stop`) rather than an update/add/remove `set`. Same write-guard
mechanism as every previous round (read-only default, central allowlist,
confirm/preview, audit journal, ROS6/ROS7 compat) - extended, not weakened
or bypassed. See "How start/stop extends the guard" below.

### Added

- **`lte_status`** (read, `src/mcp_mikrotik/server.py`): signal/status of
  one LTE/5G modem interface, via `/interface/lte/monitor <interface>
  once=yes` - operator (`current-operator`), technology
  (`access-technology`: 3G/LTE/5G), signal (`rsrp`/`rsrq`/`sinr`/`rssi`),
  `band`, `registration-status`, `cell-id`. Reuses the exact same
  "monitor-once" construction as v0.6's `interface_traffic`/`poe_status`
  (`once=""` as a structured flag, one reply, no continuous stream - see
  `MikrotikClient.lte_monitor` below). `interface` is validated for shape
  (`validate_interface_name`, reused from v0.6) before use. Returns an empty
  dict (never an error) for a device with no LTE hardware/package at all,
  same convention as `poe_status`/`system_health` for optional hardware.
- **`lte_interfaces`** (read): lists `/interface/lte` - name, running,
  disabled, apn-profiles, etc. Empty list (not an error) with no LTE
  hardware.
- **`containers`** (read): lists `/container` - name/tag, status,
  ram-usage, root-dir, interface, os. Empty list (not an error) with no
  container package/hardware support.
- **`container_config`** (read): `/container/config` (registry-url,
  tmpdir, ram-high, ...) - a single-row menu. Empty dict (not an error)
  with no container package.
- **`usb_devices`** (read): combines `/system/routerboard/usb` (physical
  USB ports, if the board exposes them) and `/disk` (attached storage - USB
  flash drives, and USB LTE/5G modems that surface as a disk rather than
  under routerboard/usb) into `{"usb_ports": [...], "disks": [...]}`, since
  which of the two a given USB device shows up under depends on the
  hardware. Either or both lists empty (never an error) if the board
  exposes neither.
- **`start_container`/`stop_container`** (WRITE, guarded - new `ALLOWLIST`
  entries `src/mcp_mikrotik/guard.py`): start/stop a container by `name` or
  `tag` (`/container/start`/`/container/stop`). Same guard mechanics as
  every other write tool - blocked by the read-only gate unless
  `MIKROTIK_ALLOW_WRITE=true`, `confirm=false` previews a before/after
  without touching the device, only `confirm=true` applies it, raises
  `ResourceNotFoundError` if `container` doesn't match any `/container`
  row's `name` or `tag` (never creates one), and goes through the v0.5
  audit-journal `_audited` decorator automatically - the device password
  never appears in the journal. See "How start/stop extends the guard"
  below for the new mechanics this round adds on top of that.
- `MikrotikClient.lte_monitor` (`src/mcp_mikrotik/client.py`): new read
  primitive, built exactly like `monitor_traffic`/`poe_monitor` - the
  callable connection form, `once=""`, automatic read-retry, transport
  failures wrapped as `DeviceCommandError`.
- `MikrotikClient.start`/`.stop` (`src/mcp_mikrotik/client.py`, new): the
  first *action-command* write primitives, alongside `update`/`add`/
  `remove`. Each sends exactly one fixed command word (`"start"`/`"stop"`)
  via the connection's `path(*segments)(cmd, **{".id": id})` callable form
  (mirroring `librouteros.api.Path.__call__`, the same mechanism its own
  `Path.remove()` uses for `.id`-targeted operations) - never a
  caller-supplied command or path. No retry, same reasoning as
  `update`/`add`/`remove` (idempotency isn't guaranteed for a repeated
  action either).
- `validation.validate_container_identifier` (`src/mcp_mikrotik/validation.py`):
  shape validation for a container `name`/`tag` identifier - non-empty, no
  control characters, length-capped. Deliberately NOT restricted to
  `_INTERFACE_NAME`/`_LIST_NAME`'s conservative charset, since a real
  container `tag` is a Docker-style image reference that legitimately
  contains `:`, `/`, and `.` (e.g.
  `"myregistry.example.com:5000/library/alpine:latest"`).

### How start/stop extends the guard

`start_container`/`stop_container` are the first `ALLOWLIST` entries whose
`action` is neither `"update"`, `"add"`, nor `"remove"` - RouterOS's
`/container/start`/`/container/stop` are ACTION commands (the CLI syntax is
`/container start <numbers>`, not a `set`), so the guard mechanism itself
was extended, carefully, to cover that shape without opening up anything
new:

- **Two new fixed `MikrotikClient` methods, `.start`/`.stop`**, each
  sending exactly one hardcoded RouterOS command word - never a command or
  path supplied by a caller (see `client.py` above). There is still no way
  to reach an arbitrary API path or command through this package; `.start`/
  `.stop` are exactly as narrow as `.update`/`.add`/`.remove` were before
  them.
- **Dispatch still goes through the same `getattr(client, op.action)`
  mechanism** every other guarded write already used (see `set_identity`'s
  A1 dispatch, `guard.py`) - `ALLOWLIST["start_container"].action ==
  "start"` and `ALLOWLIST["stop_container"].action == "stop"` are what
  actually get called, exactly as `"update"`/`"add"`/`"remove"` did for
  every prior write. `guard._set_container_running` (the shared
  implementation behind both) never calls `client.start`/`.stop` directly -
  only via that same `op.action` indirection.
- **The container is always resolved server-side, by `.id`, before the
  action fires** - `guard._find_container_row` looks up the caller-supplied
  `container` string against `/container`'s `name` field first, then `tag`
  (mirroring `set_wifi_ssid`'s ROS7-then-ROS6 fallback shape), and only
  ever passes the resolved row's own `.id` to `client.start`/`.stop`. A
  `container` that doesn't match any row raises `ResourceNotFoundError` -
  `start_container`/`stop_container` never create a container, same "never
  creates the target" invariant as `enable_interface`/`set_poe_out`/etc.
- **Same read-only gate and confirm/preview flow, unchanged.**
  `_require_allowed` (the read-only gate + allowlist check) runs first, exactly
  like every other write, before the device is ever touched by a
  `container` lookup. `confirm=false` computes and returns a before/after
  preview - `after.status` set to the *immediate* transitional status
  RouterOS's action command sets (`"starting"`/`"stopping"`), not a
  guaranteed final state, since starting/stopping a container is
  RouterOS-async (image extraction, process startup) rather than the
  synchronous field-set `enable_interface`/`set_poe_out` make - without
  touching the device; only `confirm=true` calls `client.start`/`.stop`.
- **Same `_audited` decorator, unchanged** - `start_container`/
  `stop_container` are journaled exactly like every other write, with
  `action` in the journal now correctly showing `"start"`/`"stop"` instead
  of being forced into the old three-value enum.

### Tests

61 new tests (415 → 476, full suite green): `MikrotikClient.lte_monitor`
(structured params not a command string, empty-reply handling,
transport-error wrapping, read retry) and `.start`/`.stop` (action-command
dispatch via the structured `.id` parameter, only the targeted row changes,
transport-error wrapping, no retry - extending the existing
"writes never retry" parametrized case);
`validation.validate_container_identifier` (valid/invalid/non-string
cases, including that a Docker-style `registry:port/repo:tag` identifier is
accepted); `guard.start_container`/`.stop_container` (blocked read-only,
gate-before-touch, preview/confirm, name-then-tag resolution, `.id`-targeted
dispatch proven via the same monkeypatched-action technique as
`set_identity`'s A1 test, unknown container, invalid identifier before
touching the device, audit journal outcomes including the extended
no-password-leak sweep across all twelve write tools); and `lte_status`/
`lte_interfaces`/`containers`/`container_config`/`usb_devices`/
`start_container`/`stop_container` exercised end to end through `server.py`'s
`call_tool` (happy paths, the read-only-by-default and
read-tools-never-gated cases, empty/no-hardware fallback for every new read
tool, and the invalid-input/unknown-resource error paths for the two new
write tools).

## [0.6.0] - Unreleased

Physical layer / L2 observability round, plus PoE control: read tools to
locate a device on the physical topology and read its live traffic/PoE
state, and one new guarded write tool to power-cycle a PoE port. Built on
top of the same write-guard mechanism as every previous round (read-only
default, central allowlist, confirm/preview, audit journal, ROS6/ROS7
compat) - none of it weakened or bypassed.

### Added

- **`arp_table`** (read, `src/mcp_mikrotik/server.py`): lists the IPv4 ARP
  table (`/ip/arp`) - address, mac-address, interface, dynamic, complete.
  Cross-references an IP to a MAC (or vice versa) for a statically-addressed
  device that never shows up in `dhcp_leases`.
- **`bridge_hosts`** (read): lists `/interface/bridge/host` entries -
  mac-address, on-interface, bridge, dynamic, local. Finds which physical
  bridge port a MAC is currently learned on.
- **`interface_traffic`** (read): current rx/tx rate of one interface, via
  `/interface/monitor-traffic interface=<X> once=yes`. `once=""` is sent as
  a structured flag parameter (RouterOS API convention for a boolean/flag -
  an empty value, not the string "yes") so the device replies exactly once
  and the call returns promptly, instead of opening the continuous/streaming
  form of monitor-traffic that RouterOS uses when `once` is omitted
  entirely. `interface` is validated for shape
  (`validation.validate_interface_name`, new) before ever being sent.
- **`poe_status`** (read): PoE configuration + live consumption for every
  PoE-capable ethernet port on the device. Reads `/interface/ethernet` and
  keeps only rows with a `poe-out` field, then reads
  `/interface/ethernet/poe/monitor once=yes` per port for
  voltage/current/power/`poe-out-status`. A port whose live monitor call
  fails is still listed (with its configured `poe-out`, just without the
  live fields) rather than failing the whole call. Returns an empty list
  (never an error) for a device with no PoE hardware at all.
- **`set_poe_out`** (WRITE, guarded - new `ALLOWLIST` entry
  `src/mcp_mikrotik/guard.py`): sets a PoE-capable ethernet port's
  `poe-out` mode (`/interface/ethernet set [interface] poe-out=<mode>`,
  action `update`). `poe_out` must be one of `auto-on`/`forced-on`/`off`
  (new `validation.validate_poe_out`). Killer use case: remotely
  power-cycling a locked-up antenna/camera/AP powered over PoE - `off` then
  `auto-on` again - instead of a truck roll. Same guard mechanics as every
  other write tool: blocked by the read-only gate unless
  `MIKROTIK_ALLOW_WRITE=true`, `confirm=false` previews a before/after
  without touching the device, only `confirm=true` applies it, and it never
  creates or coerces anything - raises `ResourceNotFoundError` if
  `interface_name` doesn't exist on the device at all, or exists but has no
  `poe-out` field (not PoE-capable hardware, e.g. an SFP+ cage). Goes
  through the v0.5 audit-journal `_audited` decorator automatically, like
  every other guarded write - the device password never appears in the
  journal.
- `MikrotikClient.monitor_traffic`/`.poe_monitor` (`src/mcp_mikrotik/client.py`):
  new read primitives for the two "monitor once" RouterOS commands above,
  built the same way as `ping`/`traceroute` - the callable connection form
  (`connection(cmd, **kwargs)`), automatic read-retry on a transient network
  error (`_run_read`), and transport failures wrapped as
  `DeviceCommandError`. No new timeout logic was needed: `once=""` is
  RouterOS's own "reply once and stop" contract (mirrored from its CLI
  `once=yes` flag), and the connection's existing socket timeout
  (`MikrotikClient`'s `timeout`/`MIKROTIK_TIMEOUT`) already bounds every
  command sent over it, exactly as it already did for `ping`/`traceroute`.
- `validation.validate_interface_name`/`validate_poe_out`
  (`src/mcp_mikrotik/validation.py`): shape validation for a RouterOS
  interface name and the `poe-out` enum, used by `interface_traffic` and
  `set_poe_out`.

### Tests

61 new tests (352 → 415, full suite green): `validate_interface_name`/
`validate_poe_out` (valid/invalid/non-string cases);
`MikrotikClient.monitor_traffic`/`.poe_monitor` (structured params not a
command string, empty-reply handling, transport-error wrapping, read
retry); `guard.set_poe_out` (blocked read-only, gate-before-touch,
preview/confirm, `.id`-targeted dispatch, unknown interface, non-PoE
interface, invalid `poe_out`/`interface_name` before touching the device,
audit journal outcomes including the no-password-leak sweep); and
`arp_table`/`bridge_hosts`/`interface_traffic`/`poe_status`/`set_poe_out`
exercised end to end through `server.py`'s `call_tool` (happy paths, the
read-only-by-default and read-tools-never-gated cases, empty-PoE-device
case, one-bad-port resilience for `poe_status`, and the invalid-input and
unknown-resource error paths for `set_poe_out`).

## [0.5.0] - Unreleased

Production-hardening round: layers added *around* the existing write-guard
mechanism (read-only default, central allowlist, confirm/preview, ROS6/ROS7
compat) - none of it weakens or bypasses that mechanism. See README's new
"Production features: audit log, correlation IDs, retries, circuit breaker"
section for the full writeup.

### Added

- **Audit journal** (`src/mcp_mikrotik/audit.py`, new module): every guarded
  write call in `guard.py` now emits exactly one structured JSON-lines
  event via a new `_audited` decorator applied to all nine write functions -
  `timestamp`, `correlation_id`, `device_name`, `tool`, `operation`
  (the `ALLOWLIST` key), `action`, `confirm`, `outcome`
  (`preview`/`applied`/`error`), and a `summary` of the before/after change
  (or the error). Emitted for a preview (`confirm=false`), an apply
  (`confirm=true`), and any error - including a write blocked by the
  read-only gate before the device is ever touched. Recursively strips any
  dict key that looks sensitive (`password`/`secret`/`token`/`credential`,
  case-insensitive) from the summary before it is ever serialized - the
  device password never appears in the journal. Destination is
  `MIKROTIK_AUDIT_LOG` (append-only file) if set, otherwise a plain
  `INFO`-level line via `logging` (stderr). Always best-effort: a failure
  writing the journal is logged as a warning and never blocks or fails the
  write operation it describes.
- **Correlation IDs** (`src/mcp_mikrotik/correlation.py`, new module): every
  MCP tool call (read or write) is bound a short, unique id
  (`uuid4().hex[:12]`) for its duration, via a `contextvars.ContextVar` set
  once per call in `server.py`'s `_safe` wrapper. Appears in every audit
  journal entry a write produces, and is prefixed onto the server-side log
  line if a tool call fails (`[<id>] tool <name> failed: ...` /
  `[<id>] Unhandled error in tool <name>`) - never appended to the
  exception's own message, so no caller-facing error text changes shape.
- **Read retry** (`src/mcp_mikrotik/client.py`): `MikrotikClient.path`/
  `ping`/`traceroute` now retry automatically on a transient network error -
  a fresh connect attempt failing, or an in-flight command failing because
  of an underlying `OSError` - with a short backoff (0.5s, then 1s; further
  retries reuse 1s). Up to `MIKROTIK_READ_RETRIES` extra attempts (default
  2). A `LibRouterosError` (RouterOS itself rejected the command) is never
  retried. `update`/`add`/`remove` (the write primitives) are deliberately
  untouched - no retry, ever, since a retried write isn't guaranteed
  idempotent.
- **Circuit breaker** (`src/mcp_mikrotik/client.py`, `CircuitBreaker` class):
  each pooled `MikrotikClient` now owns a thread-safe, in-memory breaker for
  its device's connection attempts. After `MIKROTIK_BREAKER_THRESHOLD`
  consecutive connection failures (default 3), the circuit opens for
  `MIKROTIK_BREAKER_COOLDOWN` seconds (default 30): further calls to that
  device - read or write - raise `CircuitOpenError` immediately (`circuit
  open for '<device>', retry after <t>s`), without attempting a connection.
  A successful connection resets the failure count and closes the circuit.
  Scoped strictly to the connection step - `guard.py`'s read-only
  gate/allowlist check always runs first, entirely before `MikrotikClient`
  is touched, so the breaker can never be used to skip it.
- `CircuitOpenError` (`src/mcp_mikrotik/exceptions.py`): a
  `DeviceConnectionError` subclass raised by the circuit breaker, so
  existing `except DeviceConnectionError` handling keeps working unchanged.
- Env vars: `MIKROTIK_AUDIT_LOG` (unset = log to stderr), `MIKROTIK_READ_RETRIES`
  (default `2`), `MIKROTIK_BREAKER_THRESHOLD` (default `3`),
  `MIKROTIK_BREAKER_COOLDOWN` (default `30`) - see `.env.example` and
  README's configuration table.

### Notes

- Purely additive: the write-guard mechanism itself (read-only default,
  central allowlist, confirm/preview, "never creates the target"/"never
  silently duplicates") is unchanged - see "Security model" in README.
  `guard.py`'s `_audited` decorator wraps every existing write function
  without altering its own logic.

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
