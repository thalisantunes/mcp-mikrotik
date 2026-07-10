# mcp-mikrotik

A [Model Context Protocol](https://modelcontextprotocol.io) server for managing
[MikroTik RouterOS](https://mikrotik.com/software) devices - read device state
(interfaces, routes, neighbors, logs, ping) and, for a small, explicit set of
write operations, change it, from an MCP client such as Claude Code.

This is a from-scratch implementation, not a fork. It exists to correct a set
of concrete failures found in an earlier project during a security audit:
an unrestricted generic "run any API command" tool, an HTTP transport bound
to `0.0.0.0` with no auth, command injection via string-built SSH calls, and
no tests. See "Security model" below for how each of those is avoided here.

## Status

v0.4: read tools covering the core device inventory plus DHCP leases, DNS
cache, firewall filter/NAT rules, address-lists, scheduler, IP pools,
wireless client registrations, system health and Simple Queue entries; a
`traceroute` diagnostic tool; and a set of guarded write tools
(`set_identity`, `enable_interface`/`disable_interface`, `set_wifi_ssid`,
`set_client_bandwidth`, `add_static_dhcp_lease`, `remove_simple_queue`, plus
v0.4's `add_to_address_list`/`remove_from_address_list` for limiting or
blocking who uses the network) that all go through the same write-guard
mechanism. See `CHANGELOG.md` for what changed since v0.1.0, and
`src/mcp_mikrotik/guard.py` for how to add the next write tool.

## Installation

Requires Python >= 3.11.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Configuration

Configuration comes from environment variables plus an optional
`devices.yaml` file.

1. Copy the examples:
   ```bash
   cp devices.yaml.example devices.yaml
   cp .env.example .env
   ```
2. Edit `devices.yaml` with your real devices and credentials. This file is
   git-ignored - it is never meant to be committed.
3. Edit `.env` (or export the variables another way) to control server-wide
   behaviour:

   | Variable                | Default        | Meaning                                             |
   |--------------------------|----------------|------------------------------------------------------|
   | `MIKROTIK_DEVICES_FILE`  | `devices.yaml` | Path to the devices YAML file                        |
   | `MIKROTIK_ALLOW_WRITE`   | `false`        | Enable write tools (see Security model)               |
   | `MIKROTIK_LOG_LEVEL`     | `INFO`         | Log level for the server process (stderr); invalid values fall back to `INFO` with a warning |
   | `MIKROTIK_TIMEOUT`       | `10`           | Fallback connect timeout (seconds) for devices without their own `timeout` |

Each device entry supports its own `port` and `use_ssl`, since a fleet is
commonly a mix of plain API (8728) and api-ssl (8729) devices, and possibly a
mix of RouterOS 6.x and 7.x. It can also override `timeout` (seconds; falls
back to `MIKROTIK_TIMEOUT`, then 10s - useful for devices behind a slow
link) and, when `use_ssl: true`, `tls_verify` (see "TLS verification for
api-ssl" below).

## Running

The server speaks MCP over **stdio** - it is meant to be launched by an MCP
client (e.g. configured as a command in Claude Code), not run as a network
service:

```bash
mcp-mikrotik
# or, without installing the console script:
python -m mcp_mikrotik.server
```

There is no HTTP transport in v0. If one is added later, it must default to
binding `127.0.0.1` (never `0.0.0.0`) and require a bearer token from an
environment variable - see the `TODO(http-transport)` note at the top of
`src/mcp_mikrotik/server.py`.

## Tools

### Read-only

| Tool | Description |
|---|---|
| `list_devices` | List configured devices (passwords never included). |
| `system_info` | RouterOS identity + resource info (board, version, uptime, CPU/memory). |
| `interfaces` | List interfaces; `include_disabled` to include disabled ones (default: excluded). |
| `ip_addresses` | List IPv4 addresses. |
| `ip_routes` | List the IPv4 routing table; optional `limit` (capped at 500). |
| `neighbors` | List neighbors discovered via CDP/MNDP/LLDP. |
| `dhcp_leases` | List DHCP server leases (address, mac, host-name, status, server, comment). |
| `simple_queues` | List Simple Queue entries (name, target, max-limit, limit-at, bytes counters, disabled) - see who already has a bandwidth limit and how much traffic they've moved. |
| `address_lists` | List firewall address-list entries (list, address, timeout, dynamic, disabled) - see who's currently in which named list. |
| `firewall_nat` | List IPv4 firewall NAT rules (chain, action, to-addresses, etc). Read-only - does not add/modify/remove rules. |
| `scheduler` | List scheduled tasks (name, on-event, interval, next-run, disabled). |
| `ip_pools` | List IP pools (name, ranges). |
| `wireless_registrations` | List wireless clients currently associated to the device. Tries the ROS7 wifi registration table first, falls back to the ROS6 wireless one; returns an empty list (not an error) for a device with no radio. |
| `dns_cache` | List cached DNS records (name, type, data, ttl). |
| `firewall_filter` | List IPv4 firewall filter rules (chain, action, etc). Read-only - does not add/modify/remove rules. |
| `system_health` | System health metrics (voltage, temperature, ...), if the device exposes any; empty list otherwise. |
| `logs` | Recent log entries; `limit` (positive, capped at 500) and optional `topics` substring filter, applied before the `limit` cut. |
| `ping` | Ping an address from the device; `address` is validated as IPv4/IPv6/hostname before use. |
| `traceroute` | Traceroute to an address from the device; returns the list of hops. `address` validated like `ping`'s; `count`/`max_hops` are capped low (and a fixed short per-hop timeout used internally) so the command can't run long enough to hit RouterOS's own API command timeout. Diagnostic only - not gated by `MIKROTIK_ALLOW_WRITE`. |
| `list_write_operations` | List every guarded write operation and the RouterOS path/action it maps to (metadata only, no gate). |

### Write (guarded)

Every write tool below requires `MIKROTIK_ALLOW_WRITE=true` and is called
twice: once with `confirm=false` (the default) to get a before/after
preview, and again with `confirm=true` to actually apply it. See "Security
model" below for the full guard mechanism.

| Tool | Description |
|---|---|
| `set_identity` | Set a device's RouterOS identity (hostname). |
| `enable_interface` | Enable a network interface by name (`disabled=no`). Errors if the interface name doesn't exist; never creates one. |
| `disable_interface` | Disable a network interface by name (`disabled=yes`). Errors if the interface name doesn't exist; never creates one. |
| `set_wifi_ssid` | Set a wireless interface's SSID. Detects whether the interface lives under the ROS7 wifi package or the ROS6 wireless package and writes to whichever one matches; errors if the interface name isn't found under either. |
| `set_client_bandwidth` | Limit a client's bandwidth via a Simple Queue targeting an IP/subnet (`target`). Updates the existing queue's `max-limit`/`limit-at` if one already targets it, otherwise creates one with a name derived from `target`. **FastTrack gotcha**: if the device has a FastTrack firewall rule, fasttracked traffic bypasses queues entirely - this may have no visible effect until FastTrack is adjusted. See "Limiting a client's bandwidth" below. |
| `add_static_dhcp_lease` | Create a static DHCP lease pinning an IP `address` to a `mac_address` (useful to give a client a stable target before limiting it). Refuses to create a second lease for a MAC that already has one. |
| `remove_simple_queue` | Remove a Simple Queue by `target` or `name` - undoes a bandwidth limit. |
| `add_to_address_list` | Add an IP/subnet `address` to a named firewall `list_name`. **Only manages the list** - see "Blocking/allowing a client via address lists" below for why this alone doesn't block/allow anything. Refuses to create a duplicate `list_name`+`address` pair. |
| `remove_from_address_list` | Remove the `list_name`+`address` entry from a firewall address-list. Same "list only" caveat as `add_to_address_list`. |

Not yet exposed, deliberately: device reboot and firewall rule writes. See
"Roadmap / non-goals" below for why.

### Limiting a client's bandwidth (v0.3)

The typical flow to find and limit a client that's consuming too much of the
link:

1. `simple_queues` and `dhcp_leases` / `wireless_registrations` to see who's
   on the network and whether they already have a limit.
2. Optionally, `add_static_dhcp_lease` to pin a chatty client's IP so its
   `target` doesn't drift to a different address on DHCP renewal.
3. `set_client_bandwidth` with `confirm=false` first to preview the
   `max-limit`/`limit-at` it would set (and whether it would create a new
   queue or update an existing one), then `confirm=true` to apply it.
4. `remove_simple_queue` (by `target` or `name`) to lift the limit later.

**FastTrack gotcha**: RouterOS's own quick-set wizards commonly add a
FastTrack rule to `/ip/firewall/filter` for performance. Fasttracked
connections bypass the whole queueing subsystem, including Simple Queue -
so a queue created by `set_client_bandwidth` can silently have zero effect
on a client whose traffic is already being fasttracked. If a limit doesn't
seem to be taking effect, check `firewall_filter` for a FastTrack rule and
adjust/disable it for the traffic you're trying to limit. `mcp-mikrotik`
does not modify firewall rules itself (see "Roadmap / non-goals" below).

### Blocking/allowing a client via address lists (v0.4)

`add_to_address_list`/`remove_from_address_list` manage entries in a named
`/ip/firewall/address-list` - nothing more. **Adding an address to a list has
no effect on traffic by itself.** It only blocks or allows anything if a
`/ip/firewall/filter` (or NAT) rule on the device already references that
same list name, e.g.:

```
/ip firewall filter add chain=forward src-address-list=blocked-clients action=drop
```

`mcp-mikrotik` does not create, modify, or inspect that rule for you (see
"Roadmap / non-goals" below for why firewall filter writes aren't exposed at
all yet) - use `firewall_filter` to check whether a rule referencing your
list already exists on the device before relying on `add_to_address_list` to
actually block or allow anyone. The typical flow:

1. Confirm (once, out of band - e.g. via WinBox/CLI, or just by reading
   `firewall_filter`) that a filter rule referencing your list name exists,
   e.g. `src-address-list=blocked-clients action=drop` on the `forward`
   chain.
2. `dhcp_leases` / `wireless_registrations` / `neighbors` to identify the
   client's IP.
3. `add_to_address_list` with `confirm=false` first to preview the entry it
   would add, then `confirm=true` to apply it. An optional `timeout` (e.g.
   `"1d"`) auto-expires the entry instead of blocking/allowing permanently.
4. `address_lists` to check current membership; `remove_from_address_list`
   to lift a block/allow later.

## Security model

Three independent controls apply to every write tool, all centralized in
`src/mcp_mikrotik/guard.py`:

1. **Read-only by default.** `MIKROTIK_ALLOW_WRITE` defaults to `false`. With
   writes disabled, any write tool returns a clear error and never touches
   the device - the gate is checked before any read or write call is made.
2. **Central allowlist, no generic command tool.** There is no tool that
   accepts an arbitrary API path or command. Each write operation is a
   dedicated, named function (e.g. `set_identity`, `enable_interface`)
   mapped to exactly one API path and action in `guard.ALLOWLIST`. There is
   no code path by which a caller can reach an API path outside that table.
   `set_wifi_ssid` and `set_client_bandwidth` are the two exceptions to "one
   tool, one allowlist entry": because RouterOS exposes wifi under different
   paths depending on generation (ROS7 `/interface/wifi` vs ROS6
   `/interface/wireless`), `set_wifi_ssid` is backed by *two* fixed, reviewed
   allowlist entries (`set_wifi_ssid_ros7`/`set_wifi_ssid_ros6`), and the
   guard function picks between them by checking which path actually has a
   matching interface name on the device. Likewise, `set_client_bandwidth`
   either updates an existing Simple Queue or creates a new one, so it is
   backed by `set_client_bandwidth_update`/`set_client_bandwidth_add`, and
   the guard function picks between them by checking whether a queue already
   targets the given `target`. In both cases the choice is made entirely by
   the guard function reading the device - never by accepting a path or an
   add-vs-update decision from the caller.
3. **Explicit confirm with before/after preview.** Every write tool takes a
   `confirm: bool` parameter. With `confirm=False` (the default), the tool
   computes and returns what would change - a `before`/`after` structure -
   without applying anything. Only `confirm=True` applies the change.

On top of the write guard:

- **Never creates the target.** Write tools that operate on a named resource
  (`enable_interface`/`disable_interface`/`set_wifi_ssid`/`remove_simple_queue`/
  `remove_from_address_list`) look it up by name first. If no interface/
  wireless network/queue/address-list entry with that name (or `target`, or
  `list_name`+`address` pair) exists on the device, the tool raises a clear
  error instead of creating one - a typo can never silently provision
  something new.
- **Never silently duplicates.** `add_static_dhcp_lease` checks for an
  existing lease on the given `mac_address` first, and `add_to_address_list`
  checks for an existing entry with the same `list_name`+`address` pair
  first, each raising `ResourceAlreadyExistsError` instead of creating a
  second one - both for `confirm=false` previews and `confirm=true` applies.
- **Structured API, not shell commands.** All device communication goes
  through [`librouteros`](https://github.com/luqasz/librouteros)'s
  structured API (`path().select()/.add()/.update()/.remove()`, and the
  callable form for one-off commands like ping). Nothing in this codebase
  builds a command by concatenating strings from user input, so command
  injection is ruled out by construction rather than by input filtering.
- **Input validation on top, for its own sake.** `ping`'s `address` is still
  validated against an IPv4/IPv6/hostname pattern before use, purely to
  reject garbage input early with a clear error - not as an injection
  defense (see previous point).
- **No secrets in output.** `Device.to_public_dict()` is the only device
  representation ever returned to a tool caller, and it omits the password
  field entirely. Passwords are never logged.
- **Structured errors.** All errors raised inside the package derive from
  `MikrotikMCPError` (see `src/mcp_mikrotik/exceptions.py`) and are caught at
  the tool boundary in `server.py`. The exception is deliberately re-raised,
  not turned into an `{"error": ...}` result dict: MCP itself turns an
  exception propagating out of a tool into a proper `isError` tool result
  carrying just that exception's (already-safe) message, and letting the
  framework do that keeps every tool's declared return type honest (a
  successful `logs` call always returns `list[dict]`, never sometimes a
  dict-shaped error instead). Unexpected exceptions are logged server-side
  and re-raised as a generic internal-error message, never as a raw
  traceback.

### TLS verification for api-ssl

RouterOS's `api-ssl` typically serves a self-signed certificate, so the
default `tls_verify: true` (which validates against the system trust store,
or an explicit `tls_ca_cert` if given) will fail out-of-the-box for most
fleets. Two ways to make an SSL device work:

- Set `tls_ca_cert: /path/to/ca.pem` on the device entry, if you provision
  RouterOS with a certificate you can pin, keeping full verification.
- Set `tls_verify: false` on that specific device to skip certificate/hostname
  validation entirely. This is a deliberate, explicit, per-device trade-off
  (it drops MITM protection on that connection) - it is never the default,
  and it is opt-in per device, not global. See `devices.yaml.example`.

## Development

```bash
pip install -e ".[dev]"
pytest
```

The test suite never talks to a real router: `tests/fakes.py` provides an
in-memory fake that implements the same minimal interface `MikrotikClient`
expects from a `librouteros` connection, and it is injected via a
`client_factory` parameter on `build_server()`.

CI (`.github/workflows/ci.yml`) runs the full suite on every push/PR against
Python 3.11 and 3.12.

## Roadmap / non-goals

- Two write operations are deliberately **not** exposed yet, each because
  the standard guard/confirm/preview mechanism isn't sufficient protection
  on its own - see the comment above `ALLOWLIST` in `guard.py`:
  - **Reboot** (`system/reboot`): there's no meaningful before/after preview
    for a reboot, and a bad batch reboot across a fleet has no dry-run or
    rollback. Needs its own confirmation/cooldown policy first.
  - **Firewall filter writes** (`ip/firewall/filter`): a single wrong rule
    (e.g. one that blocks the API port itself) can lock out all remote
    management access to the device, with no way to recover it over the
    same connection. Needs staged/rollback support (e.g. RouterOS safe
    mode) before it belongs in the allowlist.
- Further write tools should be added by extending `guard.ALLOWLIST` with
  one new named operation and function each - see the comment block at the
  top of `guard.py`. Do not add a generic write tool.
- A second entrypoint that periodically polls devices and pushes metrics to
  Firebase is planned to reuse `MikrotikClient`/`get_client` from
  `client.py`. Not implemented yet - see the `TODO(collector)` note at the
  bottom of `client.py`.

## License

MIT - see [LICENSE](LICENSE).
