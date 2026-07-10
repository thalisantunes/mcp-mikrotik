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

v0.2: read tools covering the core device inventory plus DHCP leases, DNS
cache, firewall filter rules, wireless client registrations and system
health, and a small set of guarded write tools (`set_identity`,
`enable_interface`/`disable_interface`, `set_wifi_ssid`) that all go through
the same write-guard mechanism. See `CHANGELOG.md` for what changed since
v0.1.0, and `src/mcp_mikrotik/guard.py` for how to add the next write tool.

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
| `wireless_registrations` | List wireless clients currently associated to the device. Tries the ROS7 wifi registration table first, falls back to the ROS6 wireless one; returns an empty list (not an error) for a device with no radio. |
| `dns_cache` | List cached DNS records (name, type, data, ttl). |
| `firewall_filter` | List IPv4 firewall filter rules (chain, action, etc). Read-only - does not add/modify/remove rules. |
| `system_health` | System health metrics (voltage, temperature, ...), if the device exposes any; empty list otherwise. |
| `logs` | Recent log entries; `limit` (positive, capped at 500) and optional `topics` substring filter, applied before the `limit` cut. |
| `ping` | Ping an address from the device; `address` is validated as IPv4/IPv6/hostname before use. |
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

Not yet exposed, deliberately: device reboot and firewall rule writes. See
"Roadmap / non-goals" below for why.

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
   `set_wifi_ssid` is the one exception to "one tool, one allowlist entry":
   because RouterOS exposes wifi under different paths depending on
   generation (ROS7 `/interface/wifi` vs ROS6 `/interface/wireless`), it is
   backed by *two* fixed, reviewed allowlist entries
   (`set_wifi_ssid_ros7`/`set_wifi_ssid_ros6`), and the guard function picks
   between them by checking which path actually has a matching interface
   name on the device - never by accepting a path from the caller.
3. **Explicit confirm with before/after preview.** Every write tool takes a
   `confirm: bool` parameter. With `confirm=False` (the default), the tool
   computes and returns what would change - a `before`/`after` structure -
   without applying anything. Only `confirm=True` applies the change.

On top of the write guard:

- **Never creates the target.** Write tools that operate on a named resource
  (`enable_interface`/`disable_interface`/`set_wifi_ssid`) look it up by name
  first. If no interface/wireless network with that name exists on the
  device, the tool raises a clear error instead of creating one - a typo in
  `interface_name` can never silently provision something new.
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
