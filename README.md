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

v0: read tools for the core device inventory, plus one exemplary write tool
(`set_identity`) that exercises the full write-guard mechanism end to end.
More write tools (wifi, interface enable/disable, etc.) are meant to be added
on top of the same guard - see `src/mcp_mikrotik/guard.py`.

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
   | `MIKROTIK_LOG_LEVEL`     | `INFO`         | Log level for the server process (stderr)             |

Each device entry supports its own `port` and `use_ssl`, since a fleet is
commonly a mix of plain API (8728) and api-ssl (8729) devices, and possibly a
mix of RouterOS 6.x and 7.x.

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
| `ip_routes` | List the IPv4 routing table. |
| `neighbors` | List neighbors discovered via CDP/MNDP/LLDP. |
| `logs` | Recent log entries; `limit` (capped at 500) and optional `topics` substring filter. |
| `ping` | Ping an address from the device; `address` is validated as IPv4/IPv6/hostname before use. |

### Write (guarded)

| Tool | Description |
|---|---|
| `set_identity` | Set a device's RouterOS identity (hostname). Requires `MIKROTIK_ALLOW_WRITE=true` and `confirm=true`; see below. |

## Security model

Three independent controls apply to every write tool, all centralized in
`src/mcp_mikrotik/guard.py`:

1. **Read-only by default.** `MIKROTIK_ALLOW_WRITE` defaults to `false`. With
   writes disabled, any write tool returns a clear error and never touches
   the device - the gate is checked before any read or write call is made.
2. **Central allowlist, no generic command tool.** There is no tool that
   accepts an arbitrary API path or command. Each write operation is a
   dedicated, named function (e.g. `set_identity`) mapped to exactly one API
   path and action in `guard.ALLOWLIST`. There is no code path by which a
   caller can reach an API path outside that table.
3. **Explicit confirm with before/after preview.** Every write tool takes a
   `confirm: bool` parameter. With `confirm=False` (the default), the tool
   computes and returns what would change - a `before`/`after` structure -
   without applying anything. Only `confirm=True` applies the change.

On top of the write guard:

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
  the tool boundary in `server.py`, which returns a clean `{"error": ...}`
  result. Unexpected exceptions are logged server-side and returned to the
  caller as a generic internal-error message, never as a raw traceback.

## Development

```bash
pip install -e ".[dev]"
pytest
```

The test suite never talks to a real router: `tests/fakes.py` provides an
in-memory fake that implements the same minimal interface `MikrotikClient`
expects from a `librouteros` connection, and it is injected via a
`client_factory` parameter on `build_server()`.

## Roadmap / non-goals for v0

- Additional write tools (wifi configuration, interface enable/disable,
  firewall rules, ...) should be added by extending `guard.ALLOWLIST` with
  one new named operation and function each - see the comment block at the
  top of `guard.py`. Do not add a generic write tool.
- A second entrypoint that periodically polls devices and pushes metrics to
  Firebase is planned to reuse `MikrotikClient`/`get_client` from
  `client.py`. Not implemented yet - see the `TODO(collector)` note at the
  bottom of `client.py`.

## License

MIT - see [LICENSE](LICENSE).
