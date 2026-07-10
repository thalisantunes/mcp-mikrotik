# mcp-mikrotik

A [Model Context Protocol](https://modelcontextprotocol.io) server for
[MikroTik RouterOS](https://mikrotik.com/software) devices. It lets an MCP
client (Claude Desktop, Claude Code, or any other MCP-compatible LLM tool)
read a router's live state - interfaces, routes, DHCP, wireless, VPN,
firewall, containers, logs, live traffic - and diagnose it (ping,
traceroute, torch), so an operator or an LLM can answer "what's going on
with this network" without opening WinBox. For a small, explicit,
individually-reviewed set of changes, it can also write - every write is
**read-only by default**, gated behind a central allowlist, and previewed
before it's applied.

**Philosophy:** start read-only, make writes something you opt into and can
review, never something an LLM reaches by accident. `MIKROTIK_ALLOW_WRITE`
defaults to `false` - point this at a fleet and it can only ever read until
you deliberately turn writes on. Even then there is no generic "run this
RouterOS command" tool: every write is a dedicated, named function mapped to
exactly one API path, and every one of them supports `confirm=false` to
preview a change before `confirm=true` applies it. See "Security model"
below for the full mechanism.

This is a from-scratch implementation, not a fork. It exists to correct a
set of concrete failures found in an earlier project during a security
audit: an unrestricted generic "run any API command" tool, an HTTP
transport bound to `0.0.0.0` with no auth, command injection via
string-built SSH calls, and no tests. See "Security model" below for how
each of those is avoided here.

## Status

**1.0.0.** Every planned tool round has shipped: the full read-tool
inventory (interfaces, routing, DHCP, wireless, VPN/WireGuard, containers,
LTE/5G, USB, hotspot, live traffic, backups, a heuristic security audit),
guarded writes across identity/interfaces/wifi/bandwidth/DHCP/
address-lists/PoE/containers/failover-routing/Netwatch/DNS/Wake-on-LAN/
firewall-rule-toggle/WireGuard/hotspot-vouchers/backup, and the
production-hardening layers this needs to run unattended against a real
fleet - audit journal, correlation IDs, read retry, circuit breaker. See
`CHANGELOG.md` for the full version-by-version history (what shipped in
each v0.x round), and "Roadmap & non-goals" below for what's deliberately
still out of scope, and why.

The full pytest suite currently has 988 tests, all passing against an
in-memory fake device layer (`pytest -q`) - see "Development" below.

## Installation

**Requirements:**

- Python 3.11+.
- A MikroTik device reachable over the **RouterOS API** (not WinBox, not
  SSH) - plain API port `8728`, or `api-ssl` port `8729`. RouterOS **6.49+**
  (the legacy `wireless` wifi stack) or **7.x** (the `wifi` package) are
  both supported; several read/write tools (`wireless_registrations`,
  `set_wifi_ssid`, `bgp_sessions`) detect which generation a device speaks
  and use the matching path automatically.

With `pip`:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

With [`uv`](https://docs.astral.sh/uv/):

```bash
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

Either way this installs the `mcp-mikrotik` console script (see "Running"
below) plus `.[dev]` (`pytest`/`pytest-asyncio`/`pytest-cov`) for running the
test suite locally.

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
   | `MIKROTIK_AUDIT_LOG`     | *(unset)*      | File path for the JSON-lines write-audit journal; unset logs each event via `logging` (stderr) instead. See "Production features" below. |
   | `MIKROTIK_READ_RETRIES`  | `2`            | Extra retry attempts for read operations on a transient network error |
   | `MIKROTIK_BREAKER_THRESHOLD` | `3`       | Consecutive connection failures before a device's circuit breaker opens |
   | `MIKROTIK_BREAKER_COOLDOWN`  | `30`      | Seconds a device's circuit stays open before a trial reconnect is allowed |

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

There is no HTTP transport at all - stdio only. If one is added in a future
release, it must default to binding `127.0.0.1` (never `0.0.0.0`) and
require a bearer token from an environment variable - see the
`TODO(http-transport)` note at the top of `src/mcp_mikrotik/server.py`.

## Connecting an MCP client

Since `mcp-mikrotik` speaks MCP over stdio, any MCP-compatible client can
launch it as a subprocess. For [Claude Desktop](https://claude.ai/download),
add it to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mikrotik": {
      "command": "mcp-mikrotik",
      "env": {
        "MIKROTIK_DEVICES_FILE": "/absolute/path/to/devices.yaml",
        "MIKROTIK_ALLOW_WRITE": "false"
      }
    }
  }
}
```

For [Claude Code](https://claude.com/claude-code), the equivalent is:

```bash
claude mcp add mikrotik --env MIKROTIK_DEVICES_FILE=/absolute/path/to/devices.yaml --env MIKROTIK_ALLOW_WRITE=false -- mcp-mikrotik
```

Use an **absolute** path for `MIKROTIK_DEVICES_FILE` - an MCP client
typically launches the server from its own working directory, not this
project's. Leave `MIKROTIK_ALLOW_WRITE=false` (the default) until you've
read "Security model" below and deliberately want write tools enabled.

### Example interactions

Once connected, an LLM caller uses the tools below directly by name. A few
representative exchanges:

- *"What's the status of my core-switch?"* → calls `system_info` and
  `interfaces`, summarizes board/RouterOS version/uptime and which
  interfaces are up or down.
- *"Is there a device on 192.168.88.50?"* → calls `dhcp_leases` (and, if
  nothing turns up there, `arp_table`) filtered to that address, to tell a
  DHCP-assigned host from a statically-addressed one.
- *"Limit the guest on 192.168.88.77 to 5 Mbps."* → calls
  `set_client_bandwidth(target="192.168.88.77", max_limit="5M/5M",
  confirm=false)` first, shows the before/after preview, and only calls it
  again with `confirm=true` once you confirm - this requires
  `MIKROTIK_ALLOW_WRITE=true` on the server.

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
| `wireguard_peers` | List WireGuard VPN peers (name, interface, public-key, endpoint, last-handshake, rx/tx, allowed-address, disabled). Never exposes a private-key or preshared-key, even defensively. Empty list (not an error) with no WireGuard interfaces. See "VPN & routing diagnostics" below. |
| `wireguard_interfaces` | List WireGuard tunnel interfaces (name, listen-port, public-key, running, disabled, mtu). **Never exposes a private-key** - RouterOS's own reply genuinely carries one here (unlike `wireguard_peers`), always stripped before returning. Empty list (not an error) with no WireGuard interfaces. See "WireGuard management" below. |
| `ppp_active` | List active PPP-based VPN server sessions (`/ppp/active`: name, service - l2tp/pptp/sstp/ovpn/pppoe, caller-id, address, uptime). Empty list (not an error) with no PPP server / no active sessions. |
| `ipsec_active_peers` | List active IPsec peers (remote-address, state, uptime, rx/tx, side). Empty list (not an error) for a device that doesn't use IPsec. |
| `bgp_sessions` | BGP session status (remote-address/as, state, uptime, prefix-count). Tries ROS7's `/routing/bgp/session` first, falls back to ROS6's `/routing/bgp/peer`; empty list (not an error) for a device that doesn't run BGP. |
| `ospf_neighbors` | OSPF neighbor adjacencies (address, state, router-id, adjacency). Empty list (not an error) for a device that doesn't run OSPF. |
| `netwatch` | List Netwatch host monitors (host, status up/down, interval, since, comment, disabled, plus `has-up-script`/`has-down-script` presence booleans - never the raw script body). The key read for diagnosing/building failover. See "VPN & routing diagnostics" below. |
| `dns_cache` | List cached DNS records (name, type, data, ttl). |
| `firewall_filter` | List IPv4 firewall filter rules (chain, action, etc). Read-only - does not add/modify/remove rules. |
| `connection_tracking` | List active connections from `/ip/firewall/connection`, **FILTERED** - at least one of `src_address`/`dst_address`/`dst_port`/`protocol` is required (a `ValidationError` otherwise); capped at 100 rows with a `truncated` flag. See "Connection tracking (filtered)" below. |
| `system_health` | System health metrics (voltage, temperature, ...), if the device exposes any; empty list otherwise. |
| `logs` | Recent log entries; `limit` (positive, capped at 500) and optional `topics` substring filter, applied before the `limit` cut. |
| `ping` | Ping an address from the device; `address` is validated as IPv4/IPv6/hostname before use. |
| `traceroute` | Traceroute to an address from the device; returns the list of hops. `address` validated like `ping`'s; `count`/`max_hops` are capped low (and a fixed short per-hop timeout used internally) so the command can't run long enough to hit RouterOS's own API command timeout. Diagnostic only - not gated by `MIKROTIK_ALLOW_WRITE`. |
| `arp_table` | List the IPv4 ARP table (address, mac-address, interface, dynamic, complete) - cross-reference IP↔MAC for a statically-addressed device that doesn't show up in `dhcp_leases`. |
| `bridge_hosts` | List `/interface/bridge/host` entries (mac-address, on-interface, bridge, dynamic, local) - find which physical bridge port a MAC is currently on. |
| `interface_traffic` | Current rx/tx rate of one `interface` (`/interface/monitor-traffic once=yes`); `interface` is validated for shape before use. A single instantaneous reading, not a stream - see "Physical layer & PoE control" below. |
| `poe_status` | PoE configuration + live consumption for every PoE-capable ethernet port on the device (voltage/current/power/`poe-out-status`); empty list (not an error) for a device with no PoE hardware. See "Physical layer & PoE control" below. |
| `lte_status` | Signal/status of one LTE/5G modem `interface` (`/interface/lte/monitor once=yes`) - operator, technology (3G/LTE/5G), signal (rsrp/rsrq/sinr/rssi), band, registration-status, cell-id. Empty dict (not an error) with no LTE hardware. See "LTE/5G monitoring" below. |
| `lte_interfaces` | List LTE/5G modem interfaces (name, running, disabled, apn-profiles). Empty list (not an error) with no LTE hardware. |
| `containers` | List containers (name/tag, status, ram-usage, root-dir, interface, os). Empty list (not an error) with no container package. See "Container management" below. |
| `container_config` | Container subsystem configuration (registry-url, tmpdir, ram-high). Empty dict (not an error) with no container package. |
| `usb_devices` | USB ports (`/system/routerboard/usb`) + attached storage (`/disk`) combined as `{"usb_ports": [...], "disks": [...]}`; either or both empty (not an error) with no USB hardware. See "USB" below. |
| `list_write_operations` | List every guarded write operation and the RouterOS path/action it maps to (metadata only, no gate). |
| `security_audit` | Read-only, heuristic security audit: aggregates several config reads into `{"findings": [...], "summary": {...}}`. See "Security audit" below. |
| `security_events` | Recent `/log` entries filtered to security-relevant ones (login/logout/auth-failure, critical/error topics); `limit` (positive, capped at 500, default 50) - same shape as `logs`' own `limit`. See "Security audit" below. |
| `hotspot_active` | List clients currently logged into the RouterOS hotspot (user, address, mac-address, uptime, bytes-in/bytes-out). Empty list (not an error) with no hotspot server / no one logged in. See "Hotspot vouchers" below. |
| `torch` | Live traffic snapshot of one `interface` (`/tool/torch once=yes`) - optional `src_address`/`dst_address`/`port` filters. Sorted by traffic volume (biggest talkers first) and capped at 50 flows, with `truncated`/`total_matched`. See "Live traffic monitoring (torch)" below. |
| `list_backups` | List backup files on the device (`/file`, filtered to `*.backup`): name, size, creation-time. See "Backup" below. |

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
| `set_wifi_ssid` | Set a wireless interface's SSID. Detects whether the interface lives under the ROS7 wifi package or the ROS6 wireless package and writes to whichever one matches; errors if the interface name isn't found under either. On ROS7, also detects whether the ssid is inline or lives on the interface's referenced `configuration` profile and writes to the right place - see "ROS7 wifi: `configuration`-based SSID" below. |
| `set_client_bandwidth` | Limit a client's bandwidth via a Simple Queue targeting an IP/subnet (`target`). Updates the existing queue's `max-limit`/`limit-at` if one already targets it, otherwise creates one with a name derived from `target`. **FastTrack gotcha**: if the device has a FastTrack firewall rule, fasttracked traffic bypasses queues entirely - this may have no visible effect until FastTrack is adjusted. See "Limiting a client's bandwidth" below. |
| `add_static_dhcp_lease` | Create a static DHCP lease pinning an IP `address` to a `mac_address` (useful to give a client a stable target before limiting it). Refuses to create a second lease for a MAC that already has one. |
| `remove_simple_queue` | Remove a Simple Queue by `target` or `name` - undoes a bandwidth limit. |
| `add_to_address_list` | Add an IP/subnet `address` to a named firewall `list_name`. **Only manages the list** - see "Blocking/allowing a client via address lists" below for why this alone doesn't block/allow anything. Refuses to create a duplicate `list_name`+`address` pair. |
| `remove_from_address_list` | Remove the `list_name`+`address` entry from a firewall address-list. Same "list only" caveat as `add_to_address_list`. |
| `set_poe_out` | Set a PoE-capable ethernet port's `poe-out` mode (`auto-on`/`forced-on`/`off`). Errors if `interface_name` doesn't exist, or exists but isn't PoE-capable; never creates/coerces anything. See "Physical layer & PoE control" below. |
| `start_container` | Start a container by `name` or `tag` (`/container/start`). Errors if `container` doesn't match any container; never creates one. See "Container management" below. |
| `stop_container` | Stop a container by `name` or `tag` (`/container/stop`). Errors if `container` doesn't match any container; never creates one. See "Container management" below. |
| `set_route_distance` | Adjust an existing route's `distance` (failover priority - lower wins). Resolved by the stable `dst_address`+`gateway` pair - never a dynamic `.id`/index. Errors if no route matches, or if more than one still does after that pair (`AmbiguousResourceError`). See "Failover control" below. |
| `enable_route` | Enable a route (`disabled=no`). Resolved by `dst_address`, narrowed by optional `gateway`/`comment` when more than one route shares it. |
| `disable_route` | Disable a route (`disabled=yes`). Same resolution as `enable_route`. **The returned preview's `warning` field is non-null whenever the route is the default route (`0.0.0.0/0`/`::/0`)** - disabling it cuts outbound traffic through that gateway. See "Failover control" below. |
| `add_netwatch` | Create a Netwatch host monitor (`host`, optional `interval`/`comment`). **Never accepts an up-script/down-script** - see "Failover control" below. Refuses a duplicate `host`. |
| `remove_netwatch` | Remove a Netwatch host monitor by `host` (tried first) or `comment`. Raises `AmbiguousResourceError` instead of guessing if more than one monitor still matches. |
| `add_static_dns` | Create a static DNS entry (`/ip/dns/static`) resolving `name` to `address`. `record_type` is `"A"` (default, `address` a literal IP) or `"CNAME"` (`address` is itself the alias target hostname). Refuses a duplicate `name`+`record_type` pair. See "DNS management" below. |
| `remove_static_dns` | Remove a static DNS entry by `name`, optionally narrowed by `record_type`. Errors if more than one row still matches after narrowing (`AmbiguousResourceError`) - never guesses which one to remove. |
| `clear_dns_cache` | Flush the device's DNS resolver cache (`/ip/dns/cache/flush`, no arguments). Benign (only cached answers are cleared), but still guarded/confirm-gated. |
| `remove_dhcp_lease` | Remove a DHCP lease (dynamic OR static) by `address` or `mac_address` - typically to force a client to renew its IP. **The returned preview's `warning` field is non-null if the resolved lease is STATIC** - removing it deletes the pinned IP↔MAC mapping, not just a renewable entry. See "DHCP lease removal" below. |
| `wake_on_lan` | Send a Wake-on-LAN magic packet (`/tool/wol`) for `mac_address`, out `interface`. Benign and targets no existing device row, but still guarded/confirm-gated. See "Wake-on-LAN" below. |
| `enable_firewall_rule` | Enable an **EXISTING** firewall filter rule (`disabled=no`), resolved by its `comment` (optionally narrowed by `chain`). **Never creates a rule.** See "Firewall rule toggle (by comment)" below. |
| `disable_firewall_rule` | Disable an **EXISTING** firewall filter rule (`disabled=yes`). Same resolution/never-creates guarantee as `enable_firewall_rule`. |
| `add_wireguard_interface` | Create a WireGuard tunnel interface (`name`, optional `listen_port`). RouterOS generates the private key internally - **never accepted or returned by this tool**. Refuses a duplicate `name`. See "WireGuard management" below. |
| `add_wireguard_peer` | Add a WireGuard peer to an existing `interface` (remote `public_key`, `allowed_address`, optional `endpoint_address`/`endpoint_port`/`persistent_keepalive`/`comment`). **Never accepts a private-key or preshared-key.** Errors if `interface` doesn't exist; refuses a duplicate `public_key` on the same interface. |
| `remove_wireguard_peer` | Remove a WireGuard peer from an `interface`, resolved by `public_key` or `comment`. Errors if more than one peer still matches after narrowing (`AmbiguousResourceError`) - never guesses which one to remove. |
| `add_hotspot_user` | Create a hotspot voucher user (`name`, `password`, optional `profile`/`limit_uptime`/`limit_bytes_total`). Refuses a duplicate `name`. **Result always includes `username`/`password`/`qr_payload`** - the plaintext password IS in the result (that's the point) but never in the audit journal. See "Hotspot vouchers" below. |
| `create_backup` | Create a RouterOS system backup file (`name`, optional encryption `password`). Refuses to overwrite an existing `.backup` file of the same name. `password` never appears in the result or the audit journal. See "Backup" below. |

Not yet exposed, deliberately: device reboot, backup RESTORE (`/system/backup/load`
- same risk class as reboot), and creating/generally modifying a firewall
filter rule (only the narrow `disabled` TOGGLE of an existing,
admin-authored rule is exposed - see "Firewall rule toggle (by comment)"
below). See "Roadmap / non-goals" below for why.

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
does not create or generally modify firewall rules - the only firewall
filter write exposed is the narrow `disabled` toggle of an existing rule
(`enable_firewall_rule`/`disable_firewall_rule` - see "Firewall rule toggle
(by comment)" below).

### Blocking/allowing a client via address lists (v0.4)

`add_to_address_list`/`remove_from_address_list` manage entries in a named
`/ip/firewall/address-list` - nothing more. **Adding an address to a list has
no effect on traffic by itself.** It only blocks or allows anything if a
`/ip/firewall/filter` (or NAT) rule on the device already references that
same list name, e.g.:

```
/ip firewall filter add chain=forward src-address-list=blocked-clients action=drop
```

`mcp-mikrotik` does not create or generally modify that rule for you - the
only firewall filter write exposed is the narrow `disabled` TOGGLE of an
existing, admin-authored rule (`enable_firewall_rule`/`disable_firewall_rule`
- see "Firewall rule toggle (by comment)" below, and "Roadmap / non-goals"
further below for why rule creation itself still isn't) - use
`firewall_filter` to check whether a rule referencing your list already
exists on the device before relying on `add_to_address_list` to actually
block or allow anyone. The typical flow:

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

### Physical layer & PoE control (v0.6)

Three tools for the physical/L2 layer, aimed at fleets where devices are
powered over PoE from a managed switch (e.g. a MikroTik CRS318-16P-2S+
feeding antennas at different PoE levels - 48V "high" and 24V "low"):

- `arp_table`/`bridge_hosts` (`/ip/arp` and `/interface/bridge/host` - see
  the read-tools table above) to cross-reference an IP to a MAC, and a MAC
  to the physical bridge port it's on.
- `interface_traffic` for a live rx/tx reading on one interface.
- `poe_status` for per-port PoE configuration and live consumption
  (voltage/current/power/`poe-out-status`) across every PoE-capable port -
  empty, not an error, on hardware with no PoE at all.
- `set_poe_out` to change a port's PoE output mode.

**The killer use case: remote power-cycle a locked-up antenna/camera/AP.**
Rather than a truck roll to physically unplug/replug a device, if it's
powered over PoE from a MikroTik switch:

1. `bridge_hosts` (or `arp_table`) to confirm which physical port the stuck
   device is on, if not already known.
2. `poe_status` to see its current `poe-out`/`poe-out-status` and confirm
   it's actually drawing power (voltage/current > 0) before assuming a PoE
   cycle will help.
3. `set_poe_out` with `poe_out="off"`, `confirm=false` first to preview,
   then `confirm=true` to actually cut power to the port.
4. Wait a few seconds - `poe_status` again to confirm `poe-out-status` shows
   the port is no longer powered.
5. `set_poe_out` with `poe_out="auto-on"` (preview, then confirm) to restore
   power. `forced-on` is also available for ports/devices that need power
   regardless of RouterOS's own PoE detection/negotiation.

Like every other write tool, `set_poe_out` never creates or coerces
anything: it raises `ResourceNotFoundError` if `interface_name` doesn't
exist on the device at all, or if it exists but has no `poe-out` field (not
PoE-capable hardware, e.g. an SFP+ cage) - see "Security model" below.

### LTE/5G monitoring (v0.7)

For devices with a cellular WAN modem (LTE/5G):

- `lte_interfaces` to see which LTE interfaces exist on the device (name,
  running, disabled, apn-profiles).
- `lte_status` for one interface's live signal/status - operator
  (`current-operator`), technology (`access-technology`: 3G/LTE/5G), signal
  quality (`rsrp`/`rsrq`/`sinr`/`rssi`), `band`, `registration-status`, and
  `cell-id`. Built the same "monitor-once" way as `interface_traffic`/
  `poe_status` (`/interface/lte/monitor <interface> once=yes`) - a single
  instantaneous reading, not a stream.

Both return empty (an empty list/dict, never an error) on a device with no
LTE hardware or package at all - the same convention `poe_status`/
`system_health` already use for optional hardware.

### Container management (v0.7)

RouterOS 7's container package runs OCI containers directly on the device
(e.g. a lightweight metrics agent or a small web dashboard, without a
separate host). The typical flow:

1. `containers` to see what's deployed (name/tag, status, ram-usage,
   root-dir, interface, os) and `container_config` for the subsystem-wide
   settings (registry-url, tmpdir, ram-high).
2. `start_container`/`stop_container` with `confirm=false` first to preview,
   then `confirm=true` to actually apply it. `container` matches against a
   container's `name` if it has one, falling back to its `tag` (the image
   reference, e.g. `"grafana/grafana:latest"`) otherwise - RouterOS only
   populates `name` when the container was created with one explicitly.

Unlike `enable_interface`/`set_poe_out` (which flip a field synchronously),
starting/stopping a container fires a RouterOS *action* command
(`/container/start`/`/container/stop`) that transitions asynchronously -
the preview's `after.status` reflects the immediate transitional state
(`"starting"`/`"stopping"`), not a guaranteed final one. Call `containers`
again afterward to see the settled `"running"`/`"stopped"` status. See
`CHANGELOG.md`'s "How start/stop extends the guard" for how this new
action-command shape was added to the write guard without weakening it.
Like every other write tool, `start_container`/`stop_container` never
create a container: an unmatched `container` raises
`ResourceNotFoundError`. A device with no container package/hardware
support at all raises the same `ResourceNotFoundError` (never a raw
device-side error) - the same underlying condition `containers()` already
degrades gracefully from (returns `[]` rather than erroring).

### USB (v0.7)

`usb_devices` reads `/system/routerboard/usb` (physical USB ports, on
boards that expose them) and `/disk` (attached storage - USB flash drives,
and USB LTE/5G modems that surface as a disk rather than under
routerboard/usb) and returns both as `{"usb_ports": [...], "disks":
[...]}`, since which of the two a given USB device shows up under depends
on the hardware. Either or both lists come back empty (never an error) on a
board with no USB hardware at all.

### VPN & routing diagnostics (v0.8)

Six **read-only** tools for VPN, routing-protocol, and failover diagnostics
- none of them touch the write guard or require `MIKROTIK_ALLOW_WRITE`:

- **VPN sessions/peers**: `wireguard_peers` (WireGuard), `ppp_active`
  (PPP-based VPN servers - l2tp/pptp/sstp/ovpn/pppoe), `ipsec_active_peers`
  (IPsec). Each covers a different RouterOS VPN mechanism; a device that
  doesn't use a given one returns an empty list, not an error.
  `wireguard_peers` never returns a private key, even defensively - see
  "Security model" below.
- **Routing-protocol status**: `bgp_sessions` (tries ROS7's
  `/routing/bgp/session` first, falls back to ROS6's `/routing/bgp/peer` -
  the same generation split `wireless_registrations` already handles for
  wifi) and `ospf_neighbors`. Empty list (not an error) for a device that
  doesn't run the protocol.
- **`netwatch`**: `/tool/netwatch`, RouterOS's own mechanism for watching a
  gateway or peer's reachability (commonly used to drive an up/down script
  - e.g. flipping a failover route). This is the key diagnostic read for
  understanding whether/how a device's own failover behavior is configured.
  The `up-script`/`down-script` fields are surfaced only as
  `has-up-script`/`has-down-script` presence booleans, never the raw script
  body - a Netwatch script can contain arbitrary RouterOS commands (route
  changes, credential changes, ...) that don't belong in a read tool's
  output.

These six were the **read-only foundation** v0.8 shipped for failover
tooling; v0.9 (below) adds the corresponding **write** tools.

### Failover control (v0.9)

Five guarded write tools - `set_route_distance`, `enable_route`/
`disable_route`, `add_netwatch`/`remove_netwatch` - are the **atomic
building blocks** for adjusting a RouterOS failover setup. Deliberately
small, composable steps, **not** one black-box "do a failover" command: an
LLM caller (or a human operator) combines them, previewing each one before
applying it.

**Recommended flow:**

1. `netwatch` (read) and `ip_routes` (read) to see the current setup - which
   gateways are being watched, and which routes/distances currently
   determine which one wins.
2. `add_netwatch` (`confirm=false` first to preview, then `confirm=true`) to
   start watching a gateway/peer's reachability, if not already monitored.
   **This tool never accepts an up-script/down-script parameter** (see
   below) - it only creates the observable host/status/interval/comment
   row. RouterOS's own up/down-script mechanism (configured manually,
   out-of-band, on the device - WinBox/CLI) is what actually *reacts* to a
   Netwatch status change; this package deliberately does not create or
   modify a script for you, e.g. by generating one that calls
   `set_route_distance`/`disable_route` on transition - see "Netwatch
   scripts are never accepted" below for why.
3. To actually switch which route wins, either:
   - `set_route_distance` (preview, then confirm) to change a route's
     priority (lower `distance` wins) relative to another route with the
     same `dst-address` - the non-destructive way to fail over: both routes
     stay present and enabled, only their relative priority changes.
   - `disable_route`/`enable_route` (preview, then confirm) to take a route
     out of/back into consideration entirely.
4. `ip_routes` (read) again afterward to confirm the routing table now
   reflects what you intended.

**RISK - the default route.** `disable_route`'s returned preview carries a
non-null `warning` field whenever the route being disabled is the default
route (`dst-address` = `0.0.0.0/0` or `::/0`) - disabling it cuts **all**
outbound traffic that relies on that gateway, not just traffic to one
destination. This is set on both the `confirm=false` preview and the
`confirm=true` applied result, so a caller reading only `applied`/`after`
still cannot miss it. Always read the `warning` field before calling again
with `confirm=true` - and prefer `set_route_distance` over
`disable_route`/`enable_route` for the default route specifically when
possible: changing which of two already-enabled default routes has the
lower `distance` fails over without ever leaving the device with *zero*
enabled default routes at any point in between.

**Route resolution: stable identifiers, never an index.** All three route
tools resolve the target row by its `dst-address`, narrowed by `gateway`
and/or `comment` when more than one route shares that `dst-address` -
exactly the failover shape (e.g. two `0.0.0.0/0` routes to different
gateways). Never by a RouterOS `.id` (reassigned as routes are added/
removed elsewhere on the device) or a list index (even less stable). If
nothing matches, `ResourceNotFoundError`. If more than one route still
matches after narrowing, `AmbiguousResourceError` - the tool never guesses;
the caller must add (or correct) `gateway`/`comment`.

**Netwatch resolution: same rigor as routes.** `remove_netwatch` resolves
its target by `host` (tried first if both are given), falling back to
`comment`, exactly like the route tools above - never a RouterOS `.id`.
`add_netwatch` itself refuses to create a second monitor for a `host` that
already has one, but a device can still end up with more than one row
sharing a `host`/`comment` via manual (WinBox/CLI) configuration outside
this tool; if so, `remove_netwatch` raises `AmbiguousResourceError` instead
of removing the first match - never a silent guess.

**Netwatch scripts are never accepted.** `add_netwatch` has no
`up_script`/`down_script` parameter at all - not validated-and-rejected,
genuinely absent from the tool's signature - because a Netwatch script body
can run arbitrary RouterOS commands (route changes, credential changes,
...), exactly the class of caller-controlled-arbitrary-command vector this
package's write guard exists to rule out (see "Security model" below and
`guard.py`'s module docstring). Configure up/down scripts manually on the
device (WinBox/CLI) once the monitor exists. The read-only `netwatch` tool
already only ever surfaces `has-up-script`/`has-down-script` as presence
booleans, never a script body, for the same reason.

### DNS management (v0.10)

`add_static_dns`/`remove_static_dns` manage `/ip/dns/static` - typical uses:

- **Block a malicious/unwanted domain**: `add_static_dns` with `address`
  set to `0.0.0.0` (or another sinkhole address) - any client that resolves
  the blocked `name` through this device's DNS server gets that address
  instead of the real one.
- **Internal DNS override**: point an internal hostname at a specific
  internal IP, or (`record_type="CNAME"`) alias one hostname to another.

`record_type` selects what `address` means: `"A"` (default) is a literal
IPv4/IPv6 address; `"CNAME"` means `address` is itself another hostname (the
alias target), written to RouterOS's `cname` field - a CNAME row has no
`address` field of its own on the device.

**Resolution: `name`+`record_type`, never a dynamic index.** `add_static_dns`
refuses to create a second row for the same `name`+`record_type` pair
(`ResourceAlreadyExistsError`) - this also means RouterOS round-robin DNS
(two "A" records sharing a `name` but pointing at different addresses) is
not something this tool creates; add the second record manually on the
device if that's genuinely intended. `remove_static_dns` resolves by `name`,
narrowed by `record_type` if given; if more than one row still matches after
narrowing (e.g. an existing round-robin pair), `AmbiguousResourceError` -
the tool never guesses which one to remove.

`clear_dns_cache` (`/ip/dns/cache/flush`) is unrelated to `/ip/dns/static` -
it clears cached upstream DNS *answers*, not any configured entry. Benign
(cached answers repopulate on the next resolution) but still a guarded,
confirm-gated write, like every other tool here.

### DHCP lease removal (v0.10)

`remove_dhcp_lease` removes an existing `/ip/dhcp-server/lease` row by
`address` or `mac_address` (`mac_address` is tried first if both are given -
the more stable identifier, since an `address` can be reused by a different
lease over time). The typical use is forcing a client to renew its IP: the
existing lease is deleted, and the client is offered a new one on its next
DHCP exchange.

**This removes EITHER a dynamic or a static lease.** RouterOS's `dynamic`
field on the resolved row tells them apart. Removing a DYNAMIC lease is the
ordinary case above. Removing a STATIC lease (one pinned by
`add_static_dhcp_lease`) is also allowed - not blocked outright - but it
deletes the pinned IP↔MAC mapping itself, not just a renewable entry, so the
returned preview's `warning` field is non-null whenever the resolved lease
is static, on both the `confirm=false` preview and the `confirm=true`
applied result. Always check `warning` before calling again with
`confirm=true`.

### Wake-on-LAN (v0.10)

`wake_on_lan` sends a `/tool/wol` magic packet for `mac_address`, out
`interface`. Unlike every other write tool in this package, there is
nothing existing on the device to resolve or verify first - `mac_address`/
`interface` are validated for shape only (this does NOT check that
`interface` exists on the device; RouterOS itself rejects an unknown
interface name at send time). Benign - it never changes device
configuration - but still guarded/confirm-gated like every other write
tool, so an LLM caller can't wake a machine "by accident".

### Firewall rule toggle (by comment) (v0.11)

Creating or generally modifying a firewall filter rule stays out of scope
(see "Roadmap / non-goals" below): a single wrong rule - e.g. one that
blocks the API port itself - can lock out all remote management access to
the device, with no way to recover it over the same connection. That risk
can't be designed away from inside the tool itself, so instead of exposing
rule authorship, v0.11 exposes only the narrowest safe operation on top of
an **existing** rule: flipping its `disabled` field.

**The intended workflow** (the community-suggested design this round
follows): an admin creates a rule ahead of time, on the device itself,
reviews it once, and leaves it disabled -

```
/ip firewall filter add chain=forward src-address-list=attacker-x \
  action=drop comment="Bloqueio_Ataque_X" disabled=yes
```

- and an LLM caller later enables it via `enable_firewall_rule` when it
detects the condition the rule exists to guard against:

```
enable_firewall_rule(device_name="core-switch", comment="Bloqueio_Ataque_X", confirm=false)  # preview
enable_firewall_rule(device_name="core-switch", comment="Bloqueio_Ataque_X", confirm=true)   # apply
```

If something goes wrong, the admin knows exactly which rule was toggled -
the same one they already wrote and reviewed, never a rule this package
authored on its own judgment. `disable_firewall_rule` reverses it the same
way.

**Resolution: `comment`, never a dynamic index.** Both tools resolve the
target rule by its `comment` - a STABLE, admin-controlled identifier -
optionally narrowed by `chain` if two rules share the same comment on
different chains. A `comment` that matches no rule raises
`ResourceNotFoundError` (never falls back to creating one); a `comment`
that still matches more than one rule after narrowing raises
`AmbiguousResourceError` - the tool never guesses which one to toggle. The
returned preview's `before`/`after` are the **full** matched rule (every
field RouterOS returned for it - `chain`/`action`/etc, not just
`disabled`), so the caller can confirm WHICH rule this is before ever
passing `confirm=true`.

### Connection tracking (filtered) (v0.11)

`connection_tracking` reads RouterOS's connection tracking table
(`/ip/firewall/connection`) - useful to see what a client is actually
talking to right now, e.g. while investigating the traffic a
`set_client_bandwidth`/`add_to_address_list` decision was based on.

**A filter is mandatory** - on a production router, the full table can be
large enough to blow straight past an LLM caller's context/token budget on
its own (a community-reported gotcha this tool is built to avoid). Calling
it with none of `src_address`/`dst_address`/`dst_port`/`protocol` set raises
a `ValidationError` instead of returning everything.

The result is also hard-capped at 100 rows regardless of how many match:
`truncated` is `true` whenever more rows matched than were returned, and
`total_matched` always reports the real, pre-truncation count - so a caller
always knows whether it's seeing everything or should narrow the filter
further.

Each returned entry: `protocol`, `src-address`/`src-port` and
`dst-address`/`dst-port` (RouterOS packs address+port into one field, e.g.
`"192.0.2.1:80"` - this tool splits them apart), `tcp-state` (populated for
TCP connections), `timeout`, and the `assured`/`confirmed`/`seen-reply`
flags - RouterOS's own closest equivalent to a generic "connection state"
for this table.

### Security audit (v0.12)

Two **read-only** tools, both in `src/mcp_mikrotik/security.py`, built for
the "analyze this router's security" use case: an LLM caller reads config
and recent logs and reports what it sees, rather than an operator manually
walking every menu.

**`security_audit(device_name)`** runs seven independent, defensive checks
and returns `{"findings": [{"severity", "category", "title", "detail",
"recommendation"}, ...], "summary": {"high", "medium", "low", "info"}}` -
`findings` sorted by severity (high first), `summary` always including all
four keys (0 for a severity with no findings):

1. **Insecure management services** (`/ip/service`): `telnet`/`ftp`/`www`/
   `api` enabled (cleartext/non-SSL protocols) - `high` if `telnet`/`ftp`
   is also open to any address (`address` empty or `0.0.0.0/0`), `medium`
   if `www`/`api` is, `low` if enabled but restricted to a narrower range.
   `winbox` enabled and open to any address is its own `medium` finding.
   `ssh`/`api-ssl`/`www-ssl` are never flagged - they're the secure
   counterparts a caller is expected to prefer.
2. **Firewall input chain has no final drop/reject** (`/ip/firewall/filter`
   chain=input): a conservative heuristic based on rule order alone - if
   the LAST enabled rule on chain=input isn't `action=drop`/`reject` (or
   there are no enabled input rules at all), a `medium` finding recommends
   reviewing whether unmatched management traffic is actually blocked. This
   does **not** claim certainty - RouterOS's real evaluation semantics
   (jump chains, address-list matches, etc.) are richer than one rule's
   position can prove; see `security.py`'s `_check_firewall_input_drop`
   docstring.
3. **SNMP community open** (`/snmp/community`): a community named `public`
   (RouterOS's default) or with no `addresses` restriction (empty/
   `0.0.0.0/0`) - `medium`.
4. **DNS resolver open to remote requests** (`/ip/dns`
   `allow-remote-requests=yes`) - `medium`; can be abused for DNS
   amplification/reflection if not also restricted by the firewall.
5. **RouterOS outdated** (`/system/package/update`): installed version
   differs from the latest available - `low`. Skipped (no finding) if the
   device hasn't checked for updates yet.
6. **Open wireless/wifi** (no security at all): ROS6
   `/interface/wireless/security-profiles` with `mode=none`, or ROS7
   `/interface/wifi/security` with no passphrase AND no
   `authentication-types` configured (802.1X/EAP setups legitimately have
   no passphrase, so only BOTH absent counts) - `high`.
7. **Users with a write/full policy** (`/user`): an `info` finding counting
   how many configured accounts have a `write`/`full` group - visibility,
   not a vulnerability by itself.

Each check is **defensive**: it reads its own menu(s) and, if that menu
doesn't exist on this device/RouterOS generation (`DeviceCommandError`),
contributes no findings instead of failing - the same "empty/skipped, not
an error" convention `system_health`/`poe_status`/`wireless_registrations`
already use. One check being unavailable never stops the rest of the audit.

**NEVER a scanner, NEVER definitive.** Every check here is a best-effort
read of a handful of RouterOS menus - it can both under-report (a real
misconfiguration this module doesn't know to look for) and, for check #2
specifically, over-report on an unusual-but-intentional ruleset. Findings
exist to prompt a human/LLM review, not to be treated as ground truth.

**No finding ever contains a secret.** `/ip/service`, `/snmp/community`,
`/interface/wireless/security-profiles`, `/interface/wifi/security`, and
`/user` can all carry a password/passphrase/community-string-shaped field -
no check ever copies a raw row (or a credential field from one) into a
finding; each finding's text is built from a fixed template referencing
only non-secret fields (name, mode, address restriction, boolean presence
checks, counts). See `tests/test_security.py`'s
`test_run_security_audit_never_leaks_a_secret` (unit-level, every
secret-bearing menu populated with a distinctive marker value while
multiple checks are made to fire) and `test_server.py`'s
`test_security_audit_*` (the same guarantee exercised through the actual
MCP tool call).

**`security_events(device_name, limit=50)`** filters `/log` down to
security-relevant entries: topic `account` (RouterOS's own topic for
login/logout/authentication-failure events), `critical`/`error` topics, and
a generic `system,info` entry whose message looks like a login/logout.
Filtering happens client-side (the same reasoning `logs`' `topics` filter
already documents) and is applied BEFORE the `limit` cut, so a caller
always gets the most recent `limit` MATCHING entries - `limit` is capped at
500, same shape as `logs`' own `limit`. Useful to correlate access
attempts/anomalies without reading the entire (often much larger)
unfiltered log via `logs`.

Both tools are **read-only** - neither is gated by `MIKROTIK_ALLOW_WRITE`,
and neither changes anything on the device.

### WireGuard management (v0.13)

The most security-sensitive round in this package's history: WireGuard uses
**private keys**. The absolute rule this round is built around: **no tool,
error message, preview, or audit journal entry may ever contain one.**
Private keys stay on the router - period.

Four tools, all covering `/interface/wireguard` and
`/interface/wireguard/peers`:

- **`wireguard_interfaces`** (read) - lists tunnel interfaces (name,
  listen-port, public-key, running, disabled, mtu). RouterOS's own reply for
  this menu genuinely carries a `private-key` field - always stripped
  before returning. `wireguard_peers` (v0.8) is unchanged in shape but now
  also strips a peer's `preshared-key` (a real, optional field on that menu)
  the same way.
- **`add_wireguard_interface`** (write, guarded) - creates a tunnel
  interface (`name`, optional `listen_port`). RouterOS generates the
  private key internally when the interface is created - there is no
  `private_key` parameter on this tool at all, so there is no code path
  through which a caller could ever supply (or receive back) one. The
  `confirm=false` preview's `after` only describes what will be created
  (`name`/`listen-port`) - it never invents a `public-key`, since RouterOS
  hasn't generated the key pair yet at preview time. Only the `confirm=true`
  applied result re-reads the newly created interface and reports its real
  `public-key` (safe to share - it's what a remote peer needs to connect to
  you), with `private-key` always stripped. Refuses to create a second
  interface sharing `name`.
- **`add_wireguard_peer`** (write, guarded) - registers a remote peer on an
  existing `interface`: its `public_key` (validated as a 44-character
  base64 WireGuard key), `allowed_address` (a comma-separated list of CIDR
  ranges, e.g. `"10.0.0.2/32,10.0.0.3/32"`), and optional
  `endpoint_address`/`endpoint_port`/`persistent_keepalive`/`comment`. Has
  no `private_key` or `preshared_key` parameter either - the remote peer's
  own private key (and any preshared key) are entirely out of this tool's
  scope. `interface` must already exist (create it first with
  `add_wireguard_interface`); refuses to add a duplicate peer (same
  `public_key` already registered on the same `interface`).
- **`remove_wireguard_peer`** (write, guarded) - removes a peer from an
  `interface`, resolved by `public_key` or `comment`. Errors if more than
  one peer still matches after narrowing (`AmbiguousResourceError`) - never
  guesses which one to remove.

**Typical flow** to stand up a site-to-site or road-warrior tunnel:

1. `add_wireguard_interface` (`confirm=false` to preview, then
   `confirm=true`) to create the tunnel interface on this device.
   `wireguard_interfaces` to read back its real `public-key` - give that to
   the remote peer, out of band, so it can configure its own side.
2. `add_wireguard_peer` (`confirm=false` then `confirm=true`) to register
   the remote side's `public_key` and the traffic (`allowed_address`) routed
   through it.
3. `wireguard_peers` to check `last-handshake`/rx/tx counters once the
   remote side connects, confirming the tunnel is actually passing traffic.
4. `remove_wireguard_peer` to revoke a peer later (e.g. a decommissioned
   site or a compromised key).

**How the private-key/preshared-key redaction is enforced (belt-and-suspenders,
two independent layers):**

1. **`formatting.strip_sensitive_fields`** (with
   `formatting.WIREGUARD_SENSITIVE_FIELDS = {"private-key", "preshared-key"}`)
   is applied to every row these tools ever return - both read tools
   (`wireguard_interfaces`/`wireguard_peers`, in `server.py`) and every
   write tool's before/after preview (in `guard.py`'s
   `_redact_wireguard_row`, applied **before** a `WritePreview` is ever
   constructed - see next point for why that ordering matters).
2. **The audit journal never gets a chance to see one either.** The
   write-guard's `_audited` decorator (v0.5) journals exactly whatever a
   `guard.py` function returns - so if redaction happened only in
   `server.py` (one layer up, after `guard.py` returns), a private-key
   would already be sitting in the audit journal (a file on disk, or a log
   line) by the time `server.py` got a chance to strip it. Every WireGuard
   write function in `guard.py` therefore redacts its own `before`/`after`
   before constructing the `WritePreview` the decorator will log.
   `audit._SENSITIVE_KEY` (extended this round to also match `private`, on
   top of the existing `pre.?shared` term that already covers
   `preshared-key`) is a **second, independent** line of defense on top of
   that, not a substitute for it.

See `tests/test_guard.py`'s WireGuard section, `tests/test_guard_audit.py`'s
`test_add_wireguard_interface_confirmed_call_never_leaks_private_key_into_journal`,
and `tests/test_server.py`'s
`test_add_wireguard_interface_never_leaks_private_key_anywhere` for the tests
proving all of this: a fake device (`tests/fakes.py`) simulates RouterOS
generating a real key pair - including a distinctively-marked private-key -
on interface creation, and every test asserts that marker never reaches the
tool's return value, the audit journal (`before` **and** `after`), or any
other log line.

### Hotspot vouchers (v0.14)

`hotspot_active` (read) lists who's currently logged into the RouterOS
hotspot (`/ip/hotspot/active`) - `user`, `address`, `mac-address`, `uptime`,
`bytes-in`/`bytes-out`. `add_hotspot_user` (write, guarded) creates a new
voucher - a visitor login, not a device/API credential:

```
add_hotspot_user(name="visitor-42", password="Xk7mQ2p9", limit_uptime="02:00:00")
```

`profile` (an existing `/ip/hotspot/user/profile` name, e.g. to cap shared
bandwidth), `limit_uptime` (a RouterOS duration), and `limit_bytes_total` (a
positive integer byte quota) are all optional. Refuses to create a
duplicate `name` - it never resets an existing voucher's password.

**QR/voucher payload.** The tool result always also includes `username`,
`password`, and `qr_payload` - a plain string the caller renders as a QR
code itself (this package deliberately does **not** generate a QR *image* -
that would mean pulling in an imaging dependency for something a caller's
own UI layer can do in a couple of lines). The format chosen for
`qr_payload` is `"<username>:<password>"` - a plain, self-describing
credential pair. Two alternatives were considered and rejected:

- A login URL (`http://<hotspot>/login?username=..&password=..`) would need
  a reliably-known hotspot LAN address, which this package has no way to
  determine for an arbitrary device/deployment - and RouterOS's actual
  captive-portal login is normally a POST carrying additional
  session-specific tokens (`chap-id`/`chap-challenge`), so a bare GET URL
  with a plaintext password wouldn't even reliably authenticate.
- A `WIFI:T:WPA;S:<ssid>;P:<pass>;;` payload is for auto-joining a WPA
  wireless network - a different credential (and a different protocol
  layer) than a hotspot LOGIN (walled-garden HTTP auth), which can just as
  easily run over a wired port.

`username:password` makes no claim about network topology or login
mechanics that could turn out to be wrong for a given deployment. A caller
integrating with a specific captive portal is free to build its own login
URL (or its own QR format) from `username`/`password` plus its own
known portal address.

**The deliberate password asymmetry.** Unlike every secret this package has
handled before (a device password, a WireGuard private-key - never returned
to any caller at all), a voucher's plaintext `password` **is** present in
the tool's own result on both `confirm=false` (preview) and `confirm=true`
(applied) - the caller needs it to hand to a visitor. It must still never
reach the audit journal. No new redaction code was needed for that:
`audit._SENSITIVE_KEY` already matches `"password"` case-insensitively at
any depth of the journaled `{"before": ..., "after": ...}` summary (it's
what already protects a device's own connection password - see the "Audit
journal" bullet under "Production features" below), so the exact same
`after` dict returned to the caller gets its `password` key silently
dropped before `audit.record()` ever sees it. See
`tests/test_guard_audit.py`'s
`test_add_hotspot_user_password_never_in_audit_journal` and
`tests/test_server.py`'s
`test_add_hotspot_user_password_in_result_but_never_in_audit_journal` for
the proof, at both the guard layer and the full MCP tool-call boundary.

### Live traffic monitoring (torch) (v0.14)

`torch` answers "who is consuming bandwidth on this interface **right
now**" - a single live snapshot via RouterOS's own real-time traffic
monitor (`/tool/torch interface=<interface> once=yes`), built the same
"once" monitor-style way as `interface_traffic`/`poe_status`/`lte_status`.
`interface` is validated for shape before use; optional `src_address`/
`dst_address`/`port` filters are forwarded to RouterOS itself, narrowing
the snapshot **before** it ever leaves the device - use them on a busy
interface instead of fetching every flow and filtering client-side.

Regardless of how many flows RouterOS reports for the requested instant,
the result's `flows` list is sorted by total traffic (tx+rx, biggest
talkers first) and hard-capped at 50 entries - `truncated` is `true`
whenever more flows matched than were returned, and `total_matched` always
reports the real (pre-cap) count, the same "cap it, tell the caller how
much was cut" shape `connection_tracking` (v0.11) already established.
Diagnostic only - `torch` never changes device state, so (like `ping`/
`traceroute`) it is not gated by `MIKROTIK_ALLOW_WRITE`.

### Backup (v0.14)

`create_backup` (write, guarded) creates a RouterOS system backup file
(`/system/backup/save name=<name>`) - the device's full configuration
(interfaces, firewall, users, ...) as one binary `.backup` file on its own
storage. `list_backups` (read) lists existing ones - use it after
`create_backup` to confirm a new backup landed and see its real
size/creation-time.

`create_backup` refuses to overwrite an existing `.backup` file of the same
`name` (`ResourceAlreadyExistsError`) - RouterOS's own `/system/backup/save`
would otherwise silently overwrite one. An optional `password` encrypts the
backup **file** itself (unrelated to any device/API credential) - it is
redacted before the write's preview is ever constructed (the same
"redact before constructing the preview" rule v0.13's WireGuard round
established for private/preshared keys), so it never reaches the caller or
the audit journal, either.

**Backup restore is deliberately not exposed** - see "Roadmap / non-goals"
below: loading a backup overwrites a device's entire running configuration
and reboots it, the same risk class as a remote reboot, with no meaningful
before/after preview and no rollback if the wrong file (or the right file,
at the wrong time) is loaded.

## Security model

This section is the single consolidated reference for every control this
package applies - to every read, and especially to every write. The
philosophy is simple: **read-only by default, writes are opt-in, allowlisted,
previewed, and audited.** No tool in this package ever accepts an arbitrary
RouterOS API path or a free-form command.

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
   As of v0.7, `action` isn't limited to `update`/`add`/`remove`:
   `start_container`/`stop_container` use `start`/`stop` to represent
   RouterOS's `/container/start`/`/container/stop` ACTION commands - but the
   dispatch mechanism (`getattr(client, op.action)`) and the fixed,
   individually-reviewed `MikrotikClient` method it can ever reach are
   unchanged; see `CHANGELOG.md`'s "How start/stop extends the guard". v0.10
   adds a second such pair: `clear_dns_cache`/`wake_on_lan` use `flush`/`wol`
   for RouterOS's `/ip/dns/cache/flush`/`/tool/wol` ACTION commands - same
   `getattr(client, op.action)` dispatch, same fixed reviewed
   `MikrotikClient.flush`/`.wol` methods, the only difference from
   `start`/`stop` being that neither targets a specific row/`.id` (there is
   no "list" to pick one row from - both are standalone, one-shot commands,
   dispatched via the connection's callable form like `ping`, not the
   `path(*segments)(cmd, **{".id": id})` form `start`/`stop` use).
   `set_wifi_ssid` and `set_client_bandwidth` are the two exceptions to "one
   tool, one allowlist entry": because RouterOS exposes wifi under different
   paths depending on generation (ROS7 `/interface/wifi` vs ROS6
   `/interface/wireless`) - and, on ROS7, the ssid itself lives in one of two
   different places depending on whether the interface references a named
   `configuration` (see "ROS7 wifi: `configuration`-based SSID" below) -
   `set_wifi_ssid` is backed by *three* fixed, reviewed allowlist entries
   (`set_wifi_ssid_ros7`/`set_wifi_ssid_ros7_configuration`/
   `set_wifi_ssid_ros6`), and the guard function picks between them by
   reading the device: which path has a matching interface name, and then,
   for a ROS7 match, whether that interface's ssid is inline or lives on its
   referenced configuration profile. Likewise, `set_client_bandwidth`
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

### ROS7 wifi: `configuration`-based SSID

Confirmed against real ROS7 hardware (a mANTBox): in the standard production
layout, a `/interface/wifi` interface references a named `configuration`
(e.g. `configuration=cfg1`) and has **no writable `ssid` field of its own** -
writing one directly there is rejected by RouterOS ("unknown parameter
ssid"). The ssid instead lives on the referenced
`/interface/wifi/configuration` row.

`set_wifi_ssid` resolves this automatically: for a ROS7 match, it checks the
interface's own `configuration` field, looks up the matching
`/interface/wifi/configuration` row by name, and reads/writes the ssid
there (backed by the `set_wifi_ssid_ros7_configuration` allowlist entry).
The `before`/`after` preview always reflects the ssid's real location - it
is never synthesized on a field that doesn't actually exist on the device.
Only a wifi interface with no named `configuration` at all (rare/legacy)
keeps a genuinely inline `ssid` field, written directly on `/interface/wifi`
as before. If neither shape is recognized (a `configuration` name that
doesn't resolve, or an interface with neither an inline `ssid` nor a
`configuration` reference), the tool raises a clear error rather than
sending a write RouterOS would itself reject.

On top of the write guard:

- **Never creates the target.** Write tools that operate on a named resource
  (`enable_interface`/`disable_interface`/`set_wifi_ssid`/`remove_simple_queue`/
  `remove_from_address_list`/`set_poe_out`/`start_container`/`stop_container`/
  `set_route_distance`/`enable_route`/`disable_route`/`remove_netwatch`/
  `enable_firewall_rule`/`disable_firewall_rule`/`add_wireguard_peer`/
  `remove_wireguard_peer`)
  look it up first - by name, by the v0.9 route tools' stable `dst-address`
  (+`gateway`/`comment`) identifier described in "Failover control" above,
  by the v0.11 firewall rule tools' `comment` (+`chain`) described in
  "Firewall rule toggle (by comment)" above, or, for the v0.13 WireGuard peer
  tools, by `public-key`/`comment` scoped to a given `interface` (described
  in "WireGuard management" above). If nothing matches, the tool raises a
  clear error instead of creating one - a typo can never silently provision
  something new. `set_poe_out` additionally requires the matched interface
  to actually have a `poe-out` field (i.e. be PoE-capable hardware) - a name
  that exists but isn't a PoE port raises the same clear error rather than
  doing nothing silently. `add_wireguard_peer` additionally requires its
  `interface` to already exist as a WireGuard tunnel - it never creates one
  (use `add_wireguard_interface` first). The v0.9 route tools, the v0.11
  firewall rule tools, and the v0.13 `remove_wireguard_peer` additionally
  never resolve by a RouterOS `.id` or a list index (both can shift as rows
  are added/removed elsewhere on the device); if an identifier still matches
  more than one row after narrowing, `AmbiguousResourceError` is raised
  instead of guessing which one to touch.
- **Never silently duplicates.** `add_static_dhcp_lease` checks for an
  existing lease on the given `mac_address` first, `add_to_address_list`
  checks for an existing entry with the same `list_name`+`address` pair
  first, `add_netwatch` checks for an existing monitor on the given `host`
  first, `add_wireguard_interface` checks for an existing interface with
  the given `name` first, and `add_wireguard_peer` checks for an existing
  peer with the same `public_key` on the same `interface` first - each
  raising `ResourceAlreadyExistsError` instead of creating a second one -
  both for `confirm=false` previews and `confirm=true` applies.
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
  field entirely. Passwords are never logged. Since v0.8, `wireguard_peers`
  strips a `private-key` field from every row via
  `formatting.strip_sensitive_fields` before returning it - defensively,
  since RouterOS's own `/interface/wireguard/peers` reply doesn't carry one
  in the first place (see "VPN & routing diagnostics" above). Since v0.12,
  `security_audit` never copies a raw row (or a credential-shaped field
  from one) into a finding - every finding's text comes from a fixed
  template referencing only non-secret fields, even though several of the
  menus it reads (`/ip/service`, `/snmp/community`, wireless/wifi security
  profiles, `/user`) can carry a password/passphrase/community-string field
  - see "Security audit" above. Since v0.13, `wireguard_interfaces` and
  every WireGuard write tool (`add_wireguard_interface`/`add_wireguard_peer`/
  `remove_wireguard_peer`) apply the same redaction to a genuinely
  secret-bearing menu - a tunnel interface's `private-key` and a peer's
  `preshared-key` - **before** a write's before/after preview is ever
  constructed, so `guard.py`'s own audit journal (which logs exactly what a
  write function returns) can never carry one either; see "WireGuard
  management" above for the full two-layer redaction (`guard.py` first,
  `audit._SENSITIVE_KEY` as a second, independent line of defense).
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

### Production hardening: audit log, correlation IDs, retries, circuit breaker

The remaining layers *around* the write-guard mechanism above, aimed at
running `mcp-mikrotik` unattended against a real fleet. None of them can
weaken or bypass the read-only gate, the central allowlist, or the
confirm/preview flow - every write still goes through `guard.py` exactly as
described in "Security model", and the circuit breaker in particular never
skips `guard.py`'s read-only gate/allowlist check: that check runs first,
entirely before `MikrotikClient` ever attempts a connection.

- **Audit journal.** Every guarded write call (`guard.py`, one of the
  `ALLOWLIST` operations) emits exactly one structured JSON-lines event -
  whether it previewed (`confirm=false`), applied (`confirm=true`), or
  failed at any point, however early (even a write blocked by the read-only
  gate before the device is ever touched). Each event has a `timestamp`,
  `correlation_id`, `device_name`, `tool`, `operation` (the `ALLOWLIST` key),
  `action` (`add`/`update`/`remove`/`start`/`stop`/`flush`/`wol`/`save` - see
  v0.7's `start_container`/`stop_container`, v0.10's `clear_dns_cache`/
  `wake_on_lan`, and v0.14's `create_backup`), `confirm`, `outcome`
  (`preview`/`applied`/`error`), and a `summary` of the before/after change
  plus that write's `warning` (e.g. `disable_route`'s default-route callout,
  `remove_dhcp_lease`'s static-lease callout - see `WritePreview.warning` in
  `guard.py`), or the error. `summary.warning` is `null` for every write that
  carries no special risk. **Never includes a device password or any field
  that looks like a secret** - see `src/mcp_mikrotik/audit.py`'s
  `_sanitize()`.
  Destination is `MIKROTIK_AUDIT_LOG` (a file path, appended to) if set,
  otherwise a plain `INFO`-level line via the standard logger (stderr).
  Writing the journal is always best-effort: a bad path or a permissions
  error is logged as a warning and never blocks or fails the write it is
  describing. Read tools are never journaled - only guarded writes are.
- **Correlation IDs.** Every MCP tool call (read or write) gets a short,
  unique id (`uuid4().hex[:12]`) for its duration - see
  `src/mcp_mikrotik/correlation.py`. It is bound once per call in
  `server.py`'s `_safe` wrapper, appears in every audit journal entry a
  write call produces, and is prefixed onto the server-side log line if the
  call fails - so one id lets you grep everything one tool call did, end to
  end, without changing the shape of any error message returned to the
  caller.
- **Read retry.** `path`/`ping`/`traceroute` (every read primitive in
  `src/mcp_mikrotik/client.py`) automatically retry on a *transient* network
  error - a fresh connection attempt failing, or an in-flight command
  failing because of an underlying `OSError` (a dropped socket, a timeout) -
  with a short backoff (0.5s, then 1s). Up to `MIKROTIK_READ_RETRIES` extra
  attempts (default 2). A command rejected by RouterOS itself (a
  `LibRouterosError`, not an `OSError`) is never retried - it would just be
  rejected again. **Writes never retry**, regardless of this setting:
  `update`/`add`/`remove`/`start`/`stop` aren't guaranteed idempotent, so retrying one
  could duplicate or reapply a change.
- **Circuit breaker.** Each device gets its own in-memory, thread-safe
  breaker (`client.CircuitBreaker`, one instance per pooled `MikrotikClient`
  - see `ClientPool`). After `MIKROTIK_BREAKER_THRESHOLD` consecutive
  connection failures (default 3), the circuit opens: for the next
  `MIKROTIK_BREAKER_COOLDOWN` seconds (default 30), any call to that device -
  read or write - fails immediately with a clear `circuit open for
  '<device>', retry after <t>s` error, without attempting a connection at
  all. A single successful connection resets the failure count and closes
  the circuit. This is scoped purely to the *connection* step - it never
  decides whether a write is allowed (that's the read-only gate/allowlist in
  `guard.py`, always checked first) - it exists to stop a dead device (e.g.
  an antenna that fell over) from costing a full connect timeout on every
  single tool call.

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

## Development & CI

```bash
pip install -e ".[dev]"
pytest -q
```

The test suite never talks to a real router: `tests/fakes.py` provides an
in-memory fake that implements the same minimal interface `MikrotikClient`
expects from a `librouteros` connection, and it is injected via a
`client_factory` parameter on `build_server()`. It currently has 988 tests,
zero of which touch a real device or the network.

CI (`.github/workflows/ci.yml`, GitHub Actions) runs the full `pytest` suite
on every push to `main` and every pull request, against both Python 3.11 and
3.12 - both must pass before a change is considered mergeable.

**Contributing:** a new write tool must go through `guard.py`'s
`ALLOWLIST` pattern (one named `WriteOperation` + one dedicated function -
see the comment block at the top of `guard.py`) - never a generic
"run this path" tool. Add tests alongside any new behavior (both the guard
function in `tests/test_guard.py`/`test_guard_audit.py` and the tool
registration in `tests/test_server.py`, following existing tests as a
template), and make sure `pytest -q` is green locally before opening a PR -
CI runs the identical suite.

## Roadmap & non-goals

### Delivered through 1.0

Every tool round originally planned for this project has shipped - see
`CHANGELOG.md` for the full version-by-version detail:

- **Core read tools + guarded writes** (v0.1-v0.4): device/interface/route
  reads, `set_identity`, `enable_interface`/`disable_interface`,
  `set_wifi_ssid`, `set_client_bandwidth`, `add_static_dhcp_lease`,
  `remove_simple_queue`, `add_to_address_list`/`remove_from_address_list`.
- **Production hardening** (v0.5): audit journal, correlation IDs, read
  retry, circuit breaker - see "Security model" above.
- **Physical layer, LTE, containers, USB** (v0.6-v0.7): `set_poe_out`,
  `lte_status`/`lte_interfaces`, `start_container`/`stop_container` +
  `containers`/`container_config`, `usb_devices`.
- **VPN/routing diagnostics + failover control** (v0.8-v0.9):
  `wireguard_peers`, `ppp_active`, `ipsec_active_peers`, `bgp_sessions`,
  `ospf_neighbors`, `netwatch` (read), plus the guarded failover write
  tools `set_route_distance`/`enable_route`/`disable_route`/
  `add_netwatch`/`remove_netwatch` - see "Failover control" above.
  Netwatch up/down-script configuration itself remains deliberately out of
  scope (manual, on the device) - see "Netwatch scripts are never accepted"
  above for why.
- **DNS/DHCP/Wake-on-LAN write tools** (v0.10): `add_static_dns`/
  `remove_static_dns`, `clear_dns_cache`, `remove_dhcp_lease`,
  `wake_on_lan` - see "DNS management", "DHCP lease removal", and
  "Wake-on-LAN" above. Only the two simplest static DNS record types
  (`"A"`/`"CNAME"`) are exposed; other RouterOS record types
  (`AAAA`/`MX`/`TXT`/`NS`/...) remain a future decision, not silently
  widened here.
- **Firewall rule toggle + connection tracking** (v0.11):
  `enable_firewall_rule`/`disable_firewall_rule` (a `disabled` TOGGLE only,
  on an existing, admin-authored rule resolved by `comment` - never rule
  creation or any other field) and `connection_tracking` (mandatory filter,
  hard-capped at 100 rows) - see "Firewall rule toggle (by comment)" and
  "Connection tracking (filtered)" above.
- **Security audit + security-relevant log events** (v0.12):
  `security_audit`, `security_events` - see "Security audit" above. Both
  are read-only and heuristic: `security_audit` does not (and will not)
  auto-remediate anything it finds - every finding exists to inform a
  human/LLM decision, not to be acted on automatically. Widening its check
  list (e.g. NAT exposure, more RouterOS-version-specific CVE checks) is a
  future decision, not silently expanded here.
- **WireGuard VPN management** (v0.13): `wireguard_interfaces`,
  `add_wireguard_interface`, `add_wireguard_peer`, `remove_wireguard_peer` -
  see "WireGuard management" above.
- **Hotspot vouchers, live traffic monitoring, and backup** (v0.14):
  `hotspot_active`, `torch`, `list_backups`, `add_hotspot_user`,
  `create_backup` - see "Hotspot vouchers", "Live traffic monitoring
  (torch)", and "Backup" above.
- **1.0.0**: no new tools - a polish/consolidation round (ambiguity
  handling on `remove_netwatch`, the audit journal carrying a write's
  `warning`, and this README).

### Non-goals

These are deliberately **not** exposed, not because they're technically
hard, but because the standard guard/confirm/preview mechanism isn't
sufficient protection for them on its own - see the comment above
`ALLOWLIST` in `guard.py`:

- **Device reboot** (`/system/reboot`): there's no meaningful before/after
  preview for a reboot, and a bad batch reboot across a fleet has no
  dry-run or rollback. Would need its own confirmation/cooldown policy
  first.
- **Backup RESTORE** (`/system/backup/load`): same risk class as reboot -
  loading a backup overwrites the device's entire running configuration and
  reboots it, with no meaningful before/after preview and no rollback.
  `create_backup`/`list_backups` only ever create/list backup files;
  restoring one stays a manual, on-device (WinBox/CLI) operation until it
  has its own confirmation/cooldown policy.
- **Firewall filter rule CREATION or general modification** (any
  `ip/firewall/filter` write other than the `disabled` toggle): a single
  wrong rule (e.g. one that blocks the API port itself) can lock out all
  remote management access to the device, with no way to recover it over
  the same connection. Would need staged/rollback support (e.g. RouterOS
  safe mode) before it belongs in the allowlist -
  `enable_firewall_rule`/`disable_firewall_rule` sidestep that risk
  entirely by only ever touching a rule an admin already wrote and reviewed
  themselves, never authoring one.
- **A generic "run this RouterOS command/path" tool**: this is not a gap to
  be filled later - it is the exact failure mode this project exists to
  avoid (see "Status" above). Every write will always be a dedicated, named,
  individually-reviewed function in `guard.ALLOWLIST`, never an arbitrary
  path+action a caller supplies.

### Post-1.0 ideas

- Further write tools are added by extending `guard.ALLOWLIST` with one new
  named operation and function each - see the comment block at the top of
  `guard.py`. Do not add a generic write tool.
- A second entrypoint that periodically polls devices and pushes metrics to
  Firebase is planned to reuse `MikrotikClient`/`get_client` from
  `client.py`. Not implemented yet - see the `TODO(collector)` note at the
  bottom of `client.py`.

## License

MIT - see [LICENSE](LICENSE).
