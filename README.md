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

v0.9: everything from v0.8 (the core read-tool inventory, `ping`/
`traceroute` diagnostics, guarded write tools through `stop_container`,
production-hardening layers - audit journal, correlation ids, read retry,
circuit breaker; physical layer / L2 observability; LTE/5G, containers,
USB; six read-only VPN/routing/Netwatch diagnostics tools), plus the
failover **write** round this built toward: five new guarded write tools -
`set_route_distance`, `enable_route`/`disable_route` (adjust/flip an
`/ip/route` row, resolved by the STABLE `dst-address`+`gateway` pair, never
a dynamic `.id`/index), `add_netwatch`/`remove_netwatch` (a Netwatch host
monitor - deliberately **never** accepting an up-script/down-script
parameter). `disable_route`'s preview carries a `warning` field whenever
the route being disabled is the default route (`0.0.0.0/0`/`::/0`) - see
"Failover control" below. All five go through the exact same write-guard
mechanism as every other write tool - see "Security model" below. See
`CHANGELOG.md` for what changed since v0.1.0, and `src/mcp_mikrotik/guard.py`
for how to add the next write tool.

The full pytest suite currently has 627 tests, all passing against the
in-memory fake device layer (`pytest -q`) - see "Development" below.

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
| `wireguard_peers` | List WireGuard VPN peers (name, interface, public-key, endpoint, last-handshake, rx/tx, allowed-address, disabled). Never exposes a private-key, even defensively. Empty list (not an error) with no WireGuard interfaces. See "VPN & routing diagnostics" below. |
| `ppp_active` | List active PPP-based VPN server sessions (`/ppp/active`: name, service - l2tp/pptp/sstp/ovpn/pppoe, caller-id, address, uptime). Empty list (not an error) with no PPP server / no active sessions. |
| `ipsec_active_peers` | List active IPsec peers (remote-address, state, uptime, rx/tx, side). Empty list (not an error) for a device that doesn't use IPsec. |
| `bgp_sessions` | BGP session status (remote-address/as, state, uptime, prefix-count). Tries ROS7's `/routing/bgp/session` first, falls back to ROS6's `/routing/bgp/peer`; empty list (not an error) for a device that doesn't run BGP. |
| `ospf_neighbors` | OSPF neighbor adjacencies (address, state, router-id, adjacency). Empty list (not an error) for a device that doesn't run OSPF. |
| `netwatch` | List Netwatch host monitors (host, status up/down, interval, since, comment, disabled, plus `has-up-script`/`has-down-script` presence booleans - never the raw script body). The key read for diagnosing/building failover. See "VPN & routing diagnostics" below. |
| `dns_cache` | List cached DNS records (name, type, data, ttl). |
| `firewall_filter` | List IPv4 firewall filter rules (chain, action, etc). Read-only - does not add/modify/remove rules. |
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
| `remove_netwatch` | Remove a Netwatch host monitor by `host` or `comment`. |

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
   As of v0.7, `action` isn't limited to `update`/`add`/`remove`:
   `start_container`/`stop_container` use `start`/`stop` to represent
   RouterOS's `/container/start`/`/container/stop` ACTION commands - but the
   dispatch mechanism (`getattr(client, op.action)`) and the fixed,
   individually-reviewed `MikrotikClient` method it can ever reach are
   unchanged; see `CHANGELOG.md`'s "How start/stop extends the guard".
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
  `set_route_distance`/`enable_route`/`disable_route`/`remove_netwatch`)
  look it up first - by name, or, for the v0.9 route tools, by the stable
  `dst-address` (+`gateway`/`comment`) identifier described in "Failover
  control" above. If nothing matches, the tool raises a clear error instead
  of creating one - a typo can never silently provision something new.
  `set_poe_out` additionally requires the matched interface to actually
  have a `poe-out` field (i.e. be PoE-capable hardware) - a name that
  exists but isn't a PoE port raises the same clear error rather than doing
  nothing silently. The v0.9 route tools additionally never resolve by a
  RouterOS `.id` or a list index (both can shift as routes are added/
  removed elsewhere on the device); if a route's identifier still matches
  more than one row after narrowing, `AmbiguousResourceError` is raised
  instead of guessing which one to touch.
- **Never silently duplicates.** `add_static_dhcp_lease` checks for an
  existing lease on the given `mac_address` first, `add_to_address_list`
  checks for an existing entry with the same `list_name`+`address` pair
  first, and `add_netwatch` checks for an existing monitor on the given
  `host` first - each raising `ResourceAlreadyExistsError` instead of
  creating a second one - both for `confirm=false` previews and
  `confirm=true` applies.
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
  in the first place (see "VPN & routing diagnostics" above).
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

## Production features: audit log, correlation IDs, retries, circuit breaker

v0.5 adds a set of layers *around* the write-guard mechanism above, aimed at
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
  `action` (`add`/`update`/`remove`/`start`/`stop` - see v0.7's
  `start_container`/`stop_container`), `confirm`, `outcome`
  (`preview`/`applied`/`error`), and a `summary` of the before/after change
  (or the error). **Never includes a device password or any field that
  looks like a secret** - see `src/mcp_mikrotik/audit.py`'s `_sanitize()`.
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

- **Failover write tools** (`set_route_distance`, `enable_route`/
  `disable_route`, `add_netwatch`/`remove_netwatch`) shipped in v0.9 -
  see "Failover control" above. Netwatch up/down-script configuration
  itself remains deliberately out of scope (manual, on the device) - see
  "Netwatch scripts are never accepted" above for why.
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
