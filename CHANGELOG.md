# Changelog

All notable changes to this project are documented here. Versions follow
[Semantic Versioning](https://semver.org).

## [0.11.0] - Unreleased

SAFE firewall control round: two new guarded write tools -
`enable_firewall_rule`/`disable_firewall_rule` - and one new filtered read
tool - `connection_tracking`. Same write-guard mechanism as every previous
round (read-only default, central allowlist, confirm/preview, audit
journal, no secrets logged) - none of it weakened or bypassed; the firewall
tools' `action` stays a plain `"update"` (no new dispatch mechanism), so
they need none of the `getattr(client, op.action)` extension work v0.7's
`start_container`/`stop_container` or v0.10's `clear_dns_cache`/
`wake_on_lan` needed.

### Added

- **`enable_firewall_rule`** / **`disable_firewall_rule`** (write, guarded,
  `src/mcp_mikrotik/guard.py` + `server.py`): flip an EXISTING
  `/ip/firewall/filter` rule's `disabled` field (`/ip/firewall/filter set
  disabled=no|yes`) - resolved by the rule's `comment` (a STABLE,
  admin-controlled identifier), optionally narrowed by `chain` if more than
  one rule shares that comment. **Never creates a rule**: a `comment` that
  matches nothing raises `ResourceNotFoundError` (never falls back to
  creating one); a `comment` that still matches more than one row after
  narrowing raises `AmbiguousResourceError` - the tool never guesses which
  one to toggle. The returned preview's `before`/`after` are the FULL
  matched rule (every field RouterOS returned - `chain`/`action`/etc, not
  just `disabled`), so an operator can confirm WHICH rule this is before
  ever passing `confirm=true`.

  This is the community-suggested SAFE alternative to a general
  firewall-filter write tool (still deliberately absent - see
  `guard.ALLOWLIST`'s comment and README's "Roadmap / non-goals"): an admin
  creates a rule ahead of time on the device itself (e.g. `comment=
  "Bloqueio_Ataque_X"`, `disabled=yes`), reviews it once, and an LLM caller
  later enables it via `enable_firewall_rule` when it detects the condition
  the rule exists to guard against. If something goes wrong, the admin
  knows exactly which rule was toggled - the same one they already wrote
  and reviewed, never one this package authored on its own judgment. See
  README's "Firewall rule toggle (by comment)".

- **`connection_tracking`** (read, `server.py`): lists active connections
  from RouterOS's connection tracking table (`/ip/firewall/connection`).
  Unlike every other read tool in this package, a filter is MANDATORY - at
  least one of `src_address`/`dst_address`/`dst_port`/`protocol` must be
  given, or the tool raises `ValidationError` before ever touching the
  device. This exists specifically to avoid a community-reported gotcha:
  the full connection-tracking table on a production router can be large
  enough to blow straight past an LLM caller's context/token budget on its
  own. Filtering happens client-side after reading the table (the same
  reasoning `logs`' `topics` filter already documents - RouterOS's
  structured API doesn't expose a query-by-field read here either), and the
  result is hard-capped at `MAX_CONNTRACK_LIMIT` (100) rows regardless of
  how many match - the returned `truncated` field is `true` whenever more
  rows matched than were returned, and `total_matched` always reports the
  real, pre-truncation count.

  `src_address`/`dst_address` match a row's IP, ignoring the port RouterOS
  packs into the same field (e.g. `"192.0.2.1:80"`); `dst_port` matches the
  destination's port component. `protocol` is a RouterOS protocol name
  (case-insensitive) or a numeric IP protocol number (0-255). Each returned
  entry: `protocol`, `src-address`/`src-port`, `dst-address`/`dst-port`
  (address and port split apart - see `formatting.split_address_port`),
  `tcp-state` (populated for TCP connections), `timeout`, and the
  `assured`/`confirmed`/`seen-reply` flags - RouterOS's own closest
  equivalent to a generic "connection state" for this table. See README's
  "Connection tracking (filtered)".

- `validation.validate_firewall_rule_comment`/`validate_firewall_chain`
  (`src/mcp_mikrotik/validation.py`, new): a firewall filter rule's
  `comment` (MANDATORY and non-empty here, unlike `validate_comment`'s
  OPTIONAL free-text field elsewhere - an empty comment can never reliably
  identify one specific existing rule) and its `chain` (shape-only, not
  restricted to the three built-in chains - RouterOS allows arbitrary
  custom jump-target chains too).
- `validation.validate_conntrack_dst_port`/`validate_conntrack_protocol`
  (new): `connection_tracking`'s `dst_port` (integer, 1-65535) and
  `protocol` (a RouterOS protocol name, case-insensitive, or a numeric
  0-255 protocol number) filter values.
- `formatting.split_address_port` (new): splits a RouterOS
  connection-tracking address field ("192.0.2.1:80",
  "[2001:db8::1]:80", or a bare address with no port at all) into
  `(address, port)` - used by `connection_tracking` to report/filter
  address and port as separate values instead of RouterOS's packed format.

## [0.10.0] - Unreleased

DNS/DHCP/Wake-on-LAN **write** round: five new guarded write tools -
`add_static_dns`/`remove_static_dns` (`/ip/dns/static`), `clear_dns_cache`
(`/ip/dns/cache/flush`), `remove_dhcp_lease` (`/ip/dhcp-server/lease`), and
`wake_on_lan` (`/tool/wol`). Same write-guard mechanism as every previous
round (read-only default, central allowlist, confirm/preview, audit
journal, no secrets logged, ROS6/ROS7 compat - none of these five needed
any generation branching, since static DNS, DNS cache, DHCP leases, and
`/tool/wol` all live at the same path on both RouterOS generations) - none
of it weakened or bypassed. `clear_dns_cache`/`wake_on_lan` extend the
guard's action-command mechanism (first introduced by v0.7's
`start_container`/`stop_container`) a second time - see "How
`clear_dns_cache`/`wake_on_lan` extend the guard" below.

### Added

- **`add_static_dns`** (write, guarded, `src/mcp_mikrotik/guard.py` +
  `server.py`): creates a static DNS entry (`/ip/dns/static add`) resolving
  `name` to `address`. `record_type` (default `"A"`) selects what `address`
  means - a literal IPv4/IPv6 address for `"A"`, or another hostname (the
  alias target, written to RouterOS's `cname` field) for `"CNAME"`. Typical
  uses: sinkhole a malicious domain (`address="0.0.0.0"`), or set up an
  internal DNS override/alias. Refuses to create a second row for the same
  `name`+`record_type` pair (`ResourceAlreadyExistsError`) - this tool only
  ever adds, never updates or removes an existing entry, and does not
  attempt to create RouterOS round-robin DNS (two "A" records sharing a
  `name`, different addresses) since that would require accepting a
  same-name-and-type "duplicate" as intentional.
- **`remove_static_dns`** (write, guarded): removes a static DNS entry by
  `name`, optionally narrowed by `record_type`. `ResourceNotFoundError` if
  nothing matches; `AmbiguousResourceError` if more than one row still
  matches after narrowing (e.g. an existing round-robin pair) - never
  guesses which one to remove.
- **`clear_dns_cache`** (write, guarded): flushes the device's DNS resolver
  cache (`/ip/dns/cache/flush`) - no arguments, targets no specific row
  (clears every cached answer at once). Benign (only cached *answers* are
  cleared, never configuration - they repopulate on the next resolution),
  but still confirm-gated like every other write tool here. `before`/`after`
  report the currently-cached entry count (`cached_entries`) as an
  informative read, not a specific row's fields - `after.cached_entries` is
  the *intended* post-flush count (`0`), not a verified re-read.
- **`remove_dhcp_lease`** (write, guarded): removes an existing
  `/ip/dhcp-server/lease` row by `address` or `mac_address` (`mac_address`
  tried first if both given - the more stable identifier). Typical use:
  force a client to renew its IP. Removes EITHER a dynamic or a static
  lease - not blocked outright for a static one - but the returned
  preview's new `warning` field is non-null whenever the resolved lease is
  static (`dynamic=false`): removing it deletes the pinned IP↔MAC mapping
  itself, not just a renewable entry. Set on both the `confirm=false`
  preview and the `confirm=true` applied result, same pattern as v0.9's
  `disable_route` default-route warning.
- **`wake_on_lan`** (write, guarded): sends a Wake-on-LAN magic packet
  (`/tool/wol`) for `mac_address`, out `interface`. The first guarded write
  in this package that resolves nothing on the device first - there is no
  existing row to check `mac_address`/`interface` against, only shape
  validation (`validate_mac_address`/`validate_interface_name`); RouterOS
  itself rejects an unknown `interface` at send time. Benign (never changes
  device configuration) but still confirm-gated, so an LLM caller can't
  wake a machine "by accident".
- `validation.validate_dns_name`/`validate_dns_record_type`
  (`src/mcp_mikrotik/validation.py`, new): hostname/domain shape (reused for
  both a static DNS entry's `name` and, when `record_type="CNAME"`, its
  `address`/alias-target param - unlike `validate_ping_address`, never
  accepts a literal IP), and the `"A"`/`"CNAME"` record-type enum
  (case-insensitive, normalized to upper-case). `add_static_dns`/
  `remove_static_dns` reuse the existing `validate_ip_address` (an `"A"`
  record's `address`), `validate_timeout` (`ttl`, reused - not a full
  RouterOS DNS TTL grammar, same best-effort duration/clock check already
  used for address-list `timeout`), and `validate_comment`. `remove_dhcp_lease`
  reuses `validate_ip_address`/`validate_mac_address`; `wake_on_lan` reuses
  `validate_mac_address`/`validate_interface_name` - no other new validators
  needed.
- `MikrotikClient.flush`/`.wol` (`src/mcp_mikrotik/client.py`, new): two more
  action-command write primitives, alongside `.start`/`.stop`. Unlike
  `.start`/`.stop` (which target one specific row's `.id` via
  `path(*segments)(cmd, **{".id": id})`), neither `/ip/dns/cache/flush` nor
  `/tool/wol` targets a row at all - both are standalone, one-shot commands,
  so `.flush`/`.wol` use the connection's CALLABLE form
  (`connection(cmd, **kwargs)`) instead, the same mechanism `ping`/
  `traceroute`/`monitor_traffic` already use. Each still sends exactly one
  fixed, hardcoded command string built only from a menu-path `segments`
  argument plus its own literal command word (`"flush"`/`"wol"`) - never a
  command assembled from caller input. No retry (same reasoning as every
  other write primitive). Reply is materialized with `list(...)` before
  being discarded, per the v0.7.1 lesson; `tests/fakes.py`'s
  `FakeConnection.__call__` now returns a real (empty) generator for
  `/ip/dns/cache/flush`/`/tool/wol` (reusing the existing
  `_once_reply_stream(None)` helper), so a regression back to
  unmaterialized indexing would fail the suite the same way v0.7.1's did.

### How `clear_dns_cache`/`wake_on_lan` extend the guard

These are the second pair of `ALLOWLIST` entries (after v0.7's
`start_container`/`stop_container`) whose `action` is neither `"update"`,
`"add"`, nor `"remove"` - `"flush"`/`"wol"` are RouterOS's own literal
command words for `/ip/dns/cache/flush`/`/tool/wol`, exactly the same
"`action` is a literal RouterOS command word" convention `"start"`/`"stop"`
established. Dispatch is unchanged: `ALLOWLIST["clear_dns_cache"].action ==
"flush"` and `ALLOWLIST["wake_on_lan"].action == "wol"` are what actually
get called, via the exact same `getattr(client, op.action)` indirection
every write here already uses - `guard.clear_dns_cache`/`.wake_on_lan` never
call `client.flush`/`.wol` directly. The one new wrinkle versus
`start`/`stop`: neither operation targets a specific `/container`-style row
by `.id` - see `MikrotikClient.flush`/`.wol`'s docstrings above for why they
use the connection's callable form instead of `start`/`stop`'s
`path(*segments)(cmd, **{".id": id})` form. Same read-only gate,
confirm/preview flow, and `_audited` journaling as every other write,
unchanged.

### Tests

105 new tests (627 → 732, full suite green): `validate_dns_name`/
`validate_dns_record_type` (accept/reject, including the deliberate
"a literal IP is rejected as a DNS name, unlike `validate_route_gateway`'s
interface-name exception" case); `MikrotikClient.flush`/`.wol` (fixed
command string / structured params not a command string, transport-error
wrapping, no retry - extending the existing "writes never retry"
parametrized case); guard-level coverage for all five new writes (blocked
when read-only, read-only gate before touching the device, preview vs
confirm, `ALLOWLIST.action`-driven dispatch, name+type duplicate →
`ResourceAlreadyExistsError`, round-robin ambiguity →
`AmbiguousResourceError`, not-found, the static-vs-dynamic DHCP lease
warning present/absent, `mac_address`-tried-before-`address` resolution
order); audit-journal coverage (preview/applied/error outcomes, no password
leak, folded into the existing cross-tool sweep - now 22 events); and
server-level `call_tool` coverage mirroring the guard-level cases end to
end through `FastMCP`, including the CNAME-writes-`cname`-not-`address`
case and the DHCP static-lease-warning case.

## [0.9.0] - Unreleased

Failover **write** round: the five atomic write tools v0.8's read-only
VPN/routing/Netwatch diagnostics were the foundation for -
`set_route_distance`, `enable_route`/`disable_route`, `add_netwatch`/
`remove_netwatch`. Deliberately small, composable steps an LLM caller
combines to build or adjust a failover setup - never one black-box "do a
failover" command. These writes touch **routing**: a wrong `disable_route`
call on the wrong route can cut a device's outbound traffic, so this round's
whole design is aimed at making that mistake hard to make -
resolution-by-stable-identifier (never a dynamic `.id`/index) and an
explicit default-route risk callout in the preview, on top of the unchanged
write-guard invariants (read-only default, central allowlist, confirm/
preview, audit journal, no secrets logged).

### Added

- **`set_route_distance`** (write, guarded, `src/mcp_mikrotik/guard.py` +
  `server.py`): adjusts an existing `/ip/route` row's `distance` (failover
  priority - the lower distance wins) via `set distance=<distance>`.
  Resolved by the STABLE `(dst_address, gateway)` pair - never a dynamic
  `.id`/list index, which can silently shift as routes are added/removed
  elsewhere on the device between a preview and the confirmed apply (see
  "Route resolution: stable identifiers, never an index" below). `distance`
  is validated 1-255 (`validation.validate_route_distance`) before the
  device is ever touched.
- **`enable_route`/`disable_route`** (write, guarded): flip an `/ip/route`
  row's `disabled` field, resolved by `dst_address` - narrowed by optional
  `gateway`/`comment` when more than one route shares that `dst_address`
  (exactly the failover shape: two default routes to different gateways).
  **`disable_route`'s preview carries a `warning` field** (a new, optional
  `WritePreview.warning: str | None` on `guard.WritePreview`, `None` for
  every write that has no equivalent risk) whenever the resolved route's
  `dst-address` is a default route (`0.0.0.0/0`/`::/0`) - a plain-language
  callout that disabling it cuts outbound traffic through that gateway, set
  on both the `confirm=false` preview and the `confirm=true` applied result
  so a caller reading only `applied`/`after` still cannot miss it.
  `enable_route` never carries a warning - re-enabling restores traffic
  rather than cutting it.
- **`add_netwatch`** (write, guarded): creates a `/tool/netwatch` host
  monitor - `host` (validated as a plain IP, `validate_ip_address`),
  optional `interval` (a RouterOS duration, reuses `validate_timeout`) and
  optional `comment`. **SECURITY: does NOT accept an up-script/down-script
  parameter at all** - there is no parameter on this tool a caller could
  even attempt to pass one through (see "Netwatch scripts are never
  accepted" below). Refuses to create a second monitor for a `host` that
  already has one (`ResourceAlreadyExistsError`).
- **`remove_netwatch`** (write, guarded): removes a `/tool/netwatch` row by
  `host` or `comment` (`host` tried first if both given). Requires at least
  one of the two; `ResourceNotFoundError` if neither matches.
- `exceptions.AmbiguousResourceError` (new): raised when a write tool's
  identifier matches more than one row on the device instead of the tool
  guessing which to touch - see "Route resolution" below. Mirrors the
  existing `ResourceNotFoundError`/`ResourceAlreadyExistsError` shape
  (device name, resource kind/name, plus the list of ambiguous candidates).
- `validation.validate_dst_address`/`validate_route_gateway`/
  `validate_route_distance` (new): route `dst-address` (IPv4/IPv6, optional
  `/prefix`), `gateway` (IPv4/IPv6 address OR a bare interface name -
  RouterOS also accepts a gateway expressed as an outgoing interface), and
  `distance` (integer 1-255). `add_netwatch`/`remove_netwatch` reuse the
  existing `validate_ip_address` (host) and `validate_timeout` (interval) -
  no new validators needed for those two fields.

### Route resolution: stable identifiers, never an index

All three route write tools share one resolver, `guard._resolve_route`:
match `/ip/route` rows by `dst-address`, then narrow further by `gateway`
and/or `comment` if given. **Never** by `.id` (RouterOS reassigns `.id`s as
routes are added/removed elsewhere on the device - stale between a preview
and a later confirmed apply) and never by a list index (even less stable -
shifts on every unrelated route change). If nothing matches after
narrowing, `ResourceNotFoundError`. If **more than one** row still matches
- the common real case is two routes sharing a `dst-address` for failover,
e.g. two `0.0.0.0/0` default routes pointing at different gateways -
`AmbiguousResourceError` is raised instead of silently picking the first
match; the caller must add (or correct) `gateway`/`comment` to disambiguate.
`set_route_distance` requires `gateway` up front (you're always adjusting a
*specific* gateway's priority); `enable_route`/`disable_route` accept it
(and `comment`) as optional narrowers, since sometimes `dst_address` alone
is already unambiguous.

### Netwatch scripts are never accepted

`add_netwatch`'s function signature (`guard.py` and its `server.py` tool
wrapper) has no `up_script`/`down_script` parameter at all - not "rejected
if given", genuinely absent, so there is no code path through which a
caller can smuggle an executable RouterOS script (which can run arbitrary
commands, including route or credential changes) onto a device via this
tool. See `test_add_netwatch_never_accepts_up_script_or_down_script`
(`tests/test_guard.py`, asserts `TypeError` for either kwarg) and
`test_add_netwatch_tool_schema_has_no_up_script_or_down_script_parameter`
(`tests/test_server.py`, asserts the MCP tool's own JSON parameter schema
has no such property). Up/down scripts remain a manual, out-of-band
operator step (WinBox/CLI) once the monitor exists - see README's
"Failover control".

### Tests

112 new tests (515 → 627, full suite green): `validate_dst_address`/
`validate_route_gateway`/`validate_route_distance` (accept/reject,
including the deliberate "999.1.1.1 is accepted as an interface-name shape,
not a malformed IP" edge case - see its test's docstring); guard-level
coverage for all five new writes (blocked when read-only, read-only gate
before touching the device, preview vs confirm, resolution by
`dst-address`+`gateway`, ambiguity → `AmbiguousResourceError`, not-found,
netwatch duplicate → `ResourceAlreadyExistsError`, the default-route
warning present/absent, `ALLOWLIST.action`-driven dispatch); audit-journal
coverage (preview/applied/error outcomes, no password leak, folded into the
existing cross-tool sweep); server-level `call_tool` coverage mirroring the
guard-level cases end to end through `FastMCP`, plus the netwatch
schema-inspection test above.

## [0.8.0] - Unreleased

VPN, routing, and failover diagnostics round: six new read tools covering
every VPN mechanism RouterOS supports (WireGuard, PPP-based VPN servers,
IPsec), plus BGP/OSPF routing-protocol status and Netwatch host monitoring -
the piece that actually drives failover decisions on a real device. **All
six are read-only** - none of them are gated by `MIKROTIK_ALLOW_WRITE`, none
touch `guard.ALLOWLIST`. The write side of failover (adjusting a route's
`distance`, adding/editing a Netwatch entry) is deliberately deferred to a
future round; see README's "VPN & routing diagnostics" for why these reads
come first.

### Added

- **`wireguard_peers`** (read, `src/mcp_mikrotik/server.py`): lists
  `/interface/wireguard/peers` - name, interface, public-key,
  endpoint-address/endpoint-port, current-endpoint-address/
  current-endpoint-port, last-handshake, rx/tx byte counters,
  allowed-address, disabled. **SECURITY**: a `private-key` field never
  appears on RouterOS's own `/interface/wireguard/peers` reply (only
  `/interface/wireguard` - the tunnel interfaces themselves, deliberately
  NOT exposed by any read tool this round - carries one), but the tool
  strips a `private-key` field defensively regardless, via a new shared
  helper, `formatting.strip_sensitive_fields`. See
  `test_wireguard_peers_never_exposes_private_key` (`tests/test_server.py`),
  which feeds a fake device row that includes a `private-key` field and
  asserts it never reaches the tool's output. Empty list (never an error)
  for a device with no WireGuard package/interfaces.
- **`ppp_active`** (read): lists `/ppp/active` - name, service
  (l2tp/pptp/sstp/ovpn/pppoe), caller-id, address, uptime. Covers VPN
  server sessions currently connected to the device. Empty list (not an
  error) with no PPP server configured or no active sessions.
- **`ipsec_active_peers`** (read): lists `/ip/ipsec/active-peers` -
  remote-address, state, uptime, rx/tx byte counters, side
  (initiator/responder). Empty list (not an error) for a device that
  doesn't use IPsec.
- **`bgp_sessions`** (read): BGP session status - remote-address,
  remote-as, state (established/idle/...), uptime, prefix-count. RouterOS
  splits this by generation exactly like v0.6's `wireless_registrations`
  split wifi: ROS7's `/routing/bgp/session` vs ROS6's `/routing/bgp/peer`.
  Tries ROS7 first, falls back to ROS6, empty list (not an error) for a
  device that doesn't run BGP at all.
- **`ospf_neighbors`** (read): lists `/routing/ospf/neighbor` - address,
  state (Full/Down/...), router-id, adjacency. Empty list (not an error)
  for a device that doesn't run OSPF.
- **`netwatch`** (read): lists `/tool/netwatch` - host, status (up/down),
  interval, since, comment, disabled, plus `has-up-script`/
  `has-down-script` presence booleans. The up-script/down-script fields are
  surfaced only as presence booleans, never as the raw script body (which
  can contain arbitrary RouterOS commands, e.g. route or credential
  changes, that don't belong in a read tool's output). Netwatch is the
  mechanism a RouterOS device itself already uses to watch a gateway or
  peer's reachability - this is the key read for failover diagnosis; empty
  list (not an error) with no entries configured.
- `formatting.strip_sensitive_fields` (`src/mcp_mikrotik/formatting.py`,
  new): shared helper that drops a given set of field names from every row
  before it is returned - used by `wireguard_peers` to guarantee a private
  key can never leak, belt-and-suspenders on top of RouterOS's own reply
  shape never including one in the first place.

### Read-only, unlike everything else in this round's theme

Every tool above uses the same `try: rows_to_list(client.path(*segments))
except DeviceCommandError: return []` (or the ROS7-then-ROS6 fallback loop,
for `bgp_sessions`) shape `wireless_registrations`/`system_health`/
`lte_status` already established - a device that doesn't run the relevant
feature at all returns an empty list, never a raised error. None of the six
enters `guard.ALLOWLIST`, none checks `MIKROTIK_ALLOW_WRITE`, none is
wrapped by `guard._audited` (the write-guard's audit journal only journals
writes - see v0.5's "Production features"). The actual failover write tools
(adjusting `ip_routes`' `distance` to fail over between gateways, adding/
editing a Netwatch entry) are intentionally left for a future round; these
six reads are the diagnostic foundation they will build on.

### Fixed / carried forward from the v0.7.1 lesson

v0.7.1 found that `tests/fakes.py`'s `FakeConnection.__call__` (the
callable-connection form used by `monitor_traffic`/`poe_monitor`/
`lte_monitor`) previously returned a `list` where real librouteros returns a
generator, hiding a real `TypeError` from the fake suite. None of this
round's six tools use that callable form at all - every one reads via
`MikrotikClient.path()` (`client.py`'s `path()`, already returning
`list[dict[str, Any]]` by materializing each row with `dict(row)` - see
`client.py:325`), the same construction `wireless_registrations`/
`arp_table`/`bridge_hosts` already use safely. `tests/fakes.py` is
unchanged this round; no new generator-vs-list gap was introduced.

### Tests

14 new tests (501 → 515, full suite green): `wireguard_peers` (happy path,
the explicit private-key-redaction proof, empty-for-no-WireGuard);
`ppp_active`/`ipsec_active_peers`/`ospf_neighbors` (happy path + empty for
device without the feature); `bgp_sessions` (ROS7 happy path, ROS6
fallback, empty when neither path exists - mirroring
`wireless_registrations`' three-case coverage); `netwatch` (happy path
proving `has-up-script`/`has-down-script` booleans replace the raw
`up-script`/`down-script` fields, empty for no entries). All new tools are
exercised end to end through `server.py`'s `call_tool`, against
`tests/fakes.py`'s existing `FakeConnection`/`raise_for` mechanism - no
changes to `tests/fakes.py` itself were needed.

## [0.7.1] - Unreleased

Patch round: four bugs found testing v0.7.0 against real hardware (a ROS7
mANTBox at a lab IP and a ROS6 OmniTik), none of them caught by the
in-memory fake device suite because the fakes didn't match real
librouteros/RouterOS behavior closely enough. The write-guard mechanism
itself (read-only default, central allowlist, confirm/preview, audit
journal) is unchanged - every fix below tightens it, none weakens or
bypasses it.

### Fixed

- **`interface_traffic`/`poe_status`/`lte_status` raised `TypeError` on
  every real device (CRITICAL)** - `src/mcp_mikrotik/client.py`
  (`MikrotikClient.monitor_traffic`/`.poe_monitor`/`.lte_monitor`):
  librouteros' callable connection form (`connection(cmd, **kwargs)`)
  returns a **generator**, not a list - always truthy, never subscriptable.
  The old `replies[0] if replies else {}` on that raw generator raised
  `TypeError: 'generator' object is not subscriptable` on every call
  against real hardware (100% failure rate for these three read tools).
  Fixed by materializing with `list(connection(...))` first, exactly like
  `ping`/`traceroute` already did. `tests/fakes.py`'s
  `FakeConnection.__call__` previously returned a `list` for these three
  commands, which is why the fake suite never caught this - it now returns
  a real generator (`_once_reply_stream`), so a regression back to
  `replies[0]` would fail the suite again.
- **`set_wifi_ssid` rejected on ROS7 with a named `configuration`
  (CRITICAL)** - `src/mcp_mikrotik/guard.py`: on ROS7's standard production
  wifi layout, `/interface/wifi` interfaces reference a named
  `configuration` (e.g. `configuration=cfg1`) and have **no writable
  `ssid` field of their own** - the write was rejected by RouterOS
  ("unknown parameter ssid"). The ssid actually lives on the referenced
  `/interface/wifi/configuration` row. `set_wifi_ssid` now resolves this
  server-side: it reads the matched interface's own `configuration` field,
  looks up the matching `/interface/wifi/configuration` row by name, and
  reads/writes the ssid there - backed by a new allowlist entry,
  `set_wifi_ssid_ros7_configuration` (`("interface", "wifi",
  "configuration")`, action `update`), resolved the same way as every
  other guarded write (`_require_allowed` + `getattr(client, op.action)`
  dispatch, never a caller-supplied path). The `before`/`after` preview
  always reflects the ssid's real location - never a synthesized field
  that doesn't exist on the device. A wifi interface with no named
  `configuration` at all (rare/legacy) keeps writing an inline `ssid`
  field, unchanged. An unresolvable `configuration` name raises
  `ResourceNotFoundError`; an interface with neither an inline `ssid` nor a
  `configuration` reference raises a clear `DeviceCommandError` instead of
  sending a write RouterOS would itself reject. See README's "ROS7 wifi:
  `configuration`-based SSID".
- **WPA2 passphrase leaked into the audit journal (SECURITY)** -
  `src/mcp_mikrotik/audit.py` (`_SENSITIVE_KEY`): the sensitive-key regex
  covered `password`/`secret`/`token`/`credential` but not `passphrase` -
  `set_wifi_ssid`'s ROS7-`configuration` preview/apply (see above) reads
  the configuration row as `before`/`after`, and a real device's row can
  carry the WPA2 key under `passphrase`/`security.passphrase`. Extended
  the regex to also strip `passphrase`, `psk`, and any `pre-shared`/
  `pre_shared`/`preshared` spelling (covers `wpa-pre-shared-key`,
  `wpa2-pre-shared-key`, `pre-shared-key`, `pre_shared_key`, `preshared`
  case-insensitively) - recursively, nested included, same as
  `password`/`secret` already were.
- **`start_container`/`stop_container` leaked a raw device error on a
  device with no container support** - `src/mcp_mikrotik/guard.py`
  (`_set_container_running`): `client.path(*op.path)` was not wrapped, so
  a device with no container package/hardware at all (e.g. a ROS6-only
  box) raised a raw `DeviceCommandError` straight from the device's own
  RouterOS response, instead of degrading the way the read tool
  `containers()` already does (returns `[]`, no error). Now caught and
  raised as `ResourceNotFoundError` - the same clear error already used
  for "no container matches this name/tag" - never the raw device-side
  text.

### Tests

25 new tests (476 → 501, full suite green): generator-vs-list regression
tests for `monitor_traffic`/`poe_monitor`/`lte_monitor` (both against the
fakes' contract directly and against empty/non-empty generator replies);
`guard.set_wifi_ssid`'s new `configuration`-resolution path (preview+apply
writes to the configuration row and never the interface row, unknown
`configuration` name, ambiguous interface with neither shape, read-only
gate), plus an audit-journal test proving a `passphrase` field on that
configuration row never reaches the journal; `audit._SENSITIVE_KEY`
coverage for every new spelling (`passphrase`, `security.passphrase`,
`wpa2-pre-shared-key`, `wpa-pre-shared-key`, `psk`, `pre-shared-key`,
`pre_shared_key`, `preshared`), flat and nested; `start_container`/
`stop_container` against a device with no `/container` menu at all.

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
