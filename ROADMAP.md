# Roadmap

This roadmap is shaped — and deliberately constrained — by the project's
security model. Read [`README.md`](README.md) ("Security model") and
[`CONTRIBUTING.md`](CONTRIBUTING.md) first; every item below is filtered
through the same invariants:

- **Read-only by default.** Write tools require `MIKROTIK_ALLOW_WRITE=true`.
- **No generic "run any command".** Every write is an individually named tool
  behind the central allowlist in `guard.py`, dispatched via
  `getattr(client, op.action)` for a fixed set of actions
  (`update/add/remove/start/stop/flush/wol/save/move`).
- **API-only transport.** The server speaks only the RouterOS binary API
  (`librouteros`, port 8728). It does **not** open SSH sessions. This is a
  founding decision — the fork audit that motivated this project rejected an
  SSH `command()` primitive as an injection and lockout risk. Any feature that
  can only be done over the CLI is therefore out of scope *by construction*,
  not by omission.
- **Guarded writes preview before they apply** (dry-run), validate their
  inputs (`validation.py`), and never log secrets (`audit.py`).

Nothing here is a commitment or a schedule. It's a prioritized, honest map of
what fits the model, what doesn't, and why. Community proposals are welcome —
see `CONTRIBUTING.md`.

**Recently shipped:** Wireless RF tuning + the dead-man primitive —
`set_wireless_channel`/`set_wireless_tx_power`/`set_wireless_tuning`
(guarded writes) and `get_wireless_link_quality` (read) — landed in
**v1.11**, alongside `arm_dead_man`/`cancel_dead_man`, a reusable
anti-lockout primitive (arm a local, self-removing RouterOS scheduler that
reverts a risky write after N minutes unless cancelled) that
`set_wireless_channel`/`set_wireless_tx_power` use automatically by
default. This is the compensating control the "Richer ROS7 Wi-Fi" item
below named as the reason channel/regulatory-domain changes were excluded
— see that item's updated note. All four wireless tools target
`/interface/wireless` specifically (confirmed via real hardware, 2026-07,
to be what the fleet's ac-chipset PtP radios actually run on ROS 7.21.5 —
see `docs/api-notes-wireless-rf.md`), not ROS7's newer `/interface/wifi`
package. Hardware-verified: DFS/Channel-Availability-Check behavior
(instant under `frequency-mode=superchannel`, ~60s in the general DFS
range, ~600s in the 5600-5650MHz weather-radar sub-band), a tx-power
saturation finding on a short link (default/max power measured worse CCQ
than a lower explicit power), and `adaptive-noise-immunity`/`distance`
tuning improvements on a real PtP deployment.

Before that: IPv6 write parity — `enable_ipv6_firewall_rule`/
`disable_ipv6_firewall_rule`, `add_ipv6_route`/`remove_ipv6_route`,
`add_to_ipv6_address_list`/`remove_from_ipv6_address_list` — landed in
**v1.10**, closing out Tier 3's "IPv6 parity" item entirely (reads in v1.9,
writes here). Each mirrors an existing IPv4 write tool field-for-field on
the equivalent `/ipv6/*` path — `enable_firewall_rule`/
`disable_firewall_rule`, `add_route`/`remove_route` (including its refusal
to remove a dynamic route, via `coerce_ros_bool`), `add_to_address_list`/
`remove_from_address_list` — with IPv6-only address validation rejecting an
IPv4 value outright. Handles the trap flagged below DIFFERENTLY than the
v1.9 reads: those catch `DeviceCommandError` from a disabled `ipv6` package
and return `[]`; these six writes deliberately let it propagate instead —
a write has no safe empty-result fallback. Not verified against real
hardware this round (v1.9's reads were, on both ROS6 and ROS7) — see
`CHANGELOG.md`'s v1.10 entry.

Before that: IPv6 read parity — `ipv6_addresses`, `ipv6_routes`,
`ipv6_firewall_filter`, `ipv6_neighbors`, `ipv6_firewall_address_lists`
(all read-only) — landed in **v1.9**, opening up Tier 3. Each mirrors an
existing IPv4 read tool field-for-field on the equivalent `/ipv6/*` path
(`ip_addresses`, `ip_routes` including its `limit`, `firewall_filter`,
`arp_table`, `address_lists`, respectively). Handles the trap this item was
flagged for below: the whole `/ipv6/*` subtree raises if the `ipv6` package
is disabled on the device, so every tool uses the same skip-if-missing
pattern `security_audit`/`wireguard_peers`/`ppp_active`/etc. already use —
catch `DeviceCommandError`, return `[]`, never propagate.

Before that: NTP client + clock — `ntp_client`, `system_clock`
(read), `set_ntp_servers` (guarded write) — landed in **v1.8**, closing out
Tier 2 entirely (see the note below). `ntp_client`/`system_clock` read
`/system/ntp/client` and `/system/clock`, returning every field the device's
reply actually carries (nothing invented); `set_ntp_servers` detects which
of the two field shapes a device speaks — ROS7's single `servers` list vs
ROS6's fixed `primary-ntp`/`secondary-ntp` slots, both on the SAME RouterOS
path — the same "read first, then decide" detection `set_wifi_ssid` already
established for its own ROS6/ROS7 split. Never verified against real ROS6
hardware — see `CHANGELOG.md`'s v1.8 entry for the honest gap.

Before that, Network-config visibility — `interface_monitor`, `dhcp_servers`,
`dhcp_networks`, `bridge_ports`, `bridge_vlans` — landed in **v1.7**:
`interface_monitor` reads `/interface/ethernet/monitor once=yes` for link
status/rate/duplex plus SFP/DDM optics fields when a port has an SFP cage
and module (the command path was already verified against the reference
mANTBox; the DDM field *values* remain unverified — that board has no SFP
cage, see the Feasibility note below). `dhcp_servers`/`dhcp_networks` read
`/ip/dhcp-server` and `/ip/dhcp-server/network` — the server's own config,
as opposed to the already-shipped `dhcp_leases`. `bridge_ports`/
`bridge_vlans` read `/interface/bridge/port` and `/interface/bridge/vlan` —
the honest completion of the VLAN story for a managed switch (bridge VLAN
filtering), distinct from the standalone `/interface/vlan` interfaces the
v1.2 VLAN tools manage. All read-only; every boolean field touched goes
through `formatting.coerce_ros_bool`, never a `== "true"` comparison.

AAA/PKI visibility — `certificates`, `users`,
`user_active`, `radius` — landed in **v1.6**:
`certificates` reads `/certificate` with a computed `daysUntilExpiry`
(RouterOS's date rendering handled defensively across its two known
shapes — see `formatting.parse_ros_datetime`) and a new `security_audit`
check (#8) flagging an expired or soon-to-expire (<=30 days) certificate;
`users`/`user_active` surface `/user`/`/user/active` for AAA visibility
(read only — creating/editing a `/user` login stays a non-goal, see
below); `radius` reads `/radius` with the shared `secret` field ALWAYS
stripped before returning, same redaction mechanism `ppp_secrets` uses for
`/ppp/secret`'s `password`. Static route add/remove — `add_route` /
`remove_route` — landed in **v1.5**, closing out Tier 1: `add_route`
creates a static route (never refusing a duplicate `dst-address` — that's
the normal failover shape) and `remove_route` deletes one resolved by
`dst-address`/`gateway`, **refusing outright to remove a dynamic/connected
route** (`dynamic=true`) — the single most important safety property in
that round. Both carry the same default-route `warning` `disable_route`
(v0.9) already established. NAT rule toggle + firewall mangle (read +
toggle) — `enable_nat_rule` / `disable_nat_rule`, `firewall_mangle` (read),
`enable_mangle_rule` / `disable_mangle_rule` — landed in **v1.4**,
mirroring `enable_firewall_rule` / `disable_firewall_rule` (v0.11) exactly:
toggle an EXISTING, admin-authored rule by `comment`, never create one.
PPP/PPPoE secrets — `ppp_secrets` (read), `add_ppp_secret` /
`remove_ppp_secret` (guarded) — landed in **v1.3** (read+add+remove
verified against real ROS7 hardware; password redacted in the audit
journal and never returned by the read).

## Feasibility note

Candidate API paths were probed against real hardware — a **mANTBox ax 15s on
RouterOS 7.21.5, 2026-07** — to confirm the path exists and answers over the
binary API before landing on the roadmap. Two caveats on what *(verified)*
means, per item:

- It confirms **the path responds**, not that every field is populated on every
  board. Where a feature depends on hardware the reference board lacks (e.g. SFP
  DDM optics — the mANTBox has no SFP cage), that's called out explicitly and
  the field-level behavior is **not** yet verified.
- Probing was on **ROS7**. RouterOS 6 can differ in menu paths and field names;
  where a ROS6/ROS7 split is known or likely, it's flagged. The target audience
  (WISPs) still runs plenty of ROS6, so a write item isn't "done" until it's
  checked on both.

---

## Explicitly NOT on the roadmap

These are common asks that either break the security model or are impossible
over the binary API. Documenting them saves everyone a duplicate issue.

| Not doing | Why |
|---|---|
| **Safe Mode** (`/system/safe-mode`) | *(verified)* Not an API command — `/system/safe-mode/print` returns "no such command". RouterOS safe-mode is an interactive terminal feature (Ctrl-X). It needs an SSH/console session, which this project does not open. Other MCPs that offer it drive it over SSH. Worth naming the trade-off honestly: safe-mode is RouterOS's *best* anti-lockout mechanism, and giving it up is a real cost — the API-only compensating control we offer instead is mandatory before/after **preview (dry-run)** on every write, plus (since **v1.11**) the **dead-man** primitive (`arm_dead_man`/`cancel_dead_man`) for LOCKOUT-RISK writes specifically — a local, self-removing RouterOS scheduler that reverts the change after N minutes unless explicitly cancelled. Not identical to Safe Mode (which reverts on session *disconnect*; the dead-man reverts on a *timer*, cancelled explicitly) but the same spirit, achieved API-only. See README's "Dead-man / lockout-proof writes". |
| **Text config export / diff** (`/export`) | *(verified)* `/export` is accepted over the API but returns **zero** data — it's a CLI-only renderer. A textual export/diff needs SSH. See "API-only config snapshot" below for an in-architecture alternative. |
| **Device reboot** (`/system/reboot`) | No meaningful before/after preview; a batch reboot has no dry-run or rollback. |
| **Backup restore** (`/system/backup/load`) | Same risk class as reboot — overwrites the entire running config and reboots. |
| **Firewall filter rule creation / free-form edit** | A single wrong rule (e.g. blocking the API port) causes a permanent remote lockout with no recovery path. Only enabling/disabling and reordering admin-authored rules (by comment) is exposed. The same reasoning is why write items below stop at *toggle by comment*, never *create*, for filter/NAT/mangle. |
| **Router login (`/user`) creation / edit** | Creating a RouterOS *login* grants admin/API access to the device itself — privilege escalation and a lockout vector. This is a different risk class from *service* credentials like PPP secrets or hotspot users (which only grant network/dial-in access and can't touch the box's own config), which is why those **are** on the roadmap and this is not. Reading `/user` for audit is fine (see Tier 2). |
| **Generic command execution** | Never. Only individually named, allowlisted operations. |

An **opt-in, hardened SSH transport** purely to unlock Safe Mode and `/export`
is a possible future *decision* — but it reintroduces exactly the attack
surface this project was built to avoid, so it would need a strong,
separately-argued case. The default stance is: stay API-only.

---

## Tier 1 — next up

Tier 1 items have all shipped (v1.3 – v1.5: PPP/PPPoE secrets, NAT rule
toggle + firewall mangle, and static route add/remove — see "Recently
shipped" above). Tier 2 is complete.

## Tier 2 — valued, mostly reads

**Tier 2 complete (v1.6 – v1.8).** Certificates (with expiry + a new
`security_audit` check), Users/AAA read, and RADIUS read shipped in **v1.6**;
SFP/optical monitor, DHCP server config, and bridge ports/VLAN filtering
shipped in **v1.7**; NTP client + clock (read plus guarded `set_ntp_servers`)
shipped in **v1.8**, closing out everything this tier ever named — see
"Recently shipped" above for all three rounds. Tier 3 (IPv6 parity, advanced
queuing, richer ROS7 Wi-Fi, CAPsMAN, RouterOS CVE check, API-only config
snapshot & diff) is now next — **IPv6 parity is complete** (reads in
**v1.9**, writes in **v1.10** — see "Recently shipped" above); the rest of
Tier 3 remains open.

Guarded writes for bridge VLAN filtering (assigning a port's `pvid` /
`tagged`/`untagged` membership) are a natural Tier 2/3 follow-up now that the
read side exists, but are not yet scoped — see "How items graduate" below.

## Tier 3 — larger or design-gated

- **IPv6 parity — COMPLETE.** Reads shipped in **v1.9** (`ipv6_addresses`,
  `ipv6_routes`, `ipv6_firewall_filter`, `ipv6_neighbors`,
  `ipv6_firewall_address_lists`); writes shipped in **v1.10**
  (`enable_ipv6_firewall_rule`/`disable_ipv6_firewall_rule`,
  `add_ipv6_route`/`remove_ipv6_route`, `add_to_ipv6_address_list`/
  `remove_from_ipv6_address_list`) — see "Recently shipped" above for both.
  IPv6 NAT (NPT) remains explicitly out of scope, same reasoning as its
  IPv4 write-family boundaries (see "Explicitly NOT on the roadmap" above).
- **Advanced queuing** (`/queue/tree`, PCQ) — extends simple-queue bandwidth to
  real QoS hierarchies. Read first; guarded writes later.
- **Richer ROS7 Wi-Fi** (`/interface/wifi` specifically) — today only
  `set_wifi_ssid` writes here. **UPDATE (v1.11):** the reason channel/
  regulatory-domain changes were excluded — "those can disconnect an AP
  reached over its own radio, a real remote-lockout vector" — now has a
  compensating control: the dead-man primitive (`arm_dead_man`/
  `cancel_dead_man`, see "Recently shipped" above), which
  `set_wireless_channel`/`set_wireless_tx_power` already use by default on
  `/interface/wireless` (the legacy menu, confirmed to be what this
  project's own PtP fleet actually runs). Porting channel/tx-power/tuning
  writes to `/interface/wifi` itself — a genuinely different field shape
  (`channel.frequency`/`channel.width` nested properties, no
  `tx-power-mode` equivalent at all — see `docs/api-notes-wireless-rf.md`)
  — is no longer excluded on lockout-risk grounds, just not yet scoped/
  hardware-verified. Security-profile/passphrase edits (`set_wifi_ssid`'s
  existing pattern) remain the only `/interface/wifi` write shipped. Still
  carries the same wifi-generation complexity the codebase already handles
  (`/interface/wifi` vs `/interface/wireless` on ROS6 vs `/interface/wifi/
  configuration`, plus `wifiwave2` on ROS7 before 7.13).
- **CAPsMAN / centralized Wi-Fi** (`/caps-man` on ROS6, CAPsMAN under
  `/interface/wifi` on ROS7) — centrally managed AP fleets, precisely what
  WISP/fleet operators run. Read of managed APs/provisioning first. Larger and
  generation-split, hence Tier 3, but explicitly *on* the map rather than a
  silent omission.
- **RouterOS CVE check** — extend `security_audit` (which already flags a
  stale/updatable version via `/system/package/update`) with a curated,
  embedded list of known-vulnerable releases to name specific CVEs. Design
  question: the CVE data must ship *with* the binary (no runtime network calls,
  consistent with the offline OUI table), so it goes stale between releases —
  worth it only if kept honest about its "as of" date.
- **API-only config snapshot & diff** — the in-architecture answer to the
  `/export` gap: read a defined set of config menus over the API, serialize
  into a canonical, stable form, and diff two snapshots. More work than a CLI
  `/export`, never byte-identical to it, but stays API-only and is genuinely
  useful for change tracking. Read-only.

---

## How items graduate

A roadmap item becomes a release when it has: named tools (read and/or guarded
write), input validation, before/after preview for any write, tests against the
fakes **and** — because behavior is routinely version- or hardware-sensitive —
a real ROS6 **and** ROS7 hardware check, plus zero secrets in code, tests, or
the journal. See `CONTRIBUTING.md` for the step-by-step.
