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

**Recently shipped:** Network-config visibility — `interface_monitor`,
`dhcp_servers`, `dhcp_networks`, `bridge_ports`, `bridge_vlans` — landed in
**v1.7**, closing out the rest of Tier 2 (NTP/clock is now the only item
left): `interface_monitor` reads `/interface/ethernet/monitor once=yes` for
link status/rate/duplex plus SFP/DDM optics fields when a port has an SFP
cage and module (the command path was already verified against the
reference mANTBox; the DDM field *values* remain unverified — that board has
no SFP cage, see the Feasibility note below). `dhcp_servers`/`dhcp_networks`
read `/ip/dhcp-server` and `/ip/dhcp-server/network` — the server's own
config, as opposed to the already-shipped `dhcp_leases`. `bridge_ports`/
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
| **Safe Mode** (`/system/safe-mode`) | *(verified)* Not an API command — `/system/safe-mode/print` returns "no such command". RouterOS safe-mode is an interactive terminal feature (Ctrl-X). It needs an SSH/console session, which this project does not open. Other MCPs that offer it drive it over SSH. Worth naming the trade-off honestly: safe-mode is RouterOS's *best* anti-lockout mechanism, and giving it up is a real cost — the API-only compensating control we offer instead is mandatory before/after **preview (dry-run)** on every write. |
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
shipped" above). Tier 2 is well underway.

## Tier 2 — valued, mostly reads

Certificates (with expiry + a new `security_audit` check), Users/AAA read,
and RADIUS read shipped in **v1.6**; SFP/optical monitor, DHCP server
config, and bridge ports/VLAN filtering shipped in **v1.7** — see "Recently
shipped" above. Remaining:

- **NTP / clock** (`/system/ntp/client`, `/system/clock`) — read plus setting
  NTP servers. Clock drift breaks certs, logs and scheduling. ROS6/7 split to
  handle: ROS6 uses `primary-ntp`/`secondary-ntp`; ROS7 uses a `servers` list.

Guarded writes for bridge VLAN filtering (assigning a port's `pvid` /
`tagged`/`untagged` membership) are a natural Tier 2/3 follow-up now that the
read side exists, but are not yet scoped — see "How items graduate" below.

## Tier 3 — larger or design-gated

- **IPv6 parity** — addresses, routes, firewall, neighbor discovery. Today IPv6
  is only incidental (validators accept `::/0` etc., no dedicated tools). The
  largest single coverage gap. Trap: `/ipv6/*` errors if the `ipv6` package is
  disabled — reads must use the same skip-if-missing pattern `security_audit`
  already uses, not fail.
- **Advanced queuing** (`/queue/tree`, PCQ) — extends simple-queue bandwidth to
  real QoS hierarchies. Read first; guarded writes later.
- **Richer ROS7 Wi-Fi** (`/interface/wifi`) — today only `set_wifi_ssid`.
  Scope deliberately limited to **security-profile / passphrase** edits (the
  same pattern `set_wifi_ssid` already proves), **excluding channel and
  regulatory-domain** changes: those can disconnect an AP reached over its own
  radio — a real remote-lockout vector for the WISP CPEs this project courts.
  Also carries the same wifi-generation complexity the codebase already handles
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
