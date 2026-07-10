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

Highest audience value plus the cheapest wins: three of these just extend a
pattern already shipped and proven (toggle-by-comment, add/remove a leaf
object). All paths verified present on ROS7 (see caveats above).

- **PPP / PPPoE secrets** (`/ppp/secret`) — read (`ppp_secrets`) plus guarded
  `add_ppp_secret` / `remove_ppp_secret`. Today only `ppp_active` exists (active
  *sessions*, `server.py`), not the configured secrets — this is the gap. The
  single biggest audience of a public MikroTik tool runs PPPoE as an ISP, so
  this is table-stakes for them. It's a *service* credential (network access
  only, not router admin — see the non-goal above), and there's precedent:
  `add_hotspot_user` already creates a service credential the same way.
  Passwords redacted in the audit journal, same as the WPA2 passphrase handling.
- **NAT rule toggle by comment** (`/ip/firewall/nat`) — guarded
  `enable_nat_rule` / `disable_nat_rule`, mirroring the already-shipped
  `enable_firewall_rule` / `disable_firewall_rule` exactly. `firewall_nat` is
  read-only today; toggling an admin-authored port-forward for maintenance is
  the same proven, low-risk pattern (toggle only, never create). Near-zero
  marginal cost — likely the first thing to land.
- **Firewall mangle** (`/ip/firewall/mangle`) — read (`firewall_mangle`) plus
  enable/disable-by-comment. Same pattern as filter/NAT. Mangle usually *marks*
  rather than *drops*, so a toggle here is lower-risk than filter. No rule
  creation (same lockout reasoning as filter).
- **Static route add / remove** (`/ip/route`) — guarded `add_route` /
  `remove_route`. Today only *existing* routes can be manipulated
  (`set_route_distance`, `enable_route`, `disable_route`); adding a new static
  route is a basic admin operation with no filter-class lockout risk, fully
  previewable. The `disable_route` default-route guard already establishes the
  care pattern for the dangerous edge.

## Tier 2 — valued, mostly reads

- **Certificates** (`/certificate`) — read-only list with **expiry**
  (days-until-`invalid-after`). This would add a *new* check to `security_audit`
  (which does not check cert expiry today); an expired cert is a silent outage.
  Implementation note: RouterOS date formats for `invalid-after` vary by
  version/locale — parsing needs care.
- **Users / AAA (read)** (`/user`, groups, active sessions, SSH keys) — audit
  and visibility only (no creation — see non-goals). Low implementation risk:
  `security_audit` already reads `/user` internally (`security.py`), so the path
  is warm; this just surfaces groups/sessions/keys as a first-class tool.
- **SFP / interface optical & link monitor** (`/interface/ethernet/monitor`,
  `once`) — read-only. The command path is verified; the **DDM fields**
  (SFP tx/rx power, temperature, vendor) are **not** yet verified against real
  SFP hardware (the reference board has no SFP cage) and must be checked on a
  device with optics before shipping.
- **Bridge ports & bridge VLAN filtering** (`/interface/bridge/port`,
  `/interface/bridge/vlan`) — read first. This is the honest completion of the
  VLAN story: the shipped v1.2 VLAN tools operate on standalone
  `/interface/vlan` interfaces, but VLANs on managed MikroTik switches (CRS,
  hEX) are done via **bridge VLAN filtering**, which today has zero coverage.
  Read of port membership and the bridge/vlan table first; guarded writes later.
- **DHCP server config (read)** (`/ip/dhcp-server`, `/ip/dhcp-server/network`) —
  today only `dhcp_leases` exists. Reading the server/pool/network config is a
  small, ISP-relevant gap.
- **NTP / clock** (`/system/ntp/client`, `/system/clock`) — read plus setting
  NTP servers. Clock drift breaks certs, logs and scheduling. ROS6/7 split to
  handle: ROS6 uses `primary-ntp`/`secondary-ntp`; ROS7 uses a `servers` list.
- **RADIUS (read)** (`/radius`) — visibility into AAA config; pairs with users.

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
