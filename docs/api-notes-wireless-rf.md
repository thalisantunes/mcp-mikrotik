# API notes: wireless RF tuning (v1.11)

Facts verified live against real hardware on **2026-07-13**, operating two
MikroTik PtP (point-to-point) links in production: an 8.8km management-path
link and a 120m link. Hardware: **DISC Lite5 ac** and **LHG XL 5 ac**
(IPQ4019 chipset), **RouterOS 7.21.5**, `nv2` protocol. This document is the
durable record those facts are drawn from; `guard.py`'s inline comments
reference it rather than repeating the full write-up.

Everything here is scoped to `/interface/wireless` - see "Which menu, and
why" below for why that's a deliberate choice, not an oversight.

## Which menu, and why: `/interface/wireless`, not `/interface/wifi`

RouterOS 7 ships two different wireless menus depending on which package a
device runs:

- `/interface/wireless` - the legacy "wireless" package, RouterOS 6's menu
  carried forward. Full field set: `frequency`, `channel-width`, `tx-power`,
  `tx-power-mode`, `frequency-mode` (including `superchannel`),
  `adaptive-noise-immunity`, `distance`. Its registration-table publishes
  `signal-strength`, `signal-to-noise`, `tx-ccq`, `rx-ccq`, `distance`,
  `tx-rate`/`rx-rate`, `uptime` - everything a PtP link's CCQ/SNR/distance
  diagnosis needs.
- `/interface/wifi` - the newer "wifi"/"wifi-qcom-ac" package. Channel
  settings live under a nested `channel.frequency`/`channel.width` compound
  property (or a separate named `/interface/wifi/channel` profile); `tx-power`
  exists but **`tx-power-mode` does not** - there is no equivalent of
  `all-rates-fixed`. Its registration-table publishes `mac-address`,
  `signal`, `tx-rate`, `rx-rate`, `uptime` - per MikroTik's own docs, it does
  **not** publish `signal-to-noise`, `tx-ccq`, `rx-ccq`, or `distance` at
  all.

Every field name given to us verbatim by today's live session -
`tx-power-mode`, `frequency-mode=superchannel`, `channel-width`, and a
registration-table that genuinely returned `signal-to-noise`/`tx-ccq`/
`rx-ccq`/`distance` - matches `/interface/wireless` exactly, and does not
exist (or exists in a different shape) on `/interface/wifi`. That is strong,
direct evidence the fleet's PtP radios run the legacy `wireless` package
today - plausible on its own merits too: `nv2` and full link-quality
diagnostics have historically been better supported there than on the
newer package for these ac-chipset boards.

**Consequence for this release:** `get_wireless_link_quality`,
`set_wireless_channel`, `set_wireless_tx_power`, and `set_wireless_tuning`
all target `/interface/wireless` specifically. `wireless_registrations`
(unchanged, pre-existing) keeps trying `/interface/wifi` first and falling
back to `/interface/wireless`, same as before. `/interface/wifi` write
support (with its own `channel.*` field shapes) is explicitly **out of
scope** this round - see `ROADMAP.md`.

## The dead-man pattern (the headline feature)

Validated against the single highest-risk case in this fleet: the 8.8km
link is the **only** management path to the far-end device. Before a risky
write on a device like that, arm a scheduler **local to the target device**
that reverts the change and removes itself once it fires:

```
/system scheduler add name=<name> start-date=<date> start-time=<time> \
  interval=00:00:00 policy=read,write,test,policy,reboot \
  on-event=":log warning DEADMAN; <revert-commands>; \
             /system scheduler remove [find name=\"<name>\"]"
```

Key properties, both deliberate and verified (and, for the first one,
**re-verified after an initial mistake** - documented here in full because
the correction matters more than the original claim did):

- **One-shot (`interval=00:00:00`) with an EXPLICIT future `start-date`/
  `start-time`**, computed as `arm-time + N minutes` read from the TARGET
  DEVICE's own `/system/clock` (never this host's clock) - not an
  `interval`-only recurring schedule as originally shipped. Two rounds of
  live verification on 2026-07-13:
  - **First pass (WRONG, retracted):** appeared an `interval`-only
    schedule fired *immediately* on arm. This was a misread: what looked
    like an immediate fire was the API's own audit-log line
    (`topics=system,info`, "new script scheduled by api...", which echoes
    the new on-event's text back into the log) being mistaken for an
    actual on-event RUN.
  - **Re-verified filtering strictly by `topics=script,warning`** (the
    `:log warning` this package's own on-event always emits first, so it's
    the one topic that can only appear when the on-event genuinely runs):
    an `interval`-only schedule armed at `14:22:00` with
    `interval=00:01:00` did **not** fire until `14:23:00`
    (creation+interval, exactly once), then self-removed. `interval`-only
    does **not** fire on creation - that claim is retracted.
  - **The real, correct reason one-shot is still the right design:** if
    the on-event ever ABORTS partway through - RouterOS stops an on-event
    script entirely at its first unparseable statement, so a broken revert
    command means the trailing `/system scheduler remove` never runs
    either (see finding 2 below) - an `interval`-only schedule is still
    armed and keeps **re-firing the same broken on-event every interval,
    indefinitely**, until someone removes it by hand. A one-shot schedule
    fires exactly once no matter what happens inside it: a broken revert
    fails once and stays inert, never auto-retried. Good design, just for
    a non-repetition reason rather than an immediacy one.
  - Still midnight/month/year-rollover safe: real `datetime` + `timedelta`
    arithmetic computes the deadline (`guard._dead_man_deadline`), with an
    explicit `start-date` removing any ambiguity a `start-time`-only
    schedule would have about which day it applies to.
- **Explicit `policy=`.** RouterOS's own default policy on a freshly-added
  scheduler entry happened to be permissive enough to run this on-event
  (verified live), but the one scheduler entry whose entire job is
  self-healing a lockout should not depend on a device-side default -
  finding 6 of the 2026-07 hardening review.
- **Runs entirely on-device.** If the risky write is what broke reachability,
  the revert still runs - it does not depend on the API session, this
  process, or anything remote still being able to reach the device.
- **Self-removing on success.** The scheduler's own last statement is
  `/system scheduler remove [find name="<name>"]` - but that only runs if
  every statement before it parsed cleanly (see finding 2 below); a stale,
  un-self-removed scheduler entry after a broken revert is a real,
  documented possibility this package now tests for, not an assumed-away
  edge case.

**Also verified this round: librouteros write persistence.** Every write
this package sends goes through librouteros' `Path.update()`/`.add()`/
`.remove()` methods (`client.py`'s `MikrotikClient.update`/`add`/`remove` -
`connection.path(*segments).update(**fields)` etc.), confirmed to be the
calls that actually persist a change. The *callable* form of a Path object
(`connection.path(*segments)("set", ...)`) is a lazy generator and a silent
no-op unless iterated - `client.py` never uses that form for a write; it's
reserved for genuine RouterOS ACTION commands (`start`/`stop`/`move`) that
have no `update`/`add`/`remove` equivalent. Worth checking specifically
because it's exactly the kind of bug that would make a write tool report
"applied" without ever having touched the device - confirmed not present
anywhere in this codebase.

`mcp-mikrotik` implements this as two generic, reusable primitives -
`arm_dead_man`/`cancel_dead_man` (`guard.py`) - **not** wireless-specific.
`set_wireless_channel`/`set_wireless_tx_power` (and `set_wireless_tuning`
when given a numeric `distance` - see below) use them automatically by
default; any future risky write in another domain (a route, a bridge port,
a firewall rule) can call `arm_dead_man` directly with its own revert
commands. See README's "Dead-man / lockout-proof writes" section for the
full story and the security reasoning.

### `revert_commands` hardening (finding 2, hardened further after an opus re-review - 2026-07 hardening review)

`arm_dead_man` is exposed as a standalone MCP tool with caller-supplied
`revert_commands` - unlike this package's other write tools, it does accept
free-form RouterOS script text, which needed its own compensating controls:

- **Structural allowlist, not a denylist, is the primary control**
  (`_REVERT_COMMAND_SET_FIND_RE`, `validate_revert_command`). First shipped
  as a denylist of 5 dangerous verbs; an opus re-review of finding 3 found
  that insufficient - a denylist does not uphold this package's "no
  generic command path" invariant, since anything NOT enumerated still
  passed. Concretely, all of these passed the original denylist and each
  is a genuine, distinct lockout vector: `/ip/address remove [find ...]`
  (removes a management IP), `/ip/route remove [find ...]` (removes a
  route - e.g. the only route back across an 8.8km PtP link),
  `/ip/firewall/filter remove [find ...]` (drops firewall state entirely).
  A denylist also could not catch a malformed-but-safe-charset string like
  `/interface/wireless set [find name="x` (unbalanced quote/bracket) -
  RouterOS aborts the WHOLE on-event script at that kind of parse error
  (see "One-shot ... " above), so a broken `set` that still passed a
  denylist scan could silently defeat the dead-man's own self-remove too -
  a false sense of safety net. Replaced with a positive structural
  allowlist: every `revert_commands` item MUST match
  `/<path> set [find <field>="<value>"] <field>=<value> [...]` - the exact
  shape `_arm_wireless_revert` (confirmed the only builder of
  `revert_commands` in this codebase) already produces. `set` is the only
  verb ever accepted; `[find <field>="<value>"]` (a single selector, with a
  BALANCED quote and bracket) is mandatory, never a bare `.id`; at least
  one `field=value` assignment is required. This closes the 3 destructive
  commands above and the unbalanced-quote parse-abort vector at once,
  structurally rather than by enumeration - and also blocks a dangerous
  verb smuggled inside a field VALUE via nested command substitution (e.g.
  `comment=[/system reboot]`), since the value charset excludes `[`/`]`/
  spaces.
  - **Known, documented limitation**: a revert that needs to RECREATE a
    removed resource (`add`, not `set`) cannot be expressed via
    `revert_commands` today. No current caller needs this - deliberately
    not loosened speculatively; see `ROADMAP.md`.
- **Character hardening** (kept as an additional layer): rejects `$`, `;`,
  `` ` ``, `\`, `{`, `}` - characters that could smuggle a second statement
  into one `revert_commands` item, or invoke RouterOS script
  variable-substitution/block syntax. Deliberately does **not** reject `"`/
  `[`/`]` at the character-class level - RouterOS script's own
  `[find name="X"]` idiom needs exactly these three characters, and the
  structural allowlist above is what actually constrains how they can be
  used (only inside a single, balanced `[find ...]` selector).
- **Dangerous-verb denylist**: kept as a redundant, cheap extra layer under
  the structural allowlist (no longer the primary control) - `/system
  reboot`, `/system backup load`, `/user`, `/system reset-configuration`,
  `/system routerboard`, case-insensitive substring match. Still
  exercisable: `/user` fits the structural allowlist's field-VALUE charset
  (letters and `/` are both valid there, needed for values like
  `channel-width=20/40/80mhz-ceee`), so `comment=/user` passes the shape
  check and is caught by this denylist instead.
- **The fake test double (`tests/fakes.py`) now models RouterOS's
  abort-on-first-parse-error behavior**: `FakeConnection.fire_scheduler`
  stops at the first on-event statement it doesn't recognize, never
  running anything after it (including the self-remove) - proving, in
  tests, that a broken revert command leaves a stale scheduler entry
  behind instead of silently completing (this is also why one-shot
  scheduling matters, above - without it, that broken revert would keep
  re-firing).
- **Known, documented limitation (finding 7): no value-quoting in
  `_arm_wireless_revert`'s field=value assignments.** Safe today because
  every field this module ever reverts (`frequency`, `channel-width`,
  `tx-power`, `tx-power-mode`, `distance`) is a plain RouterOS enum/number
  with no space or special character. A future caller reusing that helper
  for a field whose value CAN contain one (an SSID, a comment) would need
  to add quoting - deliberately not added speculatively; see the comment
  at that call site.

## `set_wireless_channel`: DFS / Channel Availability Check

- **`frequency-mode=superchannel`: no DFS, no CAC.** Verified live: a
  channel switch under superchannel is instant. Superchannel is RouterOS's
  "Conformance Testing Mode" (allows every channel the card supports,
  bypassing the regulatory-domain channel/power restrictions) - see
  MikroTik's own docs for the regulatory caveat before using it outside a
  controlled environment.
- **Outside superchannel** (`frequency-mode=regulatory-domain` or
  `manual-txpower`), RouterOS imposes a Channel Availability Check before
  using a DFS-governed channel:
  - **~60s** for most of the DFS range, **5250-5725MHz**.
  - **~600s (10 minutes)** specifically for the **5600-5650MHz**
    weather-radar sub-band - this matches RouterOS's own
    `skip-dfs-channels=10min-cac` option name for that exact sub-band,
    which is corroborating evidence for the ~600s figure beyond today's own
    direct observation.
- `set_wireless_channel`'s preview `warning` always reports this: which
  case applies (instant / ~60s / ~600s / not a DFS channel), read from the
  interface's *current* `frequency-mode`, never assumed.

**`deadman_minutes` floor (finding 3 of the 2026-07 hardening review):**
the default `deadman_minutes=3` (180s) is *shorter* than the weather-radar
sub-band's ~600s CAC. Arming a dead-man with a window shorter than the CAC
its own target frequency requires would let the dead-man revert the
channel while the interface is still mid-CAC - before an operator could
ever confirm the link is actually back up. `set_wireless_channel` now
refuses (`ValidationError`) to arm in that situation, naming the required
`deadman_minutes`. The preview `warning` also notes when the dead-man's
*revert* target (the prior frequency) is itself DFS-governed - reverting
there would need its own CAC too.

**No partial reverts (finding 5 of the 2026-07 hardening review):** if
`channel_width` is given but the interface's current state has no
`channel-width` field to revert TO, `set_wireless_channel` refuses to arm
entirely (`DeviceCommandError`) rather than arm a dead-man that would
restore `frequency` but silently leave `channel-width` on the new value
forever if it ever fired.

## `set_wireless_tx_power`: default power can be too much

On a **short link**, RouterOS's default (maximum) `tx-power` **saturated the
receiver** and produced a **worse** CCQ than a lower power:

| tx-power | measured signal | CCQ |
|---|---|---|
| default (max) | -27dBm | 34 |
| ~8dBm | -47dBm | 94 |

Fix: `tx-power-mode=all-rates-fixed` + an explicit `tx-power=<dbm>`. There
is no universally "right" power - it depends on link distance, antenna
gain, and how close the receiver already is to saturation - `set_wireless_
tx_power` applies whatever the caller supplies; use `get_wireless_link_
quality` before/after to judge the effect on a given link.

**Transient re-adaptation, not a failure:** changing tx-power causes
RouterOS to re-adapt its rate selection over the next few seconds - a
temporary CCQ/rate dip immediately after applying is expected. Re-check a
few seconds later, not immediately.

**Fail-safe revert (finding 4 of the 2026-07 hardening review):** the
dead-man's revert restores this interface's prior `tx-power-mode`/
`tx-power` - if either field is missing from the interface's current
state, `set_wireless_tx_power` refuses to arm (`DeviceCommandError`) rather
than fabricate a `"default"`/`"0"` fallback that could revert to a power/
mode the interface never actually had.

## `set_wireless_tuning`: `adaptive-noise-immunity` and `distance`

- **`adaptive-noise-immunity=ap-and-client-mode`**: with *good* signal but
  *poor* CCQ (a classic interference signature, as opposed to a distance/
  power problem), switching this on measurably helped. Confirmed safe (does
  not drop an already-associated link) - given alone, never arms a
  dead-man.
- **`distance=<km>`**: for a long verified PtP link, an explicit distance
  (e.g. `9` for a ~9km link) gave a better ACK timeout than leaving it on
  `dynamic`. `distance` controls RouterOS's ACK-timeout formula
  (`((distance * 1000) + 299) / 300` microseconds) - too short a timeout on
  a long link causes retries/CCQ loss even with an otherwise-clean signal.
  **Finding 1 of the 2026-07 hardening review:** unlike the named
  `dynamic`/`indoors` modes, a NUMERIC `distance` directly sets that
  ACK-timeout/TDMA slot timing - confirmed this can silently drop an
  already-associated link if the value undershoots the real link length
  (e.g. `distance=1` on a 9km link), with no protocol-level recovery of its
  own. Treated as LOCKOUT-RISK exactly like `set_wireless_channel`/
  `set_wireless_tx_power`: a numeric `distance` now arms a dead-man by
  default (`arm_deadman=True`, `deadman_minutes` default 3) whose revert
  restores the prior `distance`. `dynamic`/`indoors` (RouterOS's own named,
  self-managed modes) and `adaptive-noise-immunity` alone never do.

## `get_wireless_link_quality`: what's normalized

Extends the existing `wireless_registrations` read (same underlying
`/interface/wifi/registration-table` → `/interface/wireless/
registration-table` fallback, factored into a shared helper - see
`server._wireless_registration_rows`) with a fixed, per-peer normalized
shape focused on the fields that actually diagnose a PtP/PtMP link:
`signal_strength`, `signal_to_noise`, `tx_ccq`, `rx_ccq`, `tx_rate`,
`rx_rate`, `distance`, `uptime` (`formatting.normalize_wireless_
registration`). Never fabricates a field the underlying generation doesn't
publish (see "Which menu, and why" above for the `/interface/wifi` gap) -
those come back `None`.

## Field reference (as verified today)

| Field | Menu | Notes |
|---|---|---|
| `frequency` | `/interface/wireless` | MHz |
| `channel-width` | `/interface/wireless` | e.g. `20mhz`, `40mhz-turbo`, `20/40mhz-Ce`, ... (RouterOS's fixed enum) |
| `frequency-mode` | `/interface/wireless` | `regulatory-domain` (default) / `manual-txpower` / `superchannel` |
| `tx-power` | `/interface/wireless` | dBm, RouterOS documented range -30..40 |
| `tx-power-mode` | `/interface/wireless` | `default` / `card-rates` / `all-rates-fixed` / `manual-table` |
| `adaptive-noise-immunity` | `/interface/wireless` | `none` (default) / `client-mode` / `ap-and-client-mode` - Atheros chipsets only |
| `distance` | `/interface/wireless` | `dynamic` (default) / `indoors` / an integer number of km |
| `signal-strength`, `signal-to-noise`, `tx-ccq`, `rx-ccq`, `distance`, `tx-rate`, `rx-rate`, `uptime`, `mac-address` | `/interface/wireless/registration-table` | full set, per peer |
| `signal`, `tx-rate`, `rx-rate`, `uptime`, `mac-address` | `/interface/wifi/registration-table` | narrower set - no SNR/CCQ/distance |
