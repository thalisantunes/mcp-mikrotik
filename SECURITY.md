# Security Policy

`mcp-mikrotik` connects to and can configure real network hardware, using
real admin credentials (see `devices.yaml`). Its whole design - read-only by
default, a central allowlist instead of a generic command tool, confirm/
preview on every write, no secret ever logged or journaled - exists to keep
that surface as small and reviewable as possible (see README's "Security
model"). If you find a way around any of it, please report it privately
rather than as a public issue.

## Supported versions

This project is pre-1.x-stable in the sense that only the latest release on
`main` is supported. Security fixes are made against the latest version;
there is no maintained backport branch for older tags.

| Version           | Supported |
| ------------------ | --------- |
| Latest (`main`)    | ✅        |
| Older tagged releases | ❌     |

## What counts as a vulnerability here

Report anything that lets an MCP caller (or an attacker in a position to
influence one) do more than the documented tool surface allows, in
particular:

- A way to reach a write (`update`/`add`/`remove`/any device-mutating call)
  while `MIKROTIK_ALLOW_WRITE` is `false`, or without going through
  `guard.ALLOWLIST`'s confirm/preview flow.
- A way to reach an arbitrary RouterOS API path or command - there should be
  **no** code path to this at all; if you find one, that's the most
  serious class of bug this project can have (see README's "Status").
- A device password, WireGuard private/preshared key, hotspot voucher
  password, or backup-encryption password reaching a log line, an error
  message returned to the caller, or the audit journal
  (`MIKROTIK_AUDIT_LOG`) - see README's "WireGuard management" and
  "Production hardening" sections for what's supposed to prevent this.
- Command injection - anything that lets a value passed through a tool
  argument change *which* RouterOS command runs, rather than only its
  parameter values (see README's "Structured API, not shell commands").
- A TLS verification bypass that isn't the explicit, opt-in, per-device
  `tls_verify: false` documented in README's "TLS verification for
  api-ssl".
- Any way for one configured device's tool call to affect a different
  device, or to read config/credentials belonging to a device the caller
  didn't name.

Input-validation gaps that reject malformed input less strictly than
intended (e.g. a slightly too-permissive regex) are welcome as normal
issues/PRs rather than private reports, **unless** they let something in
the list above happen - when in doubt, report privately; it's easy to
downgrade a private report to a public issue, not the other way around.

## How to report

**Please do not open a public GitHub issue for a security report.**

Preferred: use GitHub's private vulnerability reporting for this repository
- open the [**Security** tab →
**Report a vulnerability**](https://github.com/thalisantunes/mcp-mikrotik/security/advisories/new).
This creates a private advisory only the maintainer (and anyone you invite)
can see, with room for a full writeup, and lets a fix be prepared and
coordinated before anything is disclosed publicly.

Include, as far as you can:

- What tool(s)/code path are involved.
- Steps to reproduce - ideally against the in-memory fake device layer
  (`tests/fakes.py`) so it's trivially reproducible without needing access
  to real hardware; if it only reproduces against a real device, describe
  the RouterOS version/generation.
- The impact - what an attacker gains, and what they'd need to already have
  access to for the report to matter (e.g. "requires MCP tool access" is a
  very different bar than "requires nothing").
- A suggested fix, if you have one - not required.

### Secret redaction when reporting

If your report needs to include a real value to demonstrate the bug (e.g. a
log line that leaked a credential), **redact the actual secret** first -
replace it with an obviously-fake placeholder (e.g.
`REDACTED-WOULD-BE-THE-DEVICE-PASSWORD-HERE`) and describe its shape/length
instead of pasting the real value, the same way this project's own test
suite uses distinctive marker strings (e.g.
`FAKE-PRIVATE-KEY-MUST-NEVER-LEAK-...` in `tests/fakes.py`) rather than
real key material. A private advisory is only visible to the maintainer and
anyone explicitly invited, but redacting first costs nothing and avoids a
copy/paste mistake later.

## What to expect

This is a single-maintainer open-source project, not a company with an SLA
- there's no guaranteed response time, but security reports are
prioritized over everything else. You can expect an acknowledgment, an
assessment of severity/scope, and - once a fix is ready - credit in the
advisory and `CHANGELOG.md` (unless you'd prefer to stay anonymous, which
is fine too, just say so in the report).
