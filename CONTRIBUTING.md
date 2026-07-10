# Contributing to mcp-mikrotik

Thanks for considering a contribution. This project manages real network
hardware (including admin credentials), so its bar for a merged PR is a bit
higher than a typical library: every write path has to be provably safe by
construction, not just "tested and it worked." This document explains how to
get set up, the security model every PR must respect, and how to add a new
tool (read or write) the same way the existing ~65 already are.

## Getting set up

Requirements: Python 3.11+.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

This installs the package in editable mode plus its dev tooling: `pytest`/
`pytest-asyncio`/`pytest-cov`, `ruff` (lint + format), and `mypy` (type
checking).

### Running the checks locally

Run these before opening a PR - CI (`.github/workflows/ci.yml`) runs the
same three, and a PR can't merge until all of them pass on Python 3.11,
3.12, and 3.13:

```bash
# Tests - the suite never touches a real router (see tests/fakes.py); it's
# entirely in-memory and fast.
pytest -q

# Tests + coverage report. CI fails the build under 95% - see "Test
# coverage" below for what that means in practice.
pytest --cov=mcp_mikrotik --cov-report=term-missing --cov-fail-under=95

# Lint + format (auto-fixable issues: `ruff check --fix .` / `ruff format .`)
ruff check .
ruff format --check .

# Type-check
mypy src/mcp_mikrotik
```

### Test coverage

The suite currently sits at 100% line coverage, with two narrow, explicitly
marked (`# pragma: no cover`) exceptions: the process entrypoint (`main()`/
`if __name__ == "__main__":` in `server.py`, which blocks on stdio for the
life of the process - not something a test suite drives) and a stray
`except PackageNotFoundError` fallback in `__init__.py` that only matters
when the package is imported without being installed at all. CI's floor is
set at 95%, not 100%, to leave headroom for a PR that adds a small amount of
genuinely hard-to-reach code without blocking on it - but the expectation is
still that **new code ships with tests that exercise it**, including its
error paths, not just its happy path. A PR that measurably drops coverage on
an existing module without a good reason will be asked to add tests, not to
lower the floor.

## The security model every PR must respect

This is the part that matters most. Read `README.md`'s "Security model"
section in full before writing a new write tool - what follows is the
condensed checklist a reviewer will actually check your PR against.

1. **Read-only by default.** `MIKROTIK_ALLOW_WRITE` defaults to `false`.
   Every write tool must be blocked by the read-only gate before it ever
   reads or writes anything on the device - this is `guard.py`'s
   `_require_allowed`, checked first, unconditionally.

2. **Every new write goes through the central allowlist - never a generic
   command tool.** There is exactly one place in this codebase allowed to
   call `MikrotikClient.update()/add()/remove()`/etc: `src/mcp_mikrotik/
   guard.py`. `server.py` never calls those methods directly. A new write
   is:
   - One new `WriteOperation` entry in `guard.ALLOWLIST`, naming the single
     RouterOS API path + action (`update`/`add`/`remove`/`start`/`stop`/
     `flush`/`wol`/`save`) it is allowed to touch - see the comment block at
     the top of `guard.py`.
   - One new function in `guard.py` (model it on `set_identity`, the
     module's own "exemplary write tool") that resolves the target,
     validates input, builds a `before`/`after` preview, and only applies
     the change when `confirm=True`.

   **There is no "just add a path parameter" shortcut.** A tool that
   accepts an arbitrary RouterOS path or command string will not be
   merged, no matter how it's gated - this is the exact failure mode this
   project exists to correct (see README's "Status" section). If your use
   case doesn't fit the existing allowlist shape, open an issue to discuss
   the design first rather than sending a generic-command PR.

3. **Explicit confirm, with a before/after preview.** Every write function
   takes `confirm: bool`. With `confirm=False` (the tool's default), compute
   and return what *would* change without calling the device's write
   primitive at all. Only `confirm=True` applies it. `server.py`'s tool
   wrapper passes `confirm` straight through - it never defaults it to
   `True` on the caller's behalf.

4. **Validate before ever touching the device.** Every parameter that
   reaches a write function goes through a dedicated validator in
   `validation.py` first (shape/charset/range checks - see the existing
   `validate_*` functions for the pattern). This is not an injection
   defense by itself (see point 6) - it exists to reject obviously-bad
   input with a clear error before spending a round trip to the device.

5. **Never create something a name-based lookup didn't find, never
   silently duplicate.** A write tool that targets an existing resource
   (an interface, a route, a DNS record, ...) must look it up first and
   raise `ResourceNotFoundError` if nothing matches - never fall back to
   creating one. A write tool that creates something must check for an
   existing duplicate first and raise `ResourceAlreadyExistsError` instead
   of creating a second one. Resolve by a stable, admin-meaningful
   identifier (name, comment, `dst-address`+`gateway`, ...) - **never** a
   RouterOS `.id` or a list index, both of which can shift as unrelated
   rows are added/removed elsewhere on the device. If more than one row
   still matches after narrowing, raise `AmbiguousResourceError` - never
   guess which one to touch.

6. **Structured API only - never build a command by string
   concatenation.** All device communication goes through `librouteros`'s
   structured API (`client.path(...).add()/.update()/.remove()`, or the
   callable one-off-command form). This rules out command injection by
   construction, not by input filtering - a new write function must follow
   the same pattern, never `f"...{user_input}..."`-style command building.

7. **A password/passphrase/private-key/preshared-key must never reach a
   log line, an error message, or the audit journal.** This is the single
   most security-critical rule in the codebase (see README's "WireGuard
   management" section for the two-layer redaction it's built around).
   Concretely:
   - If your new tool's `before`/`after` preview can ever carry a
     secret-shaped field (a password, a private/preshared key, ...),
     redact it **before** constructing the `WritePreview` in `guard.py` -
     not one layer up in `server.py`, after the audit journal's `_audited`
     decorator has already logged it. See `guard.py`'s
     `_redact_wireguard_row` for the pattern.
   - `audit._SENSITIVE_KEY` (in `audit.py`) is a **second, independent**
     backstop that strips any field whose name looks secret-shaped
     (`password`, `secret`, `token`, `pre.?shared`, `private`, ...) from
     the journaled summary, recursively. Don't rely on it alone - it exists
     in addition to the guard-layer redaction above, not instead of it.
   - A tool whose whole point is to hand a plaintext credential back to the
     caller (e.g. `add_hotspot_user`'s voucher password) is the one
     deliberate exception: the *result* can carry it, but the *audit
     journal* still never does - `audit._SENSITIVE_KEY` already covers
     this without extra code, since it matches on the field name, not on
     which tool produced it.

8. **Structured errors, not raw tracebacks.** Raise a subclass of
   `MikrotikMCPError` (`exceptions.py`) for anything a caller should see a
   clear message for. `server.py`'s `_safe` wrapper re-raises those as-is
   and turns anything else into a generic internal-error message - never
   let a raw exception (or a raw device error string that might embed
   something sensitive) reach a caller directly.

A PR that adds a write tool without an allowlist entry, without a
confirm/preview split, without input validation, or that risks a secret
reaching a log line, will be sent back for changes regardless of how well
it's tested otherwise - this list is not optional polish, it's the reason
this project exists as a from-scratch rewrite (see README's "Status"
section for the concrete failures it was built to avoid).

## Adding a new tool

### Adding a read-only tool

Read tools are the simpler case - no allowlist entry needed, since they
never touch `MIKROTIK_ALLOW_WRITE` or the write guard.

1. Add a `MikrotikClient` method in `client.py` if the read needs anything
   beyond a plain `client.path(*segments)` (e.g. a "monitor once" command -
   see `lte_monitor`/`poe_monitor` for the pattern, including the
   "materialize with `list(...)` before returning" note their docstrings
   call out).
2. Register a new `@mcp.tool()` function in `server.py`'s "Read tools"
   section. Give it a clear one-line docstring (server.py's docstrings are
   what an LLM caller actually reads to decide when to use a tool) and, for
   a menu that doesn't exist on every RouterOS generation/device
   (optional hardware, a package that isn't installed, ...), degrade
   gracefully: catch `DeviceCommandError` and return an empty
   list/dict rather than propagating an error - see `netwatch`/
   `lte_status`/`poe_status` for the convention.
3. Add the tool name to `EXPECTED_TOOLS` in `tests/test_server.py`.
4. Add tests: a happy-path test driven through `mcp.call_tool(...)` (not by
   calling the plain Python function directly - see `test_server.py`'s
   module docstring for why), and, if the tool degrades on
   `DeviceCommandError`, a test proving that too. If the read can leak a
   secret-shaped field from the underlying RouterOS menu (see WireGuard's
   `private-key`, a `security_audit` finding, ...), add a test proving it
   never does, the same way `test_security.py`'s
   `test_run_security_audit_never_leaks_a_secret` does.
5. Add the tool to the README's "Read-only" tools table, and to the
   relevant prose section below it if the tool is part of a larger workflow
   (e.g. "VPN & routing diagnostics").

### Adding a write tool

Follow the security-model checklist above throughout. Concretely:

1. Add a `MikrotikClient` method in `client.py` if the write needs a
   primitive beyond the existing `update`/`add`/`remove`/`start`/`stop`/
   `flush`/`wol`/`save`.
2. Add a `WriteOperation` entry to `guard.ALLOWLIST` in `guard.py` (path
   tuple + action + a one-line description).
3. Add a function in `guard.py`, modeled on `set_identity` (the module's
   own reference example): resolve the target (or check for a duplicate,
   for a creating tool), validate every input parameter via a
   `validation.py` validator, build the `before`/`after` `WritePreview`,
   and only call the device's write primitive - via `getattr(client,
   op.action)`, never a hardcoded method name, so `ALLOWLIST`'s `action`
   field actually governs what's dispatched - when `confirm=True`. Decorate
   it with `@_audited("your_operation_name")` so it's journaled like every
   other write.
4. If any input needs a new shape check, add a `validate_*` function to
   `validation.py` rather than inlining validation in `guard.py`.
5. Register a new `@mcp.tool()` function in `server.py`'s "Write tools"
   section that calls your `guard.py` function and passes `confirm`
   straight through, returning `asdict(preview)`.
6. Add the tool name to `EXPECTED_TOOLS` in `tests/test_server.py`.
7. Add tests in **three** places, following the existing tests as a
   template:
   - `tests/test_guard.py`: the guard function directly - blocked when
     `MIKROTIK_ALLOW_WRITE=false`, the read-only gate applies before the
     device is ever touched, a `confirm=False` preview changes nothing on
     the fake device, a `confirm=True` call applies it, not-found /
     already-exists / ambiguous-match error cases, and input validation
     rejecting bad values.
   - `tests/test_guard_audit.py`: the audit journal gets exactly one entry
     per call (preview, applied, or error outcome), and - if this tool's
     `before`/`after` can ever carry a secret-shaped field - a test proving
     it never reaches the journal, the same way
     `test_add_wireguard_interface_confirmed_call_never_leaks_private_key_into_journal`
     does.
   - `tests/test_server.py`: the tool registered and callable end-to-end
     through `mcp.call_tool(...)`, including that it's blocked without
     `MIKROTIK_ALLOW_WRITE=true`.
8. **Hardware note.** For a write tool that's sensitive - anything that can
   cut connectivity (touches the default route, disables an interface/
   firewall rule, ...), handles a credential/key, or was validated against
   real hardware rather than only the in-memory fake - add a short note to
   its docstring and/or the matching README section saying so: what real
   device/RouterOS generation (if any) it was confirmed against, and any
   risk a caller should know about before calling it with `confirm=True`
   (see `disable_route`'s `warning` field on the default route, or
   `set_wifi_ssid`'s "confirmed against real ROS7 hardware (a mANTBox)"
   note in README, for the shape this takes). A write tool that can lock an
   operator out of the device (see "Roadmap & non-goals" in README for the
   firewall-rule-creation example) needs a stronger justification than
   "the tests pass" before it will be merged at all - raise it as an issue
   first if you're not sure whether a new write tool crosses that line.
9. Add the tool to the README's "Write (guarded)" tools table, and to the
   relevant prose workflow section.

## Commit / PR conventions

- Keep PRs focused - one tool (or one closely related group) per PR is
  easier to review carefully than a batch of unrelated ones, given the
  security bar above.
- Update `CHANGELOG.md` for a user-visible change (a new tool, a behavior
  change, a bug fix).
- The PR template checklist (tests pass, `ruff`/`mypy` clean, security
  model respected, no secret committed, `CHANGELOG.md` updated) is the
  bar a reviewer will check against - fill it in honestly rather than as a
  formality.
