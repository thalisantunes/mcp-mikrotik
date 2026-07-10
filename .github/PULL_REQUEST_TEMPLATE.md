## What does this change

<!-- One or two sentences: what this PR does and why. -->

## Type of change

- [ ] New read-only tool
- [ ] New write tool (guarded)
- [ ] Bug fix
- [ ] Refactor / cleanup (no behavior change)
- [ ] Docs only
- [ ] CI / tooling

## Checklist

- [ ] `pytest -q` passes locally (and CI's matrix - 3.11/3.12/3.13 - is green)
- [ ] `ruff check .` and `ruff format --check .` are clean
- [ ] `mypy src/mcp_mikrotik` is clean
- [ ] New/changed behavior has tests, including error paths - not just the
      happy path (see CONTRIBUTING.md's "Test coverage")
- [ ] **Security model respected** (only relevant for a new/changed write
      tool - see CONTRIBUTING.md for the full checklist):
  - [ ] Blocked by the read-only gate (`MIKROTIK_ALLOW_WRITE=false`) before
        touching the device
  - [ ] Goes through `guard.ALLOWLIST` - one named `WriteOperation` + one
        dedicated function, never a generic "run this path/command" tool
  - [ ] Supports `confirm=False` (preview, no device write) /
        `confirm=True` (apply), with an honest `before`/`after`
  - [ ] Every input validated via a `validation.py` validator before use
  - [ ] Resolves an existing target by a stable field (name/comment/...),
        never a RouterOS `.id` or list index; never silently creates a
        duplicate
- [ ] **No secret in a log line, error message, or the audit journal** - if
      this tool's preview can ever carry a password/key, it's redacted
      **before** the `WritePreview` is constructed in `guard.py` (not one
      layer up in `server.py`)
- [ ] No credential, real device hostname/IP, or `devices.yaml` content
      committed (double-check `git diff` - see SECURITY.md's "Secret
      hygiene")
- [ ] README updated: tool added to the relevant table (+ prose section, if
      it's part of a documented workflow)
- [ ] `CHANGELOG.md` updated, for a user-visible change

## Hardware note

<!--
Only relevant for a write tool, or a change to how an existing one behaves.
Was this confirmed against real RouterOS hardware, or only against the
in-memory fake (tests/fakes.py)? If real hardware: which RouterOS
version/generation? If this tool can affect connectivity (default route,
an interface, a firewall rule, ...) or handles a credential/key, say so
explicitly here - see CONTRIBUTING.md point 8.
-->

## Test plan

<!-- How you validated this, beyond `pytest -q` passing. -->
