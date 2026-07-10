---
name: Feature request
about: Propose a new tool, or a change to an existing one
title: ""
labels: enhancement
assignees: ""
---

**What would you like to be able to do?**

Describe the use case, not just the RouterOS API call - e.g. "I want to
revoke a hotspot voucher" is more useful than "expose `/ip/hotspot/user/
remove`".

**Is this a read tool or a write tool?**

- [ ] Read-only
- [ ] Write (guarded - see below)

**If this is a write tool: which RouterOS API path(s)/action(s) would it
need?**

e.g. `/ip/hotspot/user`, action `remove`. See `guard.py`'s `ALLOWLIST` for
the shape every write tool takes - **this project will not add a generic
"run this path/command" tool**, see README's "Roadmap & non-goals". A
proposal for a new write tool should already have a resolution strategy in
mind (how the target is looked up - by name, by a stable field, ...) and
say whether it can create/duplicate something, since that shapes the
before/after preview and duplicate-checking guard.py needs.

**Does this touch anything already called out in "Roadmap & non-goals"?**

Device reboot, backup restore, and general firewall-filter-rule
authorship are deliberately out of scope today - see README for why. If
your request is one of these, it's worth reading that section first; a
proposal that addresses the specific concern raised there (e.g. a
staged/rollback mechanism) is welcome, but "just add it" isn't enough on
its own.

**Alternatives considered**

Anything you already tried, or considered and rejected, and why.

**Additional context**

Links to relevant RouterOS documentation, hardware/RouterOS-generation
this needs to work against, or anything else useful.
