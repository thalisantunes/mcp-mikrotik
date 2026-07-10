---
name: Bug report
about: Something isn't working as documented
title: ""
labels: bug
assignees: ""
---

<!--
Before filing: if this looks like a security issue (a way to reach a write
without MIKROTIK_ALLOW_WRITE, a secret leaking into a log/error/audit-journal
entry, a way to reach an arbitrary RouterOS command, or anything else in that
spirit), please do NOT open a public issue - see SECURITY.md for private
reporting instead.
-->

**Describe the bug**

A clear description of what's wrong, and what you expected instead.

**Which tool(s)**

Which MCP tool(s) this affects (e.g. `set_client_bandwidth`, `wireguard_peers`).

**To reproduce**

Steps to reproduce, ideally as the exact tool call(s) and argument(s) used
(redact any real device hostname/credential first).

**Environment**

- `mcp-mikrotik` version (or commit): 
- Python version: 
- RouterOS version/generation (6.49+ "wireless" vs 7.x "wifi"), if relevant: 
- MCP client (Claude Desktop, Claude Code, other): 

**Logs**

Relevant server-side log lines (stderr), with the correlation id if you have
one - see README's "Correlation IDs". **Please redact any password, key, or
other credential before pasting** - this project is careful never to log one
itself, but double-check before sharing.

**Additional context**

Anything else that might help - e.g. whether this reproduces against the
fake device layer (a failing `pytest` case is the fastest way to get this
fixed) or only against real hardware.
