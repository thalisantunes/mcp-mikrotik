"""Security audit + security-relevant log filtering (v0.12).

Both `run_security_audit` and `filter_security_events` back read-only MCP
tools (`security_audit`/`security_events` in server.py) - neither one is
gated by MIKROTIK_ALLOW_WRITE, and neither one changes anything on the
device. The goal is to give an LLM caller (or an operator) the "eyes" to
look at a device's configuration and recent log activity and flag things
worth a human decision, not to fix anything automatically.

HEURISTIC, NOT A DEFINITIVE SCANNER. Every check here is a best-effort,
conservative read of a handful of RouterOS menus - it can both under-report
(a real misconfiguration this module doesn't know to look for) and, for the
firewall-chain check in particular, over-report (see
`_check_firewall_input_drop`'s docstring). Findings are meant to prompt a
review, not to be treated as ground truth.

DEFENSIVE BY DESIGN: each individual check reads its own RouterOS menu(s)
and catches `DeviceCommandError` itself, treating "menu not present on this
device/RouterOS generation" as "this check has nothing to report" (an empty
list of findings) rather than an error - the same convention every other
optional-hardware read tool in this package already uses (see
`system_health`/`poe_status`/`lte_status` in server.py). One check failing
or being unavailable never stops the rest of the audit from running.

NO SECRET EVER APPEARS IN A FINDING. Every check below reads a menu at some
point - `/ip/service`, `/snmp/community`, `/interface/wireless/security-
profiles`, `/interface/wifi/security`, `/user` - that can carry a
password/passphrase/community-string-like field on some RouterOS version,
but no check ever copies a raw row (or a credential-shaped field from one)
into a `Finding`. Each finding's `detail`/`recommendation` text is built
from a fixed template referencing only non-secret fields (name, mode,
address restriction, boolean presence checks, counts) - see
`test_security_audit_never_leaks_secrets` in `tests/test_security.py`.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Callable, Iterable

from .client import MikrotikClient
from .exceptions import DeviceCommandError
from .formatting import ros_bool, rows_to_list

# --- Finding shape -----------------------------------------------------

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass
class Finding:
    severity: str  # "high" | "medium" | "low" | "info"
    category: str
    title: str
    detail: str
    recommendation: str


def _open_to_any(restriction: str | None) -> bool:
    """Whether a RouterOS "allowed from" address restriction is effectively
    unrestricted - an empty value or the explicit "0.0.0.0/0" (RouterOS's
    own way of spelling "any address"). Used by the management-services and
    SNMP checks; never inspects anything secret."""
    value = (restriction or "").strip()
    return value in ("", "0.0.0.0/0")


# --- Check 1: insecure management services (/ip/service) ---------------

# Non-SSL/cleartext management protocols this check flags when *enabled* at
# all. ssh/api-ssl/www-ssl are deliberately excluded - they are the secure
# counterparts a caller is expected to prefer, not something this check
# second-guesses.
_INSECURE_SERVICES = {"telnet", "ftp", "www", "api"}
_HIGH_IF_OPEN = {"telnet", "ftp"}
_MEDIUM_IF_OPEN = {"www", "api"}


def _check_management_services(client: MikrotikClient) -> list[Finding]:
    try:
        rows = rows_to_list(client.path("ip", "service"))
    except DeviceCommandError:
        return []

    findings: list[Finding] = []
    for row in rows:
        name = (row.get("name") or "").strip().lower()
        if ros_bool(row.get("disabled", False)):
            continue
        # RouterOS's own /ip/service field for the "available from" address
        # restriction is called "address" (despite the CLI column header
        # reading "ADDRESS" too) - not to be confused with a device's own IP.
        open_to_any = _open_to_any(row.get("address"))

        if name in _INSECURE_SERVICES:
            if open_to_any:
                severity = "high" if name in _HIGH_IF_OPEN else "medium"
                findings.append(
                    Finding(
                        severity=severity,
                        category="management-services",
                        title=f"Insecure service '{name}' is enabled and open to any address",
                        detail=(
                            f"/ip/service '{name}' is enabled (a cleartext/non-SSL management "
                            "protocol) with no 'address' restriction (empty or 0.0.0.0/0) - "
                            "reachable from anywhere that can route to this device."
                        ),
                        recommendation=(
                            f"Disable '{name}' if it isn't needed, or switch to its SSL/SSH "
                            "equivalent (api-ssl/www-ssl/ssh) and restrict 'address' to a known "
                            "management subnet."
                        ),
                    )
                )
            else:
                findings.append(
                    Finding(
                        severity="low",
                        category="management-services",
                        title=f"Insecure service '{name}' is enabled",
                        detail=(
                            f"/ip/service '{name}' is enabled - a cleartext/non-SSL management "
                            f"protocol - though access is at least restricted to "
                            f"{row.get('address')!r}."
                        ),
                        recommendation=(
                            f"Disable '{name}' if it isn't needed, or migrate to its SSL/SSH "
                            "equivalent (api-ssl/www-ssl/ssh)."
                        ),
                    )
                )
        elif name == "winbox" and open_to_any:
            findings.append(
                Finding(
                    severity="medium",
                    category="management-services",
                    title="Winbox service is open to any address",
                    detail=(
                        "/ip/service 'winbox' has no 'address' restriction (empty or 0.0.0.0/0) - "
                        "reachable from anywhere that can route to this device."
                    ),
                    recommendation=(
                        "Restrict winbox's 'address' field to a known management subnet or VPN "
                        "range."
                    ),
                )
            )
    return findings


# --- Check 2: firewall input chain has no final drop/reject ------------


def _check_firewall_input_drop(client: MikrotikClient) -> list[Finding]:
    """Conservative heuristic: looks for a drop/reject rule among the
    ENABLED rules on chain=input, and specifically checks whether the LAST
    one (in the order RouterOS itself returns them, which is also the order
    rules are evaluated in) is a drop/reject.

    This is deliberately NOT a claim that the input chain is provably
    (un)protected - RouterOS's evaluation semantics (jump chains, `disabled`
    entries interleaved, address-list-based matches, etc.) are richer than a
    single boolean this check can determine from the rule list alone. It
    exists to prompt a human review, not to replace one - see this module's
    docstring and README's "Security audit" section.
    """
    try:
        rows = rows_to_list(client.path("ip", "firewall", "filter"))
    except DeviceCommandError:
        return []

    input_rules = [row for row in rows if row.get("chain") == "input" and not ros_bool(row.get("disabled", False))]

    if not input_rules:
        return [
            Finding(
                severity="medium",
                category="firewall",
                title="No enabled firewall rules on the input chain",
                detail=(
                    "/ip/firewall/filter has no enabled rules on chain=input - RouterOS's "
                    "default policy (accept) applies to all traffic destined to the device "
                    "itself."
                ),
                recommendation=(
                    "Add an input chain with rules allowing only the management "
                    "services/sources you intend, ending in an explicit drop/reject rule."
                ),
            )
        ]

    last_action = (input_rules[-1].get("action") or "").strip().lower()
    if last_action not in ("drop", "reject"):
        return [
            Finding(
                severity="medium",
                category="firewall",
                title="Input chain does not end in a drop/reject rule",
                detail=(
                    f"{len(input_rules)} enabled rule(s) on chain=input; the last one has "
                    f"action={last_action!r}, not drop/reject. Heuristic check based on rule "
                    "order alone - review the ruleset to confirm whether unmatched input "
                    "traffic is actually blocked."
                ),
                recommendation=(
                    "Add (or move) a drop/reject rule to the end of the input chain to block "
                    "unmatched management traffic, unless this is intentional."
                ),
            )
        ]
    return []


# --- Check 3: SNMP community open (/snmp/community) ---------------------


def _check_snmp(client: MikrotikClient) -> list[Finding]:
    try:
        rows = rows_to_list(client.path("snmp", "community"))
    except DeviceCommandError:
        return []

    findings: list[Finding] = []
    for row in rows:
        name = (row.get("name") or "").strip()
        # RouterOS's own /snmp/community field restricting which hosts may
        # query this community is "addresses" (a list, default 0.0.0.0/0).
        unrestricted = _open_to_any(row.get("addresses"))
        if name.lower() == "public" or unrestricted:
            reasons = []
            if name.lower() == "public":
                reasons.append("uses the default community name 'public'")
            if unrestricted:
                reasons.append("has no 'addresses' restriction (empty or 0.0.0.0/0)")
            findings.append(
                Finding(
                    severity="medium",
                    category="snmp",
                    title=f"SNMP community {name!r} is open",
                    detail=(
                        f"/snmp/community {name!r} " + " and ".join(reasons) + " - readable by "
                        "any host that can reach the SNMP port."
                    ),
                    recommendation=(
                        "Rename the community away from the default 'public' and restrict "
                        "'addresses' to known monitoring hosts."
                    ),
                )
            )
    return findings


# --- Check 4: DNS resolver open to remote requests (/ip/dns) -----------


def _check_dns_open_resolver(client: MikrotikClient) -> list[Finding]:
    try:
        rows = rows_to_list(client.path("ip", "dns"))
    except DeviceCommandError:
        return []
    if not rows:
        return []

    settings_row = rows[0]
    if ros_bool(settings_row.get("allow-remote-requests", False)):
        return [
            Finding(
                severity="medium",
                category="dns",
                title="DNS resolver accepts remote requests",
                detail=(
                    "/ip/dns has allow-remote-requests=yes - the device answers DNS queries "
                    "from any client that can reach port 53. An open resolver like this can be "
                    "abused for DNS amplification/reflection attacks if it isn't also restricted "
                    "by the firewall."
                ),
                recommendation=(
                    "Disable allow-remote-requests unless this device is meant to be a resolver "
                    "for trusted clients, and/or restrict UDP/TCP port 53 in the input chain to "
                    "known client subnets."
                ),
            )
        ]
    return []


# --- Check 5: RouterOS version outdated ---------------------------------


def _check_routeros_version(client: MikrotikClient) -> list[Finding]:
    try:
        rows = rows_to_list(client.path("system", "package", "update"))
    except DeviceCommandError:
        return []
    if not rows:
        return []

    row = rows[0]
    installed = row.get("installed-version")
    latest = row.get("latest-version")
    if not installed or not latest:
        # Device hasn't checked for updates yet, or is offline - nothing
        # reliable to compare; skip rather than guess.
        return []
    if installed != latest:
        return [
            Finding(
                severity="low",
                category="routeros-version",
                title="RouterOS is not on the latest available version",
                detail=(
                    f"/system/package/update reports installed version {installed!r}, latest "
                    f"available {latest!r}."
                ),
                recommendation=(
                    "Review the RouterOS changelog and schedule an update - newer releases "
                    "commonly include security fixes."
                ),
            )
        ]
    return []


# --- Check 6: open wireless/wifi (no security) --------------------------


def _check_open_wireless(client: MikrotikClient) -> list[Finding]:
    findings: list[Finding] = []

    # ROS6: /interface/wireless/security-profiles, mode=none == no security
    # at all. Only the profile `name`/`mode` are ever read into a finding -
    # never a key/passphrase field.
    try:
        ros6_profiles = rows_to_list(client.path("interface", "wireless", "security-profiles"))
    except DeviceCommandError:
        ros6_profiles = []
    for row in ros6_profiles:
        if (row.get("mode") or "").strip().lower() == "none":
            name = row.get("name", "")
            findings.append(
                Finding(
                    severity="high",
                    category="wireless",
                    title=f"Wireless security profile {name!r} has no security (open network)",
                    detail=(
                        f"/interface/wireless/security-profiles {name!r} has mode=none - any "
                        "client can associate without authentication."
                    ),
                    recommendation=(
                        "Set mode=dynamic-keys with WPA2/WPA3 and a strong pre-shared key (or "
                        "802.1X), or remove/disable the profile if it isn't used."
                    ),
                )
            )

    # ROS7: /interface/wifi/security - a config with no passphrase AND no
    # authentication-types configured is effectively open. Only a boolean
    # "is a passphrase set" is ever computed - the passphrase VALUE itself
    # is never read into a finding.
    try:
        ros7_security = rows_to_list(client.path("interface", "wifi", "security"))
    except DeviceCommandError:
        ros7_security = []
    for row in ros7_security:
        has_passphrase = bool(row.get("passphrase"))
        authentication_types = (row.get("authentication-types") or "").strip()
        if not has_passphrase and not authentication_types:
            name = row.get("name", "")
            findings.append(
                Finding(
                    severity="high",
                    category="wireless",
                    title=f"WiFi security config {name!r} has no passphrase (open network)",
                    detail=(
                        f"/interface/wifi/security {name!r} has no passphrase and no "
                        "authentication-types configured - any client can associate without "
                        "authentication."
                    ),
                    recommendation=(
                        "Configure a passphrase and authentication-types (WPA2-PSK/WPA3-SAE) on "
                        "this security config, or remove/disable it if it isn't used."
                    ),
                )
            )
    return findings


# --- Check 7: users with a sensitive (write/full) policy ----------------

_SENSITIVE_GROUPS = {"full", "write"}


def _check_users(client: MikrotikClient) -> list[Finding]:
    try:
        rows = rows_to_list(client.path("user"))
    except DeviceCommandError:
        return []
    if not rows:
        return []

    sensitive_names = sorted(
        (row.get("name") or "") for row in rows if (row.get("group") or "").strip().lower() in _SENSITIVE_GROUPS
    )
    if not sensitive_names:
        return []

    return [
        Finding(
            severity="info",
            category="users",
            title=f"{len(sensitive_names)} of {len(rows)} user(s) have a write/full policy",
            detail=(
                f"/user account(s) with a write/full group: {', '.join(sensitive_names)}. "
                "Informational visibility only - not a vulnerability by itself."
            ),
            recommendation="Review whether every account with write/full access still needs it.",
        )
    ]


# --- Aggregation ----------------------------------------------------------

_CHECKS: tuple[Callable[[MikrotikClient], list[Finding]], ...] = (
    _check_management_services,
    _check_firewall_input_drop,
    _check_snmp,
    _check_dns_open_resolver,
    _check_routeros_version,
    _check_open_wireless,
    _check_users,
)


def run_security_audit(client: MikrotikClient) -> dict[str, Any]:
    """Run every check and return `{"findings": [...], "summary": {...}}`.

    Each check already catches `DeviceCommandError` around its own reads
    (see each `_check_*` function above) so a menu missing on this
    device/RouterOS generation just means that check contributes no
    findings. The `except DeviceCommandError: continue` here is a second,
    outer backstop - if a check is ever added later without its own
    try/except, one unavailable menu still can't take down the rest of the
    audit.

    `findings` is sorted by severity (high, medium, low, info); `summary`
    counts findings per severity, always including all four keys (zero for
    a severity with no findings).
    """
    findings: list[Finding] = []
    for check in _CHECKS:
        try:
            findings.extend(check(client))
        except DeviceCommandError:
            continue

    findings.sort(key=lambda finding: _SEVERITY_ORDER.get(finding.severity, len(_SEVERITY_ORDER)))

    summary = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        summary[finding.severity] = summary.get(finding.severity, 0) + 1

    return {
        "findings": [asdict(finding) for finding in findings],
        "summary": summary,
    }


# --- security_events -------------------------------------------------------

# Topic substrings that mark a /log row as security-relevant on their own:
# "account" (RouterOS's own topic for login/logout/authentication-failure
# events), "critical", "error".
_SECURITY_TOPIC_KEYWORDS = ("account", "critical", "error")

# For a generic "system,info" row (no "account" topic), fall back to
# matching common RouterOS login/logout message text - best-effort, not an
# exhaustive grammar (same spirit as validation.py's shape-only checks).
_LOGIN_MESSAGE_KEYWORDS = (
    "logged in",
    "logged out",
    "login failure",
    "user has logged in",
    "user has logged out",
)


def _is_security_event(row: dict[str, Any]) -> bool:
    topics = (row.get("topics") or "").lower()
    if any(keyword in topics for keyword in _SECURITY_TOPIC_KEYWORDS):
        return True
    message = (row.get("message") or "").lower()
    if "system" in topics and "info" in topics and any(keyword in message for keyword in _LOGIN_MESSAGE_KEYWORDS):
        return True
    return False


def filter_security_events(rows: Iterable[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    """Filter `/log` rows down to security-relevant ones, then keep the last
    `limit` matches (most recent last) - same "filter first, then cut"
    order `logs`' `topics` filter already uses (server.py), so a caller
    always gets the most recent `limit` MATCHING entries, not the last
    `limit` raw entries filtered afterward (which would silently drop
    matches on a busy log).
    """
    matches = [row for row in rows if _is_security_event(row)]
    return matches[-limit:]
